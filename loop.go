package qotp

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (*Stream, error) {
	data := make([]byte, l.mtu)
	n, rAddr, err := l.localConn.ReadFromUDPAddrPort(data, timeoutNano, nowNano)

	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		slog.Error("Listen/Error", slog.Any("error", err))
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}

	encData := data[:n]

	// Parse header
	if len(encData) < MinPacketSize {
		return nil, fmt.Errorf("packet too small: %d bytes", len(encData))
	}
	header := encData[0]
	if version := header & 0x1F; version != CryptoVersion {
		return nil, errors.New("unsupported version")
	}
	msgType := cryptoMsgType(header >> 5)

	// Decrypt and get/create connection
	conn, payload, err := decodePacket(l, encData, rAddr, msgType)
	if err != nil {
		return nil, err
	}

	if nowNano > conn.lastReadTimeNano {
		conn.lastReadTimeNano = nowNano
	}

	// Decode payload
	var p *payloadHeader
	if len(payload) == 0 && msgType == InitSnd {
		p = &payloadHeader{}
		payload = []byte{}
	} else {
		p, payload, err = decodePayload(payload)
		if err != nil {
			slog.Info("error decoding payload", slog.Any("error", err))
			return nil, err
		}
	}

	s, err := conn.handlePayload(p, payload, nowNano)
	if err != nil {
		return nil, err
	}

	// Update handshake state
	if !conn.isHandshakeDoneOnRcv {
		switch {
		case conn.isSenderOnInit && (msgType == InitRcv || msgType == InitCryptoRcv):
			conn.isHandshakeDoneOnRcv = true
		case !conn.isSenderOnInit && msgType == Data:
			conn.isHandshakeDoneOnRcv = true
		}
	}

	return s, nil
}

func (l *Listener) handleIncomingInit(encData []byte, rAddr netip.AddrPort, msgType cryptoMsgType) (
	*conn, []byte, error) {

	connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])

	switch msgType {
	case InitSnd:
		pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(encData, l.mtu)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitSnd: %w", err)
		}

		conn, err := l.getOrCreateConn(connId, rAddr, pubKeyIdSnd, pubKeyEpSnd, false, false)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := conn.prvKeyEpSnd.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDH: %w", err)
		}
		conn.sharedSecret = sharedSecret

		return conn, []byte{}, nil

	case InitCryptoSnd:
		pubKeyIdSnd, pubKeyEpSnd, message, err := decryptInitCryptoSnd(encData, l.prvKeyId, l.mtu)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitCryptoSnd: %w", err)
		}

		conn, err := l.getOrCreateConn(connId, rAddr, pubKeyIdSnd, pubKeyEpSnd, false, true)
		if err != nil {
			return nil, nil, err
		}

		sharedSecret, err := conn.prvKeyEpSnd.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDH: %w", err)
		}
		conn.sharedSecret = sharedSecret

		return conn, message.PayloadRaw, nil
	}

	return nil, nil, errors.New("invalid init message type")
}

func (l *Listener) getOrCreateConn(
	connId uint64,
	rAddr netip.AddrPort,
	pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey,
	isSender, withCrypto bool,
) (*conn, error) {

	if conn, exists := l.connMap.Get(connId); exists {
		return conn, nil
	}

	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	return l.newConn(connId, rAddr, prvKeyEp, pubKeyIdRcv, pubKeyEpRcv, isSender, withCrypto)
}

func (l *Listener) handleIncomingReply(encData []byte, msgType cryptoMsgType) (
	*conn, []byte, error) {

	connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
	conn, exists := l.connMap.Get(connId)
	if !exists {
		return nil, nil, fmt.Errorf("connection not found: %d", connId)
	}

	switch msgType {
	case InitRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(encData, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		conn.pubKeyIdRcv = pubKeyIdRcv
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret
		return conn, message.PayloadRaw, nil

	case InitCryptoRcv:
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret
		return conn, message.PayloadRaw, nil

	case Data:
		message, err := decryptData(encData, conn.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, err
		}
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
		}
		return conn, message.PayloadRaw, nil
	}

	return nil, nil, errors.New("invalid reply message type")
}

// Flush sends pending data for all connections using round-robin
func (l *Listener) Flush(nowNano uint64) (minPacing uint64) {

	minPacing = MinDeadLine
	if l.connMap.Size() == 0 {
		//if we do not have at least one connection, exit
		return minPacing
	}

	closeConnId := []uint64{}
	closeStream := map[*conn][]uint32{}
	isDataSent := false

	iter := NestedIterator(l.connMap, func(conn *conn) *LinkedMap[uint32, *Stream] {
		return conn.streams
	}, l.currentConnID, l.currentStreamID)

	for conn, stream := range iter {
		dataSent, pacingNano, err := conn.sendNext(stream, nowNano)
		if err != nil {
			slog.Info("closing connection, err", slog.Any("err", err))
			closeConnId = append(closeConnId, conn.connId)
			break
		}

		if stream.rcvClosed && stream.sndClosed && !conn.rcv.HasPendingAckForStream(stream.streamID) {
			closeStream[conn] = append(closeStream[conn], stream.streamID)
			continue
		}

		if dataSent > 0 {
			// data sent, returning early
			minPacing = 0
			l.currentConnID = &conn.connId
			l.currentStreamID = &stream.streamID
			isDataSent = true
			break
		}

		//no data sent, check if we reached the timeout for the activity
		if conn.lastReadTimeNano != 0 && nowNano > conn.lastReadTimeNano+ReadDeadLine {
			slog.Info("close connection, timeout", slog.Uint64("now", nowNano),
				slog.Uint64("last", conn.lastReadTimeNano))
			closeConnId = append(closeConnId, conn.connId)
			break
		}

		if pacingNano < minPacing {
			minPacing = pacingNano
		}
	}

	for _, connId := range closeConnId {
		l.cleanupConn(connId)
	}

	for conn, streamIDs := range closeStream {
		for _, streamID := range streamIDs {
			conn.cleanupStream(streamID, nowNano)
		}
	}

	// Only reset if we completed full iteration without sending
	if !isDataSent {
		l.currentConnID = nil
		l.currentStreamID = nil
	}
	return minPacing
}

func (l *Listener) Loop(ctx context.Context, callback func(ctx context.Context, s *Stream) error) error {
	waitNextNano := MinDeadLine
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		s, err := l.Listen(waitNextNano, uint64(time.Now().UnixNano()))
		if err != nil {
			return err
		}
		// callback in any case, s may be null, but this gives the user
		// the control to cancel the Loop every MinDeadLine
		err = callback(ctx, s)
		if err != nil {
			return err
		}
		waitNextNano = l.Flush(uint64(time.Now().UnixNano()))
		//if waitNextNano is zero, we still have data to flush, do not exit yet
		//TODO
	}
}
