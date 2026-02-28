package qotp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"
)

// =============================================================================
// Event loop - Read/Write coordination
//
// Listen() receives and processes one packet
// Flush() sends pending data using round-robin across connections/streams
// Loop() combines both in a blocking event loop
// =============================================================================

// Listen reads one packet, decrypts it, and processes the payload.
// Returns the stream that received data, or nil on timeout/no-data.
func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (*Stream, error) {
	n, rAddr, err := l.localConn.ReadFromUDPAddrPort(l.readBuf, timeoutNano, nowNano)

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

	encData := l.readBuf[:n]

	// Parse and validate header
	if len(encData) < minPacketSize {
		return nil, fmt.Errorf("packet too small: %d bytes", len(encData))
	}
	header := encData[0]
	if version := header & 0x1F; version != cryptoVersion {
		return nil, errors.New("unsupported version")
	}
	msgType := cryptoMsgType(header >> 5)

	// Decrypt and get/create connection
	c, payload, err := decodePacket(l, encData, rAddr, msgType)
	if err != nil {
		return nil, err
	}

	if nowNano > c.lastReadTimeNano {
		c.lastReadTimeNano = nowNano
	}

	// Decode transport layer payload
	var p *payloadHeader
	if len(payload) == 0 && msgType == initSnd {
		// InitSnd has no payload - create empty header
		p = &payloadHeader{}
		payload = []byte{}
	} else {
		p, payload, err = decodeProto(payload)
		if err != nil {
			slog.Info("error decoding payload", slog.Any("error", err))
			return nil, err
		}
	}

	s, err := c.processIncomingPayload(p, payload, nowNano)
	if err != nil {
		return nil, err
	}

	// Handshake completes when:
	// - Sender receives InitRcv/InitCryptoRcv
	// - Receiver receives first Data message
	if c.phase < phaseReady {
		switch {
		case (c.initMsgType == initCryptoSnd || c.initMsgType == initSnd) && (msgType == initRcv || msgType == initCryptoRcv):
			c.phase = phaseReady
		case !(c.initMsgType == initCryptoSnd || c.initMsgType == initSnd) && (msgType == data):
			c.phase = phaseReady
		}
	}

	return s, nil
}

// Flush sends pending data for all connections using round-robin.
// Returns minimum pacing interval until next send opportunity.
func (l *Listener) Flush(nowNano uint64) uint64 {
	minPacing := MinDeadLine
	if l.connMap.size() == 0 {
		return minPacing
	}

	var closeConnIds []uint64
	closeStreams := map[*conn][]uint32{}

	//needs to be defer, otherwise we lock ourselfs out.
	defer func() {
		for _, connId := range closeConnIds {
			l.cleanupConn(connId)
		}
		for conn, streamIDs := range closeStreams {
			for _, streamID := range streamIDs {
				conn.cleanupStream(streamID)
			}
		}
	}()

	startStreamID := l.currentStreamID

	for _, conn := range l.connMap.iterator(l.currentConnID) {
		for _, stream := range conn.streams.iterator(startStreamID) {
			dataSent, pacingNano, err := conn.flushStream(stream, nowNano)
			if err != nil {
				slog.Info("closing connection", slog.Any("err", err))
				closeConnIds = append(closeConnIds, conn.connId)
				l.currentConnID = nil
				l.currentStreamID = nil
				return minPacing
			}

			if stream.rcvClosed && stream.sndClosed && !conn.rcv.hasPendingAckForStream(stream.streamID) {
				closeStreams[conn] = append(closeStreams[conn], stream.streamID)
				continue
			}

			if dataSent > 0 {
				l.currentConnID = &conn.connId
				l.currentStreamID = &stream.streamID
				return 0
			}

			if conn.lastReadTimeNano != 0 && nowNano > conn.lastReadTimeNano+ReadDeadLine {
				slog.Info("close connection, timeout",
					slog.Uint64("now", nowNano),
					slog.Uint64("last", conn.lastReadTimeNano))
				closeConnIds = append(closeConnIds, conn.connId)
				l.currentConnID = nil
				l.currentStreamID = nil
				return minPacing
			}

			if pacingNano < minPacing {
				minPacing = pacingNano
			}
		}
		startStreamID = nil
	}

	l.currentConnID = nil
	l.currentStreamID = nil
	return minPacing
}

// Loop runs the event loop until context is cancelled or error occurs.
// Callback is invoked after each Listen(), even if stream is nil (allows periodic work).
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

		if err := callback(ctx, s); err != nil {
			return err
		}

		waitNextNano = l.Flush(uint64(time.Now().UnixNano()))
	}
}
