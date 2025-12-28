package qotp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"
)

func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (s *Stream, err error) {
	data := make([]byte, l.mtu)
	n, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(data, timeoutNano, nowNano)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			return nil, nil // Timeout is normal, return no dataToSend/error
		} else {
			slog.Error("Listen/Error", slog.Any("error", err))
			return nil, err
		}
	}
	if n == 0 {
		return nil, nil
	}

	conn, payload, msgType, err := l.decode(data[:n], remoteAddr)
	if err != nil {
		return nil, err
	}

	if nowNano > conn.lastReadTimeNano {
		conn.lastReadTimeNano = nowNano
	}

	var p *payloadHeader
	if len(payload) == 0 && msgType == InitSnd { //InitSnd is the only message without any payload
		p = &payloadHeader{}
		data = []byte{}
	} else {
		p, data, err = DecodePayload(payload)
		if err != nil {
			slog.Info("error in decoding payload from new connection", slog.Any("error", err))
			return nil, err
		}
	}

	s, err = conn.decode(p, data, nowNano)
	if err != nil {
		return nil, err
	}

	//Set state
	if !conn.isHandshakeDoneOnRcv {
		if conn.isSenderOnInit {
			if msgType == InitRcv || msgType == InitCryptoRcv {
				conn.isHandshakeDoneOnRcv = true
			}
		} else {
			if msgType == Data {
				conn.isHandshakeDoneOnRcv = true
			}
		}
	}

	return s, nil
}

// Flush sends pending data for all connections using round-robin
func (l *Listener) Flush(nowNano uint64) (minPacing uint64) {

	minPacing = MinDeadLine
	if l.connMap.Size() == 0 {
		//if we do not have at least one connection, exit
		return minPacing
	}

	closeConn := []*conn{}
	closeStream := map[*conn][]uint32{}
	isDataSent := false

	iter := NestedIterator(l.connMap, func(conn *conn) *LinkedMap[uint32, *Stream] {
		return conn.streams
	}, l.currentConnID, l.currentStreamID)

	for conn, stream := range iter {
		dataSent, pacingNano, err := conn.sendNext(stream, nowNano)
		if err != nil {
			slog.Info("closing connection, err", slog.Any("err", err))
			closeConn = append(closeConn, conn)
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
			closeConn = append(closeConn, conn)
			break
		}

		if pacingNano < minPacing {
			minPacing = pacingNano
		}
	}

	for _, closeConn := range closeConn {
		closeConn.cleanupConn()
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
