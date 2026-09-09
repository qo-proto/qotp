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
// Event loop: Listen receives one packet, Flush sends one, Loop alternates
// =============================================================================

// Listen reads and processes one packet. Returns the stream that received
// data, or nil on timeout.
func (l *Listener) Listen(timeoutNano uint64, nowNano uint64) (*Stream, error) {
	n, rAddr, lAddr, elapsedNano, err := l.localConn.ReadFromUDPAddrPort(l.readBuf, timeoutNano, nowNano)
	nowNano += elapsedNano // the arrival time

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

	if len(encData) < minPacketSize {
		return nil, fmt.Errorf("packet too small: %d bytes", len(encData))
	}
	header := encData[0]
	if version := header & 0x1F; version != cryptoVersion {
		return nil, errors.New("unsupported version")
	}
	msgType := cryptoMsgType(header >> 5)

	c, payload, sn, err := decodePacket(l, encData, rAddr, msgType)
	if err != nil {
		return nil, err
	}

	if nowNano > c.lastReadTimeNano {
		c.lastReadTimeNano = nowNano
	}
	if lAddr.IsValid() {
		c.localAddr = lAddr
	}

	var p *payloadHeader
	if len(payload) == 0 && msgType == initSnd { // InitSnd has no payload
		p = &payloadHeader{}
		payload = []byte{}
	} else {
		p, payload, err = decodeProto(payload)
		if err != nil {
			slog.Info("error decoding payload", slog.Any("error", err))
			return nil, err
		}
	}

	s, err := c.processIncomingPayload(p, payload, sn, nowNano)
	if err != nil {
		return nil, err
	}

	// The initiator is ready on the init reply, the responder on the first
	// Data message
	if c.phase < phaseReady {
		if c.isInitiator() {
			if msgType == initRcv || msgType == initCryptoRcv {
				c.phase = phaseReady
			}
		} else if msgType == data {
			c.phase = phaseReady
		}
	}

	return s, nil
}

// Flush sends one packet, round-robin over connections and streams, and
// returns how long until the next send is due
func (l *Listener) Flush(nowNano uint64) uint64 {
	minPacing := minDeadline
	if l.connMap.size() == 0 {
		return minPacing
	}

	startStreamID := l.currentStreamID

	for _, c := range l.connMap.iterator(l.currentConnID) {
		for _, stream := range c.streams.iterator(startStreamID) {
			dataSent, pacingNano, err := c.flushStream(stream, nowNano)
			if err != nil {
				slog.Info("closing connection", slog.Any("err", err))
				l.connMap.remove(c.connId)
				return minPacing
			}

			// Removing the cursor entry ends this walk; the rest of the
			// streams get their turn on the next Flush
			if stream.rcvClosed.Load() && stream.sndClosed.Load() && !c.rcv.hasPendingAckForStream(stream.streamID) {
				c.cleanupStream(stream.streamID)
				continue
			}

			if dataSent > 0 {
				l.currentConnID = &c.connId
				l.currentStreamID = &stream.streamID
				return 0
			}

			if c.lastReadTimeNano != 0 && nowNano > c.lastReadTimeNano+readDeadline {
				slog.Info("close connection, timeout",
					slog.Uint64("now", nowNano),
					slog.Uint64("last", c.lastReadTimeNano))
				l.connMap.remove(c.connId)
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

// Loop runs until the context is cancelled or an error occurs. The callback
// runs after every Listen, with a nil stream on timeout, for periodic work.
func (l *Listener) Loop(ctx context.Context, callback func(ctx context.Context, s *Stream) error) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		waitNextNano := l.Flush(uint64(time.Now().UnixNano()))

		s, err := l.Listen(waitNextNano, uint64(time.Now().UnixNano()))
		if err != nil {
			return err
		}

		if err := callback(ctx, s); err != nil {
			return err
		}
	}
}
