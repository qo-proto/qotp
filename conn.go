package qotp

import (
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

type Conn struct {
	// Connection identification
	connId     uint64
	remoteAddr netip.AddrPort

	// Core components
	listener *Listener
	streams  *LinkedMap[uint32, *Stream]

	// Cryptographic keys
	prvKeyEpSnd *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
	pubKeyIdRcv *ecdh.PublicKey

	// Shared secrets
	sharedSecret []byte

	// Buffers and flow control
	snd          *SendBuffer
	rcv          *ReceiveBuffer
	dataInFlight int
	rcvWndSize   uint64

	// Connection state
	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool

	nextWriteTime uint64

	// Crypto and performance
	snCrypto       uint64 //this is 48bit
	epochCryptoSnd uint64 //this is 47bit
	epochCryptoRcv uint64 //this is 47bit
	Measurements

	mu sync.Mutex
}

func (c *Conn) msgType() CryptoMsgType {
	if c.isHandshakeDoneOnRcv {
		return Data
	}

	switch {
	case c.isWithCryptoOnInit && c.isSenderOnInit:
		return InitCryptoSnd
	case c.isWithCryptoOnInit && !c.isSenderOnInit:
		return InitCryptoRcv
	case c.isSenderOnInit:
		return InitSnd
	default:
		return InitRcv
	}
}

func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range c.streams.Iterator(nil) {
		if s != nil {
			s.Close()
		}
	}
}

func (c *Conn) Stream(streamID uint32) (s *Stream) {
	//c.mu.Lock()
	//defer c.mu.Unlock() Deadlock

	v := c.streams.Get(streamID)
	if v != nil {
		return v
	}

	s = &Stream{
		streamID: streamID,
		conn:     c,
		mu:       sync.Mutex{},
	}
	c.streams.Put(streamID, s)
	return s
}

func (c *Conn) decode(p *PayloadHeader, userData []byte, rawLen int, nowNano uint64) (s *Stream, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s = c.Stream(p.StreamID)
	if p.Ack != nil {
		ackStatus, sentTimeNano := c.snd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		if ackStatus == AckStatusOk {
			c.dataInFlight -= rawLen
		} else if ackStatus == AckDup {
			c.onDuplicateAck()
		} else {
			slog.Debug("No stream?")
		}
		c.rcvWndSize = p.Ack.rcvWnd

		closeOffset := c.snd.GetOffsetClosedAt(p.StreamID)
		if closeOffset != nil {
			ackedOffset := c.snd.GetOffsetAcked(s.streamID)
			//it is marked to close
			if ackedOffset >= *closeOffset {
				//we got all data, mark as closed
				s.closedAtNano = nowNano
			}
		}
		slog.Debug("  here2")

		if nowNano > sentTimeNano {
			if ackStatus == AckStatusOk {
				rttNano := nowNano - sentTimeNano
				c.updateMeasurements(rttNano, uint64(p.Ack.len), nowNano)
			} else {
				return nil, errors.New("stream does not exist")
			}
		}
		slog.Debug("  here3")
	}

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, nowNano, userData)
	} else if p.MsgType == MsgTypeClose || p.MsgType == MsgTypePing {
		c.rcv.EmptyInsert(s.streamID, p.StreamOffset, nowNano)
	}

	if p.MsgType == MsgTypeClose {
		c.rcv.Close(s.streamID, p.StreamOffset)
		c.snd.Close(s.streamID) //also close the send buffer at the current location
	}

	return s, nil
}

// We need to check if we remove the current state, if yes, then move the state to the previous stream
func (c *Conn) cleanupStream(streamID uint32) {
	slog.Debug("Cleanup/Stream", gId(), c.debug(), slog.Uint64("streamID", uint64(streamID)))

	if c.listener.currentStreamID != nil && streamID == *c.listener.currentStreamID {
		*c.listener.currentStreamID, _, _ = c.streams.Next(streamID)
	}
	c.streams.Remove(streamID)
	//even if the stream size is 0, do not remove the connection yet, only after a certain timeout,
	// so that BBR, RTT, is preserved for a bit
}

func (c *Conn) cleanupConn() {
	slog.Debug("Cleanup/Stream", gId(), c.debug(),
		slog.Uint64("connID", c.connId), slog.Any("currId", c.listener.currentConnID))

	if c.listener.currentConnID != nil && c.connId == *c.listener.currentConnID {
		*c.listener.currentConnID, _, _ = c.listener.connMap.Next(c.connId)
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Conn) Flush(s *Stream, nowNano uint64) (data int, pacingNano uint64, err error) {
	//update state for receiver
	ack := c.rcv.GetSndAck()
	if ack != nil {
		ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.Size())
	}

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug(" Flush/Pacing", gId(), s.debug(), c.debug(),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano),
			slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		return 0, c.nextWriteTime - nowNano, nil
	}

	//Respect rwnd
	if c.dataInFlight+int(c.listener.mtu) > int(c.rcvWndSize) {
		slog.Debug(" Flush/Rwnd/Rcv", gId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		return 0, MinDeadLine, nil
	}

	// Retransmission case
	msgType := c.msgType()
	splitData, offset, msgTypeRet, err := c.snd.ReadyToRetransmit(s.streamID, ack, c.listener.mtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}

	if splitData != nil {
		c.onPacketLoss()

		slog.Debug(" Flush/Retransmit", gId(), s.debug(), c.debug())

		p := &PayloadHeader{
			MsgType:      msgTypeRet,
			Ack:          ack,
			StreamID:     s.streamID,
			StreamOffset: offset,
		}

		encData, err := c.encode(p, splitData, msgType)
		if err != nil {
			return 0, 0, err
		}

		err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
		if err != nil {
			return 0, 0, err
		}

		packetLen := len(splitData)
		pacingNano = c.calcPacing(uint64(packetLen))

		c.nextWriteTime = nowNano + pacingNano
		return packetLen, pacingNano, nil
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset, msgTypeSnd := c.snd.ReadyToSend(s.streamID, msgType, ack, c.listener.mtu, nowNano)

		if splitData != nil {
			slog.Debug(" Flush/Send", gId(), s.debug(), c.debug())

			p := &PayloadHeader{
				MsgType:      msgTypeSnd,
				Ack:          ack,
				StreamID:     s.streamID,
				StreamOffset: offset,
			}

			encData, err := c.encode(p, splitData, msgType)
			if err != nil {
				return 0, 0, err
			}

			err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
			if err != nil {
				return 0, 0, err
			}

			packetLen := len(splitData)
			c.dataInFlight += packetLen
			pacingNano = c.calcPacing(uint64(len(encData)))
			c.nextWriteTime = nowNano + pacingNano
			return packetLen, pacingNano, nil
		} else if ack != nil || !c.isInitSentOnSnd {
			slog.Debug(" Flush/Ack", gId(), s.debug(), c.debug())
			return c.writeAck(s, ack, nowNano)
		}
	}

	return 0, MinDeadLine, nil
}

func (c *Conn) writeAck(s *Stream, ack *Ack, nowNano uint64) (data int, pacingNano uint64, err error) {
	p := &PayloadHeader{
		MsgType:    MsgTypeData,
		Ack:        ack,
		StreamID:   s.streamID,
	}

	encData, err := c.encode(p, []byte{}, c.msgType())
	if err != nil {
		return 0, 0, err
	}
	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	pacingNano = c.calcPacing(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingNano
	return 0, pacingNano, nil
}

func (c *Conn) debug() slog.Attr {
	return slog.Group("connection",
		slog.Uint64("nextWrt:ms", c.nextWriteTime/msNano),
		//slog.Uint64("nextWrt:ns", c.nextWriteTime),
		slog.Int("inFlight", c.dataInFlight+c.listener.mtu),
		slog.Int("rcvBuf", c.rcv.capacity-c.rcv.size),
		slog.Uint64("rcvWnd", c.rcvWndSize),
		slog.Uint64("snCrypto", c.snCrypto),
		slog.Uint64("epochSnd", c.epochCryptoSnd),
		slog.Uint64("epochRcv", c.epochCryptoRcv))
}