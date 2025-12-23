package qotp

import (
	"crypto/ecdh"
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
		s.Close()
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

func (c *Conn) decode(p *PayloadHeader, userData []byte, nowNano uint64) (s *Stream, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	s = c.Stream(p.StreamID)
	if p.Ack != nil {
		ackStatus, sentTimeNano := c.snd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		c.rcvWndSize = p.Ack.rcvWnd

		switch ackStatus {
		case AckStatusOk:
			c.dataInFlight -= int(p.Ack.len)
			if nowNano > sentTimeNano {
				rttNano := nowNano - sentTimeNano
				c.updateMeasurements(rttNano, int(p.Ack.len)+42, nowNano) // TODO: 42 is approx overhead
			}
		case AckDup:
			c.onDuplicateAck()
		default:
			// AckNotFound, AckPartial, etc. - no action needed
		}
	}

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, nowNano, userData)
	} else if p.IsClose || userData != nil { //nil is not a ping, just an ack
		c.rcv.EmptyInsert(s.streamID, p.StreamOffset, nowNano)
	}

	if p.IsClose {
		closeOffset := p.StreamOffset + uint64(len(userData))
		c.rcv.Close(s.streamID, closeOffset) //mark the stream closed at the just received offset
		c.snd.Close(s.streamID)              //also close the send buffer at the current location

		// Auto-close receive direction if nothing left to read
		if !s.rcvClosed && closeOffset == 0 {
			s.rcvClosed = true
		}
	}

	if p.Ack != nil || p.IsClose && c.snd.checkStreamFullyAcked(s.streamID) {
		if !s.sndClosed {
			s.sndClosed = true
		}
	}

	return s, nil
}

// We need to check if we remove the current state, if yes, then move the state to the previous stream
func (c *Conn) cleanupStream(streamID uint32) {
	slog.Debug("Cleanup/Stream", gId(), c.debug(), slog.Uint64("streamId", uint64(streamID)))

	if c.listener.currentStreamID != nil && streamID == *c.listener.currentStreamID {
		tmp, _, _ := c.streams.Next(streamID)
		c.listener.currentStreamID = &tmp
	}
	c.streams.Remove(streamID)
	//even if the stream size is 0, do not remove the connection yet, only after a certain timeout,
	// so that BBR, RTT, is preserved for a bit
}

func (c *Conn) cleanupConn() {
	slog.Debug("Cleanup/Conn", gId(), c.debug())

	if c.listener.currentConnID != nil && c.connId == *c.listener.currentConnID {
		tmp, _, _ := c.listener.connMap.Next(c.connId)
		c.listener.currentConnID = &tmp
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Conn) HasActiveStreams() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams.Size() > 0
}

func (c *Conn) Flush(s *Stream, nowNano uint64) (data int, pacingNano uint64, err error) {

	// Respect pacing
	if c.nextWriteTime > nowNano {
		slog.Debug(" Flush/Pacing", gId(), s.debug(), c.debug(),
			slog.Uint64("waitTime:ms", (c.nextWriteTime-nowNano)/msNano))
		//do not sent acks, as this is also data on the line
		return 0, c.nextWriteTime - nowNano, nil
	}

	//update state for receiver
	ack := c.rcv.GetSndAck()
	if ack != nil {
		ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.Size())
	} else {
		//slog.Debug(" Flush/NoAck", gId(), s.debug(), c.debug())
	}

	//Respect rwnd
	if c.dataInFlight+int(c.listener.mtu) > int(c.rcvWndSize) {
		slog.Debug("Flush/Rwnd/Rcv", gId(), s.debug(), c.debug(), slog.Bool("ack?", ack != nil))
		if ack != nil {
			// Send ACK even if receiver indicated no more data, an ack does not add data
			return c.writeAck(s, ack, false, nowNano)
		}
		return 0, MinDeadLine, nil
	}

	// Retransmission case
	msgType := c.msgType()
	splitData, offset, isClose, err := c.snd.ReadyToRetransmit(s.streamID, ack, c.listener.mtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}

	if splitData != nil {
		c.onPacketLoss()
		slog.Debug("Flush/Retransmit", gId(), s.debug(), c.debug())
		return c.sendPacket(s, ack, splitData, offset, isClose, msgType, nowNano, false)
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset, isClose := c.snd.ReadyToSend(s.streamID, msgType, ack, c.listener.mtu, nowNano)
		if splitData != nil {
			slog.Debug("Flush/Send", gId(), s.debug(), c.debug(), slog.Any("offset", offset), slog.Any("l(data)", len(splitData)))
			return c.sendPacket(s, ack, splitData, offset, isClose, msgType, nowNano, true)
		} else if ack != nil || !c.isInitSentOnSnd {
			slog.Debug("Flush/Ack1", gId(), s.debug(), c.debug())
			return c.writeAck(s, ack, isClose, nowNano)
		}
	}

	if ack != nil {
		slog.Debug(" Flush/Ack2", gId(), s.debug(), c.debug())
		return c.writeAck(s, ack, false, nowNano)
	}
	return 0, MinDeadLine, nil
}

func (c *Conn) sendPacket(s *Stream, ack *Ack, splitData []byte, offset uint64, isClose bool, msgType CryptoMsgType, nowNano uint64, trackInFlight bool) (data int, pacingNano uint64, err error) {
	p := &PayloadHeader{
		IsClose:      isClose,
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
	if trackInFlight {
		c.dataInFlight += packetLen
	}
	pacingNano = c.calcPacing(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingNano
	return packetLen, pacingNano, nil
}

func (c *Conn) writeAck(s *Stream, ack *Ack, isClose bool, nowNano uint64) (data int, pacingNano uint64, err error) {
	slog.Info("Sending ACK",
		"streamID", s.streamID,
		"rcvWnd", ack.rcvWnd,
		"offset", ack.offset,
		"len", ack.len,
		"close", isClose)

	p := &PayloadHeader{
		IsClose:  isClose,
		Ack:      ack,
		StreamID: s.streamID,
	}

	encData, err := c.encode(p, nil, c.msgType())
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
		slog.Uint64("connID", c.connId),
		slog.Any("currId", c.listener.currentConnID),
		slog.Uint64("nextWrt:ms", c.nextWriteTime/msNano),
		//slog.Uint64("nextWrt:ns", c.nextWriteTime),
		slog.Int("inFlight", c.dataInFlight),
		slog.Int("rcvBuf", c.rcv.capacity-c.rcv.size),
		slog.Uint64("rcvWnd", c.rcvWndSize),
		slog.Uint64("snCrypto", c.snCrypto),
		slog.Uint64("epochSnd", c.epochCryptoSnd),
		slog.Uint64("epochRcv", c.epochCryptoRcv),
		slog.Bool("initsent", c.isInitSentOnSnd),
		slog.Bool("hndshke", c.isHandshakeDoneOnRcv))
}
