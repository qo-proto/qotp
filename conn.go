package qotp

import (
	"crypto/ecdh"
	"errors"
	"net/netip"
	"sync"
)

type Conn struct {
	// Identity
	connId     uint64
	remoteAddr netip.AddrPort
	listener   *Listener

	// Crypto keys
	prvKeyEpSnd  *ecdh.PrivateKey
	pubKeyEpRcv  *ecdh.PublicKey
	pubKeyIdRcv  *ecdh.PublicKey
	sharedSecret []byte

	// Crypto state
	snCrypto       uint64 //this is 48bit
	epochCryptoSnd uint64 //this is 47bit
	epochCryptoRcv uint64 //this is 47bit

	// Handshake state
	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool

	// Flow control
	streams       *LinkedMap[uint32, *Stream]
	snd           *SendBuffer
	rcv           *ReceiveBuffer
	dataInFlight  int
	rcvWndSize    uint64
	nextWriteTime uint64

	// Metrics
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

// streamLocked returns or creates a stream. Caller must hold c.mu.
func (c *Conn) streamLocked(streamID uint32) *Stream {
	// Check if stream is in TIME_WAIT (receive side completed)
	if c.rcv.IsFinished(streamID) {
		return nil // Stream is closed, decode() will handle TIME_WAIT ACKs
	}

	v, exists := c.streams.Get(streamID)
	if exists {
		return v
	}

	s := &Stream{
		streamID: streamID,
		conn:     c,
	}
	c.streams.Put(streamID, s)
	return s
}

// Stream returns or creates a stream. Thread-safe.
func (c *Conn) Stream(streamID uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streamLocked(streamID)
}

func (conn *Conn) encode(p *PayloadHeader, userData []byte, msgType CryptoMsgType) (encData []byte, err error) {
	// Create payload early for cases that need it
	var packetData []byte

	// Handle message encoding based on connection state
	switch msgType {
	case InitSnd:
		_, encData = encryptInitSnd(
			conn.listener.prvKeyId.PublicKey(),
			conn.prvKeyEpSnd.PublicKey(),
			conn.listener.mtu,
		)
		conn.isInitSentOnSnd = true
	case InitCryptoSnd:
		packetData, _ = EncodePayload(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			conn.pubKeyIdRcv,
			conn.listener.prvKeyId.PublicKey(),
			conn.prvKeyEpSnd,
			conn.snCrypto,
			conn.listener.mtu,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case InitCryptoRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptInitCryptoRcv(
			conn.connId,
			conn.pubKeyEpRcv,
			conn.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case InitRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptInitRcv(
			conn.connId,
			conn.listener.prvKeyId.PublicKey(),
			conn.pubKeyEpRcv,
			conn.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case Data:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptData(
			conn.connId,
			conn.isSenderOnInit,
			conn.sharedSecret,
			conn.snCrypto,
			conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown message type")
	}

	//update state ofter encode of packet
	conn.snCrypto++
	//rollover
	if conn.snCrypto > (1<<48)-1 {
		if conn.epochCryptoSnd+1 > (1<<47)-1 {
			//47, as the last bit is used for sender / receiver differentiation
			//quic has key rotation (via bitflip), qotp does not.
			return nil, errors.New("exhausted 2^95 sn number, cannot continue, you just " +
				"sent ~5 billion ZettaBytes.\nNow you need to reconnect manually. This " +
				"is roughly 28 million times all the data humanity has ever created.")
		}
		conn.epochCryptoSnd++
		conn.snCrypto = 0
	}
	return encData, nil
}

func (c *Conn) decode(p *PayloadHeader, userData []byte, nowNano uint64) (s *Stream, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if p.Ack != nil {
		ackStatus, sentTimeNano, packetSize := c.snd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack
		c.rcvWndSize = p.Ack.rcvWnd

		switch ackStatus {
		case AckStatusOk:
			c.dataInFlight -= int(p.Ack.len)
			if nowNano > sentTimeNano {
				rttNano := nowNano - sentTimeNano
				c.updateMeasurements(rttNano, packetSize, nowNano) // TODO: 42 is approx overhead
			}

			ackStream := c.streamLocked(p.Ack.streamID)
			if ackStream != nil && !ackStream.sndClosed && c.snd.CheckStreamFullyAcked(p.Ack.streamID) {
				ackStream.sndClosed = true
			}
		case AckDup:
			c.onDuplicateAck()
		default:
			// AckNotFound, AckPartial, etc. - no action needed
		}
	}

	s = c.streamLocked(p.StreamID)
	if s == nil {
		// Stream is finished - just ACK and return
		if c.rcv.IsFinished(p.StreamID) {
			if len(userData) > 0 {
				c.rcv.QueueAckForClosedStream(p.StreamID, p.StreamOffset, uint16(len(userData)))
			} else if p.IsClose || userData != nil {
				c.rcv.QueueAckForClosedStream(p.StreamID, p.StreamOffset, 0)
			}
		}
		return nil, nil
	}

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, nowNano, userData)
	} else if p.IsClose || userData != nil { //nil is not a ping, just an ack
		c.rcv.EmptyInsert(s.streamID, p.StreamOffset)
	}

	if p.IsClose {
		closeOffset := p.StreamOffset + uint64(len(userData))
		c.rcv.Close(s.streamID, closeOffset) //mark the stream closed at the just received offset
	}

	if !s.rcvClosed && c.rcv.IsReadyToClose(s.streamID) {
		s.rcvClosed = true
	}

	if !s.sndClosed && c.snd.CheckStreamFullyAcked(s.streamID) {
		s.sndClosed = true
	}

	return s, nil
}

// We need to check if we remove the current state, if yes, then move the state to the previous stream
func (c *Conn) cleanupStream(streamID uint32, nowNano uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.listener.currentStreamID != nil && streamID == *c.listener.currentStreamID {
		tmp, _, _ := c.streams.Next(streamID)
		c.listener.currentStreamID = &tmp
	}
	c.streams.Remove(streamID)

	c.snd.RemoveStream(streamID)
	c.rcv.RemoveStream(streamID)
}

func (c *Conn) cleanupConn() {
	if c.listener.currentConnID != nil && c.connId == *c.listener.currentConnID {
		tmp, _, _ := c.listener.connMap.Next(c.connId)
		c.listener.currentConnID = &tmp
	}
	c.listener.connMap.Remove(c.connId)
}

func (c *Conn) HasActiveStreams() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, val := range c.streams.Iterator(nil) {
		if val != nil && (!val.rcvClosed || !val.sndClosed) {
			return true
		}
	}

	return false
}

func (c *Conn) Flush(s *Stream, nowNano uint64) (data int, pacingNano uint64, err error) {

	// Respect pacing
	if c.nextWriteTime > nowNano || c.dataInFlight >= int(c.cwnd) {
		ack := c.rcv.GetSndAck()
		if ack != nil {
			ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.Size())
			return c.writeAck(s, ack, false, nowNano)
		}
		if c.nextWriteTime > nowNano {
			return 0, c.nextWriteTime - nowNano, nil
		}
		return 0, MinDeadLine, nil
	}

	//update state for receiver
	ack := c.rcv.GetSndAck()
	if ack != nil {
		ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.Size())
	}

	//Respect rwnd
	if c.dataInFlight+int(c.listener.mtu) > int(c.rcvWndSize) {
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
		return c.sendPacket(s, ack, splitData, offset, isClose, msgType, nowNano, false)
	}

	//next check if we can send packets, during handshake we can only send 1 packet
	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset, isClose := c.snd.ReadyToSend(s.streamID, msgType, ack, c.listener.mtu)
		if splitData != nil {
			return c.sendPacket(s, ack, splitData, offset, isClose, msgType, nowNano, true)
		} else if ack != nil || !c.isInitSentOnSnd {
			return c.writeAck(s, ack, isClose, nowNano)
		}
	}

	if ack != nil {
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
	
 	c.snd.UpdatePacketSize(s.streamID, offset, uint16(len(splitData)), uint16(len(encData)), nowNano)

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

func (c *Conn) Rcv() *ReceiveBuffer {
	return c.rcv
}
