package qotp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

type conn struct {
	connId     uint64
	remoteAddr netip.AddrPort
	listener   *Listener

	prvKeyEpSnd  *ecdh.PrivateKey
	pubKeyEpRcv  *ecdh.PublicKey
	pubKeyIdRcv  *ecdh.PublicKey
	sharedSecret []byte

	snCrypto       uint64
	epochCryptoSnd uint64
	epochCryptoRcv uint64

	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool

	streams       *LinkedMap[uint32, *Stream]
	snd           *SendBuffer
	rcv           *ReceiveBuffer
	dataInFlight  int
	rcvWndSize    uint64
	nextWriteTime uint64

	Measurements
	mu sync.Mutex
}

func (c *conn) Stream(streamID uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stream(streamID)
}

func (c *conn) stream(streamID uint32) *Stream {
	if c.rcv.IsFinished(streamID) {
		return nil
	}
	if v, exists := c.streams.Get(streamID); exists {
		return v
	}
	s := &Stream{streamID: streamID, conn: c}
	c.streams.Put(streamID, s)
	return s
}

func (c *conn) HasActiveStreams() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, val := range c.streams.Iterator(nil) {
		if val != nil && (!val.rcvClosed || !val.sndClosed) {
			return true
		}
	}
	return false
}

func (c *conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.streams.Iterator(nil) {
		s.Close()
	}
}

func (c *conn) cleanupStream(streamID uint32, nowNano uint64) {
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

func decodePacket(l *Listener, encData []byte, rAddr netip.AddrPort, msgType cryptoMsgType) (*conn, []byte, error) {
	connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])

	switch msgType {
	case InitSnd, InitCryptoSnd:
		return decodeInit(l, encData, rAddr, connId, msgType)
	case InitRcv, InitCryptoRcv, Data:
		conn, exists := l.connMap.Get(connId)
		if !exists {
			return nil, nil, fmt.Errorf("connection not found: %d", connId)
		}
		payload, err := conn.decode(encData, msgType)
		return conn, payload, err
	}
	return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
}

func decodeInit(l *Listener, encData []byte, rAddr netip.AddrPort, connId uint64, msgType cryptoMsgType) (*conn, []byte, error) {
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

func (c *conn) decode(encData []byte, msgType cryptoMsgType) ([]byte, error) {
	switch msgType {
	case InitRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(encData, c.prvKeyEpSnd)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		c.pubKeyIdRcv = pubKeyIdRcv
		c.pubKeyEpRcv = pubKeyEpRcv
		c.sharedSecret = sharedSecret
		return message.PayloadRaw, nil

	case InitCryptoRcv:
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, c.prvKeyEpSnd)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		c.pubKeyEpRcv = pubKeyEpRcv
		c.sharedSecret = sharedSecret
		return message.PayloadRaw, nil

	case Data:
		message, err := decryptData(encData, c.isSenderOnInit, c.epochCryptoRcv, c.sharedSecret)
		if err != nil {
			return nil, err
		}
		if message.currentEpochCrypt > c.epochCryptoRcv {
			c.epochCryptoRcv = message.currentEpochCrypt
		}
		return message.PayloadRaw, nil
	}
	return nil, fmt.Errorf("unexpected message type: %v", msgType)
}

func (c *conn) encode(p *payloadHeader, userData []byte, msgType cryptoMsgType) ([]byte, error) {
	var encData []byte
	var err error

	switch msgType {
	case InitSnd:
		_, encData, err = encryptInitSnd(
			c.listener.prvKeyId.PublicKey(),
			c.prvKeyEpSnd.PublicKey(),
			c.listener.mtu,
		)
	case InitCryptoSnd:
		packetData, _ := encodeProto(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			c.pubKeyIdRcv,
			c.listener.prvKeyId.PublicKey(),
			c.prvKeyEpSnd,
			c.snCrypto,
			c.listener.mtu,
			packetData,
		)
	case InitRcv, InitCryptoRcv, Data:
		packetData, _ := encodeProto(p, userData)
		encData, err = encryptPacket(
			msgType,
			c.connId,
			c.prvKeyEpSnd,
			c.listener.prvKeyId.PublicKey(),
			c.pubKeyEpRcv,
			c.sharedSecret,
			c.snCrypto,
			c.epochCryptoSnd,
			c.isSenderOnInit,
			packetData,
		)
	default:
		return nil, errors.New("unknown message type")
	}

	if err != nil {
		return nil, err
	}

	if msgType != Data {
		c.isInitSentOnSnd = true
	}

	c.snCrypto++
	if c.snCrypto > (1<<48)-1 {
		if c.epochCryptoSnd >= (1<<47)-1 {
			return nil, errors.New("exhausted 2^95 sequence numbers")
		}
		c.epochCryptoSnd++
		c.snCrypto = 0
	}
	return encData, nil
}

func (c *conn) handlePayload(p *payloadHeader, userData []byte, nowNano uint64) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if p.Ack != nil {
		ackStatus, sentTimeNano, packetSize := c.snd.AcknowledgeRange(p.Ack)
		c.rcvWndSize = p.Ack.rcvWnd

		switch ackStatus {
		case AckStatusOk:
			c.dataInFlight -= int(p.Ack.len)
			if nowNano > sentTimeNano {
				c.updateMeasurements(nowNano-sentTimeNano, packetSize, nowNano)
			}
			if ackStream := c.stream(p.Ack.streamID); ackStream != nil && !ackStream.sndClosed && c.snd.CheckStreamFullyAcked(p.Ack.streamID) {
				ackStream.sndClosed = true
			}
		case AckDup:
			c.onDuplicateAck()
		}
	}

	s := c.stream(p.StreamID)
	if s == nil {
		if c.rcv.IsFinished(p.StreamID) {
			if len(userData) > 0 {
				c.rcv.QueueAck(p.StreamID, p.StreamOffset, uint16(len(userData)))
			} else if p.IsClose || userData != nil {
				c.rcv.QueueAck(p.StreamID, p.StreamOffset, 0)
			}
		}
		return nil, nil
	}

	if len(userData) > 0 {
		c.rcv.Insert(s.streamID, p.StreamOffset, nowNano, userData)
	} else if p.IsClose || userData != nil {
		c.rcv.QueueAck(s.streamID, p.StreamOffset, 0)
	}

	if p.IsClose {
		c.rcv.Close(s.streamID, p.StreamOffset+uint64(len(userData)))
	}

	if !s.rcvClosed && c.rcv.IsReadyToClose(s.streamID) {
		s.rcvClosed = true
	}
	if !s.sndClosed && c.snd.CheckStreamFullyAcked(s.streamID) {
		s.sndClosed = true
	}

	return s, nil
}

func (c *conn) sendNext(s *Stream, nowNano uint64) (int, uint64, error) {
	ack := c.rcv.GetSndAck()
	if ack != nil {
		ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.Size())
	}

	isBlockedByPacing := c.nextWriteTime > nowNano
	isBlockedByCwnd := c.dataInFlight >= int(c.cwnd)
	isBlockedByRwnd := c.dataInFlight+int(c.listener.mtu) > int(c.rcvWndSize)

	if isBlockedByPacing || isBlockedByCwnd || isBlockedByRwnd {
		if ack == nil {
			if isBlockedByPacing {
				return 0, c.nextWriteTime - nowNano, nil
			}
			return 0, MinDeadLine, nil
		}
		return c.writePacket(s, ack, nil, 0, false, nowNano, false)
	}

	msgType := c.msgType()
	splitData, offset, isClose, err := c.snd.ReadyToRetransmit(s.streamID, ack, c.listener.mtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		c.onPacketLoss()
		return c.writePacket(s, ack, splitData, offset, isClose, nowNano, false)
	}

	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset, isClose := c.snd.ReadyToSend(s.streamID, msgType, ack, c.listener.mtu)
		if splitData != nil {
			return c.writePacket(s, ack, splitData, offset, isClose, nowNano, true)
		}
		if ack != nil || !c.isInitSentOnSnd {
			return c.writePacket(s, ack, nil, 0, isClose, nowNano, false)
		}
	}

	if ack != nil {
		return c.writePacket(s, ack, nil, 0, false, nowNano, false)
	}

	return 0, MinDeadLine, nil
}

func (c *conn) writePacket(s *Stream, ack *Ack, data []byte, offset uint64, isClose bool, nowNano uint64, trackInFlight bool) (int, uint64, error) {
	p := &payloadHeader{
		IsClose:      isClose,
		Ack:          ack,
		StreamID:     s.streamID,
		StreamOffset: offset,
	}

	encData, err := c.encode(p, data, c.msgType())
	if err != nil {
		return 0, 0, err
	}

	if data != nil {
		c.snd.UpdatePacketSize(s.streamID, offset, uint16(len(data)), uint16(len(encData)), nowNano)
	}

	pacingNano, err := c.write(encData, nowNano)
	if err != nil {
		return 0, 0, err
	}

	dataLen := len(data)
	if trackInFlight && dataLen > 0 {
		c.dataInFlight += dataLen
	}

	return dataLen, pacingNano, nil
}

func (c *conn) write(encData []byte, nowNano uint64) (uint64, error) {
	if err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano); err != nil {
		return 0, err
	}
	pacingNano := c.calcPacing(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingNano
	return pacingNano, nil
}

func (c *conn) msgType() cryptoMsgType {
	if c.isHandshakeDoneOnRcv {
		return Data
	}
	switch {
	case c.isWithCryptoOnInit && c.isSenderOnInit:
		return InitCryptoSnd
	case c.isWithCryptoOnInit:
		return InitCryptoRcv
	case c.isSenderOnInit:
		return InitSnd
	default:
		return InitRcv
	}
}

func (l *Listener) getOrCreateConn(connId uint64, rAddr netip.AddrPort, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, isSender, withCrypto bool) (*conn, error) {
	if conn, exists := l.connMap.Get(connId); exists {
		return conn, nil
	}
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return l.newConn(connId, rAddr, prvKeyEp, pubKeyIdRcv, pubKeyEpRcv, isSender, withCrypto)
}