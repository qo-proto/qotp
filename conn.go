package qotp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// conn represents a QOTP connection to a remote peer.
// A single conn can multiplex multiple streams.
// Thread-safe: all public methods acquire mu.
type conn struct {
	connId     uint64
	remoteAddr netip.AddrPort
	listener   *Listener

	// Cryptographic state
	prvKeyEpSnd  *ecdh.PrivateKey
	pubKeyEpRcv  *ecdh.PublicKey
	pubKeyIdRcv  *ecdh.PublicKey
	sharedSecret []byte

	// Sequence numbers: 48-bit sn + 47-bit epoch = 2^95 total space
	snCrypto       uint64
	epochCryptoSnd uint64
	epochCryptoRcv uint64

	// Handshake state
	isSenderOnInit       bool
	isWithCryptoOnInit   bool
	isHandshakeDoneOnRcv bool
	isInitSentOnSnd      bool

	// Stream and buffer management
	streams      *linkedMap[uint32, *Stream]
	snd          *sender
	rcv          *receiver
	dataInFlight int
	rcvWndSize   uint64

	// Pacing
	nextWriteTime uint64

	// Activity tracking
	lastReadTimeNano uint64

	measurements
	mu sync.Mutex
}

// =============================================================================
// Public methods
// =============================================================================

func (c *conn) Stream(streamID uint32) *Stream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getOrCreateStream(streamID)
}

func (c *conn) HasActiveStreams() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, val := range c.streams.iterator(nil) {
		if val != nil && (!val.rcvClosed || !val.sndClosed) {
			return true
		}
	}
	return false
}

// =============================================================================
// Connection lifecycle
// =============================================================================

func (l *Listener) getOrCreateConn(connId uint64, rAddr netip.AddrPort, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, isSender, withCrypto bool) (*conn, error) {
	if conn, exists := l.connMap.get(connId); exists {
		return conn, nil
	}
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return l.newConn(connId, rAddr, prvKeyEp, pubKeyIdRcv, pubKeyEpRcv, isSender, withCrypto)
}

func (c *conn) closeAllStreams() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.streams.iterator(nil) {
		s.Close()
	}
}

func (c *conn) cleanupStream(streamID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listener.currentStreamID != nil && streamID == *c.listener.currentStreamID {
		tmp, _, _ := c.streams.next(streamID)
		c.listener.currentStreamID = &tmp
	}
	c.streams.remove(streamID)
	c.snd.removeStream(streamID)
	c.rcv.removeStream(streamID)
}

// =============================================================================
// Stream management
// =============================================================================

// getOrCreateStream returns or creates a getOrCreateStream. Returns nil if getOrCreateStream was already finished.
// Caller must hold c.mu.
func (c *conn) getOrCreateStream(streamID uint32) *Stream {
	if c.rcv.isFinished(streamID) {
		return nil
	}
	if v, exists := c.streams.get(streamID); exists {
		return v
	}
	s := &Stream{streamID: streamID, conn: c}
	c.streams.put(streamID, s)
	return s
}

// =============================================================================
// Packet decoding (receive path)
// =============================================================================

func decodePacket(l *Listener, encData []byte, rAddr netip.AddrPort, msgType cryptoMsgType) (*conn, []byte, error) {
	connId := getUint64(encData[headerSize : headerSize+connIdSize])

	switch msgType {
	case initSnd, initCryptoSnd:
		return decodeInitPacket(l, encData, rAddr, connId, msgType)
	case initRcv, initCryptoRcv, data:
		conn, exists := l.connMap.get(connId)
		if !exists {
			return nil, nil, fmt.Errorf("connection not found: %d", connId)
		}
		payload, err := conn.decode(encData, msgType)
		return conn, payload, err
	}
	return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
}

func decodeInitPacket(l *Listener, encData []byte, rAddr netip.AddrPort, connId uint64, msgType cryptoMsgType) (*conn, []byte, error) {
	switch msgType {
	case initSnd:
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

	case initCryptoSnd:
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
		return conn, message.payloadRaw, nil
	}
	return nil, nil, errors.New("invalid init message type")
}

func (c *conn) decode(encData []byte, msgType cryptoMsgType) ([]byte, error) {
	switch msgType {
	case initRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(encData, c.prvKeyEpSnd)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		c.pubKeyIdRcv = pubKeyIdRcv
		c.pubKeyEpRcv = pubKeyEpRcv
		c.sharedSecret = sharedSecret
		return message.payloadRaw, nil

	case initCryptoRcv:
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, c.prvKeyEpSnd)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		c.pubKeyEpRcv = pubKeyEpRcv
		c.sharedSecret = sharedSecret
		return message.payloadRaw, nil

	case data:
		message, err := decryptData(encData, c.isSenderOnInit, c.epochCryptoRcv, c.sharedSecret)
		if err != nil {
			return nil, err
		}
		if message.currentEpochCrypt > c.epochCryptoRcv {
			c.epochCryptoRcv = message.currentEpochCrypt
		}
		return message.payloadRaw, nil
	}
	return nil, fmt.Errorf("unexpected message type: %v", msgType)
}

// =============================================================================
// Packet encoding (send path)
// =============================================================================

func (c *conn) encode(p *payloadHeader, userData []byte, msgType cryptoMsgType) ([]byte, error) {
	var encData []byte
	var err error

	switch msgType {
	case initSnd:
		_, encData, err = encryptInitSnd(
			c.listener.prvKeyId.PublicKey(),
			c.prvKeyEpSnd.PublicKey(),
			c.listener.mtu,
		)
	case initCryptoSnd:
		packetData, _ := encodeProto(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			c.pubKeyIdRcv,
			c.listener.prvKeyId.PublicKey(),
			c.prvKeyEpSnd,
			c.snCrypto,
			c.listener.mtu,
			packetData,
		)
	case initRcv, initCryptoRcv, data:
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

	if msgType != data {
		c.isInitSentOnSnd = true
	}

	// Sequence number management: 48-bit sn rolls over into 47-bit epoch.
	// Total space: 2^95. Exhaustion requires manual reconnection.
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

// =============================================================================
// Payload handling
// =============================================================================

// processIncomingPayload processes a decoded payload, updating stream and ACK state.
//
// userData semantics:
//   - nil: ACK-only packet, no stream data
//   - []byte{} (empty): PING packet
//   - []byte{...}: actual data
func (c *conn) processIncomingPayload(p *payloadHeader, userData []byte, nowNano uint64) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Process ACK if present
	if p.ack != nil {
		ackStatus, sentTimeNano, packetSize := c.snd.acknowledgeRange(p.ack)
		c.rcvWndSize = p.ack.rcvWnd

		switch ackStatus {
		case ackStatusOk:
			c.dataInFlight -= int(p.ack.len)
			if nowNano > sentTimeNano {
				c.updateMeasurements(nowNano-sentTimeNano, packetSize, nowNano)
			}
			if ackStream := c.getOrCreateStream(p.ack.streamId); ackStream != nil && !ackStream.sndClosed && c.snd.checkStreamFullyAcked(p.ack.streamId) {
				ackStream.sndClosed = true
			}
		case ackDup:
			c.onDuplicateAck()
		}
	}

	// Get or create stream; nil if stream already finished
	s := c.getOrCreateStream(p.streamId)
	if s == nil {
		// Stream finished but peer still sending - ACK to stop retransmits
		if c.rcv.isFinished(p.streamId) {
			if len(userData) > 0 {
				c.rcv.queueAck(p.streamId, p.streamOffset, uint16(len(userData)))
			} else if p.isClose || userData != nil {
				c.rcv.queueAck(p.streamId, p.streamOffset, 0)
			}
		}
		return nil, nil
	}

	// Insert data or queue ACK for empty packets (PING/CLOSE)
	if len(userData) > 0 {
		c.rcv.insert(s.streamID, p.streamOffset, nowNano, userData)
	} else if p.isClose || userData != nil {
		c.rcv.queueAck(s.streamID, p.streamOffset, 0)
	}

	// Handle stream close
	if p.isClose {
		c.rcv.close(s.streamID, p.streamOffset+uint64(len(userData)))
	}

	// Update stream close state
	if !s.rcvClosed && c.rcv.isReadyToClose(s.streamID) {
		s.rcvClosed = true
	}
	if !s.sndClosed && c.snd.checkStreamFullyAcked(s.streamID) {
		s.sndClosed = true
	}

	return s, nil
}

// =============================================================================
// Send path
// =============================================================================

// flushStream sends the next packet for this stream.
// Returns (bytesSent, nextWakeupNano, error).
// bytesSent=0 with nextWakeupNano>0 means blocked by pacing/cwnd/rwnd.
func (c *conn) flushStream(s *Stream, nowNano uint64) (int, uint64, error) {
	ack := c.rcv.getSndAck()
	if ack != nil {
		ack.rcvWnd = uint64(c.rcv.capacity) - uint64(c.rcv.size())
	}

	// Check send blockers
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
		// Blocked but have ACK to send
		return c.encodeAndWrite(s, ack, nil, 0, false, nowNano, false)
	}

	// Try retransmission first (oldest unacked packet)
	msgType := c.msgType()
	splitData, offset, isClose, err := c.snd.readyToRetransmit(s.streamID, ack, c.listener.mtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		c.onPacketLoss()
		return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, false)
	}

	// Try sending new data (only after handshake or if init not yet sent)
	if c.isHandshakeDoneOnRcv || !c.isInitSentOnSnd {
		splitData, offset, isClose := c.snd.readyToSend(s.streamID, msgType, ack, c.listener.mtu)
		if splitData != nil {
			return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, true)
		}
		if ack != nil || !c.isInitSentOnSnd {
			return c.encodeAndWrite(s, ack, nil, 0, isClose, nowNano, false)
		}
	}

	// Send ACK-only if pending
	if ack != nil {
		return c.encodeAndWrite(s, ack, nil, 0, false, nowNano, false)
	}

	return 0, MinDeadLine, nil
}

func (c *conn) encodeAndWrite(s *Stream, ack *ack, data []byte, offset uint64, isClose bool, nowNano uint64, trackInFlight bool) (int, uint64, error) {
	p := &payloadHeader{
		isClose:      isClose,
		ack:          ack,
		streamId:     s.streamID,
		streamOffset: offset,
	}

	encData, err := c.encode(p, data, c.msgType())
	if err != nil {
		return 0, 0, err
	}

	if data != nil {
		c.snd.updatePacketSize(s.streamID, offset, uint16(len(data)), uint16(len(encData)), nowNano)
	}

	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}
	pacingNano := c.calcPacing(uint64(len(encData)))
	c.nextWriteTime = nowNano + pacingNano

	dataLen := len(data)
	if trackInFlight && dataLen > 0 {
		c.dataInFlight += dataLen
	}

	return dataLen, pacingNano, nil
}

// =============================================================================
// Helpers
// =============================================================================

// msgType returns the crypto message type based on handshake state.
func (c *conn) msgType() cryptoMsgType {
	if c.isHandshakeDoneOnRcv {
		return data
	}
	switch {
	case c.isWithCryptoOnInit && c.isSenderOnInit:
		return initCryptoSnd
	case c.isWithCryptoOnInit:
		return initCryptoRcv
	case c.isSenderOnInit:
		return initSnd
	default:
		return initRcv
	}
}
