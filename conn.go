package qotp

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

type keyState struct {
	prev, cur, next []byte
	prvKeyEp        *ecdh.PrivateKey
	prvKeyEpNext    *ecdh.PrivateKey
}

type rcvKeyState struct {
	keyState
	pubKeyEp        *ecdh.PublicKey
	pubKeyEpNext    *ecdh.PublicKey
}

type connPhase int

const (
	phaseCreated          connPhase = iota // nothing sent
	phaseInitSent                          // init sent, awaiting reply
	phaseReady                             // handshake complete, idle
	phaseKeyUpdatePending                  // received KEY_UPDATE, need to send ACK
)

// conn represents a QOTP connection to a remote peer.
// A single conn can multiplex multiple streams.
// Thread-safe: all public methods acquire mu.
type conn struct {
	connId     uint64
	remoteAddr netip.AddrPort
	listener   *Listener

	snCrypto    uint64
	pubKeyIdRcv *ecdh.PublicKey // Identity
	sndKeys     *keyState
	rcvKeys     *rcvKeyState

	// Handshake state
	//isSenderOnInit bool
	initMsgType cryptoMsgType
	phase       connPhase

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

	// MTU negotiation
	mtu               int  // negotiated max UDP payload (starts conservative, updated after handshake)
	mtuSent           bool // whether we've sent our maxPayload to the peer
	consecutiveLosses int

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

func (c *conn) keyUpdateFlags() (isKeyUpdate, isKeyUpdateAck bool) {
	isKeyUpdate = c.sndKeys.prvKeyEpNext != nil && c.sndKeys.next == nil
	isKeyUpdateAck = c.phase == phaseKeyUpdatePending && c.rcvKeys.prvKeyEpNext != nil
	return
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

// negotiateMTU sets the connection's MTU to min(remoteMaxPayload, localMaxPayload).
func (c *conn) negotiateMTU(remoteMaxPayload uint16) {
	remote := int(remoteMaxPayload)
	local := c.listener.maxPayload
	negotiated := local
	if remote < negotiated {
		negotiated = remote
	}
	if negotiated < conservativeMTU {
		negotiated = conservativeMTU
	}
	c.mtu = negotiated
	c.updateMTU(negotiated)
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
	s := &Stream{streamID: streamID, conn: c, reliable: true}
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
		pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(encData, l.maxPayload)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitSnd: %w", err)
		}
		conn, err := l.getOrCreateConn(connId, rAddr, pubKeyIdSnd, pubKeyEpSnd, false, false)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, err := conn.sndKeys.prvKeyEp.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDH: %w", err)
		}
		conn.sndKeys.cur = sharedSecret
		conn.rcvKeys.cur = sharedSecret //initially, both are the same, as sync is for free
		return conn, []byte{}, nil

	case initCryptoSnd:
		pubKeyIdSnd, pubKeyEpSnd, message, err := decryptInitCryptoSnd(encData, l.prvKeyId, l.maxPayload)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitCryptoSnd: %w", err)
		}
		conn, err := l.getOrCreateConn(connId, rAddr, pubKeyIdSnd, pubKeyEpSnd, false, true)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, err := conn.sndKeys.prvKeyEp.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, fmt.Errorf("ECDH: %w", err)
		}
		conn.sndKeys.cur = sharedSecret
		conn.rcvKeys.cur = sharedSecret //initially, both are the same, as sync is for free
		return conn, message.payloadRaw, nil
	}
	return nil, nil, errors.New("invalid init message type")
}

func (c *conn) decode(encData []byte, msgType cryptoMsgType) ([]byte, error) {
	switch msgType {
	case initRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		c.pubKeyIdRcv = pubKeyIdRcv
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		return message.payloadRaw, nil

	case initCryptoRcv:
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		return message.payloadRaw, nil

	case data:
		secrets := [][]byte{c.rcvKeys.cur}
		if c.rcvKeys.prev != nil {
			secrets = append(secrets, c.rcvKeys.prev)
		}
		if c.rcvKeys.next != nil {
			secrets = append(secrets, c.rcvKeys.next)
		}
		message, err := decryptData(encData, c.initMsgType == initCryptoSnd || c.initMsgType == initSnd, secrets)
		if err != nil {
			return nil, err
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
			c.sndKeys.prvKeyEp.PublicKey(),
			c.listener.maxPayload,
		)
	case initCryptoSnd:
		packetData, _ := encodeProto(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			c.pubKeyIdRcv,
			c.listener.prvKeyId.PublicKey(),
			c.sndKeys.prvKeyEp,
			c.snCrypto,
			c.listener.maxPayload,
			packetData,
		)
	case initRcv, initCryptoRcv, data:
		packetData, _ := encodeProto(p, userData)
		encData, err = encryptPacket(
			msgType,
			c.connId,
			c.sndKeys.prvKeyEp,
			c.listener.prvKeyId.PublicKey(),
			c.rcvKeys.pubKeyEp,
			c.sndKeys.cur,
			c.snCrypto,
			c.initMsgType == initCryptoSnd || c.initMsgType == initSnd,
			packetData,
		)
	default:
		return nil, errors.New("unknown message type")
	}

	if err != nil {
		return nil, err
	}

	if msgType != data {
		c.phase = phaseInitSent
	}

	c.snCrypto++
	// At halfway: initiate rotation
	if c.snCrypto == 1<<46 && c.sndKeys.prvKeyEpNext == nil {
		newKey, err := generateKey()
		if err != nil {
			return nil, err
		}
		c.sndKeys.prvKeyEpNext = newKey
	}

	// At overflow: rotate
	if c.snCrypto == 1<<47 {
		if c.sndKeys.next == nil {
			return nil, errors.New("key rotation not completed before overflow")
		}
		c.sndKeys.prev = c.sndKeys.cur
		c.sndKeys.cur = c.sndKeys.next
		c.sndKeys.next = nil
		c.sndKeys.prvKeyEp = c.sndKeys.prvKeyEpNext
		c.sndKeys.prvKeyEpNext = nil
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

	// Handle key update from peer
	if p.isKeyUpdate && len(p.keyUpdatePub) == pubKeySize {
		if err := c.handlePeerKeyUpdate(p.keyUpdatePub); err != nil {
			return nil, fmt.Errorf("key update failed: %w", err)
		}
	}

	if p.isKeyUpdateAck && len(p.keyUpdatePubAck) == pubKeySize {
		if err := c.handleKeyUpdateAck(p.keyUpdatePubAck); err != nil {
			return nil, fmt.Errorf("key update failed: %w", err)
		}
	}

	// Process ACK if present
	if p.ack != nil {
		ackStatus, sentTimeNano, deliveredAtSend := c.snd.acknowledgeRange(p.ack)
		c.rcvWndSize = p.ack.rcvWnd

		switch ackStatus {
		case ackStatusOk:
			c.dataInFlight -= int(p.ack.len)
			if nowNano > sentTimeNano {
				c.updateMeasurements(nowNano-sentTimeNano, p.ack.len, deliveredAtSend, nowNano)
			}
			if c.consecutiveLosses > 0 {
				c.consecutiveLosses = 0
				if c.mtu < c.negotiatedMTU {
					c.mtu = c.negotiatedMTU
				}
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
			} else if p.isClose || userData != nil || p.isKeyUpdate || p.isKeyUpdateAck {
				c.rcv.queueAck(p.streamId, p.streamOffset, 0)
			}
		}
		return nil, nil
	}

	// Handle MTU update from peer
	if p.isMtuUpdate && p.mtuUpdateValue > 0 {
		c.negotiateMTU(p.mtuUpdateValue)
	}

	// Insert data or queue ACK for empty packets (PING/CLOSE)
	if len(userData) > 0 {
		c.rcv.insert(s.streamID, p.streamOffset, nowNano, userData)
	} else if userData != nil || p.isClose || p.isMtuUpdate || p.isKeyUpdate || p.isKeyUpdateAck {
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

func (c *conn) handlePeerKeyUpdate(peerNewPubKeyBytes []byte) error {
	peerNewPubKey, err := ecdh.X25519().NewPublicKey(peerNewPubKeyBytes)
	if err != nil {
		return err
	}

	// Retransmit of PREVIOUS round's KEY_UPDATE (already rotated past)
	if c.rcvKeys.pubKeyEp != nil &&
		bytes.Equal(c.rcvKeys.pubKeyEp.Bytes(), peerNewPubKeyBytes) {
		return nil // Ignore, we've moved on
	}

	// Retransmit of CURRENT round's KEY_UPDATE
	if c.rcvKeys.pubKeyEpNext != nil &&
		bytes.Equal(c.rcvKeys.pubKeyEpNext.Bytes(), peerNewPubKeyBytes) {
		c.phase = phaseKeyUpdatePending
		return nil
	}

	// NEW KEY_UPDATE - rotate if needed, then process
	if c.rcvKeys.next != nil {
		c.rcvKeys.prev = c.rcvKeys.cur
		c.rcvKeys.cur = c.rcvKeys.next
		c.rcvKeys.next = nil
		c.rcvKeys.prvKeyEp = c.rcvKeys.prvKeyEpNext
		c.rcvKeys.prvKeyEpNext = nil
		c.rcvKeys.pubKeyEp = c.rcvKeys.pubKeyEpNext // MUST be before setting to nil
		c.rcvKeys.pubKeyEpNext = nil
		c.phase = phaseReady
	}

	// Generate fresh key for this KEY_UPDATE
	newPriv, err := generateKey()
	if err != nil {
		return err
	}
	c.rcvKeys.prvKeyEpNext = newPriv
	c.rcvKeys.pubKeyEpNext = peerNewPubKey

	// Compute next secret
	newSecret, err := c.rcvKeys.prvKeyEpNext.ECDH(peerNewPubKey)
	if err != nil {
		return err
	}
	c.rcvKeys.next = newSecret

	c.phase = phaseKeyUpdatePending
	return nil
}

func (c *conn) handleKeyUpdateAck(peerNewPubKeyBytes []byte) error {
	if c.sndKeys.prvKeyEpNext == nil || c.sndKeys.next != nil {
		// Already processed or unexpected - retransmission
		return nil
	}

	peerNewPubKey, err := ecdh.X25519().NewPublicKey(peerNewPubKeyBytes)
	if err != nil {
		return err
	}

	// NOW I can compute my new send secret
	newSecret, err := c.sndKeys.prvKeyEpNext.ECDH(peerNewPubKey)
	if err != nil {
		return err
	}
	c.sndKeys.next = newSecret
	return nil
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
	isBlockedByRwnd := c.dataInFlight+c.mtu > int(c.rcvWndSize)
	isKeyUpdate, isKeyUpdateAck := c.keyUpdateFlags()

	// Pacing and congestion window block everything (including retransmits)
	if isBlockedByPacing || isBlockedByCwnd {
		if ack == nil {
			if isBlockedByPacing {
				return 0, c.nextWriteTime - nowNano, nil
			}
			return 0, MinDeadLine, nil
		}
		// Blocked but have ACK to send
		offset := c.snd.ensureKeyFlagsTracked(s.streamID, isKeyUpdate, isKeyUpdateAck)
		return c.encodeAndWrite(s, ack, nil, offset, false, isKeyUpdate, isKeyUpdateAck, nowNano, false)
	}

	// Reserve space for pktMtuUpdate if it will be injected.
	// The exact injection depends on close/keyUpdate flags (determined below),
	// but reserving space pessimistically is correct — at worst the packet is 2 bytes smaller.
	msgType := c.msgType()
	effectiveMtu := c.mtu
	if c.willInjectMtu(msgType) {
		effectiveMtu -= 2
	}

	// Try retransmission first (oldest unacked packet).
	// Retransmissions bypass the receive window check: the data was already
	// counted in dataInFlight when first sent, and the receiver's window was
	// open at that time. Blocking retransmits on rwnd causes deadlocks when
	// a lost packet creates a gap in the receiver's reassembly buffer.
	splitData, offset, isClose, isKeyUpdate, isKeyUpdateAck, err := c.snd.readyToRetransmit(s.streamID, ack, effectiveMtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		c.onPacketLoss()
		c.consecutiveLosses++
		if c.consecutiveLosses >= mtuFallbackThreshold && c.mtu > conservativeMTU {
			c.mtu = conservativeMTU
		}
		return c.encodeAndWrite(s, ack, splitData, offset, isClose, isKeyUpdate, isKeyUpdateAck, nowNano, false)
	}

	// Receive window blocks new data only (retransmits already handled above)
	if isBlockedByRwnd {
		if ack == nil {
			return 0, MinDeadLine, nil
		}
		offset := c.snd.ensureKeyFlagsTracked(s.streamID, isKeyUpdate, isKeyUpdateAck)
		return c.encodeAndWrite(s, ack, nil, offset, false, isKeyUpdate, isKeyUpdateAck, nowNano, false)
	}

	// Try sending new data (only after handshake or if init not yet sent)
	if c.phase == phaseReady || c.phase == phaseCreated {

		splitData, offset, isClose := c.snd.readyToSend(s.streamID, msgType, ack, effectiveMtu, isKeyUpdate, isKeyUpdateAck, s.reliable)
		if splitData != nil {
			return c.encodeAndWrite(s, ack, splitData, offset, isClose, isKeyUpdate, isKeyUpdateAck, nowNano, true)
		}
		if ack != nil || c.phase == phaseCreated || isKeyUpdate {
			offset := c.snd.ensureKeyFlagsTracked(s.streamID, isKeyUpdate, isKeyUpdateAck)
			return c.encodeAndWrite(s, ack, nil, offset, isClose, isKeyUpdate, isKeyUpdateAck, nowNano, false)
		}
	}

	// Send ACK-only if pending
	if ack != nil || isKeyUpdateAck {
		offset := c.snd.ensureKeyFlagsTracked(s.streamID, isKeyUpdate, isKeyUpdateAck)
		return c.encodeAndWrite(s, ack, nil, offset, false, isKeyUpdate, isKeyUpdateAck, nowNano, false)
	}

	return 0, MinDeadLine, nil
}

func (c *conn) encodeAndWrite(s *Stream, ack *ack, data []byte, offset uint64, isClose, isKeyUpdate, isKeyUpdateAck bool, nowNano uint64, trackInFlight bool) (int, uint64, error) {
	p := &payloadHeader{
		isClose:      isClose,
		needsReTx:    s.reliable || isClose || isKeyUpdate || isKeyUpdateAck,
		ack:          ack,
		streamId:     s.streamID,
		streamOffset: offset,
	}

	// Include maxPayload via pktMtuUpdate in the proto payload.
	// pktMtuUpdate is mutually exclusive with close/keyUpdate flags, so skip if those are set.
	if !isClose && !isKeyUpdate && !isKeyUpdateAck {
		switch c.msgType() {
		case initCryptoSnd, initRcv, initCryptoRcv:
			// Init packets carry proto payloads and are retransmitted until acknowledged.
			p.isMtuUpdate = true
			p.mtuUpdateValue = uint16(c.listener.maxPayload)
		case initSnd:
			// No proto payload — sender's MTU is sent in the first data packet after handshake.
		default:
			// Data packets: send MTU once (for initSnd sender's first data packet).
			if !c.mtuSent {
				p.isMtuUpdate = true
				p.mtuUpdateValue = uint16(c.listener.maxPayload)
			}
		}
	}

	if isKeyUpdate && c.sndKeys.prvKeyEpNext != nil {
		p.isKeyUpdate = true
		p.keyUpdatePub = c.sndKeys.prvKeyEpNext.PublicKey().Bytes()
	}

	if isKeyUpdateAck && c.rcvKeys.prvKeyEpNext != nil {
		p.isKeyUpdateAck = true
		p.keyUpdatePubAck = c.rcvKeys.prvKeyEpNext.PublicKey().Bytes()
	}

	encData, err := c.encode(p, data, c.msgType())
	if err != nil {
		return 0, 0, err
	}

	if data != nil {
		c.snd.updatePacketSize(s.streamID, offset, uint16(len(data)), uint16(len(encData)), nowNano, c.totalDelivered)
	}

	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	if !c.mtuSent && p.isMtuUpdate {
		c.mtuSent = true
	}

	if isKeyUpdateAck {
		c.phase = phaseReady
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
	if c.phase >= phaseReady {
		return data
	}
	return c.initMsgType
}

// willInjectMtu returns true if pktMtuUpdate will be added to the next packet.
// Used to reserve space in the data splitting calculation.
func (c *conn) willInjectMtu(msgType cryptoMsgType) bool {
	switch msgType {
	case initCryptoSnd, initRcv, initCryptoRcv:
		return true
	case initSnd:
		return false
	default:
		return !c.mtuSent
	}
}