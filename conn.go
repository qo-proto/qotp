package qotp

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
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
//
// Concurrency model: all protocol state (measurements, pacing, MTU, phase,
// dataInFlight, rcvWndSize, key state) is owned by the single event-loop
// goroutine (Listener.Loop) and accessed without locks — do not touch it
// from other goroutines. Cross-goroutine access is limited to: the streams
// map (guarded by mu against user-goroutine Stream() calls; Flush iterates
// it via the linkedMap's internal lock), the send/receive buffers (their
// own locks), and the stream close flags (atomic).
type conn struct {
	connId     uint64
	remoteAddr netip.AddrPort
	listener   *Listener

	snCrypto    uint64
	pubKeyIdRcv *ecdh.PublicKey // Identity
	sndKeys     *keyState
	rcvKeys     *rcvKeyState

	// Handshake state
	initMsgType cryptoMsgType
	phase       connPhase

	// Stream and buffer management
	streams      *sharedLinkedMap[uint32, *Stream]
	snd          *sender
	rcv          *receiver
	dataInFlight int
	rcvWndSize   uint64

	// Pacing
	nextWriteTime uint64

	// Activity tracking
	lastReadTimeNano uint64

	// Cumulative acked payload bytes, any order (unlike the contiguous
	// acked offset, this does not freeze at head-of-line holes). Atomic:
	// read by user goroutines for progress/rate sampling.
	deliveredBytes atomic.Uint64

	// MTU negotiation
	mtu               int  // current max UDP payload (starts conservative, may fall back on losses)
	negotiatedMTU     int  // negotiated value (for restoring after fallback)
	mtuSent           bool // whether we've sent our maxPayload to the peer
	consecutiveLosses int
	mtuFlapCount      int // completed fallback→restore cycles; high count hints at an MTU black hole

	// Key update retransmission: the pending KU is re-attached once per RTO
	// until acked; on an idle connection, KU-only packets are re-sent
	kuLastSentNano uint64 // last time a packet carrying the KU went out
	kuSendCount    uint   // RTO-paced re-sends this round; errors past maxRetry

	// Handshake retransmission: untracked init packets (InitSnd, empty
	// crypto dials, InitRcv) are re-sent with backoff in phaseInitSent,
	// same give-up as data retransmits (~5s)
	initLastSentNano uint64
	initSendCount    uint

	measurements
	mu sync.Mutex
}

// =============================================================================
// Public methods
// =============================================================================

func (c *conn) Stream(streamID uint32) *Stream {
	return c.getOrCreateStream(streamID)
}

func (c *conn) HasActiveStreams() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, val := range c.streams.iterator(nil) {
		if val != nil && (!val.rcvClosed.Load() || !val.sndClosed.Load()) {
			return true
		}
	}
	return false
}

// kuPending reports a KEY_UPDATE we initiated that the peer has not acked yet.
func (c *conn) kuPending() bool {
	return c.sndKeys.prvKeyEpNext != nil && c.sndKeys.next == nil
}

// kuAckPending reports a KEY_UPDATE_ACK we owe the peer.
func (c *conn) kuAckPending() bool {
	return c.phase == phaseKeyUpdatePending && c.rcvKeys.prvKeyEpNext != nil
}

// kuAttachDue returns true when the pending KEY_UPDATE should be attached to
// the next outgoing packet: on first send, then once per RTO until the
// KEY_UPDATE_ACK arrives. The key is not attached to every packet — any
// single carrier may be lost, and the next RTO tick re-sends it.
func (c *conn) kuAttachDue(nowNano uint64) bool {
	if !c.kuPending() {
		return false
	}
	return c.kuLastSentNano == 0 || nowNano-c.kuLastSentNano > c.rtoNano()
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

// cleanupStream removes stream state. A stale round-robin cursor pointing at
// the removed stream is fine: linkedMap.iterator falls back to the beginning.
func (c *conn) cleanupStream(streamID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streams.remove(streamID)
	c.snd.removeStream(streamID)
	c.rcv.removeStream(streamID)
}

// negotiateMTU sets the connection's MTU to min(remoteMaxPayload, localMaxPayload).
func (c *conn) negotiateMTU(remoteMaxPayload uint16) {
	negotiated := max(min(c.listener.maxPayload, int(remoteMaxPayload)), conservativeMTU)
	c.mtu = negotiated
	c.negotiatedMTU = negotiated
}

// =============================================================================
// Stream management
// =============================================================================

// getOrCreateStream returns or creates a stream. Returns nil if the stream
// was already finished. Self-locking: callable from the event loop and from
// user goroutines (conn.Stream).
//
// c.mu serializes the isFinished check against cleanupStream: without it, a
// concurrent cleanup between the check and the insert could resurrect a
// finished stream. The map itself is internally locked (sharedLinkedMap).
func (c *conn) getOrCreateStream(streamID uint32) *Stream {
	// Fast path: existing stream, no allocation, no c.mu. The finished
	// check must come first — a finished stream may still be in the map,
	// and finished trumps presence.
	if c.rcv.isFinished(streamID) {
		return nil
	}
	if v, exists := c.streams.get(streamID); exists {
		return v
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rcv.isFinished(streamID) {
		return nil
	}
	s := &Stream{streamID: streamID, conn: c, reliable: true, reorderDeadlineNano: defaultReorderDeadlineNano}
	s, _ = c.streams.getOrPut(streamID, s)
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
	var pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey
	var senderMaxPayload uint16
	var payload []byte
	var err error

	switch msgType {
	case initSnd:
		pubKeyIdSnd, pubKeyEpSnd, senderMaxPayload, err = decryptInitSnd(encData)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitSnd: %w", err)
		}
		payload = []byte{} // InitSnd carries no proto payload
	case initCryptoSnd:
		pubKeyIdSnd, pubKeyEpSnd, payload, err = decryptInitCryptoSnd(encData, l.prvKeyId)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt InitCryptoSnd: %w", err)
		}
	default:
		return nil, nil, errors.New("invalid init message type")
	}

	conn, err := l.getOrCreateConn(connId, rAddr, pubKeyIdSnd, pubKeyEpSnd, false, msgType == initCryptoSnd)
	if err != nil {
		return nil, nil, err
	}
	// InitCryptoSnd carries the peer's maxPayload in the proto payload instead
	if msgType == initSnd {
		conn.negotiateMTU(senderMaxPayload)
	}

	sharedSecret, err := conn.sndKeys.prvKeyEp.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	conn.sndKeys.cur = sharedSecret
	conn.rcvKeys.cur = sharedSecret //initially, both are the same, as sync is for free
	return conn, payload, nil
}

func (c *conn) decode(encData []byte, msgType cryptoMsgType) ([]byte, error) {
	switch msgType {
	case initRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, payload, err := decryptInitRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		c.pubKeyIdRcv = pubKeyIdRcv
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		return payload, nil

	case initCryptoRcv:
		sharedSecret, pubKeyEpRcv, payload, err := decryptInitCryptoRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		return payload, nil

	case data:
		secrets := [][]byte{c.rcvKeys.cur}
		if c.rcvKeys.prev != nil {
			secrets = append(secrets, c.rcvKeys.prev)
		}
		if c.rcvKeys.next != nil {
			secrets = append(secrets, c.rcvKeys.next)
		}
		return decryptData(encData, c.isInitiator(), secrets)

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
			c.isInitiator(),
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
	// At halfway: initiate rotation. >= (not ==) so a transient keygen
	// failure retries on the next packet instead of being skipped forever.
	if c.snCrypto >= 1<<46 && c.sndKeys.prvKeyEpNext == nil {
		newKey, err := generateKey()
		if err != nil {
			return nil, err
		}
		c.sndKeys.prvKeyEpNext = newKey
		c.kuLastSentNano = 0
		c.kuSendCount = 0
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
// processIncomingPayload runs on the event-loop goroutine only; the protocol
// state it touches is loop-owned (see conn doc). Stream-map access goes
// through the self-locking getOrCreateStream.
func (c *conn) processIncomingPayload(p *payloadHeader, userData []byte, nowNano uint64) (*Stream, error) {
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
		ackStatus, ackedPkt, lostCount := c.snd.acknowledgeRange(p.ack)
		c.rcvWndSize = p.ack.rcvWnd

		if ackStatus == ackStatusOk {
			c.dataInFlight -= int(p.ack.len)
			c.deliveredBytes.Add(uint64(p.ack.len))
			// Karn's algorithm: an ACK for retransmitted data is ambiguous
			// (original or retransmit?) - never measure RTT/bandwidth from it
			if ackedPkt.sentCount == 0 && nowNano > ackedPkt.sentTimeNano {
				c.updateMeasurements(nowNano-ackedPkt.sentTimeNano, p.ack.len, ackedPkt, nowNano)
			}
			// Losses feed the windowed fairness throttle (see
			// updateThrottle); no per-event reaction — the throttle's
			// window is the congestion-event granularity
			if lostCount > 0 {
				c.windowLostPackets += uint64(lostCount)
			}
			if c.consecutiveLosses > 0 {
				c.consecutiveLosses = 0
				if c.mtu < c.negotiatedMTU {
					c.mtu = c.negotiatedMTU
					c.mtuFlapCount++
					if c.mtuFlapCount > mtuFlapWarnThreshold {
						slog.Warn("MTU flapping: repeated fallback/restore cycles, path may drop large packets",
							"cycles", c.mtuFlapCount,
							"negotiatedMTU", c.negotiatedMTU,
							"conservativeMTU", conservativeMTU)
					}
				}
			}
			if ackStream := c.getOrCreateStream(p.ack.streamId); ackStream != nil && !ackStream.sndClosed.Load() && c.snd.checkStreamFullyAcked(p.ack.streamId) {
				ackStream.sndClosed.Store(true)
			}
		}
	}

	// No stream header (ACK-only packet): streamId/offset are unset, so there
	// is no stream to touch. The ACK above was the whole payload.
	if userData == nil {
		return nil, nil
	}

	// Get or create stream; nil if stream already finished
	s := c.getOrCreateStream(p.streamId)
	if s == nil {
		// Stream finished but peer still sending - ACK to stop retransmits
		if c.rcv.isFinished(p.streamId) {
			if len(userData) > 0 {
				c.rcv.queueAck(p.streamId, p.streamOffset, uint16(len(userData)))
			} else {
				// Empty packet (ping/close/key-update): still ACK it
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
		if !p.needsReTx {
			c.rcv.markUnreliable(s.streamID)
		}
		c.rcv.insert(s.streamID, p.streamOffset, nowNano, userData)
		c.rcv.checkGap(s.streamID, nowNano, s.reorderDeadlineNano)
	} else {
		// Empty packet (ping/close/key-update): still ACK it
		c.rcv.queueAck(s.streamID, p.streamOffset, 0)
	}

	// Handle stream close
	if p.isClose {
		c.rcv.close(s.streamID, p.streamOffset+uint64(len(userData)))
		c.rcv.checkGap(s.streamID, nowNano, s.reorderDeadlineNano)
	}

	// Update stream close state
	if !s.rcvClosed.Load() && c.rcv.isReadyToClose(s.streamID) {
		s.rcvClosed.Store(true)
	}
	if !s.sndClosed.Load() && c.snd.checkStreamFullyAcked(s.streamID) {
		s.sndClosed.Store(true)
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
// bytesSent=0 with nextWakeupNano>0 means blocked by pacing/rwnd.
func (c *conn) flushStream(s *Stream, nowNano uint64) (int, uint64, error) {
	ack := c.rcv.getSndAck()
	if ack != nil {
		// max(0): size can briefly exceed capacity when an in-order segment
		// is accepted over the limit to break a reassembly deadlock
		ack.rcvWnd = uint64(max(c.rcv.capacity-c.rcv.size(), 0))
	}

	// Expired best-effort packets (unreliable data, pings) are dropped, not
	// retransmitted: release their in-flight accounting
	droppedBytes, _ := c.snd.drainExpiredBestEffort(s.streamID, c.rtoNano(), nowNano)
	c.dataInFlight -= droppedBytes

	// Skip receive gaps on unreliable streams whose reorder deadline passed
	// (covers the case where the sender went silent mid-gap)
	c.rcv.checkGap(s.streamID, nowNano, s.reorderDeadlineNano)

	// Key update handling: the pending KU is attached to the next outgoing
	// packet by encodeAndWrite, then re-attached once per RTO until the
	// KEY_UPDATE_ACK arrives. On an idle connection a KU-only packet is sent
	// instead. Gives up after maxRetry re-sends, like data retransmits.
	// KUAck needs no timer: a lost ack is re-triggered by the peer's KU retransmit.
	isKeyUpdateAck := c.kuAckPending()
	kuSendDue := c.kuAttachDue(nowNano)
	// Give up only when the NEXT re-send would be due, so the final re-send
	// gets its full response window before the error fires
	if kuSendDue && c.kuSendCount >= maxRetry {
		return 0, 0, errors.New("key update: max retry attempts exceeded")
	}

	// Check send blockers
	isBlockedByPacing := c.nextWriteTime > nowNano

	isBlockedByRwnd := c.dataInFlight+c.mtu > int(c.rcvWndSize)

	// Pacing blocks everything (including retransmits)
	if isBlockedByPacing {
		if ack == nil {
			return 0, c.nextWriteTime - nowNano, nil
		}
		// Blocked but have ACK to send
		return c.sendControlPacket(s, ack, nowNano)
	}

	// Reserve space for key update pubkeys and the MTU update field:
	// encodeAndWrite attaches them from connection state, so the sender must
	// size data accordingly. Pessimistic reservation is correct — at worst
	// the packet is a few bytes smaller.
	msgType := c.msgType()
	effectiveMtu := c.mtu
	if kuSendDue {
		effectiveMtu -= pubKeySize
	}
	if isKeyUpdateAck {
		effectiveMtu -= pubKeySize
	}
	if c.willInjectMtu(msgType) {
		effectiveMtu -= 2
	}

	// Try retransmission first (oldest unacked packet).
	// Retransmissions bypass the receive window check: the data was already
	// counted in dataInFlight when first sent, and the receiver's window was
	// open at that time. Blocking retransmits on rwnd causes deadlocks when
	// a lost packet creates a gap in the receiver's reassembly buffer.
	splitData, offset, isClose, err := c.snd.readyToRetransmit(s.streamID, ack, effectiveMtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		c.consecutiveLosses++
		if c.consecutiveLosses >= mtuFallbackThreshold && c.mtu > conservativeMTU {
			c.mtu = conservativeMTU
		}
		return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, false)
	}

	// Handshake re-send: in phaseInitSent the response hasn't arrived. Inits
	// carrying tracked 0-RTT data retransmit via the in-flight buffer above;
	// untracked inits (InitSnd, empty dials, InitRcv) are re-sent here with
	// the same backoff and give-up as data retransmits.
	if c.phase == phaseInitSent && !c.snd.hasInFlight(s.streamID) {
		// Cap the backoff attempt so the final re-send gets its full response
		// window; the error fires only once that window has also expired
		attempt := c.initSendCount
		if attempt > maxRetry-1 {
			attempt = maxRetry - 1
		}
		waitNano, err := backoff(c.rtoNano(), attempt)
		if err != nil {
			return 0, 0, err
		}
		if nowNano-c.initLastSentNano > waitNano {
			if c.initSendCount >= maxRetry {
				return 0, 0, errors.New("handshake: max retry attempts exceeded")
			}
			c.initSendCount++
			return c.sendControlPacket(s, ack, nowNano)
		}
	}

	// Receive window blocks new data only. Retransmits are handled above;
	// ACKs and KU-only packets carry no data and may pass.
	if isBlockedByRwnd {
		if ack == nil && !kuSendDue {
			return 0, minDeadline, nil
		}
		return c.sendControlPacket(s, ack, nowNano)
	}

	// Try sending new data (only after handshake or if init not yet sent)
	if c.phase == phaseReady || c.phase == phaseCreated {

		splitData, offset, isClose := c.snd.readyToSend(s.streamID, msgType, ack, effectiveMtu, s.reliable)
		if splitData != nil {
			return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, true)
		}
		if ack != nil || c.phase == phaseCreated || kuSendDue {
			return c.sendControlPacket(s, ack, nowNano)
		}
	}

	// Send ACK-only if pending
	if ack != nil || isKeyUpdateAck {
		return c.sendControlPacket(s, ack, nowNano)
	}

	return 0, minDeadline, nil
}

func (c *conn) encodeAndWrite(s *Stream, ack *ack, data []byte, offset uint64, isClose bool, nowNano uint64, trackInFlight bool) (int, uint64, error) {
	// Key update flags are derived from connection state. The pending KU is
	// attached once per RTO (kuAttachDue); the pending KUAck is attached
	// until sent once (phase flips to Ready below).
	isKeyUpdate := c.kuAttachDue(nowNano)
	isKeyUpdateAck := c.kuAckPending()

	p := &payloadHeader{
		isClose:      isClose,
		needsReTx:    s.reliable || isClose || isKeyUpdate || isKeyUpdateAck,
		ack:          ack,
		streamId:     s.streamID,
		streamOffset: offset,
	}

	// Include maxPayload via the MTU update field in the proto payload.
	// Skipped on close/keyUpdate packets to keep them at their expected size.
	// InitSnd embeds MTU in its fixed crypto header instead (willInjectMtu is false).
	if !isClose && !isKeyUpdate && !isKeyUpdateAck && c.willInjectMtu(c.msgType()) {
		p.isMtuUpdate = true
		p.mtuUpdateValue = uint16(c.listener.maxPayload)
	}

	if isKeyUpdate {
		p.isKeyUpdate = true
		p.keyUpdatePub = c.sndKeys.prvKeyEpNext.PublicKey().Bytes()
	}

	if isKeyUpdateAck {
		p.isKeyUpdateAck = true
		p.keyUpdatePubAck = c.rcvKeys.prvKeyEpNext.PublicKey().Bytes()
	}

	encData, err := c.encode(p, data, c.msgType())
	if err != nil {
		return 0, 0, err
	}

	elapsedNano, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	// Stamp with the send-completion time: the write can block (full socket
	// buffer), and a pre-block stamp would inflate this packet's RTT sample
	// by our own send stall
	if data != nil {
		c.snd.markSent(s.streamID, offset, uint16(len(data)), nowNano+elapsedNano,
			c.totalDelivered, c.deliveredTimeNano, c.firstSentTimeNano)
	}

	if !c.mtuSent && (p.isMtuUpdate || c.msgType() == initSnd) {
		c.mtuSent = true
	}

	if p.isKeyUpdate {
		if c.kuLastSentNano != 0 {
			c.kuSendCount++ // an RTO passed without a KUAck: this is a re-send
		}
		c.kuLastSentNano = nowNano
	}

	// encode() moved us to phaseInitSent for init packets: stamp for the
	// handshake re-send timer
	if c.phase == phaseInitSent {
		c.initLastSentNano = nowNano
	}

	if isKeyUpdateAck {
		c.phase = phaseReady
	}

	// Token-bucket pacing with burst allowance: schedule the next send
	// relative to the previous nextWriteTime, not nowNano. The event loop
	// sends one packet per wakeup and read deadlines quantize to ~1ms
	// (epoll granularity), so scheduling from nowNano silently discards
	// every send opportunity a late wakeup skipped — capping throughput at
	// one packet per wakeup and locking the bw estimator onto that
	// artifact. Carrying the pacing credit forward lets a late wakeup send
	// a short back-to-back burst instead, so the achieved rate tracks the
	// paced rate. The credit is floored at maxBurstPackets so a long-idle
	// connection can't dump an unbounded burst into the queue.
	pacingNano := c.calcPacing(uint64(len(encData)))
	floor := uint64(0)
	if debt := maxBurstPackets * pacingNano; nowNano > debt {
		floor = nowNano - debt
	}
	c.nextWriteTime = max(c.nextWriteTime, floor) + pacingNano

	dataLen := len(data)
	if trackInFlight && dataLen > 0 {
		c.dataInFlight += dataLen
	}

	return dataLen, pacingNano, nil
}

// sendControlPacket sends a packet carrying no stream data (ACK, key update,
// or handshake re-send) at the stream's current send offset. Key-update and
// MTU fields are attached by encodeAndWrite from connection state.
func (c *conn) sendControlPacket(s *Stream, ack *ack, nowNano uint64) (int, uint64, error) {
	return c.encodeAndWrite(s, ack, nil, c.snd.getSendOffset(s.streamID), false, nowNano, false)
}

// =============================================================================
// Helpers
// =============================================================================

// isInitiator reports whether this side opened the connection (it dialed and
// sent the init packet). Determines the AEAD nonce direction bit and which
// message completes the handshake.
func (c *conn) isInitiator() bool {
	return c.initMsgType == initSnd || c.initMsgType == initCryptoSnd
}

// msgType returns the crypto message type based on handshake state.
func (c *conn) msgType() cryptoMsgType {
	if c.phase >= phaseReady {
		return data
	}
	return c.initMsgType
}

// willInjectMtu returns true if the MTU update field will be added to the next packet.
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