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

// secrets is the sliding window of shared secrets a direction will accept:
// the current one, plus its neighbours while a key change is in flight.
type secrets struct {
	prev, cur, next []byte
}

// keyState is the sending side: our own ephemeral key, and the replacement
// generated when a rotation starts.
type keyState struct {
	secrets
	prvKeyEp     *ecdh.PrivateKey
	prvKeyEpNext *ecdh.PrivateKey
}

// rcvKeyState is the receiving side. It has no current private key of its own:
// what it needs is the peer's public keys, and one private key to answer the
// next rotation with.
type rcvKeyState struct {
	secrets
	prvKeyEpNext *ecdh.PrivateKey
	pubKeyEp     *ecdh.PublicKey
	pubKeyEpNext *ecdh.PublicKey
}

type connPhase int

const (
	phaseCreated  connPhase = iota // nothing sent
	phaseInitSent                  // init sent, awaiting reply
	phaseReady                     // handshake complete
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
	// The address this peer sent to, learned from inbound packets. Replies go
	// out from it so a wildcard-bound socket on a multi-homed host does not
	// answer from the wrong source. Zero for a dialed connection.
	localAddr netip.Addr
	listener  *Listener

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

	// Receive-window probing: when the last probe went out, and how many have
	// gone unanswered. Both reset when the window opens, so a fresh block
	// probes at once rather than waiting out the previous interval.
	rwndProbeNano  uint64
	rwndProbeCount uint

	// Sequence number of the newest packet a window was taken from. The window
	// is free space, so it is only meaningful as of the moment it was built:
	// an older packet arriving late carries a smaller, stale value, and
	// applying it would block the sender for no reason. Reset when the receive
	// key rotates, because the peer's sequence number restarts with it.
	rcvSnHigh uint64

	// Activity tracking
	lastReadTimeNano uint64

	// Cumulative acked payload bytes, any order (unlike the contiguous
	// acked offset, this does not freeze at head-of-line holes). Atomic:
	// read by user goroutines for progress/rate sampling.
	deliveredBytes atomic.Uint64

	// MTU negotiation
	mtu int // current max UDP payload
	// Largest wire size an ACK has proven the path carries. Only first
	// transmissions count: an ACK for a retransmit could answer either send,
	// so its size is ambiguous.
	mtuConfirmed  int
	mtuDowngraded bool // path black-holed the working size; stay conservative

	// Key update retransmission: the pending KU is re-attached once per RTO
	// until acked; on an idle connection, KU-only packets are re-sent
	kuLastSentNano uint64 // last time a packet carrying the KU went out
	kuSendCount    uint   // RTO-paced re-sends this round; errors past maxRetry
	// A KEY_UPDATE_ACK we owe the peer. A flag rather than a phase: as a phase
	// it excluded the connection from the "may send new data" test, so data
	// stalled for a packet even though the ack would have ridden along on it.
	kuAckDue bool

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
	return c.kuAckDue && c.rcvKeys.prvKeyEpNext != nil
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

// observeMTU folds one acknowledged packet into what is known about the path.
// The MTU only ever moves on evidence: an ACK proves a size traverses the
// path, and a smaller retransmit succeeding where larger sends failed proves
// the working size does not. Ordinary loss says nothing either way.
func (c *conn) observeMTU(pkt *sendPacket) {
	size := int(pkt.wireLen)

	// A first transmission is unambiguous, so it can raise the confirmed size.
	if pkt.sentCount == 0 {
		if size > c.mtuConfirmed {
			c.mtuConfirmed = size
		}
		return
	}

	// Otherwise this is a retransmit. Only the probe-sized ones say anything:
	// the packet failed at the working size repeatedly and got through once
	// shrunk, which is what an MTU black hole looks like. (An ACK for a
	// retransmit is transmission-ambiguous, but after this many failed
	// attempts a late ACK for the original is remote.)
	if c.mtuDowngraded || c.mtu <= conservativeMTU {
		return
	}
	// Once the working size has been seen to get through, loss is congestion,
	// not an MTU problem, and a probe succeeding proves nothing new. Only an
	// unconfirmed size can be downgraded. (A path that shrinks mid-connection
	// is caught by clearing mtuConfirmed when the network changes, which needs
	// migration support QOTP does not have yet.)
	if c.mtuConfirmed >= c.mtu {
		return
	}
	if pkt.sentCount >= maxRetry-mtuProbeLastAttempts && size <= conservativeMTU {
		slog.Warn("path does not carry the negotiated MTU; downgraded for this connection",
			"was", c.mtu,
			"confirmed", c.mtuConfirmed,
			"now", conservativeMTU)
		c.mtu = conservativeMTU
		c.mtuDowngraded = true
	}
}

// negotiateMTU sets the MTU ceiling. It runs on every packet, so it must leave
// a loss-triggered fallback alone; the ACK path restores the working value.
func (c *conn) negotiateMTU(remoteMaxPayload uint16) {
	// A downgrade is permanent for the life of the connection: the path has
	// demonstrated it cannot carry the larger size, and no amount of the peer
	// re-advertising its interface MTU changes that.
	if c.mtuDowngraded {
		return
	}
	c.mtu = max(min(c.listener.maxPayload, int(remoteMaxPayload)), conservativeMTU)
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
	// The high bit is the wire reliability marker, not an identifier.
	if streamID > maxStreamID {
		return nil
	}

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

func decodePacket(l *Listener, encData []byte, rAddr netip.AddrPort, msgType cryptoMsgType) (*conn, []byte, uint64, error) {
	connId := getUint64(encData[headerSize : headerSize+connIdSize])

	switch msgType {
	case initSnd, initCryptoSnd:
		conn, payload, err := decodeInitPacket(l, encData, rAddr, connId, msgType)
		return conn, payload, 0, err
	case initRcv, initCryptoRcv, data:
		conn, exists := l.connMap.get(connId)
		if !exists {
			return nil, nil, 0, fmt.Errorf("connection not found: %d", connId)
		}
		payload, sn, err := conn.decode(encData, msgType)
		return conn, payload, sn, err
	}
	return nil, nil, 0, fmt.Errorf("unknown message type: %v", msgType)
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
	l.logSecret("QOTP_SHARED_SECRET", connId, sharedSecret)
	if msgType == initCryptoSnd && l.keyLogWriter != nil {
		if ssId, err := l.prvKeyId.ECDH(pubKeyEpSnd); err == nil {
			l.logSecret("QOTP_SHARED_SECRET_ID", connId, ssId)
		}
	}
	return conn, payload, nil
}

// decode returns the payload and, for Data packets, the sequence number that
// orders it against other packets from the same peer. Init packets return 0:
// they are the first of a connection, so there is nothing to be stale against.
func (c *conn) decode(encData []byte, msgType cryptoMsgType) ([]byte, uint64, error) {
	switch msgType {
	case initRcv:
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, payload, err := decryptInitRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, 0, fmt.Errorf("decrypt InitRcv: %w", err)
		}
		c.pubKeyIdRcv = pubKeyIdRcv
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		c.listener.logSecret("QOTP_SHARED_SECRET", c.connId, sharedSecret)
		return payload, 0, nil

	case initCryptoRcv:
		sharedSecret, pubKeyEpRcv, payload, err := decryptInitCryptoRcv(encData, c.sndKeys.prvKeyEp)
		if err != nil {
			return nil, 0, fmt.Errorf("decrypt InitCryptoRcv: %w", err)
		}
		c.rcvKeys.pubKeyEp = pubKeyEpRcv
		c.rcvKeys.cur = sharedSecret
		c.sndKeys.cur = sharedSecret
		c.listener.logSecret("QOTP_SHARED_SECRET", c.connId, sharedSecret)
		return payload, 0, nil

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
	return nil, 0, fmt.Errorf("unexpected message type: %v", msgType)
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
		packetData := encodeProto(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			c.pubKeyIdRcv,
			c.listener.prvKeyId.PublicKey(),
			c.sndKeys.prvKeyEp,
			c.snCrypto,
			packetData,
		)
	case initRcv, initCryptoRcv, data:
		packetData := encodeProto(p, userData)
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
//
// processIncomingPayload runs on the event-loop goroutine only; the protocol
// state it touches is loop-owned (see conn doc). Stream-map access goes
// through the self-locking getOrCreateStream.
func (c *conn) processIncomingPayload(p *payloadHeader, userData []byte, sn uint64, nowNano uint64) (*Stream, error) {
	// Handle key update from peer
	if len(p.keyUpdatePub) == pubKeySize {
		if err := c.handlePeerKeyUpdate(p.keyUpdatePub); err != nil {
			return nil, fmt.Errorf("key update failed: %w", err)
		}
	}

	if len(p.keyUpdatePubAck) == pubKeySize {
		if err := c.handleKeyUpdateAck(p.keyUpdatePubAck); err != nil {
			return nil, fmt.Errorf("key update failed: %w", err)
		}
	}

	if p.maxPayload > 0 {
		c.negotiateMTU(p.maxPayload)
	}
	// Carried by every packet, so a peer that drained its buffer can tell us
	// with anything at all -- it does not need something to acknowledge. Only
	// from the newest packet seen, though: free space is a snapshot, and a
	// reordered older packet carries a smaller, stale one.
	if sn >= c.rcvSnHigh {
		c.rcvSnHigh = sn
		c.rcvWndSize = p.rcvWnd
	}

	// Process ACK if present
	if p.ack != nil {
		ackedPkt, lostCount := c.snd.acknowledgeRange(p.ack, c.lossEpochNano)
		if ackedPkt != nil {
			c.dataInFlight -= int(p.ack.len)
			c.deliveredBytes.Add(uint64(p.ack.len))
			// Losses feed the windowed fairness throttle (see updateThrottle);
			// no per-event reaction — the throttle's window is the
			// congestion-event granularity.
			//
			// Counted before updateMeasurements: that call can end a round,
			// and ending a round is what evaluates the window. Counting after
			// put this ACK's losses in the window that opens next, so a burst
			// was always judged one window late.
			if lostCount > 0 {
				c.windowLostPackets += uint64(lostCount)
			}
			// Karn's algorithm: an ACK for retransmitted data is ambiguous
			// (original or retransmit?) - never measure RTT/bandwidth from it
			if ackedPkt.sentCount == 0 && nowNano > ackedPkt.sentTimeNano {
				c.updateMeasurements(nowNano-ackedPkt.sentTimeNano, ackedPkt, nowNano)
			}
			c.observeMTU(ackedPkt)
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
			c.rcv.queueAck(p.streamId, p.streamOffset, uint16(len(userData)))
		}
		return nil, nil
	}

	// Insert data or queue ACK for empty packets (PING/CLOSE)
	if p.unreliable {
		c.rcv.markUnreliable(s.streamID)
	}

	if len(userData) > 0 {
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
		c.kuAckDue = true
		return nil
	}

	// NEW KEY_UPDATE - rotate if needed, then process
	if c.rcvKeys.next != nil {
		c.rcvKeys.prev = c.rcvKeys.cur
		c.rcvKeys.cur = c.rcvKeys.next
		c.rcvKeys.next = nil
		c.rcvKeys.prvKeyEpNext = nil
		c.rcvKeys.pubKeyEp = c.rcvKeys.pubKeyEpNext // MUST be before setting to nil
		c.rcvKeys.pubKeyEpNext = nil
		c.rcvSnHigh = 0 // the peer's sequence number restarts with its key
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

	c.kuAckDue = true
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

	// Expired best-effort packets (unreliable data, pings) are dropped, not
	// retransmitted: release their in-flight accounting
	c.dataInFlight -= c.snd.drainExpiredBestEffort(s.streamID, c.rtoNano(), nowNano)

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
	if !isBlockedByRwnd {
		c.rwndProbeNano, c.rwndProbeCount = 0, 0
	}

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
	// Try retransmission first (oldest unacked packet).
	// Retransmissions bypass the receive window check: the data was already
	// counted in dataInFlight when first sent, and the receiver's window was
	// open at that time. Blocking retransmits on rwnd causes deadlocks when
	// a lost packet creates a gap in the receiver's reassembly buffer.
	// The probe carries the same reservations, just at the conservative size.
	probeMtu := effectiveMtu - (c.mtu - conservativeMTU)
	splitData, offset, isClose, err := c.snd.readyToRetransmit(
		s.streamID, ack, effectiveMtu, probeMtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, false)
	}

	// Handshake re-send: in phaseInitSent the response hasn't arrived. Inits
	// carrying tracked 0-RTT data retransmit via the in-flight buffer above;
	// untracked inits (InitSnd, empty dials, InitRcv) are re-sent here with
	// the same backoff and give-up as data retransmits.
	if c.phase == phaseInitSent && !c.snd.hasInFlight(s.streamID) {
		// The final re-send gets its full response window before the error
		// fires: backoff clamps the attempt, the count below does not
		if nowNano-c.initLastSentNano > backoff(c.rtoNano(), c.initSendCount) {
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
		// The window is only ever learned from an ACK, and a peer with nothing
		// to acknowledge sends none — so a blocked sender that goes quiet is
		// deadlocked until some unrelated packet times out. Probe once per RTO
		// instead: with no ACK of our own to carry, the control packet below
		// carries a stream header, the peer acknowledges that, and every ACK
		// refreshes the window.
		// Backed off like a retransmit, and for the same reason: a peer that
		// stays shut is not going to answer sooner for being asked more often.
		// Responsiveness does not depend on the interval anyway -- the peer
		// announces a reopened window itself, and every probe it does answer
		// carries the current one. Unlike a retransmit this never gives up:
		// a peer refusing data is behaving correctly, and only silence, caught
		// by the read deadline, ends the connection.
		if ack == nil && !kuSendDue {
			every := backoff(c.rtoNano(), c.rwndProbeCount)
			if waited := nowNano - c.rwndProbeNano; waited < every {
				return 0, every - waited, nil
			}
			c.rwndProbeNano, c.rwndProbeCount = nowNano, c.rwndProbeCount+1
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

	// Nothing to send. If our own receive buffer has drained well past what we
	// last advertised, a peer blocked on the stale value would sit out its
	// probe timer for no reason -- any packet carries the new window, so send
	// one. Best-effort: the sender's probe stays the guarantee.
	if c.rcv.windowReopened(c.mtu) {
		return c.sendControlPacket(s, nil, nowNano)
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
		maxPayload: uint16(c.listener.maxPayload),
		rcvWnd:     c.rcv.freeAdvertise(),
		isClose:    isClose,
		// The stream's property, not the packet's: whether a given packet is
		// retransmitted is sendPacket.needsReTx.
		unreliable:   !s.reliable,
		ack:          ack,
		streamId:     s.streamID,
		streamOffset: offset,
	}

	if isKeyUpdate {
		p.keyUpdatePub = c.sndKeys.prvKeyEpNext.PublicKey().Bytes()
	}
	if isKeyUpdateAck {
		p.keyUpdatePubAck = c.rcvKeys.prvKeyEpNext.PublicKey().Bytes()
	}

	encData, err := c.encode(p, data, c.msgType())
	if err != nil {
		return 0, 0, err
	}

	// The reported write duration is unused; see the stamp below.
	_, err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, c.localAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	// Stamped before the write. A write reports its duration from a clock read
	// after the syscall returns, so a deschedule in between lands inside it and
	// dates the packet later than it left, making RTT samples come out short --
	// and rttMin, a minimum filter, keeps the worst one for its whole TTL.
	// Erring early instead only inflates a sample, which the filter discards.
	if data != nil {
		c.snd.markSent(s.streamID, offset, uint16(len(data)), uint16(len(encData)), nowNano,
			c.totalDelivered, c.deliveredTimeNano, c.firstSentTimeNano)
	}

	if isKeyUpdate {
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
		c.kuAckDue = false
	}

	// Token-bucket pacing with burst allowance: schedule the next send
	// relative to the previous nextWriteTime, not nowNano. The event loop
	// sends one packet per wakeup and read deadlines quantize to ~1ms
	// (epoll granularity), so scheduling from nowNano silently discards
	// every send opportunity a late wakeup skipped — capping throughput at
	// one packet per wakeup and locking the bw estimator onto that
	// artifact. Carrying the pacing credit forward lets a late wakeup send
	// a short back-to-back burst instead, so the achieved rate tracks the
	// paced rate. Credit and debt are both capped at maxBurstPackets: a
	// long-idle connection cannot bank an unbounded burst, and packets that
	// bypass the pacing gate (ACKs) cannot push the next send arbitrarily
	// far out.
	pacingNano := c.calcPacing(uint64(len(encData)))
	burst := maxBurstPackets * pacingNano
	floor := uint64(0)
	if nowNano > burst {
		floor = nowNano - burst
	}
	c.nextWriteTime = min(max(c.nextWriteTime, floor)+pacingNano, nowNano+burst)

	dataLen := len(data)
	if trackInFlight && dataLen > 0 {
		c.dataInFlight += dataLen
	}

	return dataLen, pacingNano, nil
}

// sendControlPacket sends a packet carrying no stream data (ACK, key update,
// handshake re-send, or a window probe) at the stream's current send offset.
// Key-update and MTU fields are attached by encodeAndWrite from connection
// state.
//
// A window probe is deliberately not tracked in the send buffer. It does not
// need to be: the window rides the packet header, so any reply carries it, and
// the reply's attribution is irrelevant. Tracking would reserve the
// zero-payload slot -- one per (stream, offset) -- and a probe whose ACK was
// lost would then hold that slot until it drained, blocking the next probe:
// the recovery path stalling itself.
func (c *conn) sendControlPacket(s *Stream, ack *ack, nowNano uint64) (int, uint64, error) {
	offset := c.snd.getSendOffset(s.streamID)

	// A connection that only ever receives sends nothing the peer will ACK, so
	// it never gets an RTT sample and stays on the cold-start pacing fallback
	// for its whole life. Until the first sample, carry a stream header on an
	// outgoing control packet and track it: the peer ACKs any packet with a
	// stream header, and that ACK is the sample. This rides the ACK path
	// deliberately — ACKs bypass the pacing gate, so unlike a ping it still
	// gets out when the connection is pacing-blocked.
	if c.srtt == 0 && c.msgType() == data && c.snd.trackProbe(s.streamID) {
		return c.encodeAndWrite(s, ack, []byte{}, offset, false, nowNano, false)
	}
	return c.encodeAndWrite(s, ack, nil, offset, false, nowNano, false)
}

// =============================================================================
// Helpers
// =============================================================================

// isInitiator reports whether this side dialed. Sets the AEAD nonce direction
// bit and decides which message completes the handshake.
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
