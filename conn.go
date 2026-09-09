package qotp

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
)

// secrets a direction accepts: the current one plus its neighbours while a
// key change is in flight
type secrets struct {
	prev, cur, next []byte
}

// keyState is the sending side: our ephemeral key and its replacement once a
// rotation starts
type keyState struct {
	secrets
	prvKeyEp     *ecdh.PrivateKey
	prvKeyEpNext *ecdh.PrivateKey
}

// rcvKeyState is the receiving side: the peer's public keys, and a private
// key to answer the next rotation with
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

// conn is a connection to one peer, multiplexing streams.
//
// All protocol state is owned by the event-loop goroutine and accessed
// without locks. Other goroutines may only touch the streams map (mu), the
// send/receive buffers (their own locks) and the stream close flags (atomic).
type conn struct {
	connId     uint64
	remoteAddr netip.AddrPort
	// The address the peer sent to, so a wildcard-bound socket on a
	// multi-homed host replies from the right source. Zero when dialed.
	localAddr netip.Addr
	listener  *Listener

	snCrypto    uint64
	pubKeyIdRcv *ecdh.PublicKey
	sndKeys     *keyState
	rcvKeys     *rcvKeyState

	initMsgType cryptoMsgType
	phase       connPhase

	streams      *sharedLinkedMap[uint32, *Stream]
	snd          *sender
	rcv          *receiver
	dataInFlight int
	rcvWndSize   uint64

	nextWriteTime uint64

	// When the last receive-window probe went out; reset when the window
	// opens so a fresh block probes at once
	rwndProbeNano uint64

	// Sequence number of the newest packet a window was taken from: the
	// window is a snapshot of free space, so an older packet arriving late
	// carries a stale one. Reset with the receive key, as the peer's
	// sequence number restarts with it.
	rcvSnHigh uint64

	lastReadTimeNano uint64

	// Acked payload bytes in any order; unlike the contiguous acked offset
	// this does not freeze at head-of-line holes. Read by user goroutines.
	deliveredBytes atomic.Uint64

	mtu int // current max UDP payload
	// Largest wire size an ACK for a first transmission has proven; an ACK
	// for a retransmit could answer either send
	mtuConfirmed  int
	mtuDowngraded bool

	// The pending key update is re-attached once per RTO until acked
	kuLastSentNano uint64
	kuSendCount    uint
	// A flag rather than a phase: a phase excluded the connection from
	// sending new data, so data stalled for a packet the ack could have
	// ridden along on
	kuAckDue bool

	// Untracked init packets are re-sent with backoff in phaseInitSent
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

// kuAttachDue reports whether the pending KEY_UPDATE should ride on the next
// packet: on first send, then once per RTO until acked.
func (c *conn) kuAttachDue(nowNano uint64) bool {
	if !c.kuPending() {
		return false
	}
	return c.kuLastSentNano == 0 || nowNano-c.kuLastSentNano > c.rtoNano()
}

// =============================================================================
// Connection lifecycle
// =============================================================================

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
	c.streams.remove(streamID)
	c.snd.removeStream(streamID)
	c.rcv.removeStream(streamID)
}

// observeMTU moves the MTU only on evidence: an ACK for a first transmission
// proves a size traverses the path; a probe-sized retransmit succeeding where
// the working size repeatedly failed proves the working size does not.
func (c *conn) observeMTU(pkt *sendPacket) {
	size := int(pkt.wireLen)

	if pkt.sentCount == 0 {
		c.mtuConfirmed = max(c.mtuConfirmed, size)
		return
	}

	// Once the working size has been seen to get through, later loss is
	// congestion, not an MTU problem
	if c.mtuDowngraded || c.mtu <= conservativeMTU || c.mtuConfirmed >= c.mtu {
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

// negotiateMTU runs on every packet; a downgrade is permanent because the
// path, not the peer's advertisement, decided it
func (c *conn) negotiateMTU(remoteMaxPayload uint16) {
	if c.mtuDowngraded {
		return
	}
	c.mtu = max(min(c.listener.maxPayload, int(remoteMaxPayload)), conservativeMTU)
}

// =============================================================================
// Stream management
// =============================================================================

// getOrCreateStream returns nil for a finished stream. Callable from any
// goroutine; c.mu keeps the finished check and the insert atomic against
// cleanupStream, or a concurrent cleanup could resurrect a finished stream.
func (c *conn) getOrCreateStream(streamID uint32) *Stream {
	if streamID > maxStreamID { // the high bit is the wire reliability marker
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.rcv.isFinished(streamID) {
		return nil
	}
	s := &Stream{streamID: streamID, conn: c, reliable: true, gapTimeoutNano: defaultGapTimeoutNano}
	s, _ = c.streams.getOrPut(streamID, s)
	return s
}

// =============================================================================
// Packet decoding (receive path)
// =============================================================================

func decodePacket(l *Listener, encData []byte, rAddr netip.AddrPort, msgType cryptoMsgType) (*conn, []byte, uint64, error) {
	connId := binary.LittleEndian.Uint64(encData[headerSize : headerSize+connIdSize])

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
// orders it against other packets from the peer (0 for init packets).
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
	// Halfway to overflow: start a rotation. >= so a failed keygen retries.
	if c.snCrypto >= 1<<46 && c.sndKeys.prvKeyEpNext == nil {
		newKey, err := generateKey()
		if err != nil {
			return nil, err
		}
		c.sndKeys.prvKeyEpNext = newKey
		c.kuLastSentNano = 0
		c.kuSendCount = 0
	}

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

// processIncomingPayload applies a decoded payload. userData is nil for an
// ACK-only packet, empty for a ping, and the data otherwise.
func (c *conn) processIncomingPayload(p *payloadHeader, userData []byte, sn uint64, nowNano uint64) (*Stream, error) {
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
	// Only the newest packet's window: an older one is a stale snapshot
	if sn >= c.rcvSnHigh {
		c.rcvSnHigh = sn
		c.rcvWndSize = p.rcvWnd
	}

	if p.ack != nil {
		ackedPkt, lostCount := c.snd.acknowledgeRange(p.ack, c.lossEpochNano)
		if ackedPkt != nil {
			c.dataInFlight -= int(p.ack.len)
			c.deliveredBytes.Add(uint64(p.ack.len))
			// Before updateMeasurements, which may end the round that
			// evaluates the window; after, a burst was judged a window late
			c.windowLostPackets += uint64(lostCount)
			// Karn: an ACK for retransmitted data is ambiguous, never measure it
			if ackedPkt.sentCount == 0 && nowNano > ackedPkt.sentTimeNano {
				c.updateMeasurements(nowNano-ackedPkt.sentTimeNano, ackedPkt, nowNano)
			}
			c.observeMTU(ackedPkt)
			if ackStream := c.getOrCreateStream(p.ack.streamId); ackStream != nil && !ackStream.sndClosed.Load() && c.snd.checkStreamFullyAcked(p.ack.streamId) {
				ackStream.sndClosed.Store(true)
			}
		}
	}

	if userData == nil { // ACK-only: no stream header
		return nil, nil
	}

	s := c.getOrCreateStream(p.streamId)
	if s == nil {
		// Finished stream, peer still sending: ACK so it stops
		if c.rcv.isFinished(p.streamId) {
			c.rcv.queueAck(p.streamId, p.streamOffset, uint16(len(userData)))
		}
		return nil, nil
	}

	if p.unreliable {
		c.rcv.markUnreliable(s.streamID)
	}

	if len(userData) > 0 {
		c.rcv.insert(s.streamID, p.streamOffset, nowNano, userData)
		c.rcv.checkGap(s.streamID, nowNano, s.gapTimeoutNano)
	} else { // ping, close or key update: still ACKed
		c.rcv.queueAck(s.streamID, p.streamOffset, 0)
	}

	if p.isClose {
		c.rcv.close(s.streamID, p.streamOffset+uint64(len(userData)))
		c.rcv.checkGap(s.streamID, nowNano, s.gapTimeoutNano)
	}

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

	// Retransmit of a previous round's KEY_UPDATE, already rotated past
	if c.rcvKeys.pubKeyEp != nil &&
		bytes.Equal(c.rcvKeys.pubKeyEp.Bytes(), peerNewPubKeyBytes) {
		return nil
	}

	// Retransmit of the current round's
	if c.rcvKeys.pubKeyEpNext != nil &&
		bytes.Equal(c.rcvKeys.pubKeyEpNext.Bytes(), peerNewPubKeyBytes) {
		c.kuAckDue = true
		return nil
	}

	// New KEY_UPDATE: rotate first if the previous one is still pending
	if c.rcvKeys.next != nil {
		c.rcvKeys.prev = c.rcvKeys.cur
		c.rcvKeys.cur = c.rcvKeys.next
		c.rcvKeys.next = nil
		c.rcvKeys.prvKeyEpNext = nil
		c.rcvKeys.pubKeyEp = c.rcvKeys.pubKeyEpNext
		c.rcvKeys.pubKeyEpNext = nil
		c.rcvSnHigh = 0 // the peer's sequence number restarts with its key
	}

	newPriv, err := generateKey()
	if err != nil {
		return err
	}
	c.rcvKeys.prvKeyEpNext = newPriv
	c.rcvKeys.pubKeyEpNext = peerNewPubKey

	newSecret, err := c.rcvKeys.prvKeyEpNext.ECDH(peerNewPubKey)
	if err != nil {
		return err
	}
	c.rcvKeys.next = newSecret

	c.kuAckDue = true
	return nil
}

func (c *conn) handleKeyUpdateAck(peerNewPubKeyBytes []byte) error {
	if c.sndKeys.prvKeyEpNext == nil || c.sndKeys.next != nil { // retransmit
		return nil
	}

	peerNewPubKey, err := ecdh.X25519().NewPublicKey(peerNewPubKeyBytes)
	if err != nil {
		return err
	}

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

// flushStream sends at most one packet for the stream and returns the bytes
// of payload sent and how long until the next send is due.
func (c *conn) flushStream(s *Stream, nowNano uint64) (int, uint64, error) {
	ack := c.rcv.getSndAck()

	// Expired best-effort packets are dropped, not retransmitted
	c.dataInFlight -= c.snd.drainExpiredBestEffort(s.streamID, c.rtoNano(), nowNano)

	// Also here, not only on arrival, for a sender that went silent mid-gap
	c.rcv.checkGap(s.streamID, nowNano, s.gapTimeoutNano)

	// A lost KEY_UPDATE_ACK needs no timer: the peer's re-sent KEY_UPDATE
	// asks for it again
	isKeyUpdateAck := c.kuAckPending()
	kuSendDue := c.kuAttachDue(nowNano)
	// Give up only when the next re-send is due, so the last one gets its
	// full response window
	if kuSendDue && c.kuSendCount >= maxRetry {
		return 0, 0, errors.New("key update: max retry attempts exceeded")
	}

	isBlockedByRwnd := c.dataInFlight+c.mtu > int(c.rcvWndSize)
	if !isBlockedByRwnd {
		c.rwndProbeNano = 0
	}

	// Pacing blocks everything but ACKs
	if c.nextWriteTime > nowNano {
		if ack == nil {
			return 0, c.nextWriteTime - nowNano, nil
		}
		return c.sendControlPacket(s, ack, nowNano)
	}

	// encodeAndWrite attaches key-update pubkeys from connection state, so
	// reserve their space here. The MTU probe keeps the same reservations.
	msgType := c.msgType()
	effectiveMtu := c.mtu
	if kuSendDue {
		effectiveMtu -= pubKeySize
	}
	if isKeyUpdateAck {
		effectiveMtu -= pubKeySize
	}
	probeMtu := effectiveMtu - (c.mtu - conservativeMTU)

	// Retransmits bypass the receive window: the data was counted in
	// dataInFlight when first sent. Blocking them deadlocks on the gap the
	// lost packet left in the receiver's buffer.
	splitData, offset, isClose, err := c.snd.readyToRetransmit(
		s.streamID, ack, effectiveMtu, probeMtu, c.rtoNano(), msgType, nowNano)
	if err != nil {
		return 0, 0, err
	}
	if splitData != nil {
		return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, false)
	}

	// Inits carrying tracked 0-RTT data retransmit above; untracked inits
	// (InitSnd, empty dials, InitRcv) are re-sent here with the same backoff
	if c.phase == phaseInitSent && !c.snd.hasInFlight(s.streamID) {
		if nowNano-c.initLastSentNano > backoff(c.rtoNano(), c.initSendCount) {
			if c.initSendCount >= maxRetry {
				return 0, 0, errors.New("handshake: max retry attempts exceeded")
			}
			c.initSendCount++
			return c.sendControlPacket(s, ack, nowNano)
		}
	}

	// The window is only learned from ACKs, and a peer with nothing to
	// acknowledge sends none, so a blocked sender that goes quiet would
	// deadlock. Probe once per RTO with a control packet: it carries a stream
	// header, the peer ACKs that, and every ACK carries the window. The peer
	// also announces a reopened window itself; the probe is the retry for a
	// lost announcement and the keepalive during a long block. It never gives
	// up: a peer refusing data is behaving correctly, and only silence (the
	// read deadline) ends the connection.
	if isBlockedByRwnd {
		if ack == nil && !kuSendDue {
			if waited := nowNano - c.rwndProbeNano; waited < c.rtoNano() {
				return 0, c.rtoNano() - waited, nil
			}
			c.rwndProbeNano = nowNano
		}
		return c.sendControlPacket(s, ack, nowNano)
	}

	if c.phase == phaseReady || c.phase == phaseCreated {
		splitData, offset, isClose := c.snd.readyToSend(s.streamID, msgType, ack, effectiveMtu, s.reliable)
		if splitData != nil {
			return c.encodeAndWrite(s, ack, splitData, offset, isClose, nowNano, true)
		}
		if ack != nil || c.phase == phaseCreated || kuSendDue {
			return c.sendControlPacket(s, ack, nowNano)
		}
	}

	if ack != nil || isKeyUpdateAck {
		return c.sendControlPacket(s, ack, nowNano)
	}

	// The peer's view of our window is stale: it is blocked on a value that
	// has since opened, or still sending into a buffer that is full. Any
	// packet carries the current window, so send one now.
	if c.rcv.windowChanged(c.mtu) {
		return c.sendControlPacket(s, nil, nowNano)
	}

	return 0, minDeadline, nil
}

func (c *conn) encodeAndWrite(s *Stream, ack *ack, data []byte, offset uint64, isClose bool, nowNano uint64, trackInFlight bool) (int, uint64, error) {
	isKeyUpdate := c.kuAttachDue(nowNano)
	isKeyUpdateAck := c.kuAckPending()

	p := &payloadHeader{
		maxPayload:   uint16(c.listener.maxPayload),
		rcvWnd:       c.rcv.freeAdvertise(),
		isClose:      isClose,
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

	err = c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr, c.localAddr, nowNano)
	if err != nil {
		return 0, 0, err
	}

	// Stamped with the time before the write: a stamp after it can date the
	// packet later than it left (a deschedule inside the syscall), which
	// makes an RTT sample short, and the min filter keeps a short sample
	// for its whole TTL. Erring early only inflates a sample, which the
	// filter discards.
	if data != nil {
		c.snd.markSent(s.streamID, offset, uint16(len(data)), uint16(len(encData)), nowNano, c.acked)
	}

	if isKeyUpdate {
		if c.kuLastSentNano != 0 {
			c.kuSendCount++ // an RTO passed without a KUAck: this is a re-send
		}
		c.kuLastSentNano = nowNano
	}

	if c.phase == phaseInitSent {
		c.initLastSentNano = nowNano
	}

	if isKeyUpdateAck {
		c.kuAckDue = false
	}

	// Token-bucket pacing: the next send is scheduled from the previous
	// nextWriteTime, not from now. The loop sends one packet per wakeup and
	// wakeups quantize to about 1ms, so scheduling from now would discard
	// every slot a late wakeup skipped and cap throughput at one packet per
	// wakeup. Credit and debt are both capped at maxBurstLen.
	pacingNano := c.calcPacing(uint64(len(encData)))
	burst := maxBurstLen * pacingNano
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

// sendControlPacket sends a packet without stream data (ACK, key update,
// handshake re-send, window probe). It is not tracked in the send buffer: a
// tracked probe whose ACK was lost would hold the stream's one zero-payload
// slot for an RTO and block the next probe.
func (c *conn) sendControlPacket(s *Stream, ack *ack, nowNano uint64) (int, uint64, error) {
	offset := c.snd.getSendOffset(s.streamID)

	// A receive-only connection never gets an RTT sample, so until the first
	// one, carry a stream header and track the packet: the peer ACKs any
	// packet with a stream header. Rides the ACK path because ACKs bypass
	// the pacing gate.
	if c.srtt == 0 && c.msgType() == data && c.snd.trackProbe(s.streamID) {
		return c.encodeAndWrite(s, ack, []byte{}, offset, false, nowNano, false)
	}
	return c.encodeAndWrite(s, ack, nil, offset, false, nowNano, false)
}

// =============================================================================
// Helpers
// =============================================================================

// isInitiator reports whether this side dialed
func (c *conn) isInitiator() bool {
	return c.initMsgType == initSnd || c.initMsgType == initCryptoSnd
}

func (c *conn) msgType() cryptoMsgType {
	if c.phase >= phaseReady {
		return data
	}
	return c.initMsgType
}
