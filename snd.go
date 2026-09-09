package qotp

import (
	"errors"
	"sync"
)

// =============================================================================
// Send buffer - queued data and in-flight packets, with retransmission
//
// In-flight packets live in one map per retransmission generation (index =
// sentCount), each in send order. All packets of a generation share the same
// backoff, so every map is ordered by expiry and only the heads need
// checking: a loss burst retransmits one packet per loop iteration instead
// of stalling behind the just-retransmitted head.
// =============================================================================

const sndBufferCapacity = 16 * 1024 * 1024

// packetKey is offset (48-bit) and length (16-bit), what an ACK carries
type packetKey uint64

func createPacketKey(offset uint64, length uint16) packetKey {
	return packetKey((offset << 16) | uint64(length))
}

func (p packetKey) offset() uint64 {
	return uint64(p) >> 16
}

type sendPacket struct {
	data         []byte
	sentTimeNano uint64   // when this packet last went out (RTT, RTO)
	ackedAtSend  ackState // ACK bookkeeping to compute a bandwidth sample
	wireLen      uint16   // encrypted size, what pacing counts
	sentCount    uint
	ackGap       uint8 // later-sent originals ACKed, capped at fastRetxThreshold
	isClose      bool
	needsReTx    bool
}

type sender struct {
	streams  map[uint32]*transmitBuffer
	capacity int
	size     int // queued and in-flight bytes across all streams
	mu       sync.Mutex
}

func newSendBuffer(capacity int) *sender {
	return &sender{
		streams:  make(map[uint32]*transmitBuffer),
		capacity: capacity,
	}
}

// caller holds sb.mu
func (sb *sender) getOrCreateStream(streamID uint32) *transmitBuffer {
	if stream := sb.streams[streamID]; stream != nil {
		return stream
	}
	stream := newStreamSendBuffer()
	sb.streams[streamID] = stream
	return stream
}

type transmitBuffer struct {
	inFlight        []*linkedMap[packetKey, *sendPacket] // per generation, index = sentCount
	queuedData      []byte
	bytesSentOffset uint64
	pingRequested   bool
	closeAtOffset   *uint64
	closeSent       bool
}

func newStreamSendBuffer() *transmitBuffer {
	inFlight := make([]*linkedMap[packetKey, *sendPacket], maxRetry+1)
	for i := range inFlight {
		inFlight[i] = newLinkedMap[packetKey, *sendPacket]()
	}
	return &transmitBuffer{inFlight: inFlight}
}

// An ACK does not say which generation, so lookups probe all maps

func (t *transmitBuffer) inFlightGet(key packetKey) (*sendPacket, bool) {
	for _, m := range t.inFlight {
		if pkt, ok := m.get(key); ok {
			return pkt, true
		}
	}
	return nil, false
}

func (t *transmitBuffer) inFlightRemove(key packetKey) (*sendPacket, bool) {
	for _, m := range t.inFlight {
		if pkt, ok := m.remove(key); ok {
			return pkt, true
		}
	}
	return nil, false
}

// reserveZeroPayloadKey claims the slot for a zero-payload packet (ping or
// ACK probe) at the send offset. All zero-payload packets at one offset share
// a key, so at most one may be outstanding, and a pending close owns it.
func (t *transmitBuffer) reserveZeroPayloadKey() (packetKey, bool) {
	if t.closeAtOffset != nil {
		return 0, false
	}
	key := createPacketKey(t.bytesSentOffset, 0)
	if _, exists := t.inFlightGet(key); exists {
		return 0, false
	}
	t.inFlight[0].put(key, &sendPacket{needsReTx: false})
	return key, true
}

func (t *transmitBuffer) inFlightAny() bool {
	for _, m := range t.inFlight {
		if m.size() > 0 {
			return true
		}
	}
	return false
}

// =============================================================================
// Queueing
// =============================================================================

// queueData returns how much was taken: less than len(userData) when full
func (sb *sender) queueData(streamID uint32, userData []byte) int {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	chunk := userData[:min(len(userData), sb.capacity-sb.size)]
	if len(chunk) == 0 {
		return 0
	}
	stream := sb.getOrCreateStream(streamID)
	stream.queuedData = append(stream.queuedData, chunk...)
	sb.size += len(chunk)
	return len(chunk)
}

// trackProbe reserves the zero-payload key for an ACK probe; a pending ping
// takes precedence
func (sb *sender) trackProbe(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamID)
	if stream.pingRequested {
		return false
	}
	_, ok := stream.reserveZeroPayloadKey()
	return ok
}

func (sb *sender) queuePing(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.getOrCreateStream(streamID).pingRequested = true
}

// =============================================================================
// Send
// =============================================================================

// readyToSend moves the next packet from queued to in flight; nil if none
func (sb *sender) readyToSend(streamID uint32, msgType cryptoMsgType, ack *ack, mtu int, reliable bool) (
	data []byte, offset uint64, isClose bool) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false
	}

	// A ping is dropped if the zero-payload key is taken by a FIN or an
	// ACK probe, whose ACK would otherwise be attributed to the ping
	if stream.pingRequested {
		stream.pingRequested = false
		if key, ok := stream.reserveZeroPayloadKey(); ok {
			return []byte{}, key.offset(), false
		}
	}

	if len(stream.queuedData) > 0 {
		return sb.sendQueuedData(stream, msgType, ack, mtu, reliable)
	}

	// Standalone FIN
	if stream.closeAtOffset != nil &&
		stream.bytesSentOffset >= *stream.closeAtOffset &&
		!stream.closeSent {

		closeKey := createPacketKey(stream.bytesSentOffset, 0)
		if _, ok := stream.inFlightGet(closeKey); ok {
			return nil, 0, false
		}

		stream.closeSent = true
		stream.inFlight[0].put(closeKey, &sendPacket{isClose: true, needsReTx: true})
		return []byte{}, closeKey.offset(), true
	}

	return nil, 0, false
}

func (sb *sender) sendQueuedData(stream *transmitBuffer, msgType cryptoMsgType, ack *ack, mtu int, reliable bool) (
	data []byte, offset uint64, isClose bool) {

	// InitSnd carries no stream data; booking a zero-length packet for it
	// would hold the zero-payload slot for an RTO and drop a queued ping
	if msgType == initSnd {
		return nil, 0, false
	}
	overhead := calcCryptoOverheadWithData(msgType, ack, stream.bytesSentOffset)
	if overhead > mtu {
		return nil, 0, false
	}
	maxData := mtu - overhead

	length := min(uint64(maxData), uint64(len(stream.queuedData)))
	data = stream.queuedData[:length]
	key := createPacketKey(stream.bytesSentOffset, uint16(length))

	if stream.closeAtOffset != nil {
		packetEnd := stream.bytesSentOffset + length
		if packetEnd >= *stream.closeAtOffset {
			isClose = true
			stream.closeSent = true
		}
	}

	// Close always retransmits
	needsReTx := isClose || (len(data) > 0 && reliable)
	stream.inFlight[0].put(key, &sendPacket{data: data, isClose: isClose, needsReTx: needsReTx})
	stream.queuedData = stream.queuedData[length:]
	stream.bytesSentOffset += length

	return data, key.offset(), isClose
}

// =============================================================================
// Retransmit
// =============================================================================

// readyToRetransmit returns the oldest expired reliable packet, split if the
// MTU shrank. A packet close to giving up goes out at probeMtu (see
// conn.observeMTU).
func (sb *sender) readyToRetransmit(
	streamID uint32, ack *ack, mtu, probeMtu int,
	baseRTO uint64, msgType cryptoMsgType,
	nowNano uint64) (data []byte, offset uint64, isClose bool, err error) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false, nil
	}

	// Oldest expired head across the generations; a non-expired head clears
	// its whole generation
	gen := -1
	var key packetKey
	var pkt *sendPacket
	for g, m := range stream.inFlight {
		k, p, ok := m.first()
		// Step past best-effort entries (generation 0 only, never
		// retransmitted) so a ping with a lost ACK cannot block the data
		// behind it
		for ok && !p.needsReTx {
			k, p, ok = m.next(k)
		}
		if !ok {
			continue
		}
		// The last generation has nothing further to schedule, so its
		// give-up wait is one RTO, not the backed-off one
		rtoWithBackoff := backoff(baseRTO, uint(g))
		if uint(g) >= maxRetry {
			rtoWithBackoff = baseRTO
		}
		fastRetx := g == 0 && p.ackGap >= fastRetxThreshold
		if !fastRetx && (p.sentTimeNano >= nowNano || nowNano-p.sentTimeNano <= rtoWithBackoff) {
			continue // not expired yet
		}
		if pkt == nil || p.sentTimeNano < pkt.sentTimeNano {
			gen, key, pkt = g, k, p
		}
	}
	if pkt == nil {
		return nil, 0, false, nil
	}

	if pkt.sentCount >= maxRetry {
		return nil, 0, false, errors.New("max retry attempts exceeded")
	}

	if pkt.sentCount >= maxRetry-mtuProbeLastAttempts && probeMtu < mtu {
		mtu = probeMtu
	}

	overhead := calcCryptoOverheadWithData(msgType, ack, key.offset())
	if overhead < 0 || overhead > mtu {
		return nil, 0, false, errors.New("overhead larger than MTU")
	}
	maxData := mtu - overhead

	if len(pkt.data) <= maxData {
		stream.inFlight[gen].remove(key)
		pkt.sentTimeNano = nowNano
		pkt.sentCount++
		pkt.ackGap = 0
		stream.inFlight[gen+1].put(key, pkt)
		return pkt.data, key.offset(), pkt.isClose, nil
	}

	return sb.splitAndRetransmit(stream, gen, key, pkt, maxData, nowNano)
}

func (sb *sender) splitAndRetransmit(
	stream *transmitBuffer, gen int, key packetKey, pkt *sendPacket,
	maxData int, nowNano uint64,
) ([]byte, uint64, bool, error) {

	leftData := pkt.data[:maxData]
	rightData := pkt.data[maxData:]

	// Left part goes out now; the right part keeps its stamp and generation
	leftKey := createPacketKey(key.offset(), uint16(maxData))
	stream.inFlight[gen+1].put(leftKey, &sendPacket{
		data:         leftData,
		sentTimeNano: nowNano,
		sentCount:    pkt.sentCount + 1,
		needsReTx:    pkt.needsReTx,
	})

	rightKey := createPacketKey(key.offset()+uint64(maxData), uint16(len(rightData)))
	pkt.data = rightData
	stream.inFlight[gen].replace(key, rightKey, pkt)

	return leftData, key.offset(), false, nil
}

// drainExpiredBestEffort drops best-effort packets (unreliable data, pings)
// older than one RTO and returns their payload bytes
func (sb *sender) drainExpiredBestEffort(streamID uint32, baseRTO uint64, nowNano uint64) (droppedBytes int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}

	// Best-effort packets only ever live in generation 0
	for {
		key, pkt, ok := stream.inFlight[0].first()
		if !ok || pkt.needsReTx || pkt.sentTimeNano >= nowNano ||
			nowNano-pkt.sentTimeNano <= baseRTO {
			return droppedBytes
		}
		stream.inFlight[0].remove(key)
		if len(pkt.data) > 0 {
			droppedBytes += len(pkt.data)
			sb.size -= len(pkt.data)
		}
	}
}

// =============================================================================
// Acknowledgment
// =============================================================================

// acknowledgeRange retires the ACKed packet (nil if nothing matched) and
// reports how many older originals this ACK declared lost: an ACK for an
// original is gap evidence for every older un-ACKed original, and one whose
// ackGap reaches fastRetxThreshold is lost. ACKs for retransmits are
// ambiguous and give no evidence.
//
// A packet sent at or before lossEpochNano was in flight when we last
// responded, so its loss is not new evidence (RFC 6582, RFC 9002 7.3.2).
// That gates only the count; it is still retransmitted.
func (sb *sender) acknowledgeRange(ack *ack, lossEpochNano uint64) (ackedPkt *sendPacket, lostCount int) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[ack.streamId]
	if stream == nil {
		return nil, 0
	}

	key := createPacketKey(ack.offset, ack.len)

	if pkt, ok := stream.inFlight[0].get(key); ok {
		for k, p, more := stream.inFlight[0].first(); more && k != key; k, p, more = stream.inFlight[0].next(k) {
			if p.needsReTx && p.ackGap < fastRetxThreshold {
				p.ackGap++
				if p.ackGap == fastRetxThreshold && p.sentTimeNano > lossEpochNano {
					lostCount++
				}
			}
		}
		stream.inFlight[0].remove(key)
		sb.size -= len(pkt.data)
		return pkt, lostCount
	}

	pkt, ok := stream.inFlightRemove(key)
	if !ok {
		return nil, 0
	}

	sb.size -= len(pkt.data)
	return pkt, 0
}

// markSent stamps the packet once it is built and written
func (sb *sender) markSent(streamID uint32, offset uint64, length, wireLen uint16, nowNano uint64, acked ackState) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return
	}

	key := createPacketKey(offset, length)
	if pkt, ok := stream.inFlightGet(key); ok {
		pkt.sentTimeNano = nowNano
		pkt.wireLen = wireLen
		// No ACK yet: anchor the intervals at this send
		if acked.timeNano == 0 {
			acked.timeNano = nowNano
		}
		if acked.sentNano == 0 {
			acked.sentNano = nowNano
		}
		pkt.ackedAtSend = acked
	}
}

// =============================================================================
// Stream lifecycle
// =============================================================================

func (sb *sender) close(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamID)
	if stream.closeAtOffset == nil {
		offset := stream.bytesSentOffset + uint64(len(stream.queuedData))
		stream.closeAtOffset = &offset
	}
}

func (sb *sender) removeStream(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	delete(sb.streams, streamID)
}

func (sb *sender) checkStreamFullyAcked(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil || stream.closeAtOffset == nil {
		return false
	}

	return !stream.inFlightAny() && stream.bytesSentOffset >= *stream.closeAtOffset
}

func (sb *sender) hasInFlight(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return false
	}
	return stream.inFlightAny()
}

// getOffsetAcked is the contiguous acked offset: where in-flight begins
func (sb *sender) getOffsetAcked(streamID uint32) uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}
	// Each generation is in ascending offset order, so its head is its lowest
	acked := stream.bytesSentOffset
	for _, m := range stream.inFlight {
		if firstKey, _, ok := m.first(); ok && firstKey.offset() < acked {
			acked = firstKey.offset()
		}
	}
	return acked
}

func (sb *sender) getSendOffset(streamID uint32) uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if stream := sb.streams[streamID]; stream != nil {
		return stream.bytesSentOffset
	}
	return 0
}

func (sb *sender) isCloseRequested(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	return stream != nil && stream.closeAtOffset != nil
}
