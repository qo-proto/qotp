package qotp

import (
	"sync"
)

// =============================================================================
// Receive buffer - reorders incoming segments and delivers them in order
// =============================================================================

const rcvBufferCapacity = 16 * 1024 * 1024 // 16MB

type rcvInsertStatus int

const (
	rcvInsertOk rcvInsertStatus = iota
	rcvInsertDuplicate
	rcvInsertBufferFull
)

// =============================================================================
// Connection-level receive buffer (manages all streams)
// =============================================================================

type receiver struct {
	streams         map[uint32]*reassemblyBuffer
	finishedStreams map[uint32]bool
	capacity        int
	len             int
	ackList         []*ack
	advertised      uint64 // free space the peer was last told about
	// Payload admitted, counted on arrival so it does not freeze behind a
	// head-of-line hole like the delivered offset does
	received uint64
	mu       sync.Mutex
}

func newReceiveBuffer(capacity int) *receiver {
	return &receiver{
		streams:         make(map[uint32]*reassemblyBuffer),
		finishedStreams: make(map[uint32]bool),
		capacity:        capacity,
	}
}

func (rb *receiver) getOrCreateStream(streamID uint32) *reassemblyBuffer {
	if s := rb.streams[streamID]; s != nil {
		return s
	}
	s := newRcvBuffer()
	rb.streams[streamID] = s
	return s
}

// =============================================================================
// Per-stream receive buffer
// =============================================================================

type reassemblyBuffer struct {
	segments      *linkedMap[uint64, []byte] // offset -> data, sorted
	nextInOrder   uint64
	closeAtOffset *uint64

	// Unreliable streams skip head-of-line gaps after a timeout
	unreliable    bool
	gapStartNano  uint64      // when the current gap was first seen, 0 = none
	skippedRanges [][2]uint64 // recent [from, to) skips, to count late arrivals
	latePackets   uint64
	lateBytes     uint64
}

const maxSkippedRanges = 16

func (s *reassemblyBuffer) recordSkip(from, to uint64) {
	if len(s.skippedRanges) == maxSkippedRanges {
		s.skippedRanges = s.skippedRanges[1:]
	}
	s.skippedRanges = append(s.skippedRanges, [2]uint64{from, to})
}

// countIfLate counts data arriving for a range already skipped as lost
func (s *reassemblyBuffer) countIfLate(offset, dataLen uint64) {
	if !s.unreliable {
		return
	}
	end := offset + dataLen
	for _, r := range s.skippedRanges {
		if offset < r[1] && end > r[0] {
			s.latePackets++
			s.lateBytes += dataLen
			return
		}
	}
}

func newRcvBuffer() *reassemblyBuffer {
	return &reassemblyBuffer{segments: newLinkedMap[uint64, []byte]()}
}

// =============================================================================
// Insert
// =============================================================================

// insert stores a segment. Overlaps with neighbouring segments are left in
// place and resolved on delivery: overlapping bytes from an honest peer are
// identical, and the peer is authenticated.
func (rb *receiver) insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) rcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.getOrCreateStream(streamID)

	// Past the close offset: ACK so the peer stops, but drop
	if stream.closeAtOffset != nil && offset >= *stream.closeAtOffset {
		rb.ackList = append(rb.ackList, &ack{streamId: streamID, offset: offset, len: uint16(dataLen)})
		return rcvInsertDuplicate
	}

	// In-order data is accepted even when full: it is drainable at once, and
	// rejecting it would deadlock on a full buffer
	advancesDelivery := offset <= stream.nextInOrder && offset+uint64(dataLen) > stream.nextInOrder
	if !advancesDelivery && rb.len+dataLen > rb.capacity {
		return rcvInsertBufferFull
	}

	// Always ACK: a retransmit means the first ACK was lost
	rb.ackList = append(rb.ackList, &ack{streamId: streamID, offset: offset, len: uint16(dataLen)})

	if offset+uint64(dataLen) <= stream.nextInOrder {
		stream.countIfLate(offset, uint64(dataLen))
		return rcvInsertDuplicate
	}

	// Trim what was already delivered or skipped
	if offset < stream.nextInOrder {
		trim := stream.nextInOrder - offset
		stream.countIfLate(offset, trim)
		offset += trim
		userData = userData[trim:]
		dataLen = len(userData)
	}

	// Same offset: keep the longer segment
	newBytes := dataLen
	if existing, exists := stream.segments.get(offset); exists {
		if dataLen <= len(existing) {
			return rcvInsertDuplicate
		}
		rb.len -= len(existing)
		newBytes -= len(existing)
	}

	stream.segments.putOrdered(offset, userData)
	rb.len += dataLen
	rb.received += uint64(newBytes)
	return rcvInsertOk
}

// =============================================================================
// Read
// =============================================================================

// removeOldestInOrder returns all contiguous in-order data, nil if none
func (rb *receiver) removeOldestInOrder(streamID uint32) []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil {
		return nil
	}

	var result []byte
	for {
		off, val, ok := stream.segments.first()
		if !ok || off > stream.nextInOrder {
			break
		}
		stream.segments.remove(off)
		rb.len -= len(val)
		// Skip the part an earlier segment already delivered
		if end := off + uint64(len(val)); end > stream.nextInOrder {
			result = append(result, val[stream.nextInOrder-off:]...)
			stream.nextInOrder = end
		}
	}
	return result
}

// =============================================================================
// Unreliable streams - gap skipping
// =============================================================================

// markUnreliable is sticky for the stream's lifetime
func (rb *receiver) markUnreliable(streamID uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.getOrCreateStream(streamID).unreliable = true
}

// checkGap skips the head-of-line gap of an unreliable stream once it has
// been open longer than timeoutNano. The gap ends at the next buffered
// segment, or at the close offset when the tail of the stream was lost.
func (rb *receiver) checkGap(streamID uint32, nowNano uint64, timeoutNano uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil || !stream.unreliable {
		return
	}

	var target uint64
	firstOff, _, ok := stream.segments.first()
	switch {
	case ok && firstOff > stream.nextInOrder:
		target = firstOff
	case !ok && stream.closeAtOffset != nil && *stream.closeAtOffset > stream.nextInOrder:
		target = *stream.closeAtOffset
	default:
		stream.gapStartNano = 0
		return
	}

	if stream.gapStartNano == 0 {
		stream.gapStartNano = nowNano
		return
	}
	if nowNano-stream.gapStartNano <= timeoutNano {
		return
	}

	stream.recordSkip(stream.nextInOrder, target)
	stream.nextInOrder = target
	stream.gapStartNano = 0
}

func (rb *receiver) bytesReceived() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.received
}

func (rb *receiver) lateStats(streamID uint32) (packets uint64, bytes uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if s := rb.streams[streamID]; s != nil {
		return s.latePackets, s.lateBytes
	}
	return 0, 0
}

// =============================================================================
// Stream lifecycle
// =============================================================================

func (rb *receiver) close(streamID uint32, closeOffset uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.getOrCreateStream(streamID)
	if s.closeAtOffset == nil {
		s.closeAtOffset = &closeOffset
	}
}

func (rb *receiver) isReadyToClose(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.streams[streamID]
	return s != nil && s.closeAtOffset != nil && s.nextInOrder >= *s.closeAtOffset
}

func (rb *receiver) removeStream(streamID uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.finishedStreams[streamID] = true
	delete(rb.streams, streamID)
}

func (rb *receiver) isFinished(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.finishedStreams[streamID]
}

// =============================================================================
// ACK management
// =============================================================================

func (rb *receiver) queueAck(streamID uint32, offset uint64, length uint16) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.ackList = append(rb.ackList, &ack{streamId: streamID, offset: offset, len: length})
}

func (rb *receiver) getSndAck() *ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.ackList) == 0 {
		return nil
	}
	ack := rb.ackList[0]
	rb.ackList = rb.ackList[1:]
	return ack
}

func (rb *receiver) hasPendingAcks() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return len(rb.ackList) > 0
}

func (rb *receiver) hasPendingAckForStream(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for _, ack := range rb.ackList {
		if ack.streamId == streamID {
			return true
		}
	}
	return false
}

// =============================================================================
// Misc
// =============================================================================

func (rb *receiver) size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.len
}

// =============================================================================
// Receive window
// =============================================================================

// free is the space left; caller holds the lock. In-order data accepted over
// the limit can push len past capacity briefly.
func (rb *receiver) free() uint64 {
	return uint64(max(rb.capacity-rb.len, 0))
}

// freeAdvertise returns the window for an outgoing packet and records it
func (rb *receiver) freeAdvertise() uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.advertised = rb.free()
	return rb.advertised
}

// windowReopened reports that the buffer drained usefully since the peer was
// last told. The margin is the silly-window rule: a slowly draining buffer
// must not generate a packet per read.
func (rb *receiver) windowReopened(mtu int) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.free() >= rb.advertised+uint64(2*max(mtu, conservativeMTU))
}
