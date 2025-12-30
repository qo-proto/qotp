package qotp

import (
	"bytes"
	"sync"
)

// =============================================================================
// Receive buffer - Handles incoming data with reordering and deduplication
//
// Per-stream RcvBuffer stores out-of-order segments in a sorted map.
// RemoveOldestInOrder returns contiguous data starting from next expected offset.
// Overlapping segments are validated for data integrity (must match).
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
	finishedStreams map[uint32]bool // Streams that have been fully closed and cleaned up
	capacity        int
	len            int
	ackList         []*ack
	mu              sync.Mutex
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
	segments      *linkedMap[uint64, []byte] // offset -> segment data
	nextInOrder   uint64                     // Next expected offset for in-order delivery
	closeAtOffset *uint64                    // Stream closes at this offset (FIN received)
}

func newRcvBuffer() *reassemblyBuffer {
	return &reassemblyBuffer{segments: newLinkedMap[uint64, []byte]()}
}

// =============================================================================
// Insert - Add received segment to buffer
//
// Handles: duplicates, out-of-order, overlapping segments, capacity limits.
// Always ACKs received data (sender may be retransmitting due to lost ACK).
// Overlapping data must match exactly or panics (data integrity violation).
// =============================================================================

func (rb *receiver) insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) rcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.getOrCreateStream(streamID)

	// Data after close offset - ACK but drop
	if stream.closeAtOffset != nil && offset >= *stream.closeAtOffset {
		rb.ackList = append(rb.ackList, &ack{streamId: streamID, offset: offset, len: uint16(dataLen)})
		return rcvInsertDuplicate
	}

	if rb.len+dataLen > rb.capacity {
		return rcvInsertBufferFull
	}

	// Always ACK (may be retransmit due to lost ACK)
	rb.ackList = append(rb.ackList, &ack{streamId: streamID, offset: offset, len: uint16(dataLen)})

	// Already delivered to application
	if offset+uint64(dataLen) <= stream.nextInOrder {
		return rcvInsertDuplicate
	}

	// Exact offset match - keep larger segment
	if existing, exists := stream.segments.get(offset); exists {
		if dataLen <= len(existing) {
			return rcvInsertDuplicate
		}
		stream.segments.remove(offset)
		rb.len -= len(existing)
		stream.segments.putOrdered(offset, userData)
		rb.len += dataLen
		return rcvInsertOk
	}

	// Insert first so Prev/Next are O(1)
	stream.segments.putOrdered(offset, userData)
	rb.len += dataLen

	finalOffset, finalData := offset, userData

	// Handle previous segment overlap
	if prevOff, prev, exists := stream.segments.prev(offset); exists {
		prevEnd := prevOff + uint64(len(prev))
		if prevEnd > offset {
			overlapLen := prevEnd - offset
			if overlapLen >= uint64(dataLen) {
				// Completely covered by previous - remove ourselves
				stream.segments.remove(offset)
				rb.len -= dataLen
				return rcvInsertDuplicate
			}
			// Trim front: remove, adjust, re-insert
			assertOverlap(prev[offset-prevOff:], userData[:overlapLen])
			stream.segments.remove(offset)
			rb.len -= dataLen
			finalOffset = prevEnd
			finalData = userData[overlapLen:]
			stream.segments.putOrdered(finalOffset, finalData)
			rb.len += len(finalData)
		}
	}

	// Handle next segment overlap
	if nextOff, next, exists := stream.segments.next(finalOffset); exists {
		ourEnd := finalOffset + uint64(len(finalData))
		if ourEnd > nextOff {
			stream.segments.remove(finalOffset)
			rb.len -= len(finalData)

			nextEnd := nextOff + uint64(len(next))
			overlapStart := nextOff - finalOffset

			if ourEnd >= nextEnd {
				// We completely cover next - remove it
				stream.segments.remove(nextOff)
				rb.len -= len(next)
				assertOverlap(next, finalData[overlapStart:overlapStart+uint64(len(next))])
			} else {
				// Partial overlap - shorten our data
				assertOverlap(next[:ourEnd-nextOff], finalData[overlapStart:])
				finalData = finalData[:overlapStart]
			}

			stream.segments.putOrdered(finalOffset, finalData)
			rb.len += len(finalData)
		}
	}

	return rcvInsertOk
}

func assertOverlap(existing, incoming []byte) {
	if !bytes.Equal(existing, incoming) {
		panic("segment overlap mismatch - data integrity violation")
	}
}

// =============================================================================
// Read - Deliver in-order data to application
// =============================================================================

// removeOldestInOrder returns all contiguous in-order data for the stream.
// Returns nil if no in-order data available.
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
		if !ok || off != stream.nextInOrder {
			break
		}
		stream.segments.remove(off)
		rb.len -= len(val)
		result = append(result, val...)
		stream.nextInOrder = off + uint64(len(val))
	}
	return result
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

func (rb *receiver) getOffsetClosedAt(streamID uint32) *uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if s := rb.streams[streamID]; s != nil {
		return s.closeAtOffset
	}
	return nil
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
