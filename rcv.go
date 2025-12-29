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

type RcvInsertStatus int

const (
	RcvInsertOk RcvInsertStatus = iota
	RcvInsertDuplicate
	RcvInsertBufferFull
)

// =============================================================================
// Per-stream receive buffer
// =============================================================================

type RcvBuffer struct {
	segments      *LinkedMap[uint64, []byte] // offset -> segment data
	nextInOrder   uint64                         // Next expected offset for in-order delivery
	closeAtOffset *uint64                        // Stream closes at this offset (FIN received)
}

func newRcvBuffer() *RcvBuffer {
	return &RcvBuffer{segments: NewLinkedMap[uint64, []byte]()}
}

// =============================================================================
// Connection-level receive buffer (manages all streams)
// =============================================================================

type ReceiveBuffer struct {
	streams         map[uint32]*RcvBuffer
	finishedStreams map[uint32]bool // Streams that have been fully closed and cleaned up
	capacity        int
	size            int
	ackList         []*Ack
	mu              sync.Mutex
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:         make(map[uint32]*RcvBuffer),
		finishedStreams: make(map[uint32]bool),
		capacity:        capacity,
	}
}

func (rb *ReceiveBuffer) getOrCreateStream(streamID uint32) *RcvBuffer {
	if s := rb.streams[streamID]; s != nil {
		return s
	}
	s := newRcvBuffer()
	rb.streams[streamID] = s
	return s
}

// =============================================================================
// Insert - Add received segment to buffer
//
// Handles: duplicates, out-of-order, overlapping segments, capacity limits.
// Always ACKs received data (sender may be retransmitting due to lost ACK).
// Overlapping data must match exactly or panics (data integrity violation).
// =============================================================================

func (rb *ReceiveBuffer) Insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) RcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.getOrCreateStream(streamID)

	// Data after close offset - ACK but drop
	if stream.closeAtOffset != nil && offset >= *stream.closeAtOffset {
		rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: uint16(dataLen)})
		return RcvInsertDuplicate
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	// Always ACK (may be retransmit due to lost ACK)
	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: uint16(dataLen)})

	// Already delivered to application
	if offset+uint64(dataLen) <= stream.nextInOrder {
		return RcvInsertDuplicate
	}

	// Exact offset match - keep larger segment
	if existing, exists := stream.segments.Get(offset); exists {
		if dataLen <= len(existing) {
			return RcvInsertDuplicate
		}
		stream.segments.Remove(offset)
		rb.size -= len(existing)
		stream.segments.PutOrdered(offset, userData)
		rb.size += dataLen
		return RcvInsertOk
	}

	// Insert first so Prev/Next are O(1)
	stream.segments.PutOrdered(offset, userData)
	rb.size += dataLen

	finalOffset, finalData := offset, userData

	// Handle previous segment overlap
	if prevOff, prev, exists := stream.segments.Prev(offset); exists {
		prevEnd := prevOff + uint64(len(prev))
		if prevEnd > offset {
			overlapLen := prevEnd - offset
			if overlapLen >= uint64(dataLen) {
				// Completely covered by previous - remove ourselves
				stream.segments.Remove(offset)
				rb.size -= dataLen
				return RcvInsertDuplicate
			}
			// Trim front: remove, adjust, re-insert
			assertOverlap(prev[offset-prevOff:], userData[:overlapLen])
			stream.segments.Remove(offset)
			rb.size -= dataLen
			finalOffset = prevEnd
			finalData = userData[overlapLen:]
			stream.segments.PutOrdered(finalOffset, finalData)
			rb.size += len(finalData)
		}
	}

	// Handle next segment overlap
	if nextOff, next, exists := stream.segments.Next(finalOffset); exists {
		ourEnd := finalOffset + uint64(len(finalData))
		if ourEnd > nextOff {
			stream.segments.Remove(finalOffset)
			rb.size -= len(finalData)

			nextEnd := nextOff + uint64(len(next))
			overlapStart := nextOff - finalOffset

			if ourEnd >= nextEnd {
				// We completely cover next - remove it
				stream.segments.Remove(nextOff)
				rb.size -= len(next)
				assertOverlap(next, finalData[overlapStart:overlapStart+uint64(len(next))])
			} else {
				// Partial overlap - shorten our data
				assertOverlap(next[:ourEnd-nextOff], finalData[overlapStart:])
				finalData = finalData[:overlapStart]
			}

			stream.segments.PutOrdered(finalOffset, finalData)
			rb.size += len(finalData)
		}
	}

	return RcvInsertOk
}

func assertOverlap(existing, incoming []byte) {
	if !bytes.Equal(existing, incoming) {
		panic("segment overlap mismatch - data integrity violation")
	}
}

// =============================================================================
// Read - Deliver in-order data to application
// =============================================================================

// RemoveOldestInOrder returns all contiguous in-order data for the stream.
// Returns nil if no in-order data available.
func (rb *ReceiveBuffer) RemoveOldestInOrder(streamID uint32) []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil {
		return nil
	}

	var result []byte
	for {
		off, val, ok := stream.segments.First()
		if !ok || off != stream.nextInOrder {
			break
		}
		stream.segments.Remove(off)
		rb.size -= len(val)
		result = append(result, val...)
		stream.nextInOrder = off + uint64(len(val))
	}
	return result
}

// =============================================================================
// Stream lifecycle
// =============================================================================

func (rb *ReceiveBuffer) Close(streamID uint32, closeOffset uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.getOrCreateStream(streamID)
	if s.closeAtOffset == nil {
		s.closeAtOffset = &closeOffset
	}
}

func (rb *ReceiveBuffer) IsReadyToClose(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.streams[streamID]
	return s != nil && s.closeAtOffset != nil && s.nextInOrder >= *s.closeAtOffset
}

func (rb *ReceiveBuffer) GetOffsetClosedAt(streamID uint32) *uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if s := rb.streams[streamID]; s != nil {
		return s.closeAtOffset
	}
	return nil
}

func (rb *ReceiveBuffer) RemoveStream(streamID uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.finishedStreams[streamID] = true
	delete(rb.streams, streamID)
}

func (rb *ReceiveBuffer) IsFinished(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.finishedStreams[streamID]
}

// =============================================================================
// ACK management
// =============================================================================

func (rb *ReceiveBuffer) QueueAck(streamID uint32, offset uint64, length uint16) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: length})
}

func (rb *ReceiveBuffer) GetSndAck() *Ack {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.ackList) == 0 {
		return nil
	}
	ack := rb.ackList[0]
	rb.ackList = rb.ackList[1:]
	return ack
}

func (rb *ReceiveBuffer) HasPendingAcks() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return len(rb.ackList) > 0
}

func (rb *ReceiveBuffer) HasPendingAckForStream(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for _, ack := range rb.ackList {
		if ack.streamID == streamID {
			return true
		}
	}
	return false
}

// =============================================================================
// Misc
// =============================================================================

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}