package qotp

import (
	"bytes"
	"sync"
)

type RcvInsertStatus int

const (
	RcvInsertOk RcvInsertStatus = iota
	RcvInsertDuplicate
	RcvInsertBufferFull

	rcvBufferCapacity = 16 * 1024 * 1024 // 16MB
)

type RcvValue struct {
	data            []byte
	receiveTimeNano uint64
}

type RcvBuffer struct {
	segments       *LinkedMap[uint64, RcvValue]
	nextInOrder    uint64  // Next expected offset
	closeAtOffset  *uint64
}

type ReceiveBuffer struct {
	streams         map[uint32]*RcvBuffer
	finishedStreams map[uint32]bool
	capacity        int
	size            int
	ackList         []*Ack
	mu              sync.Mutex
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{segments: NewLinkedMap[uint64, RcvValue]()}
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
	s := NewRcvBuffer()
	rb.streams[streamID] = s
	return s
}

func (rb *ReceiveBuffer) queueAck(streamID uint32, offset uint64, length uint16) {
	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: length})
}

func (rb *ReceiveBuffer) EmptyInsert(streamID uint32, offset uint64) RcvInsertStatus {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.queueAck(streamID, offset, 0)
	return RcvInsertOk
}

func (rb *ReceiveBuffer) IsReadyToClose(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.streams[streamID]
	return s != nil && s.closeAtOffset != nil && s.nextInOrder >= *s.closeAtOffset
}

func (rb *ReceiveBuffer) QueueAckForClosedStream(streamID uint32, offset uint64, length uint16) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.queueAck(streamID, offset, length)
}

func (rb *ReceiveBuffer) Insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) RcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.getOrCreateStream(streamID)

	// Data after close - ACK but drop
	if stream.closeAtOffset != nil && offset >= *stream.closeAtOffset {
		rb.queueAck(streamID, offset, uint16(dataLen))
		return RcvInsertDuplicate
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	// Always ACK (may be retransmit due to lost ACK)
	rb.queueAck(streamID, offset, uint16(dataLen))

	// Already delivered
	if offset+uint64(dataLen) <= stream.nextInOrder {
		return RcvInsertDuplicate
	}

	// Exact offset match - keep larger segment
	if existing, exists := stream.segments.Get(offset); exists {
		if dataLen <= len(existing.data) {
			return RcvInsertDuplicate
		}
		stream.segments.Remove(offset)
		rb.size -= len(existing.data)
		stream.segments.PutOrdered(offset, RcvValue{data: userData, receiveTimeNano: nowNano})
		rb.size += dataLen
		return RcvInsertOk
	}

	finalOffset, finalData := offset, userData

	// Handle previous segment overlap
	if prevOff, prev, exists := stream.segments.Prev(offset); exists {
		prevEnd := prevOff + uint64(len(prev.data))
		if prevEnd > offset {
			overlapLen := prevEnd - offset
			if overlapLen >= uint64(dataLen) {
				return RcvInsertDuplicate
			}
			assertOverlap(prev.data[offset-prevOff:], userData[:overlapLen])
			finalOffset = prevEnd
			finalData = userData[overlapLen:]
		}
	}

	// Insert segment
	stream.segments.PutOrdered(finalOffset, RcvValue{data: finalData, receiveTimeNano: nowNano})
	rb.size += len(finalData)

	// Handle next segment overlap
	if nextOff, next, exists := stream.segments.Next(finalOffset); exists {
		ourEnd := finalOffset + uint64(len(finalData))
		if ourEnd > nextOff {
			stream.segments.Remove(finalOffset)
			rb.size -= len(finalData)

			nextEnd := nextOff + uint64(len(next.data))
			overlapStart := nextOff - finalOffset

			if ourEnd >= nextEnd {
				// We completely cover next segment
				stream.segments.Remove(nextOff)
				rb.size -= len(next.data)
				assertOverlap(next.data, finalData[overlapStart:overlapStart+uint64(len(next.data))])
			} else {
				// Partial overlap - shorten our data
				assertOverlap(next.data[:ourEnd-nextOff], finalData[overlapStart:])
				finalData = finalData[:overlapStart]
			}

			stream.segments.PutOrdered(finalOffset, RcvValue{data: finalData, receiveTimeNano: nowNano})
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

func (rb *ReceiveBuffer) Close(streamID uint32, closeOffset uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	s := rb.getOrCreateStream(streamID)
	if s.closeAtOffset == nil {
		s.closeAtOffset = &closeOffset
	}
}

func (rb *ReceiveBuffer) GetOffsetClosedAt(streamID uint32) *uint64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if s := rb.streams[streamID]; s != nil {
		return s.closeAtOffset
	}
	return nil
}

// RemoveOldestInOrder returns all contiguous in-order data for the stream.
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
		rb.size -= len(val.data)
		result = append(result, val.data...)
		stream.nextInOrder = off + uint64(len(val.data))
	}
	return result
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
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

func (rb *ReceiveBuffer) RemoveStream(streamID uint32) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.finishedStreams[streamID] = true
	delete(rb.streams, streamID)
}

func (rb *ReceiveBuffer) IsFinished(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	_, ok := rb.finishedStreams[streamID]
	return ok
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