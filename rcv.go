package qotp

import (
	"bytes"
	"log/slog"
	"sync"
)

type RcvInsertStatus int

const (
	RcvInsertOk RcvInsertStatus = iota
	RcvInsertDuplicate
	RcvInsertBufferFull
)

type RcvValue struct {
	data            []byte
	receiveTimeNano uint64
}

type RcvBuffer struct {
	segments                   *SortedMap[uint64, RcvValue]
	nextInOrderOffsetToWaitFor uint64 // Next expected offset
	closeAtOffset              *uint64
}

type ReceiveBuffer struct {
	streams  map[uint32]*RcvBuffer
	capacity int // Max buffer size
	size     int // Current size
	ackList  []*Ack
	mu       *sync.Mutex
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments: NewSortedMap[uint64, RcvValue](),
	}
}

func NewReceiveBuffer(capacity int) *ReceiveBuffer {
	return &ReceiveBuffer{
		streams:  make(map[uint32]*RcvBuffer),
		capacity: capacity,
		ackList:  []*Ack{},
		mu:       &sync.Mutex{},
	}
}

func (rb *ReceiveBuffer) getOrCreateStream(streamID uint32) *RcvBuffer {
	stream := rb.streams[streamID]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamID] = stream
	}
	return stream
}

func (rb *ReceiveBuffer) EmptyInsert(streamID uint32, offset uint64) RcvInsertStatus {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: 0})

	return RcvInsertOk
}

func (rb *ReceiveBuffer) IsReadyToClose(streamID uint32) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil || stream.closeAtOffset == nil {
		return false
	}

	return stream.nextInOrderOffsetToWaitFor >= *stream.closeAtOffset
}

func (rb *ReceiveBuffer) Insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) RcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	stream := rb.getOrCreateStream(streamID)

	if stream.closeAtOffset != nil {
		if offset >= *stream.closeAtOffset {
			// Data after close offset - protocol violation
			// Still ACK it (already added to ackList above) but drop the data
			rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: uint16(dataLen)})
			return RcvInsertDuplicate // Drop it
		}
	}

	if rb.size+dataLen > rb.capacity {
		return RcvInsertBufferFull
	}

	// Now we need to add the ack to the list even if it's a duplicate,
	// as the ack may have been lost, we need to send it again
	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: uint16(dataLen)})

	// Check if the incoming segment is completely before the next expected offset.
	// This means all data in this segment has already been delivered to the user application.
	// For example: if nextInOrderOffsetToWaitFor = 1000, and we receive data at offset 500-600,
	// that data was already processed and delivered, so it's a duplicate we can safely ignore.
	if offset+uint64(dataLen) <= stream.nextInOrderOffsetToWaitFor {
		return RcvInsertDuplicate
	}

	// Check if we already have a segment starting at this exact offset
	if existingData, exists := stream.segments.Get(offset); exists {
		existingLen := len(existingData.data)

		// If incoming data is smaller or equal in size, it's a duplicate - ignore it
		// If incoming data is larger, replace the existing segment with the larger one
		if dataLen <= existingLen {
			return RcvInsertDuplicate
		} else {
			// Incoming segment is larger - remove the smaller existing one
			// and continue to insert the larger segment
			stream.segments.Remove(offset)
			rb.size -= existingLen
		}

		stream.segments.Put(offset, RcvValue{data: userData, receiveTimeNano: nowNano})
		rb.size += dataLen
		return RcvInsertOk
	}
	// first check if the previous is overlapping
	finalOffset := offset
	finalUserData := userData

	if prevOffset, prevData, exists := stream.segments.Prev(offset); exists {
		prevEnd := prevOffset + uint64(len(prevData.data))
		// Check if the previous segment overlaps with our incoming segment
		if prevEnd > offset {
			//adjust our offset, move it foward, for testing, check that overlap is the same
			overlapLen := prevEnd - offset
			if overlapLen >= uint64(dataLen) {
				// Completely overlapped by previous - this is a duplicate
				return RcvInsertDuplicate
			}
			existingOverlap := prevData.data[offset-prevOffset:]
			incomingOverlap := userData[:overlapLen]
			if !bytes.Equal(existingOverlap, incomingOverlap) {
				panic("Previous segment overlap mismatch - data integrity violation")
			}

			// Adjust our offset and data slice
			finalOffset = prevEnd
			finalUserData = userData[overlapLen:]
		}
	}

	if nextOffset, nextData, exists := stream.segments.Next(offset); exists {
		ourEnd := finalOffset + uint64(len(finalUserData))
		if ourEnd > nextOffset {
			// We overlap with next segment
			nextEnd := nextOffset + uint64(len(nextData.data))

			if ourEnd >= nextEnd {
				// We completely overlap the next segment - remove it since we have more data
				stream.segments.Remove(nextOffset)
				rb.size -= len(nextData.data)

				// Assert that our overlapping portion matches the next segment data
				ourOverlapStart := nextOffset - finalOffset
				incomingOverlap := finalUserData[ourOverlapStart : ourOverlapStart+uint64(len(nextData.data))]
				if !bytes.Equal(nextData.data, incomingOverlap) {
					panic("Next segment complete overlap mismatch - data integrity violation")
				}
			} else {
				// Partial overlap - shorten our data
				overlapLen := ourEnd - nextOffset
				ourOverlapStart := nextOffset - finalOffset
				existingOverlap := nextData.data[:overlapLen]
				incomingOverlap := finalUserData[ourOverlapStart:]
				if !bytes.Equal(existingOverlap, incomingOverlap) {
					panic("Next segment partial overlap mismatch - data integrity violation")
				}

				// Shorten our data to remove overlap
				finalUserData = finalUserData[:ourOverlapStart]
			}
		}
	}

	// Now we have the correct offset and data slice - store it
	stream.segments.Put(finalOffset, RcvValue{data: finalUserData, receiveTimeNano: nowNano})
	rb.size += len(finalUserData)

	return RcvInsertOk
}

func (rb *ReceiveBuffer) Close(streamID uint32, closeOffset uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rcv := rb.getOrCreateStream(streamID)
	if rcv.closeAtOffset == nil {
		rcv.closeAtOffset = &closeOffset
	} else if *rcv.closeAtOffset != closeOffset {
		slog.Warn("rcv close offset mismatch", gId(),
			slog.Uint64("existing", *rcv.closeAtOffset),
			slog.Uint64("new", closeOffset))
	}
}

func (rb *ReceiveBuffer) GetOffsetClosedAt(streamID uint32) (offset *uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil {
		return nil
	}

	return stream.closeAtOffset
}

func (rb *ReceiveBuffer) RemoveOldestInOrder(streamID uint32) (data []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.streams) == 0 {
		return nil
	}

	stream := rb.streams[streamID]
	if stream == nil {
		return nil
	}

	// Check if there is any dataToSend at all
	oldestOffset, oldestValue, ok := stream.segments.Min()
	if !ok {
		return nil
	}

	if oldestOffset == stream.nextInOrderOffsetToWaitFor {
		stream.segments.Remove(oldestOffset)
		rb.size -= len(oldestValue.data)

		stream.nextInOrderOffsetToWaitFor = oldestOffset + uint64(len(oldestValue.data))
		return oldestValue.data
	} else if oldestOffset > stream.nextInOrderOffsetToWaitFor {
		// Out of order; wait until segment offset available, signal that
		return nil
	} else {
		//Dupe, overlap, do nothing. Here we could think about adding the non-overlapping part. But if
		//it's correctly implemented, this should not happen.
		slog.Warn("RemoveOldestInOrder: unexpected overlap",
			slog.Uint64("oldest", oldestOffset),
			slog.Uint64("expected", stream.nextInOrderOffsetToWaitFor))
		return nil
	}
}

func (rb *ReceiveBuffer) Size() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

func (rb *ReceiveBuffer) Available() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.capacity - rb.size
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
