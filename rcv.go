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
	streams    map[uint32]*RcvBuffer
	lastStream uint32
	capacity   int // Max buffer size
	size       int // Current size
	ackList    []*Ack
	mu         *sync.Mutex
}

func NewRcvBuffer() *RcvBuffer {
	return &RcvBuffer{
		segments:                   NewSortedMap[uint64, RcvValue](),
		nextInOrderOffsetToWaitFor: 0,
		closeAtOffset:              nil,
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

func (rb *ReceiveBuffer) EmptyInsert(streamID uint32, offset uint64, nowNano uint64) RcvInsertStatus {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	stream := rb.streams[streamID]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamID] = stream
	}

	
	rb.ackList = append(rb.ackList, &Ack{streamID: streamID, offset: offset, len: 0})

	return RcvInsertOk
}

func (rb *ReceiveBuffer) Insert(streamID uint32, offset uint64, nowNano uint64, userData []byte) RcvInsertStatus {
	dataLen := len(userData)

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Get or create stream buffer
	stream := rb.streams[streamID]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamID] = stream
	}

	if rb.size+dataLen > rb.capacity {
		slog.Debug("Rcv/BufferFull", slog.Int("rb.size+dataLen", rb.size+dataLen), slog.Int("rb.capacity", rb.capacity))
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
		slog.Debug("Rcv/Duplicate/WithUser", slog.Uint64("offset", offset), slog.Int("len(data)", dataLen))
		return RcvInsertDuplicate
	}

	// Check if we already have a segment starting at this exact offset
	if existingData, exists := stream.segments.Get(offset); exists {
		existingLen := len(existingData.data)

		// If incoming data is smaller or equal in size, it's a duplicate - ignore it
		// If incoming data is larger, replace the existing segment with the larger one
		if dataLen <= existingLen {
			slog.Debug("Rcv/Duplicate/SmallerOrEqual",
				slog.Uint64("offset", offset),
				slog.Int("incoming_len", dataLen),
				slog.Int("existing_len", existingLen))
			return RcvInsertDuplicate
		} else {
			// Incoming segment is larger - remove the smaller existing one
			// and continue to insert the larger segment
			stream.segments.Remove(offset)
			rb.size -= existingLen
			slog.Debug("Rcv/Replace/WithLarger",
				slog.Uint64("offset", offset),
				slog.Int("old_len", existingLen),
				slog.Int("new_len", dataLen))
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
			overlapLen := prevOffset + uint64(len(prevData.data)) - offset
			if overlapLen >= uint64(dataLen) {
				// Completely overlapped by previous - this is a duplicate
				slog.Debug("Rcv/Duplicate/CompletelyOverlappedByPrev",
					slog.Uint64("offset", offset), slog.Int("len(data)", dataLen))
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

			slog.Debug("Rcv/AdjustForPrevOverlap",
				slog.Uint64("original_offset", offset),
				slog.Uint64("adjusted_offset", finalOffset),
				slog.Int("overlap_len", int(overlapLen)))
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

				slog.Debug("Rcv/ReplaceNext/CompleteOverlap",
					slog.Uint64("next_offset", nextOffset),
					slog.Int("next_len", len(nextData.data)),
					slog.Uint64("our_offset", finalOffset),
					slog.Int("our_len", len(finalUserData)))
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

				slog.Debug("Rcv/AdjustForNextOverlap",
					slog.Uint64("adjusted_offset", finalOffset),
					slog.Int("original_len", len(userData)),
					slog.Int("final_len", len(finalUserData)))
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

	// Get or create stream buffer
	stream := rb.streams[streamID]
	if stream == nil {
		stream = NewRcvBuffer()
		rb.streams[streamID] = stream
	}
	if stream.closeAtOffset == nil {
		stream.closeAtOffset = &closeOffset
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

func (rb *ReceiveBuffer) RemoveOldestInOrder(streamID uint32) (offset uint64, data []byte, receiveTimeNano uint64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if len(rb.streams) == 0 {
		return 0, nil, 0
	}

	stream := rb.streams[streamID]
	if stream == nil {
		return 0, nil, 0
	}

	// Check if there is any dataToSend at all
	oldestOffset, oldestValue, ok := stream.segments.Min()
	if !ok {
		return 0, nil, 0
	}

	if oldestOffset == stream.nextInOrderOffsetToWaitFor {
		stream.segments.Remove(oldestOffset)
		rb.size -= len(oldestValue.data)

		nextOffset := oldestOffset
		if nextOffset < stream.nextInOrderOffsetToWaitFor {
			diff := stream.nextInOrderOffsetToWaitFor - oldestOffset
			oldestValue.data = oldestValue.data[diff:]
			nextOffset = stream.nextInOrderOffsetToWaitFor
		}

		stream.nextInOrderOffsetToWaitFor = nextOffset + uint64(len(oldestValue.data))
		return oldestOffset, oldestValue.data, oldestValue.receiveTimeNano
	} else if oldestOffset > stream.nextInOrderOffsetToWaitFor {
		// Out of order; wait until segment offset available, signal that
		return 0, nil, 0
	} else {
		//Dupe, overlap, do nothing. Here we could think about adding the non-overlapping part. But if
		//it's correctly implemented, this should not happen.
		return 0, nil, 0
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
