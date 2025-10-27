package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRcvSingleSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)

	// Verify empty after reading
	_, data, _ = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestRcvDuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertDuplicate, status)

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestRcvGapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 10, 0, []byte("later"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, 0, []byte("early"))
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("early"), data)

	// Gap remains - cannot read out-of-order segment
	offset, data, _ = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)

	// Fill the gap
	status = rb.Insert(1, 5, 0, []byte("middl"))
	assert.Equal(t, RcvInsertOk, status)

	// Now can read the complete sequence
	offset, data, _ = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(5), offset)
	assert.Equal(t, []byte("middl"), data)

	offset, data, _ = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(10), offset)
	assert.Equal(t, []byte("later"), data)
}

func TestRcvMultipleStreams(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert segments from different streams
	status := rb.Insert(1, 0, 0, []byte("stream1-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(2, 0, 0, []byte("stream2-first"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 13, 0, []byte("stream1-second"))
	assert.Equal(t, RcvInsertOk, status)

	// Read from stream 1
	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream1-first"), data)

	// Read from stream 2
	offset, data, _ = rb.RemoveOldestInOrder(2)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("stream2-first"), data)

	// Read second segment from stream 1
	offset, data, _ = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(13), offset)
	assert.Equal(t, []byte("stream1-second"), data)
}

func TestRcvBufferFullExact(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, 0, []byte("more"))
	assert.Equal(t, RcvInsertBufferFull, status)
	assert.Equal(t, 4, rb.Size())

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("data"), data)
}

func TestRcvRemoveWithHigherOffset(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, 0, []byte("12345"))
	assert.Equal(t, RcvInsertBufferFull, status)

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Nil(t, data)
}

func TestRcvRemoveWithHigherOffsetEmptyAfterLast(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, 0, []byte("1"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("1"), data)

	// Should be empty after reading
	_, data, _ = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestRcvPreviousOverlapPartialIntegrityViolation(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert previous segment: offset=100, data="ABCDE"
	status := rb.Insert(1, 100, 0, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert overlapping segment with mismatched data - should panic
	assert.PanicsWithValue(t, "Previous segment overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 102, 0, []byte("XXFG")) // "XX" doesn't match "CD"
	})
}

func TestRcvPreviousOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert previous segment: offset=100, data="ABCDEFGH"
	status := rb.Insert(1, 100, 0, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert completely overlapped segment: offset=102, data="CD"
	status = rb.Insert(1, 102, 0, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// Should still only have the original segment
	stream := rb.streams[1]
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue.data)

	// Should not have created new segment
	_, exists = stream.segments.Get(102)
	assert.False(t, exists)
}

func TestRcvNextOverlapMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert next segment first: offset=105, data="EFGH"
	status := rb.Insert(1, 105, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert overlapping segment with mismatched overlap data - should panic
	assert.PanicsWithValue(t, "Next segment partial overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 100, 0, []byte("ABCDEF")) // "F" at position 105 doesn't match "E"
	})
}

func TestRcvNextOverlapPartial(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert next segment first: offset=105, data="EFGH"
	status := rb.Insert(1, 105, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert overlapping segment: offset=100, data="ABCDEE"
	status = rb.Insert(1, 100, 0, []byte("ABCDEE"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Should have shortened incoming segment to remove only the overlapping "E"
	// Keeps "ABCDE" (the non-overlapping portion)
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDE"), rcvValue.data)

	// Should still have next segment: offset=105, data="EFGH"
	rcvValue, exists = stream.segments.Get(105)
	assert.True(t, exists)
	assert.Equal(t, []byte("EFGH"), rcvValue.data)
}

func TestRcvNextOverlapCompleteMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert next segment first: offset=105, data="EF"
	status := rb.Insert(1, 105, 0, []byte("EF"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert segment with mismatched complete overlap data - should panic
	assert.PanicsWithValue(t, "Next segment complete overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 100, 0, []byte("ABCDEFGH")) // "FG" at positions 105-106 doesn't match "EF"
	})
}

func TestRcvNextOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert next segment first: offset=105, data="EF"
	status := rb.Insert(1, 105, 0, []byte("EF"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert segment that completely covers the next with matching overlap data
	status = rb.Insert(1, 100, 0, []byte("ABCDEEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Should have our full segment: offset=100, data="ABCDEEFGH"
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEEFGH"), rcvValue.data)

	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestRcvBothOverlaps(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert previous segment: offset=90, data="12345"
	status := rb.Insert(1, 90, 0, []byte("12345"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert next segment: offset=105, data="WXYZ"
	status = rb.Insert(1, 105, 0, []byte("WXYZ"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert segment that overlaps both with matching data
	status = rb.Insert(1, 92, 0, []byte("345ABCDEFGHIJWXYZUV"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Previous segment should stay unchanged
	rcvValue, exists := stream.segments.Get(90)
	assert.True(t, exists)
	assert.Equal(t, []byte("12345"), rcvValue.data)

	// Adjusted incoming segment: offset=95, data="ABCDEFGHIJWXYZUV"
	rcvValue, exists = stream.segments.Get(95)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGHIJWXYZUV"), rcvValue.data)

	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestRcvExactSameOffsetSmallerData(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert larger segment first
	status := rb.Insert(1, 100, 0, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert smaller segment at same offset - should be duplicate
	status = rb.Insert(1, 100, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertDuplicate, status)

	stream := rb.streams[1]

	// Should keep the larger segment
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue.data)
}

func TestRcvExactSameOffsetLargerData(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert smaller segment first
	status := rb.Insert(1, 100, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)

	// Insert larger segment at same offset - should replace
	status = rb.Insert(1, 100, 0, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Should have the larger segment
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue.data)
}

func TestRcvAlreadyDeliveredSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert and read a segment to advance nextInOrderOffsetToWaitFor
	status := rb.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)

	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("ABCD"), data)

	// Now nextInOrderOffsetToWaitFor should be 4
	stream := rb.streams[1]
	assert.Equal(t, uint64(4), stream.nextInOrderOffsetToWaitFor)

	// Try to insert segment that's completely before delivered data
	status = rb.Insert(1, 0, 0, []byte("AB"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// Try to insert segment that partially overlaps delivered data
	status = rb.Insert(1, 2, 0, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// Insert segment that starts exactly at next expected offset
	status = rb.Insert(1, 4, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)
}

func TestRcvSizeAccountingCorrect(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert first segment
	status := rb.Insert(1, 0, 0, []byte("ABCDE")) // 5 bytes
	assert.Equal(t, RcvInsertOk, status)
	assert.Equal(t, 5, rb.Size())

	// Insert overlapping segment with matching overlap data
	status = rb.Insert(1, 2, 0, []byte("CDEFG")) // overlaps with "CDE"
	assert.Equal(t, RcvInsertOk, status)

	// First segment stays: "ABCDE" (5 bytes)
	// New segment adjusted: "FG" at offset 5 (2 bytes)
	// Total: 5 + 2 = 7 bytes
	assert.Equal(t, 7, rb.Size())

	// Read first segment
	offset, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, []byte("ABCDE"), data)
	assert.Equal(t, 2, rb.Size()) // Only "FG" remains

	// Read second segment
	offset, data, _ = rb.RemoveOldestInOrder(1)
	assert.Equal(t, uint64(5), offset)
	assert.Equal(t, []byte("FG"), data)
	assert.Equal(t, 0, rb.Size())
}

func TestRcvOverlapDataMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert previous segment
	status := rb.Insert(1, 100, 0, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)

	// Try to insert overlapping segment with different data - should panic
	assert.Panics(t, func() {
		rb.Insert(1, 102, 0, []byte("XXFG")) // "XX" doesn't match "CD"
	})
}

func TestRcvClose(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert and read some data
	rb.Insert(1, 0, 0, []byte("ABCD"))
	_, data, _ := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("ABCD"), data)

	// Close at offset 10 (peer sent CLOSE at offset 10)
	rb.Close(1, 10)

	stream := rb.streams[1]
	assert.NotNil(t, stream.closeAtOffset)
	assert.Equal(t, uint64(10), *stream.closeAtOffset)
}

func TestRcvCloseIdempotent(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	rb.Insert(1, 0, 0, []byte("ABCD"))
	rb.Close(1, 10)

	firstOffset := *rb.streams[1].closeAtOffset

	// Read data
	rb.RemoveOldestInOrder(1)

	// Close again with different offset - should not change (idempotent)
	rb.Close(1, 20)
	secondOffset := *rb.streams[1].closeAtOffset

	assert.Equal(t, firstOffset, secondOffset)
	assert.Equal(t, uint64(10), secondOffset)
}

func TestRcvEmptyInsertAndAck(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// EmptyInsert - ack should be added
	status := rb.EmptyInsert(1, 0, 0)
	assert.Equal(t, RcvInsertOk, status)
	ack := rb.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(0), ack.len)
	
	// Close stream at offset 10
	rb.Close(1, 10)
	
	// EmptyInsert after close - ack should still be added
	status = rb.EmptyInsert(1, 4, 0)
	assert.Equal(t, RcvInsertOk, status)
	
	ack = rb.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint32(1), ack.streamID)
	assert.Equal(t, uint64(4), ack.offset)
	assert.Equal(t, uint16(0), ack.len)
}

func TestRcvInsertAfterClose(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	// Close at offset 100
	rb.Close(1, 100)
	
	// Insert after close - should add ack
	status := rb.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)
	
	ack := rb.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint32(1), ack.streamID)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(4), ack.len)
}

func TestRcvDuplicateAfterCloseGeneratesAck(t *testing.T) {
	rb := NewReceiveBuffer(1000)
	
	status := rb.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)
	
	// Consume first ACK
	rb.GetSndAck()
	
	// Close at offset 100
	rb.Close(1, 100)
	
	// Duplicate after close - should still generate ack (line 93-94 in rcv.go)
	status = rb.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertDuplicate, status)
	
	ack := rb.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(4), ack.len)
}