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

	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("data"), data)

	// Verify empty after reading
	data = rb.RemoveOldestInOrder(1)
	require.Empty(t, data)
}

func TestRcvDuplicateSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertDuplicate, status)

	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("data"), data)
}

func TestRcvGapBetweenSegments(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 10, 0, []byte("later"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 0, 0, []byte("early"))
	assert.Equal(t, RcvInsertOk, status)

	// Should get early segment first
	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("early"), data)

	// Gap remains - cannot read out-of-order segment
	data = rb.RemoveOldestInOrder(1)
	assert.Nil(t, data)

	// Fill the gap
	status = rb.Insert(1, 5, 0, []byte("middl"))
	assert.Equal(t, RcvInsertOk, status)

	// Now can read the complete sequence
	data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("middl"), data)

	data = rb.RemoveOldestInOrder(1)
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
	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("stream1-first"), data)

	// Read from stream 2
	data = rb.RemoveOldestInOrder(2)
	assert.Equal(t, []byte("stream2-first"), data)

	// Read second segment from stream 1
	data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("stream1-second"), data)
}

func TestRcvBufferFull(t *testing.T) {
	rb := NewReceiveBuffer(4)

	status := rb.Insert(1, 0, 0, []byte("data"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 4, 0, []byte("more"))
	assert.Equal(t, RcvInsertBufferFull, status)
	assert.Equal(t, 4, rb.Size())

	// Read to free space
	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("data"), data)

	// Now second insert should work
	status = rb.Insert(1, 4, 0, []byte("more"))
	assert.Equal(t, RcvInsertOk, status)
}

func TestRcvAlreadyDeliveredSegment(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Insert and read to advance nextInOrderOffsetToWaitFor
	status := rb.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)

	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("ABCD"), data)

	// Try to insert segment that's completely before delivered data
	status = rb.Insert(1, 0, 0, []byte("AB"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// Try to insert segment that partially overlaps delivered data
	status = rb.Insert(1, 2, 0, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// Insert segment at next expected offset
	status = rb.Insert(1, 4, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)
}

func TestRcvPreviousOverlapPartialIntegrityViolation(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 100, 0, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)

	// Overlapping segment with mismatched data - should panic
	assert.PanicsWithValue(t, "Previous segment overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 102, 0, []byte("XXFG"))
	})
}

func TestRcvPreviousOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 100, 0, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Completely overlapped segment
	status = rb.Insert(1, 102, 0, []byte("CD"))
	assert.Equal(t, RcvInsertDuplicate, status)

	stream := rb.streams[1]
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue.data)
}

func TestRcvNextOverlapMismatchPanic(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 105, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)

	// Overlapping segment with mismatched data - should panic
	assert.PanicsWithValue(t, "Next segment partial overlap mismatch - data integrity violation", func() {
		rb.Insert(1, 100, 0, []byte("ABCDEF"))
	})
}

func TestRcvNextOverlapPartial(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 105, 0, []byte("EFGH"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 100, 0, []byte("ABCDEE"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Should have shortened incoming segment
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDE"), rcvValue.data)

	rcvValue, exists = stream.segments.Get(105)
	assert.True(t, exists)
	assert.Equal(t, []byte("EFGH"), rcvValue.data)
}

func TestRcvNextOverlapComplete(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 105, 0, []byte("EF"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 100, 0, []byte("ABCDEEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEEFGH"), rcvValue.data)

	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestRcvBothOverlaps(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 90, 0, []byte("12345"))
	assert.Equal(t, RcvInsertOk, status)

	status = rb.Insert(1, 105, 0, []byte("WXYZ"))
	assert.Equal(t, RcvInsertOk, status)

	// Segment that overlaps both
	status = rb.Insert(1, 92, 0, []byte("345ABCDEFGHIJWXYZUV"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]

	// Previous segment unchanged
	rcvValue, exists := stream.segments.Get(90)
	assert.True(t, exists)
	assert.Equal(t, []byte("12345"), rcvValue.data)

	// Adjusted incoming segment
	rcvValue, exists = stream.segments.Get(95)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGHIJWXYZUV"), rcvValue.data)

	// Next segment removed (completely overlapped)
	_, exists = stream.segments.Get(105)
	assert.False(t, exists)
}

func TestRcvExactSameOffsetReplace(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Smaller first
	status := rb.Insert(1, 100, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)

	// Larger replaces
	status = rb.Insert(1, 100, 0, []byte("ABCDEFGH"))
	assert.Equal(t, RcvInsertOk, status)

	stream := rb.streams[1]
	rcvValue, exists := stream.segments.Get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue.data)
}

func TestRcvSizeAccounting(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.Insert(1, 0, 0, []byte("ABCDE"))
	assert.Equal(t, RcvInsertOk, status)
	assert.Equal(t, 5, rb.Size())

	// Overlapping segment
	status = rb.Insert(1, 2, 0, []byte("CDEFG"))
	assert.Equal(t, RcvInsertOk, status)
	assert.Equal(t, 7, rb.Size()) // 5 + 2

	// Read first segment
	data := rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("ABCDE"), data)
	assert.Equal(t, 2, rb.Size())

	// Read second segment
	data = rb.RemoveOldestInOrder(1)
	assert.Equal(t, []byte("FG"), data)
	assert.Equal(t, 0, rb.Size())
}

func TestRcvClose(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Basic close
	rb.Insert(1, 0, 0, []byte("ABCD"))
	rb.Close(1, 10)
	stream := rb.streams[1]
	assert.NotNil(t, stream.closeAtOffset)
	assert.Equal(t, uint64(10), *stream.closeAtOffset)

	// Idempotent - same offset ok, different offset warns but keeps first
	rb.Close(1, 20)
	assert.Equal(t, uint64(10), *stream.closeAtOffset)

	// Data before close offset - accepted
	rb2 := NewReceiveBuffer(1000)
	rb2.Close(1, 10)
	status := rb2.Insert(1, 0, 0, []byte("ABCD"))
	assert.Equal(t, RcvInsertOk, status)

	// Data at/after close offset - dropped but ACKed
	status = rb2.Insert(1, 10, 0, []byte("XXXX"))
	assert.Equal(t, RcvInsertDuplicate, status)

	// First ack is from Insert at offset 0
	ack := rb2.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(4), ack.len)

	// Second ack is from Insert at offset 10 (dropped but still ACKed)
	ack = rb2.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(10), ack.offset)
	assert.Equal(t, uint16(4), ack.len)
}

func TestRcvEmptyInsertAndAck(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	status := rb.EmptyInsert(1, 0)
	assert.Equal(t, RcvInsertOk, status)

	ack := rb.GetSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(0), ack.len)
}

func TestRcvCloseBasics(t *testing.T) {
	rb := NewReceiveBuffer(1000)

	// Basic close
	rb.Insert(1, 0, 0, []byte("ABCD"))
	rb.Close(1, 10)
	assert.Equal(t, uint64(10), *rb.streams[1].closeAtOffset)

	// Idempotent
	rb.Close(1, 20)
	assert.Equal(t, uint64(10), *rb.streams[1].closeAtOffset)

	// Data before close - accepted
	rb2 := NewReceiveBuffer(1000)
	rb2.Close(1, 10)
	assert.Equal(t, RcvInsertOk, rb2.Insert(1, 0, 0, []byte("ABCD")))
	assert.Equal(t, RcvInsertOk, rb2.Insert(1, 4, 0, []byte("EFGH")))
}