package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// CONSTRUCTOR TESTS
// =============================================================================

func TestReceiveBuffer_New(t *testing.T) {
	rb := newReceiveBuffer(1000)

	assert.NotNil(t, rb)
	assert.NotNil(t, rb.streams)
	assert.NotNil(t, rb.finishedStreams)
	assert.Equal(t, 1000, rb.capacity)
	assert.Equal(t, 0, rb.len)
}

func TestReceiveBuffer_New_ZeroCapacity(t *testing.T) {
	rb := newReceiveBuffer(0)

	assert.NotNil(t, rb)
	assert.Equal(t, 0, rb.capacity)
}

// =============================================================================
// BASIC INSERT AND READ TESTS
// =============================================================================

func TestReceiveBuffer_Insert_SingleSegment(t *testing.T) {
	rb := newReceiveBuffer(1000)

	status := rb.insert(1, 0, 0, []byte("data"))

	assert.Equal(t, rcvInsertOk, status)
}

func TestReceiveBuffer_RemoveOldestInOrder_SingleSegment(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	data := rb.removeOldestInOrder(1)

	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_RemoveOldestInOrder_EmptyAfterRead(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))
	rb.removeOldestInOrder(1)

	data := rb.removeOldestInOrder(1)

	require.Empty(t, data)
}

func TestReceiveBuffer_RemoveOldestInOrder_NonexistentStream(t *testing.T) {
	rb := newReceiveBuffer(1000)

	data := rb.removeOldestInOrder(999)

	assert.Nil(t, data)
}

// =============================================================================
// DUPLICATE SEGMENT TESTS
// =============================================================================

func TestReceiveBuffer_Insert_DuplicateSegment(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	status := rb.insert(1, 0, 0, []byte("data"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_DuplicateDoesNotAffectData(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))
	rb.insert(1, 0, 0, []byte("data"))

	data := rb.removeOldestInOrder(1)

	assert.Equal(t, []byte("data"), data)
}

func TestReceiveBuffer_Insert_AlreadyDelivered_Complete(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))
	rb.removeOldestInOrder(1)

	// Segment completely before delivered data
	status := rb.insert(1, 0, 0, []byte("AB"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_AlreadyDelivered_Partial(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))
	rb.removeOldestInOrder(1)

	// Segment partially overlaps delivered data
	status := rb.insert(1, 2, 0, []byte("CD"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_AfterDelivered(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))
	rb.removeOldestInOrder(1)

	// Insert at next expected offset
	status := rb.insert(1, 4, 0, []byte("EFGH"))

	assert.Equal(t, rcvInsertOk, status)
}

// =============================================================================
// OUT-OF-ORDER AND GAP TESTS
// =============================================================================

func TestReceiveBuffer_Insert_OutOfOrder(t *testing.T) {
	rb := newReceiveBuffer(1000)

	status := rb.insert(1, 10, 0, []byte("later"))

	assert.Equal(t, rcvInsertOk, status)
}

func TestReceiveBuffer_RemoveOldestInOrder_WithGap(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 10, 0, []byte("later"))
	rb.insert(1, 0, 0, []byte("early"))

	// Should get early segment first
	data := rb.removeOldestInOrder(1)
	assert.Equal(t, []byte("early"), data)

	// Gap remains - cannot read out-of-order segment
	data = rb.removeOldestInOrder(1)
	assert.Nil(t, data)
}

func TestReceiveBuffer_RemoveOldestInOrder_GapFilled(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 10, 0, []byte("later"))
	rb.insert(1, 0, 0, []byte("early"))
	rb.removeOldestInOrder(1)

	// Fill the gap
	rb.insert(1, 5, 0, []byte("middl"))

	// Now get ALL contiguous data in one call
	data := rb.removeOldestInOrder(1)
	assert.Equal(t, []byte("middllater"), data)
}

// =============================================================================
// MULTIPLE STREAM TESTS
// =============================================================================

func TestReceiveBuffer_Insert_MultipleStreams(t *testing.T) {
	rb := newReceiveBuffer(1000)

	status1 := rb.insert(1, 0, 0, []byte("stream1-first"))
	status2 := rb.insert(2, 0, 0, []byte("stream2-first"))

	assert.Equal(t, rcvInsertOk, status1)
	assert.Equal(t, rcvInsertOk, status2)
}

func TestReceiveBuffer_RemoveOldestInOrder_MultipleStreams(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("stream1-first"))
	rb.insert(2, 0, 0, []byte("stream2-first"))
	rb.insert(1, 13, 0, []byte("stream1-second"))

	// Read from stream 1 - gets ALL contiguous data
	data1 := rb.removeOldestInOrder(1)
	assert.Equal(t, []byte("stream1-firststream1-second"), data1)

	// Read from stream 2
	data2 := rb.removeOldestInOrder(2)
	assert.Equal(t, []byte("stream2-first"), data2)
}

// =============================================================================
// BUFFER CAPACITY TESTS
// =============================================================================

func TestReceiveBuffer_Insert_BufferFull(t *testing.T) {
	rb := newReceiveBuffer(4)
	rb.insert(1, 0, 0, []byte("data"))

	status := rb.insert(1, 4, 0, []byte("more"))

	assert.Equal(t, rcvInsertBufferFull, status)
	assert.Equal(t, 4, rb.size())
}

func TestReceiveBuffer_Insert_AfterReadFreesSpace(t *testing.T) {
	rb := newReceiveBuffer(4)
	rb.insert(1, 0, 0, []byte("data"))
	rb.removeOldestInOrder(1)

	status := rb.insert(1, 4, 0, []byte("more"))

	assert.Equal(t, rcvInsertOk, status)
}

func TestReceiveBuffer_Insert_ExactCapacity(t *testing.T) {
	rb := newReceiveBuffer(8)

	status := rb.insert(1, 0, 0, []byte("12345678"))

	assert.Equal(t, rcvInsertOk, status)
	assert.Equal(t, 8, rb.size())
}

// =============================================================================
// OVERLAP TESTS - PREVIOUS SEGMENT
// =============================================================================

func TestReceiveBuffer_Insert_PreviousOverlap_PartialMismatch_Panics(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCDE"))

	assert.PanicsWithValue(t, "segment overlap mismatch - data integrity violation", func() {
		rb.insert(1, 102, 0, []byte("XXFG"))
	})
}

func TestReceiveBuffer_Insert_PreviousOverlap_Complete(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCDEFGH"))

	status := rb.insert(1, 102, 0, []byte("CD"))

	assert.Equal(t, rcvInsertDuplicate, status)

	stream := rb.streams[1]
	rcvValue, exists := stream.segments.get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue)
}

func TestReceiveBuffer_Insert_PreviousOverlap_PartialMatch(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCDE"))

	// Overlapping with matching data
	status := rb.insert(1, 103, 0, []byte("DEFGH"))

	assert.Equal(t, rcvInsertOk, status)
}

// =============================================================================
// OVERLAP TESTS - NEXT SEGMENT
// =============================================================================

func TestReceiveBuffer_Insert_NextOverlap_Mismatch_Panics(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 105, 0, []byte("EFGH"))

	assert.PanicsWithValue(t, "segment overlap mismatch - data integrity violation", func() {
		rb.insert(1, 100, 0, []byte("ABCDEF"))
	})
}

func TestReceiveBuffer_Insert_NextOverlap_Partial(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 105, 0, []byte("EFGH"))

	status := rb.insert(1, 100, 0, []byte("ABCDEE"))

	assert.Equal(t, rcvInsertOk, status)

	stream := rb.streams[1]

	// Should have shortened incoming segment
	rcvValue, exists := stream.segments.get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDE"), rcvValue)

	rcvValue, exists = stream.segments.get(105)
	assert.True(t, exists)
	assert.Equal(t, []byte("EFGH"), rcvValue)
}

func TestReceiveBuffer_Insert_NextOverlap_Complete(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 105, 0, []byte("EF"))

	status := rb.insert(1, 100, 0, []byte("ABCDEEFGH"))

	assert.Equal(t, rcvInsertOk, status)

	stream := rb.streams[1]

	rcvValue, exists := stream.segments.get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEEFGH"), rcvValue)

	// Next segment should be removed (completely overlapped)
	_, exists = stream.segments.get(105)
	assert.False(t, exists)
}

// =============================================================================
// OVERLAP TESTS - BOTH SIDES
// =============================================================================

func TestReceiveBuffer_Insert_BothOverlaps(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 90, 0, []byte("12345"))
	rb.insert(1, 105, 0, []byte("WXYZ"))

	// Segment that overlaps both
	status := rb.insert(1, 92, 0, []byte("345ABCDEFGHIJWXYZUV"))

	assert.Equal(t, rcvInsertOk, status)

	stream := rb.streams[1]

	// Previous segment unchanged
	rcvValue, exists := stream.segments.get(90)
	assert.True(t, exists)
	assert.Equal(t, []byte("12345"), rcvValue)

	// Adjusted incoming segment
	rcvValue, exists = stream.segments.get(95)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGHIJWXYZUV"), rcvValue)

	// Next segment removed (completely overlapped)
	_, exists = stream.segments.get(105)
	assert.False(t, exists)
}

// =============================================================================
// EXACT OFFSET REPLACEMENT TESTS
// =============================================================================

func TestReceiveBuffer_Insert_ExactOffset_LargerReplaces(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCD"))

	status := rb.insert(1, 100, 0, []byte("ABCDEFGH"))

	assert.Equal(t, rcvInsertOk, status)

	stream := rb.streams[1]
	rcvValue, exists := stream.segments.get(100)
	assert.True(t, exists)
	assert.Equal(t, []byte("ABCDEFGH"), rcvValue)
}

func TestReceiveBuffer_Insert_ExactOffset_SmallerIsDuplicate(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCDEFGH"))

	status := rb.insert(1, 100, 0, []byte("ABCD"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_ExactOffset_SameSizeIsDuplicate(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 100, 0, []byte("ABCD"))

	status := rb.insert(1, 100, 0, []byte("ABCD"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

// =============================================================================
// SIZE ACCOUNTING TESTS
// =============================================================================

func TestReceiveBuffer_Size_AfterInsert(t *testing.T) {
	rb := newReceiveBuffer(1000)

	rb.insert(1, 0, 0, []byte("ABCDE"))

	assert.Equal(t, 5, rb.size())
}

func TestReceiveBuffer_Size_OverlappingAddsOnlyNew(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCDE"))

	rb.insert(1, 2, 0, []byte("CDEFG"))

	assert.Equal(t, 7, rb.size()) // 5 + 2
}

func TestReceiveBuffer_Size_AfterRead(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCDE"))
	rb.insert(1, 2, 0, []byte("CDEFG"))

	data := rb.removeOldestInOrder(1)

	assert.Equal(t, []byte("ABCDEFG"), data)
	assert.Equal(t, 0, rb.size())
}

// =============================================================================
// CLOSE TESTS
// =============================================================================

func TestReceiveBuffer_Close_Basic(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))

	rb.close(1, 10)

	stream := rb.streams[1]
	assert.NotNil(t, stream.closeAtOffset)
	assert.Equal(t, uint64(10), *stream.closeAtOffset)
}

func TestReceiveBuffer_Close_Idempotent(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 10)

	rb.close(1, 20)

	assert.Equal(t, uint64(10), *rb.streams[1].closeAtOffset)
}

func TestReceiveBuffer_Close_CreatesStream(t *testing.T) {
	rb := newReceiveBuffer(1000)

	rb.close(1, 10)

	assert.NotNil(t, rb.streams[1])
}

func TestReceiveBuffer_Insert_BeforeCloseOffset(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 10)

	status := rb.insert(1, 0, 0, []byte("ABCD"))

	assert.Equal(t, rcvInsertOk, status)
}

func TestReceiveBuffer_Insert_AtCloseOffset(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 10)

	status := rb.insert(1, 10, 0, []byte("XXXX"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_AfterCloseOffset(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 10)

	status := rb.insert(1, 15, 0, []byte("XXXX"))

	assert.Equal(t, rcvInsertDuplicate, status)
}

func TestReceiveBuffer_Insert_AfterClose_StillAcked(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 10)
	rb.insert(1, 0, 0, []byte("ABCD"))

	rb.insert(1, 10, 0, []byte("XXXX"))

	// First ack is from Insert at offset 0
	ack := rb.getSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
	assert.Equal(t, uint16(4), ack.len)

	// Second ack is from Insert at offset 10 (dropped but still ACKed)
	ack = rb.getSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint64(10), ack.offset)
	assert.Equal(t, uint16(4), ack.len)
}

// =============================================================================
// ISREADYTOCLOSE TESTS
// =============================================================================

func TestReceiveBuffer_IsReadyToClose_NoStream(t *testing.T) {
	rb := newReceiveBuffer(1000)

	assert.False(t, rb.isReadyToClose(1))
}

func TestReceiveBuffer_IsReadyToClose_NoCloseSet(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	assert.False(t, rb.isReadyToClose(1))
}

func TestReceiveBuffer_IsReadyToClose_NotYetReached(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))
	rb.close(1, 10)

	assert.False(t, rb.isReadyToClose(1))
}

func TestReceiveBuffer_IsReadyToClose_ReachedAfterRead(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCD"))
	rb.close(1, 4)
	rb.removeOldestInOrder(1)

	assert.True(t, rb.isReadyToClose(1))
}

func TestReceiveBuffer_IsReadyToClose_ExactlyAtOffset(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("ABCDEFGHIJ"))
	rb.close(1, 10)
	rb.removeOldestInOrder(1)

	assert.True(t, rb.isReadyToClose(1))
}

// =============================================================================
// GETOFFSETCLOSEDAT TESTS
// =============================================================================

func TestReceiveBuffer_GetOffsetClosedAt_NoStream(t *testing.T) {
	rb := newReceiveBuffer(1000)

	result := rb.getOffsetClosedAt(1)

	assert.Nil(t, result)
}

func TestReceiveBuffer_GetOffsetClosedAt_NotClosed(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	result := rb.getOffsetClosedAt(1)

	assert.Nil(t, result)
}

func TestReceiveBuffer_GetOffsetClosedAt_Closed(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.close(1, 100)

	result := rb.getOffsetClosedAt(1)

	require.NotNil(t, result)
	assert.Equal(t, uint64(100), *result)
}

// =============================================================================
// REMOVESTREAM TESTS
// =============================================================================

func TestReceiveBuffer_RemoveStream(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	rb.removeStream(1)

	assert.Nil(t, rb.streams[1])
	assert.True(t, rb.finishedStreams[1])
}

func TestReceiveBuffer_RemoveStream_NonexistentIsOk(t *testing.T) {
	rb := newReceiveBuffer(1000)

	rb.removeStream(999)

	assert.True(t, rb.finishedStreams[999])
}

// =============================================================================
// ISFINISHED TESTS
// =============================================================================

func TestReceiveBuffer_IsFinished_NotFinished(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	assert.False(t, rb.isFinished(1))
}

func TestReceiveBuffer_IsFinished_AfterRemove(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))
	rb.removeStream(1)

	assert.True(t, rb.isFinished(1))
}

func TestReceiveBuffer_IsFinished_NeverExisted(t *testing.T) {
	rb := newReceiveBuffer(1000)

	assert.False(t, rb.isFinished(999))
}

// =============================================================================
// ACK MANAGEMENT TESTS
// =============================================================================

func TestReceiveBuffer_QueueAck(t *testing.T) {
	rb := newReceiveBuffer(1000)

	rb.queueAck(1, 100, 50)

	ack := rb.getSndAck()
	assert.NotNil(t, ack)
	assert.Equal(t, uint32(1), ack.streamId)
	assert.Equal(t, uint64(100), ack.offset)
	assert.Equal(t, uint16(50), ack.len)
}

func TestReceiveBuffer_GetSndAck_Empty(t *testing.T) {
	rb := newReceiveBuffer(1000)

	ack := rb.getSndAck()

	assert.Nil(t, ack)
}

func TestReceiveBuffer_GetSndAck_FIFO(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.queueAck(1, 100, 10)
	rb.queueAck(2, 200, 20)

	ack1 := rb.getSndAck()
	ack2 := rb.getSndAck()

	assert.Equal(t, uint32(1), ack1.streamId)
	assert.Equal(t, uint32(2), ack2.streamId)
}

func TestReceiveBuffer_HasPendingAcks_Empty(t *testing.T) {
	rb := newReceiveBuffer(1000)

	assert.False(t, rb.hasPendingAcks())
}

func TestReceiveBuffer_HasPendingAcks_WithAcks(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	assert.True(t, rb.hasPendingAcks())
}

func TestReceiveBuffer_HasPendingAckForStream_NoAcks(t *testing.T) {
	rb := newReceiveBuffer(1000)

	assert.False(t, rb.hasPendingAckForStream(1))
}

func TestReceiveBuffer_HasPendingAckForStream_WrongStream(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	assert.False(t, rb.hasPendingAckForStream(2))
}

func TestReceiveBuffer_HasPendingAckForStream_CorrectStream(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))

	assert.True(t, rb.hasPendingAckForStream(1))
}

// =============================================================================
// INSERT GENERATES ACK TESTS
// =============================================================================

func TestReceiveBuffer_Insert_GeneratesAck(t *testing.T) {
	rb := newReceiveBuffer(1000)

	rb.insert(1, 50, 0, []byte("data"))

	ack := rb.getSndAck()
	require.NotNil(t, ack)
	assert.Equal(t, uint32(1), ack.streamId)
	assert.Equal(t, uint64(50), ack.offset)
	assert.Equal(t, uint16(4), ack.len)
}

func TestReceiveBuffer_Insert_Duplicate_StillGeneratesAck(t *testing.T) {
	rb := newReceiveBuffer(1000)
	rb.insert(1, 0, 0, []byte("data"))
	rb.getSndAck() // consume first ack

	rb.insert(1, 0, 0, []byte("data"))

	ack := rb.getSndAck()
	require.NotNil(t, ack)
	assert.Equal(t, uint64(0), ack.offset)
}
