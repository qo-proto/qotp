package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// CONSTRUCTOR TESTS
// =============================================================================

func TestSendBuffer_New(t *testing.T) {
	sb := NewSendBuffer(1000)

	assert.NotNil(t, sb)
	assert.NotNil(t, sb.streams)
	assert.Equal(t, 1000, sb.capacity)
	assert.Equal(t, 0, sb.size)
}

func TestSendBuffer_New_ZeroCapacity(t *testing.T) {
	sb := NewSendBuffer(0)

	assert.NotNil(t, sb)
	assert.Equal(t, 0, sb.capacity)
}

// =============================================================================
// QUEUEDATA TESTS
// =============================================================================

func TestSendBuffer_QueueData_Basic(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte("test"))

	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("test"), sb.streams[1].queuedData)
}

func TestSendBuffer_QueueData_CapacityLimit_Partial(t *testing.T) {
	sb := NewSendBuffer(3)

	n, status := sb.QueueData(1, []byte("test"))

	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, n)
}

func TestSendBuffer_QueueData_CapacityLimit_Full(t *testing.T) {
	sb := NewSendBuffer(4)
	sb.QueueData(1, []byte("test"))

	n, status := sb.QueueData(1, []byte("more"))

	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_EmptyData(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte{})

	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_NilData(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, nil)

	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_CreatesStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))

	assert.NotNil(t, sb.streams[1])
}

// =============================================================================
// QUEUEPING TESTS
// =============================================================================

func TestSendBuffer_QueuePing(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueuePing(1)

	assert.True(t, sb.streams[1].pingRequested)
}

func TestSendBuffer_QueuePing_CreatesStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueuePing(1)

	assert.NotNil(t, sb.streams[1])
}

// =============================================================================
// READYTOSEND TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_Basic(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("hello"))

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, []byte("hello"), data)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToSend_UpdatesBytesSentOffset(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("hello"))

	sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, uint64(5), sb.streams[1].bytesSentOffset)
}

func TestSendBuffer_ReadyToSend_TracksInFlight(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("hello"))
	sb.readyToSend(1, Data, nil, 1000)

	_, info, ok := sb.streams[1].inFlight.First()

	assert.True(t, ok)
	assert.Equal(t, []byte("hello"), info.data)
}

func TestSendBuffer_ReadyToSend_NoData(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("hello"))
	sb.readyToSend(1, Data, nil, 1000)

	data, _, _ := sb.readyToSend(1, Data, nil, 1000)

	assert.Nil(t, data)
}

func TestSendBuffer_ReadyToSend_NonexistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	data, _, _ := sb.readyToSend(999, Data, nil, 1000)

	assert.Nil(t, data)
}

func TestSendBuffer_ReadyToSend_Ping(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueuePing(1)

	data, _, _ := sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, []byte{}, data)
	assert.Equal(t, 1, sb.streams[1].inFlight.Size())
}

func TestSendBuffer_ReadyToSend_PingPriority(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("data"))
	sb.QueuePing(1)

	// Ping should be sent first
	data, _, _ := sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte{}, data)

	// Then data
	data, _, _ = sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte("data"), data)
}

// =============================================================================
// READYTOSEND MTU SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_MTUSplit_First(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))

	// MTU of 44 allows 5 bytes data (44 - 39 overhead)
	data, offset, _ := sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToSend_MTUSplit_Second(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.readyToSend(1, Data, nil, 44)

	data, offset, _ := sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(5), offset)
}

// =============================================================================
// ACKNOWLEDGERANGE TESTS
// =============================================================================

func TestSendBuffer_AcknowledgeRange_Basic(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)

	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, 0, sb.streams[1].inFlight.Size())
}

func TestSendBuffer_AcknowledgeRange_Duplicate(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.Equal(t, AckDup, status)
}

func TestSendBuffer_AcknowledgeRange_NonexistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 999, offset: 0, len: 4})

	assert.Equal(t, AckNotFound, status)
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Middle(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("012345678901"))
	sb.readyToSend(1, Data, nil, 43) // 4 bytes
	sb.readyToSend(1, Data, nil, 43) // 4 bytes
	sb.readyToSend(1, Data, nil, 43) // 4 bytes

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})

	assert.Equal(t, 2, sb.streams[1].inFlight.Size())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Last(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("012345678901"))
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})

	assert.Equal(t, 1, sb.streams[1].inFlight.Size())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_First(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("012345678901"))
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.Equal(t, 0, sb.streams[1].inFlight.Size())
}

// =============================================================================
// READYTORETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_NotExpired(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test1"))
	sb.readyToSend(1, Data, nil, 1000)

	data, _, _, err := sb.readyToRetransmit(1, nil, 1000, 100, Data, 50)

	assert.Nil(t, err)
	assert.Nil(t, data)
}

func TestSendBuffer_ReadyToRetransmit_Expired(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test1"))
	sb.readyToSend(1, Data, nil, 1000)

	data, offset, _, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToRetransmit_NonexistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	data, _, _, err := sb.readyToRetransmit(999, nil, 1000, 50, Data, 200)

	assert.Nil(t, err)
	assert.Nil(t, data)
}

func TestSendBuffer_ReadyToRetransmit_EmptyInFlight(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	data, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)

	assert.Nil(t, err)
	assert.Nil(t, data)
}

// =============================================================================
// READYTORETRANSMIT SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_Split_Left(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.readyToSend(1, Data, nil, 1000)

	// MTU 45 = 6 bytes data after overhead
	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToRetransmit_Split_Right(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.readyToRetransmit(1, nil, 45, 50, Data, 200)

	data, offset, _, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
}

// =============================================================================
// PING RETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_PingRemoved(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueuePing(1)
	sb.readyToSend(1, Data, nil, 1000)

	data, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)

	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, 0, sb.streams[1].inFlight.Size())
}

// =============================================================================
// CLOSE TESTS
// =============================================================================

func TestSendBuffer_Close_BeforeSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))

	sb.Close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_BeforeSend_DataHasCloseFlag(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_AfterSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	sb.Close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_AfterSend_EmptyClosePacket(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	sb.Close(1)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_EmptyStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.Close(1)

	assert.Equal(t, uint64(0), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_EmptyStream_ClosePacket(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.Close(1)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)

	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_Idempotent(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	firstOffset := *sb.streams[1].closeAtOffset

	sb.readyToSend(1, Data, nil, 1000)
	sb.Close(1)

	assert.Equal(t, firstOffset, *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_PartialSend_FirstPacketNoClose(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))

	data, _, isClose := sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, 5, len(data))
	assert.False(t, isClose)
}

func TestSendBuffer_Close_PartialSend_SecondPacketHasClose(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.readyToSend(1, Data, nil, 44)
	sb.Close(1)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, []byte("56789"), data)
	assert.Equal(t, uint64(5), offset)
	assert.True(t, isClose)
}

// =============================================================================
// CLOSE RETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_Close_Retransmit_KeepsCloseFlag(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)

	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_LeftNoClose(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)

	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_RightHasClose(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)
	sb.readyToRetransmit(1, nil, 45, 50, Data, 200)

	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
	assert.True(t, isClose)
}

// =============================================================================
// CHECKSTREAMFULLYACKED TESTS
// =============================================================================

func TestSendBuffer_CheckStreamFullyAcked_NoStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	assert.False(t, sb.CheckStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_NotClosed(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))

	assert.False(t, sb.CheckStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_ClosedButNotSent(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	assert.False(t, sb.CheckStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_SentButNotAcked(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)

	assert.False(t, sb.CheckStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_FullyAcked(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.True(t, sb.CheckStreamFullyAcked(1))
}

// =============================================================================
// GETOFFSETS TESTS
// =============================================================================

func TestSendBuffer_GetOffsetClosedAt_NoStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	assert.Nil(t, sb.GetOffsetClosedAt(1))
}

func TestSendBuffer_GetOffsetClosedAt_NotClosed(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))

	assert.Nil(t, sb.GetOffsetClosedAt(1))
}

func TestSendBuffer_GetOffsetClosedAt_Closed(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	result := sb.GetOffsetClosedAt(1)

	assert.NotNil(t, result)
	assert.Equal(t, uint64(4), *result)
}

func TestSendBuffer_GetOffsetAcked_NoStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_NoAcks(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("01234567"))
	sb.readyToSend(1, Data, nil, 44)
	sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_PartialAck(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("01234567"))
	sb.readyToSend(1, Data, nil, 44)
	sb.readyToSend(1, Data, nil, 44)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 5})

	assert.Equal(t, uint64(5), sb.GetOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_FullAck(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("01234567"))
	sb.readyToSend(1, Data, nil, 44)
	sb.readyToSend(1, Data, nil, 44)
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 5})
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 3})

	assert.Equal(t, uint64(8), sb.GetOffsetAcked(1))
}

// =============================================================================
// MULTIPLE STREAMS TESTS
// =============================================================================

func TestSendBuffer_MultipleStreams_QueueData(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))

	assert.Equal(t, []byte("stream1"), sb.streams[1].queuedData)
	assert.Equal(t, []byte("stream2"), sb.streams[2].queuedData)
	assert.Equal(t, []byte("stream3"), sb.streams[3].queuedData)
}

func TestSendBuffer_MultipleStreams_ReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))

	data1, _, _ := sb.readyToSend(1, Data, nil, 1000)
	data2, _, _ := sb.readyToSend(2, Data, nil, 1000)
	data3, _, _ := sb.readyToSend(3, Data, nil, 1000)

	assert.Equal(t, []byte("stream1"), data1)
	assert.Equal(t, []byte("stream2"), data2)
	assert.Equal(t, []byte("stream3"), data3)
}

func TestSendBuffer_MultipleStreams_AckIsolation(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.readyToSend(2, Data, nil, 1000)
	sb.readyToSend(3, Data, nil, 1000)

	sb.AcknowledgeRange(&Ack{streamID: 2, offset: 0, len: 7})

	assert.Equal(t, 1, sb.streams[1].inFlight.Size())
	assert.Equal(t, 0, sb.streams[2].inFlight.Size())
	assert.Equal(t, 1, sb.streams[3].inFlight.Size())
}

// =============================================================================
// UPDATEPACKETSIZE TESTS
// =============================================================================

func TestSendBuffer_UpdatePacketSize(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)

	sb.UpdatePacketSize(1, 0, 4, 50, 12345)

	_, info, ok := sb.streams[1].inFlight.First()
	assert.True(t, ok)
	assert.Equal(t, uint16(50), info.packetSize)
	assert.Equal(t, uint64(12345), info.sentTimeNano)
}

func TestSendBuffer_UpdatePacketSize_NonexistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Should not panic
	sb.UpdatePacketSize(999, 0, 4, 50, 12345)
}

func TestSendBuffer_UpdatePacketSize_NonexistentPacket(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)

	// Wrong offset - should not panic
	sb.UpdatePacketSize(1, 100, 4, 50, 12345)
}

func TestSendBuffer_AcknowledgeRange_ReturnsPacketInfo(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)
	sb.UpdatePacketSize(1, 0, 4, 50, 12345)

	status, sentTime, packetSize := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(12345), sentTime)
	assert.Equal(t, uint16(50), packetSize)
}

// =============================================================================
// REMOVESTREAM TESTS
// =============================================================================

func TestSendBuffer_RemoveStream(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))

	sb.RemoveStream(1)

	assert.Nil(t, sb.streams[1])
}

func TestSendBuffer_RemoveStream_NonexistentIsOk(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Should not panic
	sb.RemoveStream(999)
}

// =============================================================================
// PACKETKEY TESTS
// =============================================================================

func TestPacketKey_CreateAndOffset(t *testing.T) {
	key := createPacketKey(0x123456789ABC, 0x1234)

	assert.Equal(t, uint64(0x123456789ABC), key.offset())
}

func TestPacketKey_ZeroValues(t *testing.T) {
	key := createPacketKey(0, 0)

	assert.Equal(t, uint64(0), key.offset())
}

func TestPacketKey_MaxValues(t *testing.T) {
	key := createPacketKey(0xFFFFFFFFFFFF, 0xFFFF)

	assert.Equal(t, uint64(0xFFFFFFFFFFFF), key.offset())
}