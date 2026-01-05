package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// CONSTRUCTOR TESTS
// =============================================================================

func TestSendBuffer_New(t *testing.T) {
	sb := newSendBuffer(1000)

	assert.NotNil(t, sb)
	assert.NotNil(t, sb.streams)
	assert.Equal(t, 1000, sb.capacity)
	assert.Equal(t, 0, sb.size)
}

func TestSendBuffer_New_ZeroCapacity(t *testing.T) {
	sb := newSendBuffer(0)

	assert.NotNil(t, sb)
	assert.Equal(t, 0, sb.capacity)
}

// =============================================================================
// QUEUEDATA TESTS
// =============================================================================

func TestSendBuffer_QueueData_Basic(t *testing.T) {
	sb := newSendBuffer(1000)

	n, status := sb.queueData(1, []byte("test"))

	assert.Equal(t, insertStatusOk, status)
	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("test"), sb.streams[1].queuedData)
}

func TestSendBuffer_QueueData_CapacityLimit_Partial(t *testing.T) {
	sb := newSendBuffer(3)

	n, status := sb.queueData(1, []byte("test"))

	assert.Equal(t, insertStatusSndFull, status)
	assert.Equal(t, 3, n)
}

func TestSendBuffer_QueueData_CapacityLimit_Full(t *testing.T) {
	sb := newSendBuffer(4)
	sb.queueData(1, []byte("test"))

	n, status := sb.queueData(1, []byte("more"))

	assert.Equal(t, insertStatusSndFull, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_EmptyData(t *testing.T) {
	sb := newSendBuffer(1000)

	n, status := sb.queueData(1, []byte{})

	assert.Equal(t, insertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_NilData(t *testing.T) {
	sb := newSendBuffer(1000)

	n, status := sb.queueData(1, nil)

	assert.Equal(t, insertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSendBuffer_QueueData_CreatesStream(t *testing.T) {
	sb := newSendBuffer(1000)

	sb.queueData(1, []byte("test"))

	assert.NotNil(t, sb.streams[1])
}

// =============================================================================
// QUEUEPING TESTS
// =============================================================================

func TestSendBuffer_QueuePing(t *testing.T) {
	sb := newSendBuffer(1000)

	sb.queuePing(1)

	assert.True(t, sb.streams[1].pingRequested)
}

func TestSendBuffer_QueuePing_CreatesStream(t *testing.T) {
	sb := newSendBuffer(1000)

	sb.queuePing(1)

	assert.NotNil(t, sb.streams[1])
}

// =============================================================================
// READYTOSEND TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_Basic(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, []byte("hello"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToSend_UpdatesBytesSentOffset(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, uint64(5), sb.streams[1].bytesSentOffset)
}

func TestSendBuffer_ReadyToSend_TracksInFlight(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	_, info, ok := sb.streams[1].inFlight.first()

	assert.True(t, ok)
	assert.Equal(t, []byte("hello"), info.data)
}

func TestSendBuffer_ReadyToSend_NoData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, _, _ := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToSend_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	d, _, _ := sb.readyToSend(999, data, nil, 1000, false, false)

	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToSend_Ping(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)

	d, _, _ := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, []byte{}, d)
	assert.Equal(t, 1, sb.streams[1].inFlight.size())
}

func TestSendBuffer_ReadyToSend_PingPriority(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("data"))
	sb.queuePing(1)

	// Ping should be sent first
	d1, _, _ := sb.readyToSend(1, data, nil, 1000, false, false)
	assert.Equal(t, []byte{}, d1)

	// Then data
	d1, _, _ = sb.readyToSend(1, data, nil, 1000, false, false)
	assert.Equal(t, []byte("data"), d1)
}

// =============================================================================
// READYTOSEND MTU SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_MTUSplit_First(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))

	// MTU of 44 allows 5 bytes data (44 - 39 overhead)
	d, offset, _ := sb.readyToSend(1, data, nil, 44, false, false)

	assert.Equal(t, 5, len(d))
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToSend_MTUSplit_Second(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 44, false, false)

	d, offset, _ := sb.readyToSend(1, data, nil, 44, false, false)

	assert.Equal(t, 5, len(d))
	assert.Equal(t, uint64(5), offset)
}

// =============================================================================
// ACKNOWLEDGERANGE TESTS
// =============================================================================

func TestSendBuffer_AcknowledgeRange_Basic(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	status, _, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Equal(t, ackStatusOk, status)
	assert.Equal(t, 0, sb.streams[1].inFlight.size())
}

func TestSendBuffer_AcknowledgeRange_Duplicate(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	status, _, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Equal(t, ackDup, status)
}

func TestSendBuffer_AcknowledgeRange_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	status, _, _ := sb.acknowledgeRange(&ack{streamId: 999, offset: 0, len: 4})

	assert.Equal(t, ackNotFound, status)
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Middle(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, 43, false, false) // 4 bytes
	sb.readyToSend(1, data, nil, 43, false, false) // 4 bytes
	sb.readyToSend(1, data, nil, 43, false, false) // 4 bytes

	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})

	assert.Equal(t, 2, sb.streams[1].inFlight.size())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Last(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})

	sb.acknowledgeRange(&ack{streamId: 1, offset: 8, len: 4})

	assert.Equal(t, 1, sb.streams[1].inFlight.size())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_First(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.readyToSend(1, data, nil, 43, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})
	sb.acknowledgeRange(&ack{streamId: 1, offset: 8, len: 4})

	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Equal(t, 0, sb.streams[1].inFlight.size())
}

// =============================================================================
// READYTORETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_NotExpired(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, _, _, _, _, err := sb.readyToRetransmit(1, nil, 1000, 100, data, 50)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToRetransmit_Expired(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, offset, _, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), d)
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToRetransmit_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	d, _, _, _, _, err := sb.readyToRetransmit(999, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToRetransmit_EmptyInFlight(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	d, _, _, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

// =============================================================================
// READYTORETRANSMIT SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_Split_Left(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	// MTU 45 = 6 bytes data after overhead
	d, offset, isClose, _, _, err := sb.readyToRetransmit(1, nil, 45, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(d))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToRetransmit_Split_Right(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.readyToRetransmit(1, nil, 45, 50, data, 200)

	d, offset, _, _, _, err := sb.readyToRetransmit(1, nil, 45, 50, data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(d))
	assert.Equal(t, uint64(6), offset)
}

// =============================================================================
// PING RETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_PingRemoved(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, _, _, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
	assert.Equal(t, 0, sb.streams[1].inFlight.size())
}

// =============================================================================
// CLOSE TESTS
// =============================================================================

func TestSendBuffer_Close_BeforeSend(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))

	sb.close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_BeforeSend_DataHasCloseFlag(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_AfterSend(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	sb.close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_AfterSend_EmptyClosePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, []byte{}, d)
	assert.Equal(t, uint64(4), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_EmptyStream(t *testing.T) {
	sb := newSendBuffer(1000)

	sb.close(1)

	assert.Equal(t, uint64(0), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_EmptyStream_ClosePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, false, false)

	assert.Equal(t, []byte{}, d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_Idempotent(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	firstOffset := *sb.streams[1].closeAtOffset

	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.close(1)

	assert.Equal(t, firstOffset, *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_PartialSend_FirstPacketNoClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))

	d, _, isClose := sb.readyToSend(1, data, nil, 44, false, false)

	assert.Equal(t, 5, len(d))
	assert.False(t, isClose)
}

func TestSendBuffer_Close_PartialSend_SecondPacketHasClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 44, false, false)

	assert.Equal(t, []byte("56789"), d)
	assert.Equal(t, uint64(5), offset)
	assert.True(t, isClose)
}

// =============================================================================
// CLOSE RETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_Close_Retransmit_KeepsCloseFlag(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, offset, isClose, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_LeftNoClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	d, offset, isClose, _, _, err := sb.readyToRetransmit(1, nil, 45, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(d))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_RightHasClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.readyToRetransmit(1, nil, 45, 50, data, 200)

	d, offset, isClose, _, _, err := sb.readyToRetransmit(1, nil, 45, 50, data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(d))
	assert.Equal(t, uint64(6), offset)
	assert.True(t, isClose)
}

// =============================================================================
// KEY UPDATE TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_KeyUpdate_WithData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true, false)

	assert.Equal(t, []byte("hello"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)

	// Verify key update flag is tracked
	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.True(t, info.isKeyUpdate)
	assert.False(t, info.isKeyUpdateAck)
}

func TestSendBuffer_ReadyToSend_KeyUpdateAck_WithData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, false, true)

	assert.Equal(t, []byte("hello"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)

	// Verify key update ack flag is tracked
	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.False(t, info.isKeyUpdate)
	assert.True(t, info.isKeyUpdateAck)
}

func TestSendBuffer_ReadyToSend_KeyUpdateBoth_WithData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	d, _, _ := sb.readyToSend(1, data, nil, 1000, true, true)

	assert.Equal(t, []byte("hello"), d)

	// Verify both flags are tracked
	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.True(t, info.isKeyUpdate)
	assert.True(t, info.isKeyUpdateAck)
}

func TestSendBuffer_ReadyToSend_KeyUpdate_NoData(t *testing.T) {
	sb := newSendBuffer(1000)
	// Create empty stream
	sb.getOrCreateStream(1)

	// readyToSend returns nil when no data - caller uses ensureKeyFlagsTracked
	d, _, _ := sb.readyToSend(1, data, nil, 1000, true, false)
	assert.Nil(t, d)

	// ensureKeyFlagsTracked does the tracking
	offset := sb.ensureKeyFlagsTracked(1, true, false)
	assert.Equal(t, uint64(0), offset)

	// Verify tracked in-flight
	assert.Equal(t, 1, sb.streams[1].inFlight.size())
	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.True(t, info.isKeyUpdate)
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_ReadyToSend_KeyUpdateAck_NoData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.getOrCreateStream(1)

	// readyToSend returns nil when no data - caller uses ensureKeyFlagsTracked
	d, _, _ := sb.readyToSend(1, data, nil, 1000, false, true)
	assert.Nil(t, d)

	// ensureKeyFlagsTracked does the tracking
	offset := sb.ensureKeyFlagsTracked(1, false, true)
	assert.Equal(t, uint64(0), offset)

	// Verify tracked in-flight
	assert.Equal(t, 1, sb.streams[1].inFlight.size())
	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.True(t, info.isKeyUpdateAck)
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_ReadyToSend_PingNotSentWithKeyUpdate(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)

	// With key update, ping is skipped and key update packet sent
	d, _, _ := sb.readyToSend(1, data, nil, 1000, true, false)

	assert.Equal(t, []byte{}, d)

	// Should have one packet tracked with key update
	assert.Equal(t, 1, sb.streams[1].inFlight.size())
	_, info, _ := sb.streams[1].inFlight.first()
	assert.True(t, info.isKeyUpdate)
}

// =============================================================================
// KEY UPDATE RETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_KeyUpdate_Preserved(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true, false)

	d, offset, isClose, isKeyUpdate, isKeyUpdateAck, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
	assert.True(t, isKeyUpdate)
	assert.False(t, isKeyUpdateAck)
}

func TestSendBuffer_ReadyToRetransmit_KeyUpdateAck_Preserved(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, true)

	d, offset, isClose, isKeyUpdate, isKeyUpdateAck, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
	assert.False(t, isKeyUpdate)
	assert.True(t, isKeyUpdateAck)
}

func TestSendBuffer_ReadyToRetransmit_KeyUpdate_Split_LeftPreserved(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 1000, true, false)

	// Split at MTU 77 (overhead ~71 + 6 bytes data)
	d, _, _, isKeyUpdate, isKeyUpdateAck, err := sb.readyToRetransmit(1, nil, 77, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(d))
	assert.True(t, isKeyUpdate)
	assert.False(t, isKeyUpdateAck)
}

func TestSendBuffer_ReadyToRetransmit_KeyUpdateNoData_Retransmits(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.getOrCreateStream(1)
	// Use ensureKeyFlagsTracked to set up in-flight KEY_UPDATE packet (as flushStream does)
	sb.ensureKeyFlagsTracked(1, true, false)

	d, offset, isClose, isKeyUpdate, isKeyUpdateAck, err := sb.readyToRetransmit(1, nil, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte{}, d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
	assert.True(t, isKeyUpdate)
	assert.False(t, isKeyUpdateAck)
}

// =============================================================================
// ENSURE KEY FLAGS TRACKED TESTS
// =============================================================================

func TestSendBuffer_EnsureKeyFlagsTracked_KeyUpdate(t *testing.T) {
	sb := newSendBuffer(1000)

	offset := sb.ensureKeyFlagsTracked(1, true, false)

	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 1, sb.streams[1].inFlight.size())

	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.True(t, info.isKeyUpdate)
	assert.False(t, info.isKeyUpdateAck)
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_EnsureKeyFlagsTracked_KeyUpdateAck(t *testing.T) {
	sb := newSendBuffer(1000)

	offset := sb.ensureKeyFlagsTracked(1, false, true)

	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 1, sb.streams[1].inFlight.size())

	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.False(t, info.isKeyUpdate)
	assert.True(t, info.isKeyUpdateAck)
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_EnsureKeyFlagsTracked_NoFlags(t *testing.T) {
	sb := newSendBuffer(1000)

	offset := sb.ensureKeyFlagsTracked(1, false, false)

	assert.Equal(t, uint64(0), offset)
	// No packet should be tracked
	assert.Equal(t, 0, sb.streams[1].inFlight.size())
}

func TestSendBuffer_EnsureKeyFlagsTracked_AlreadyTracked(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.ensureKeyFlagsTracked(1, true, false)

	// Call again - should not add duplicate
	offset := sb.ensureKeyFlagsTracked(1, true, false)

	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, 1, sb.streams[1].inFlight.size())
}

func TestSendBuffer_EnsureKeyFlagsTracked_WithExistingData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	offset := sb.ensureKeyFlagsTracked(1, true, false)

	// Should use bytesSentOffset (5)
	assert.Equal(t, uint64(5), offset)
	// Now 2 packets in flight
	assert.Equal(t, 2, sb.streams[1].inFlight.size())
}

// =============================================================================
// NEEDS RETX TESTS
// =============================================================================

func TestSendBuffer_NeedsReTx_DataPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	_, info, _ := sb.streams[1].inFlight.first()
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_PingPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	_, info, _ := sb.streams[1].inFlight.first()
	assert.False(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_ClosePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	_, info, _ := sb.streams[1].inFlight.first()
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_KeyUpdatePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.getOrCreateStream(1)
	sb.ensureKeyFlagsTracked(1, true, false)

	_, info, _ := sb.streams[1].inFlight.first()
	assert.True(t, info.needsReTx)
}

// =============================================================================
// CHECKSTREAMFULLYACKED TESTS
// =============================================================================

func TestSendBuffer_CheckStreamFullyAcked_NoStream(t *testing.T) {
	sb := newSendBuffer(1000)

	assert.False(t, sb.checkStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_NotClosed(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))

	assert.False(t, sb.checkStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_ClosedButNotSent(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)

	assert.False(t, sb.checkStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_SentButNotAcked(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)

	assert.False(t, sb.checkStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_FullyAcked(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.True(t, sb.checkStreamFullyAcked(1))
}

// =============================================================================
// GETOFFSETS TESTS
// =============================================================================

func TestSendBuffer_GetOffsetClosedAt_NoStream(t *testing.T) {
	sb := newSendBuffer(1000)

	assert.Nil(t, sb.getOffsetClosedAt(1))
}

func TestSendBuffer_GetOffsetClosedAt_NotClosed(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))

	assert.Nil(t, sb.getOffsetClosedAt(1))
}

func TestSendBuffer_GetOffsetClosedAt_Closed(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)

	result := sb.getOffsetClosedAt(1)

	assert.NotNil(t, result)
	assert.Equal(t, uint64(4), *result)
}

func TestSendBuffer_GetOffsetAcked_NoStream(t *testing.T) {
	sb := newSendBuffer(1000)

	assert.Equal(t, uint64(0), sb.getOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_NoAcks(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("01234567"))
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.readyToSend(1, data, nil, 44, false, false)

	assert.Equal(t, uint64(0), sb.getOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_PartialAck(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("01234567"))
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 5})

	assert.Equal(t, uint64(5), sb.getOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_FullAck(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("01234567"))
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.readyToSend(1, data, nil, 44, false, false)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 5})
	sb.acknowledgeRange(&ack{streamId: 1, offset: 5, len: 3})

	assert.Equal(t, uint64(8), sb.getOffsetAcked(1))
}

// =============================================================================
// MULTIPLE STREAMS TESTS
// =============================================================================

func TestSendBuffer_MultipleStreams_QueueData(t *testing.T) {
	sb := newSendBuffer(1000)

	sb.queueData(1, []byte("stream1"))
	sb.queueData(2, []byte("stream2"))
	sb.queueData(3, []byte("stream3"))

	assert.Equal(t, []byte("stream1"), sb.streams[1].queuedData)
	assert.Equal(t, []byte("stream2"), sb.streams[2].queuedData)
	assert.Equal(t, []byte("stream3"), sb.streams[3].queuedData)
}

func TestSendBuffer_MultipleStreams_ReadyToSend(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("stream1"))
	sb.queueData(2, []byte("stream2"))
	sb.queueData(3, []byte("stream3"))

	d1, _, _ := sb.readyToSend(1, data, nil, 1000, false, false)
	d2, _, _ := sb.readyToSend(2, data, nil, 1000, false, false)
	d3, _, _ := sb.readyToSend(3, data, nil, 1000, false, false)

	assert.Equal(t, []byte("stream1"), d1)
	assert.Equal(t, []byte("stream2"), d2)
	assert.Equal(t, []byte("stream3"), d3)
}

func TestSendBuffer_MultipleStreams_AckIsolation(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("stream1"))
	sb.queueData(2, []byte("stream2"))
	sb.queueData(3, []byte("stream3"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.readyToSend(2, data, nil, 1000, false, false)
	sb.readyToSend(3, data, nil, 1000, false, false)

	sb.acknowledgeRange(&ack{streamId: 2, offset: 0, len: 7})

	assert.Equal(t, 1, sb.streams[1].inFlight.size())
	assert.Equal(t, 0, sb.streams[2].inFlight.size())
	assert.Equal(t, 1, sb.streams[3].inFlight.size())
}

// =============================================================================
// UPDATEPACKETSIZE TESTS
// =============================================================================

func TestSendBuffer_UpdatePacketSize(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	sb.updatePacketSize(1, 0, 4, 50, 12345)

	_, info, ok := sb.streams[1].inFlight.first()
	assert.True(t, ok)
	assert.Equal(t, uint16(50), info.packetSize)
	assert.Equal(t, uint64(12345), info.sentTimeNano)
}

func TestSendBuffer_UpdatePacketSize_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	// Should not panic
	sb.updatePacketSize(999, 0, 4, 50, 12345)
}

func TestSendBuffer_UpdatePacketSize_NonexistentPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)

	// Wrong offset - should not panic
	sb.updatePacketSize(1, 100, 4, 50, 12345)
}

func TestSendBuffer_AcknowledgeRange_ReturnsPacketInfo(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false, false)
	sb.updatePacketSize(1, 0, 4, 50, 12345)

	status, sentTime, packetSize := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Equal(t, ackStatusOk, status)
	assert.Equal(t, uint64(12345), sentTime)
	assert.Equal(t, uint16(50), packetSize)
}

// =============================================================================
// REMOVESTREAM TESTS
// =============================================================================

func TestSendBuffer_RemoveStream(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))

	sb.removeStream(1)

	assert.Nil(t, sb.streams[1])
}

func TestSendBuffer_RemoveStream_NonexistentIsOk(t *testing.T) {
	sb := newSendBuffer(1000)

	// Should not panic
	sb.removeStream(999)
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