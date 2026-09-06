package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// CONSTRUCTOR TESTS
// =============================================================================

// inFlightSize returns the number of unacked packets across all generations.
// Test-only: production code checks inFlightAny() instead.
func (t *transmitBuffer) inFlightSize() int {
	size := 0
	for _, m := range t.inFlight {
		size += m.size()
	}
	return size
}

// dataOverhead is the crypto+proto overhead of a Data packet with a stream
// header and no ACK. The MTU-split tests size against it rather than a literal,
// so they follow header-format changes automatically.
var dataOverhead = calcCryptoOverheadWithData(data, nil, 0)

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

	n := sb.queueData(1, []byte("test"))

	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("test"), sb.streams[1].queuedData)
}

func TestSendBuffer_QueueData_CapacityLimit_Partial(t *testing.T) {
	sb := newSendBuffer(3)

	n := sb.queueData(1, []byte("test"))

	assert.Equal(t, 3, n)
	assert.Equal(t, []byte("tes"), sb.streams[1].queuedData)
}

func TestSendBuffer_QueueData_CapacityLimit_Full(t *testing.T) {
	sb := newSendBuffer(4)
	sb.queueData(1, []byte("test"))

	n := sb.queueData(1, []byte("more"))

	assert.Equal(t, 0, n)
	assert.Equal(t, []byte("test"), sb.streams[1].queuedData)
}

func TestSendBuffer_QueueData_EmptyData(t *testing.T) {
	sb := newSendBuffer(1000)

	n := sb.queueData(1, []byte{})

	assert.Equal(t, 0, n)
	assert.Nil(t, sb.streams[1])
}

func TestSendBuffer_QueueData_NilData(t *testing.T) {
	sb := newSendBuffer(1000)

	n := sb.queueData(1, nil)

	assert.Equal(t, 0, n)
	assert.Nil(t, sb.streams[1])
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

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true)

	assert.Equal(t, []byte("hello"), d)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToSend_UpdatesBytesSentOffset(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))

	sb.readyToSend(1, data, nil, 1000, true)

	assert.Equal(t, uint64(5), sb.streams[1].bytesSentOffset)
}

func TestSendBuffer_ReadyToSend_TracksInFlight(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))
	sb.readyToSend(1, data, nil, 1000, true)

	_, info, ok := sb.streams[1].inFlight[0].first()

	assert.True(t, ok)
	assert.Equal(t, []byte("hello"), info.data)
}

func TestSendBuffer_ReadyToSend_NoData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("hello"))
	sb.readyToSend(1, data, nil, 1000, true)

	d, _, _ := sb.readyToSend(1, data, nil, 1000, true)

	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToSend_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	d, _, _ := sb.readyToSend(999, data, nil, 1000, true)

	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToSend_Ping(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)

	d, _, _ := sb.readyToSend(1, data, nil, 1000, true)

	assert.Equal(t, []byte{}, d)
	assert.Equal(t, 1, sb.streams[1].inFlightSize())
}

func TestSendBuffer_ReadyToSend_PingPriority(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("data"))
	sb.queuePing(1)

	// Ping should be sent first
	d1, _, _ := sb.readyToSend(1, data, nil, 1000, true)
	assert.Equal(t, []byte{}, d1)

	// Then data
	d1, _, _ = sb.readyToSend(1, data, nil, 1000, true)
	assert.Equal(t, []byte("data"), d1)
}

// =============================================================================
// READYTOSEND MTU SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToSend_MTUSplit_First(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))

	// MTU allowing exactly 5 bytes of data
	d, offset, _ := sb.readyToSend(1, data, nil, dataOverhead+5, true)

	assert.Equal(t, 5, len(d))
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToSend_MTUSplit_Second(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, dataOverhead+5, true)

	d, offset, _ := sb.readyToSend(1, data, nil, dataOverhead+5, true)

	assert.Equal(t, 5, len(d))
	assert.Equal(t, uint64(5), offset)
}

// =============================================================================
// ACKNOWLEDGERANGE TESTS
// =============================================================================

func TestSendBuffer_AcknowledgeRange_Basic(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)

	pkt, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.NotNil(t, pkt)
	assert.Equal(t, 0, sb.streams[1].inFlightSize())
}

func TestSendBuffer_AcknowledgeRange_Duplicate(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	pkt, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Nil(t, pkt, "a duplicate matches nothing in flight")
}

func TestSendBuffer_AcknowledgeRange_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	pkt, _ := sb.acknowledgeRange(&ack{streamId: 999, offset: 0, len: 4})

	assert.Nil(t, pkt, "an unknown stream matches nothing in flight")
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Middle(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, dataOverhead+4, true) // 4 bytes
	sb.readyToSend(1, data, nil, dataOverhead+4, true) // 4 bytes
	sb.readyToSend(1, data, nil, dataOverhead+4, true) // 4 bytes

	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})

	assert.Equal(t, 2, sb.streams[1].inFlightSize())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_Last(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})

	sb.acknowledgeRange(&ack{streamId: 1, offset: 8, len: 4})

	assert.Equal(t, 1, sb.streams[1].inFlightSize())
}

func TestSendBuffer_AcknowledgeRange_OutOfOrder_First(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("012345678901"))
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.readyToSend(1, data, nil, dataOverhead+4, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 4, len: 4})
	sb.acknowledgeRange(&ack{streamId: 1, offset: 8, len: 4})

	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.Equal(t, 0, sb.streams[1].inFlightSize())
}

// =============================================================================
// READYTORETRANSMIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_NotExpired(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, true)

	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 100, data, 50)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToRetransmit_Expired(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, true)

	d, offset, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), d)
	assert.Equal(t, uint64(0), offset)
}

func TestSendBuffer_ReadyToRetransmit_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	d, _, _, err := sb.readyToRetransmit(999, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

func TestSendBuffer_ReadyToRetransmit_EmptyInFlight(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
}

// =============================================================================
// READYTORETRANSMIT SPLIT TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_Split_Left(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 1000, true)

	// MTU allowing exactly 6 bytes of data
	d, offset, isClose, err := sb.readyToRetransmit(1, nil, dataOverhead+6, dataOverhead+6, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(d))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_ReadyToRetransmit_Split_Right(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.readyToRetransmit(1, nil, dataOverhead+6, dataOverhead+6, 50, data, 200)

	d, offset, _, err := sb.readyToRetransmit(1, nil, dataOverhead+4, dataOverhead+4, 50, data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(d))
	assert.Equal(t, uint64(6), offset)
}

// =============================================================================
// BEST-EFFORT DRAIN TESTS
// =============================================================================

func TestSendBuffer_ReadyToRetransmit_PingNotRetransmitted(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, true)

	// Expired ping: not retransmitted, and left for drainExpiredBestEffort
	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
	assert.Equal(t, 1, sb.streams[1].inFlightSize())
}

func TestSendBuffer_DrainBestEffort_ExpiredPing(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, true)

	droppedBytes := sb.drainExpiredBestEffort(1, 50, 200)

	assert.Equal(t, 0, droppedBytes, "ping carries no data")
	assert.Equal(t, 0, sb.streams[1].inFlightSize())
}

func TestSendBuffer_DrainBestEffort_ExpiredUnreliableData(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, false) // reliable=false

	droppedBytes := sb.drainExpiredBestEffort(1, 50, 200)

	assert.Equal(t, 5, droppedBytes)
	assert.Equal(t, 0, sb.streams[1].inFlightSize())
	assert.Equal(t, 0, sb.size, "sender capacity must be released")
}

func TestSendBuffer_DrainBestEffort_NotExpired(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, false)

	droppedBytes := sb.drainExpiredBestEffort(1, 100, 50)

	assert.Equal(t, 0, droppedBytes)
	assert.Equal(t, 1, sb.streams[1].inFlightSize())
}

func TestSendBuffer_DrainBestEffort_ReliableUntouched(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, true) // reliable

	droppedBytes := sb.drainExpiredBestEffort(1, 50, 200)

	assert.Equal(t, 0, droppedBytes)
	assert.Equal(t, 1, sb.streams[1].inFlightSize())
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

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true)

	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_AfterSend(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	sb.close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_AfterSend_EmptyClosePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true)

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

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true)

	assert.Equal(t, []byte{}, d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_Idempotent(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	firstOffset := *sb.streams[1].closeAtOffset

	sb.readyToSend(1, data, nil, 1000, true)
	sb.close(1)

	assert.Equal(t, firstOffset, *sb.streams[1].closeAtOffset)
}

func TestSendBuffer_Close_PartialSend_FirstPacketNoClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))

	d, _, isClose := sb.readyToSend(1, data, nil, dataOverhead+5, true)

	assert.Equal(t, 5, len(d))
	assert.False(t, isClose)
}

func TestSendBuffer_Close_PartialSend_SecondPacketHasClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, dataOverhead+5, true)

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
	sb.readyToSend(1, data, nil, 1000, true)

	d, offset, isClose, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_LeftNoClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, true)

	d, offset, isClose, err := sb.readyToRetransmit(1, nil, dataOverhead+6, dataOverhead+6, 50, data, 200)

	assert.Nil(t, err)
	assert.Equal(t, 6, len(d))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
}

func TestSendBuffer_Close_RetransmitSplit_RightHasClose(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0123456789"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, true)
	sb.readyToRetransmit(1, nil, dataOverhead+6, dataOverhead+6, 50, data, 200)

	d, offset, isClose, err := sb.readyToRetransmit(1, nil, dataOverhead+4, dataOverhead+4, 50, data, 300)

	assert.Nil(t, err)
	assert.Equal(t, 4, len(d))
	assert.Equal(t, uint64(6), offset)
	assert.True(t, isClose)
}

// =============================================================================
// NEEDS RETX TESTS
// =============================================================================

func TestSendBuffer_AcknowledgeRange_ReturnsSentCount(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200) // one retransmit

	ackedPkt, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.NotNil(t, ackedPkt)
	assert.Equal(t, uint(1), ackedPkt.sentCount, "ack after retransmit must be flagged as ambiguous")
}

func TestSendBuffer_ReadyToRetransmit_FinalRetryGetsWindow(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test1"))
	sb.readyToSend(1, data, nil, 1000, true)

	// Exhaust all retransmit attempts (sentCount reaches maxRetry)
	for i := 1; i <= int(maxRetry); i++ {
		d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, uint64(i*1000))
		assert.NoError(t, err)
		assert.NotNil(t, d, "retransmit %d", i)
	}

	// Immediately after the final retransmit: response window still open
	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, uint64(int(maxRetry)*1000+10))
	assert.NoError(t, err)
	assert.Nil(t, d, "final retransmit must get its response window before the error")

	// Window expired without an ACK: give up
	_, _, _, err = sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, uint64(int(maxRetry)*1000+10_000))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max retry")
}

func TestSendBuffer_ReadyToSend_PingSkippedWhenClosePending(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.close(1)

	d, offset, isClose := sb.readyToSend(1, data, nil, 1000, true)

	// The ping is dropped (its zero-length key would collide with the FIN's);
	// the FIN goes out instead
	assert.Equal(t, []byte{}, d)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
	assert.False(t, sb.streams[1].pingRequested)
	_, info, ok := sb.streams[1].inFlight[0].first()
	assert.True(t, ok)
	assert.True(t, info.isClose)
}

func TestSendBuffer_NeedsReTx_DataPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)

	_, info, _ := sb.streams[1].inFlight[0].first()
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_PingPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, true)

	_, info, _ := sb.streams[1].inFlight[0].first()
	assert.False(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_ClosePacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, true)

	_, info, _ := sb.streams[1].inFlight[0].first()
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_UnreliableDataPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false)

	_, info, _ := sb.streams[1].inFlight[0].first()
	assert.False(t, info.needsReTx)
}

func TestSendBuffer_NeedsReTx_UnreliableCloseStillRetransmits(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, false)

	_, info, _ := sb.streams[1].inFlight[0].first()
	assert.True(t, info.needsReTx)
}

func TestSendBuffer_Unreliable_PingNotRetransmitted(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queuePing(1)
	sb.readyToSend(1, data, nil, 1000, false)

	// Expired ping is never retransmitted; removal is drainExpiredBestEffort's job
	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
	sb.drainExpiredBestEffort(1, 50, 200)
	assert.Equal(t, 0, sb.streams[1].inFlightSize())
}

func TestSendBuffer_Unreliable_DataNotRetransmitted(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, false)

	// Expired unreliable data is never retransmitted; drain removes it
	d, _, _, err := sb.readyToRetransmit(1, nil, 1000, 1000, 50, data, 200)

	assert.Nil(t, err)
	assert.Nil(t, d)
	droppedBytes := sb.drainExpiredBestEffort(1, 50, 200)
	assert.Equal(t, 4, droppedBytes)
	assert.Equal(t, 0, sb.streams[1].inFlightSize())
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
	sb.readyToSend(1, data, nil, 1000, true)

	assert.False(t, sb.checkStreamFullyAcked(1))
}

func TestSendBuffer_CheckStreamFullyAcked_FullyAcked(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.close(1)
	sb.readyToSend(1, data, nil, 1000, true)
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
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
	sb.readyToSend(1, data, nil, dataOverhead+5, true)

	assert.Equal(t, uint64(0), sb.getOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_PartialAck(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("01234567"))
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
	sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 5})

	assert.Equal(t, uint64(5), sb.getOffsetAcked(1))
}

func TestSendBuffer_GetOffsetAcked_FullAck(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("01234567"))
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
	sb.readyToSend(1, data, nil, dataOverhead+5, true)
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

	d1, _, _ := sb.readyToSend(1, data, nil, 1000, true)
	d2, _, _ := sb.readyToSend(2, data, nil, 1000, true)
	d3, _, _ := sb.readyToSend(3, data, nil, 1000, true)

	assert.Equal(t, []byte("stream1"), d1)
	assert.Equal(t, []byte("stream2"), d2)
	assert.Equal(t, []byte("stream3"), d3)
}

func TestSendBuffer_MultipleStreams_AckIsolation(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("stream1"))
	sb.queueData(2, []byte("stream2"))
	sb.queueData(3, []byte("stream3"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.readyToSend(2, data, nil, 1000, true)
	sb.readyToSend(3, data, nil, 1000, true)

	sb.acknowledgeRange(&ack{streamId: 2, offset: 0, len: 7})

	assert.Equal(t, 1, sb.streams[1].inFlightSize())
	assert.Equal(t, 0, sb.streams[2].inFlightSize())
	assert.Equal(t, 1, sb.streams[3].inFlightSize())
}

// =============================================================================
// MARKSENT TESTS
// =============================================================================

func TestSendBuffer_MarkSent(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)

	sb.markSent(1, 0, 4, 44, 12345, 5000, 0, 0)

	_, info, ok := sb.streams[1].inFlight[0].first()
	assert.True(t, ok)
	assert.Equal(t, uint64(12345), info.sentTimeNano)
	assert.Equal(t, uint64(5000), info.deliveredAtSend)
}

func TestSendBuffer_MarkSent_NonexistentStream(t *testing.T) {
	sb := newSendBuffer(1000)

	// Should not panic
	sb.markSent(999, 0, 4, 44, 12345, 0, 0, 0)
}

func TestSendBuffer_MarkSent_NonexistentPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)

	// Wrong offset - should not panic
	sb.markSent(1, 100, 4, 44, 12345, 0, 0, 0)
}

func TestSendBuffer_AcknowledgeRange_ReturnsPacketInfo(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("test"))
	sb.readyToSend(1, data, nil, 1000, true)
	sb.markSent(1, 0, 4, 44, 12345, 5000, 0, 0)

	ackedPkt, _ := sb.acknowledgeRange(&ack{streamId: 1, offset: 0, len: 4})

	assert.NotNil(t, ackedPkt)
	assert.Equal(t, uint64(12345), ackedPkt.sentTimeNano)
	assert.Equal(t, uint64(5000), ackedPkt.deliveredAtSend)
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

// Ping and ACK probe share one in-flight key, so whichever gets there first
// owns it — otherwise the peer's ACK is misattributed to the other.
func TestSendBuffer_ZeroPayloadKey_SingleOwner(t *testing.T) {
	t.Run("probe blocks a later ping", func(t *testing.T) {
		sb := newSendBuffer(1000)
		sb.queueData(1, []byte("data"))
		assert.True(t, sb.trackProbe(1))

		sb.queuePing(1)
		d, _, _ := sb.readyToSend(1, data, nil, 1000, true)
		assert.Equal(t, []byte("data"), d, "ping must be dropped, not overwrite the probe")
	})

	t.Run("ping blocks a later probe", func(t *testing.T) {
		sb := newSendBuffer(1000)
		sb.queuePing(1)
		assert.False(t, sb.trackProbe(1), "probe must defer to a pending ping")
	})

	t.Run("close owns the key", func(t *testing.T) {
		sb := newSendBuffer(1000)
		sb.close(1)
		assert.False(t, sb.trackProbe(1))
		sb.queuePing(1)
		d, _, isClose := sb.readyToSend(1, data, nil, 1000, true)
		assert.True(t, isClose, "the FIN owns the key, not the ping")
		assert.Empty(t, d)
	})
}

// A packet close to giving up is retransmitted at the probe size. The
// retransmit is the probe: if it gets through where the working size did not,
// the path cannot carry the working size.
func TestSendBuffer_RetransmitProbesAtSmallerMtu(t *testing.T) {
	sb := newSendBuffer(10000)
	sb.queueData(1, make([]byte, 4000))

	big := dataOverhead + 400
	probe := dataOverhead + 40

	d, _, _ := sb.readyToSend(1, data, nil, big, true)
	assert.Equal(t, 400, len(d), "first send uses the working size")

	// sentCount is 0 on the first retransmit, so the working size is used
	// until it reaches maxRetry-mtuProbeLastAttempts.
	now := uint64(1000)
	for want := uint(0); want < maxRetry-mtuProbeLastAttempts; want++ {
		now += 1_000_000
		d, _, _, err := sb.readyToRetransmit(1, nil, big, probe, 1, data, now)
		assert.NoError(t, err)
		assert.Equal(t, 400, len(d), "retransmit at sentCount=%d still uses the working size", want)
	}

	// Now at the probe stage: the same data goes out shrunk.
	now += 1_000_000
	d, _, _, err := sb.readyToRetransmit(1, nil, big, probe, 1, data, now)
	assert.NoError(t, err)
	assert.Equal(t, 40, len(d), "the last attempts must probe at the smaller size")
}

// The give-up schedule: five retransmits spaced by doubling backoff, then a
// single round trip to hear back. The last wait is deliberately not backed
// off -- there is no further retransmit to space out, so 16x RTO there would
// add seconds to how long a broken path takes to surface.
func TestSendBuffer_GiveUpSchedule(t *testing.T) {
	const rto = uint64(200 * msNano)
	const step = rto / 8
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("x"))
	sb.readyToSend(1, data, nil, 1200, true)
	sb.markSent(1, 0, 1, 60, 0, 0, 0, 0)

	// Walk the clock forward, recording when each retransmit and the final
	// give-up happen.
	var events []uint64
	var gaveUp bool
	for nowNano := step; nowNano < 60*rto; nowNano += step {
		d, _, _, err := sb.readyToRetransmit(1, nil, 1200, 1200, rto, data, nowNano)
		if err != nil {
			assert.Contains(t, err.Error(), "max retry attempts exceeded")
			events = append(events, nowNano)
			gaveUp = true
			break
		}
		if d != nil {
			events = append(events, nowNano)
		}
	}
	assert.True(t, gaveUp, "the schedule must terminate")
	assert.Len(t, events, int(maxRetry)+1, "maxRetry retransmits, then the give-up")

	// Gaps between events, rounded to whole RTOs.
	var gaps []uint64
	prev := uint64(0)
	for _, e := range events {
		gaps = append(gaps, (e-prev)/rto)
		prev = e
	}
	assert.Equal(t, []uint64{1, 2, 4, 8, 10, 1}, gaps,
		"doubling, capped at maxRTO, then one round trip to hear back")

	assert.Less(t, float64(events[len(events)-1])/float64(secondNano), 5.5,
		"whole schedule well inside the 30s read deadline")
}

// InitSnd carries no stream data and goes out through the control path. It
// must not book a zero-length packet: that holds the stream's one zero-payload
// slot, so a ping queued around the handshake is dropped instead of sent.
func TestSendBuffer_InitSnd_DoesNotBookAPhantomPacket(t *testing.T) {
	sb := newSendBuffer(1000)
	sb.queueData(1, []byte("0-RTT data waits for the handshake"))

	d, _, _ := sb.readyToSend(1, initSnd, nil, conservativeMTU, true)
	assert.Nil(t, d, "InitSnd takes the control path, not the data path")
	assert.False(t, sb.hasInFlight(1), "and books nothing")

	// So a ping queued at the same moment still gets its slot.
	sb.queuePing(1)
	d, _, _ = sb.readyToSend(1, data, nil, conservativeMTU, true)
	assert.NotNil(t, d)
	assert.Empty(t, d, "the ping is a zero-payload packet")

	// The queued data is untouched and goes out once the handshake completes.
	assert.Equal(t, 34, len(sb.streams[1].queuedData))
}
