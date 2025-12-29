package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSndQueueData(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)
	assert.Equal(t, []byte("test"), sb.streams[1].queuedData)

	// Capacity limit - partial insert
	sb2 := NewSendBuffer(3)
	n, status = sb2.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, n)

	// Empty data rejected
	n, status = sb.QueueData(2, []byte{})
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)

	n, status = sb.QueueData(2, nil)
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSndReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("hello"))

	// Basic send
	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte("hello"), data)
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)
	assert.Equal(t, uint64(5), sb.streams[1].bytesSentOffset)

	// Verify in-flight tracking
	_, info, ok := sb.streams[1].inFlight.First()
	assert.True(t, ok)
	assert.Equal(t, []byte("hello"), info.data)

	// No data returns nil
	data, _, _ = sb.readyToSend(1, Data, nil, 1000)
	assert.Nil(t, data)

	// Non-existent stream returns nil
	data, _, _ = sb.readyToSend(999, Data, nil, 1000)
	assert.Nil(t, data)
}

func TestSndReadyToSendMTUSplit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))

	// MTU of 44 allows 5 bytes data (44 - 39 overhead)
	data, offset, _ := sb.readyToSend(1, Data, nil, 44)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(0), offset)

	data, offset, _ = sb.readyToSend(1, Data, nil, 44)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(5), offset)
}

func TestSndAcknowledge(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)

	status, _, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, 0, sb.streams[1].inFlight.Size())

	// Duplicate ack
	status, _, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckDup, status)

	// Non-existent stream
	status, _, _ = sb.AcknowledgeRange(&Ack{streamID: 999, offset: 0, len: 4})
	assert.Equal(t, AckNotFound, status)
}

func TestSndAcknowledgeOutOfOrder(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("012345678901"))

	// Send in 4-byte chunks
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	sb.readyToSend(1, Data, nil, 43)
	assert.Equal(t, 3, sb.streams[1].inFlight.Size())

	// Ack middle, last, first
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.Equal(t, 2, sb.streams[1].inFlight.Size())

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})
	assert.Equal(t, 1, sb.streams[1].inFlight.Size())

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, 0, sb.streams[1].inFlight.Size())
}

func TestSndRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test1"))
	sb.readyToSend(1, Data, nil, 1000)

	// Too early - RTO not expired
	data, _, _, err := sb.readyToRetransmit(1, nil, 1000, 100, Data, 50)
	assert.Nil(t, err)
	assert.Nil(t, data)

	// RTO expired
	data, offset, _, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
}

func TestSndRetransmitSplit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.readyToSend(1, Data, nil, 1000)

	// Retransmit with smaller MTU causes split
	// MTU 45 = 6 bytes data after overhead
	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)

	// Remaining 4 bytes in second packet
	data, offset, _, err = sb.readyToRetransmit(1, nil, 45, 50, Data, 300)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
}

func TestSndPing(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueuePing(1)

	data, _, _ := sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, 1, sb.streams[1].inFlight.Size())

	// Ping timeout removes without retransmit
	data, _, _, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, 0, sb.streams[1].inFlight.Size())
}

func TestSndClose(t *testing.T) {
	// Close before send - close flag on data packet
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseAfterSend(t *testing.T) {
	// Close after data sent - separate empty close packet
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

func TestSndCloseEmptyStream(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.Close(1)

	assert.Equal(t, uint64(0), *sb.streams[1].closeAtOffset)

	data, offset, isClose := sb.readyToSend(1, Data, nil, 1000)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseIdempotent(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	firstOffset := *sb.streams[1].closeAtOffset

	sb.readyToSend(1, Data, nil, 1000)
	sb.Close(1) // Second close should not change offset

	assert.Equal(t, firstOffset, *sb.streams[1].closeAtOffset)
}

func TestSndClosePartialSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))

	// Send first 5 bytes
	data, _, isClose := sb.readyToSend(1, Data, nil, 44)
	assert.Equal(t, 5, len(data))
	assert.False(t, isClose)

	sb.Close(1)
	assert.Equal(t, uint64(10), *sb.streams[1].closeAtOffset)

	// Second packet has close flag
	data, offset, isClose := sb.readyToSend(1, Data, nil, 44)
	assert.Equal(t, []byte("56789"), data)
	assert.Equal(t, uint64(5), offset)
	assert.True(t, isClose)
}

func TestSndCloseRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)

	// Retransmit keeps close flag
	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseRetransmitSplitCorrectFlag(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	sb.Close(1)
	sb.readyToSend(1, Data, nil, 1000)

	// Split: left packet should NOT have close flag
	data, offset, isClose, err := sb.readyToRetransmit(1, nil, 45, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)

	// Right packet SHOULD have close flag
	data, offset, isClose, err = sb.readyToRetransmit(1, nil, 45, 50, Data, 300)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
	assert.True(t, isClose)
}

func TestSndCheckStreamFullyAcked(t *testing.T) {
	sb := NewSendBuffer(1000)

	// No stream
	assert.False(t, sb.CheckStreamFullyAcked(1))

	// Not closed
	sb.QueueData(1, []byte("test"))
	assert.False(t, sb.CheckStreamFullyAcked(1))

	// Closed but not sent
	sb.Close(1)
	assert.False(t, sb.CheckStreamFullyAcked(1))

	// Sent but not acked
	sb.readyToSend(1, Data, nil, 1000)
	assert.False(t, sb.CheckStreamFullyAcked(1))

	// Fully acked
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.True(t, sb.CheckStreamFullyAcked(1))
}

func TestSndGetOffsets(t *testing.T) {
	sb := NewSendBuffer(1000)

	// No stream
	assert.Nil(t, sb.GetOffsetClosedAt(1))
	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))

	// With data
	sb.QueueData(1, []byte("01234567"))
	sb.readyToSend(1, Data, nil, 44)
	sb.readyToSend(1, Data, nil, 44)

	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 5})
	assert.Equal(t, uint64(5), sb.GetOffsetAcked(1))

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 3})
	assert.Equal(t, uint64(8), sb.GetOffsetAcked(1))

	// Close offset
	sb.Close(1)
	assert.NotNil(t, sb.GetOffsetClosedAt(1))
	assert.Equal(t, uint64(8), *sb.GetOffsetClosedAt(1))
}

func TestSndMultipleStreams(t *testing.T) {
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

	// Ack one stream doesn't affect others
	sb.AcknowledgeRange(&Ack{streamID: 2, offset: 0, len: 7})
	assert.Equal(t, 1, sb.streams[1].inFlight.Size())
	assert.Equal(t, 0, sb.streams[2].inFlight.Size())
	assert.Equal(t, 1, sb.streams[3].inFlight.Size())
}

func TestSndUpdatePacketSize(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.readyToSend(1, Data, nil, 1000)

	// Update packet size
	sb.UpdatePacketSize(1, 0, 4, 50, 12345)

	_, info, ok := sb.streams[1].inFlight.First()
	assert.True(t, ok)
	assert.Equal(t, uint16(50), info.packetSize)
	assert.Equal(t, uint64(12345), info.sentTimeNano)

	// Ack returns packet size
	status, sentTime, packetSize := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(12345), sentTime)
	assert.Equal(t, uint16(50), packetSize)
}

func TestSndRemoveStream(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))

	assert.NotNil(t, sb.streams[1])
	sb.RemoveStream(1)
	assert.Nil(t, sb.streams[1])
}
