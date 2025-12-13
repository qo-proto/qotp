package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSndInsert(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)

	stream := sb.streams[1]
	assert.Equal(t, []byte("test"), stream.queuedData)
	assert.Equal(t, uint64(0), stream.bytesSentOffset)

	// Capacity limit
	sb2 := NewSendBuffer(3)
	nr, status := sb2.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, nr)
}

func TestSndAcknowledgeRangeBasic(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("testdata"))
	sb.ReadyToSend(1, Data, nil, 1000, 100)

	status, sentTime := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 8})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(100), sentTime)
	assert.Equal(t, uint64(8), sb.streams[1].bytesSentOffset)
}

func TestSndAcknowledgeRangeNonExistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	status, sentTime := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckNoStream, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndAcknowledgeRangeNonExistentRange(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.streams[1] = NewStreamBuffer()

	status, sentTime := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckDup, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndEmptyData(t *testing.T) {
	sb := NewSendBuffer(1000)

	n, status := sb.QueueData(1, []byte{})
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)

	n, status = sb.QueueData(1, nil)
	assert.Equal(t, InsertStatusNoData, status)
	assert.Equal(t, 0, n)
}

func TestSndAcknowledgeGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("012345678901"))

	// Send in 4-byte chunks
	sb.ReadyToSend(1, Data, nil, 43, 100)
	sb.ReadyToSend(1, Data, nil, 43, 100)
	sb.ReadyToSend(1, Data, nil, 43, 100)

	stream := sb.streams[1]
	assert.Equal(t, 3, stream.dataInFlightMap.Size())

	// Ack out of order: middle, last, first
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.Equal(t, 2, stream.dataInFlightMap.Size())

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})
	assert.Equal(t, 1, stream.dataInFlightMap.Size())

	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, 0, stream.dataInFlightMap.Size())
	assert.Equal(t, uint64(12), stream.bytesSentOffset)
}

func TestSndDuplicateAck(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)

	status, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)

	status, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckDup, status)
}

func TestSndGetOffsetClosedAt(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Not closed
	offset := sb.GetOffsetClosedAt(1)
	assert.Nil(t, offset)

	// Close
	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)
	sb.Close(1)

	offset = sb.GetOffsetClosedAt(1)
	assert.NotNil(t, offset)
	assert.Equal(t, uint64(4), *offset)
}

func TestSndGetOffsetAcked(t *testing.T) {
	sb := NewSendBuffer(1000)

	// No stream
	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))

	// Send data
	sb.QueueData(1, []byte("01234567"))
	sb.ReadyToSend(1, Data, nil, 44, 100) // 5 bytes
	sb.ReadyToSend(1, Data, nil, 44, 100) // 3 bytes

	// Nothing acked yet
	assert.Equal(t, uint64(0), sb.GetOffsetAcked(1))

	// Ack first packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 5})
	assert.Equal(t, uint64(5), sb.GetOffsetAcked(1))

	// Ack second packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 3})
	assert.Equal(t, uint64(8), sb.GetOffsetAcked(1))
}

func TestSndReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	nowNano := uint64(100)

	sb.QueueData(1, []byte("test1"))
	sb.QueueData(2, []byte("test2"))

	// Basic send
	data, offset, _ := sb.ReadyToSend(1, Data, nil, 1000, nowNano)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)

	// Verify tracking
	stream := sb.streams[1]
	rangePair, v, ok := stream.dataInFlightMap.First()
	assert.True(t, ok)
	assert.Equal(t, uint16(5), rangePair.length())
	assert.Equal(t, nowNano, v.sentTimeNano)

	// MTU limiting
	sb.QueueData(3, []byte("toolongdata"))
	data, _, _ = sb.ReadyToSend(3, Data, nil, 15, nowNano)
	assert.True(t, len(data) <= 15)

	// No data available
	data, _, _ = sb.ReadyToSend(4, Data, nil, 1000, nowNano)
	assert.Nil(t, data)
}

func TestSndReadyToRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test1"))
	sb.ReadyToSend(1, Data, nil, 1000, 100)

	// Too early for RTO
	data, _, _, err := sb.ReadyToRetransmit(1, nil, 1000, 100, Data, 150)
	assert.Nil(t, err)
	assert.Nil(t, data)

	// RTO expired
	data, offset, _, err := sb.ReadyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)

	// MTU split
	sb2 := NewSendBuffer(1000)
	sb2.QueueData(1, []byte("testdata"))
	sb2.ReadyToSend(1, Data, nil, 1000, 100)

	data, _, _, err = sb2.ReadyToRetransmit(1, nil, 20, 99, Data, 200)
	assert.Nil(t, err)
	assert.True(t, len(data) <= 20)
}

func TestSndRetransmitWithGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))

	sb.ReadyToSend(1, Data, nil, 44, 100)
	sb.ReadyToSend(1, Data, nil, 44, 100)

	// Ack second packet, leaving first in flight
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 5})
	assert.Equal(t, 1, sb.streams[1].dataInFlightMap.Size())

	// Retransmit first packet
	data, offset, _, err := sb.ReadyToRetransmit(1, nil, 44, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("01234"), data)
	assert.Equal(t, uint64(0), offset)
}

func TestSndMultipleStreams(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))

	data1, offset1, _ := sb.ReadyToSend(1, Data, nil, 1000, 100)
	data2, offset2, _ := sb.ReadyToSend(2, Data, nil, 1000, 200)
	data3, offset3, _ := sb.ReadyToSend(3, Data, nil, 1000, 300)

	assert.Equal(t, []byte("stream1"), data1)
	assert.Equal(t, []byte("stream2"), data2)
	assert.Equal(t, []byte("stream3"), data3)
	assert.Equal(t, uint64(0), offset1)
	assert.Equal(t, uint64(0), offset2)
	assert.Equal(t, uint64(0), offset3)
}

func TestSndPingTimeout(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueuePing(1)

	data, _, _ := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, 1, sb.streams[1].dataInFlightMap.Size())

	// Timeout - should remove without retransmit
	data, _, _, err := sb.ReadyToRetransmit(1, nil, 43, 50, Data, 200)
	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, 0, sb.streams[1].dataInFlightMap.Size())
}

// Close tests

func TestSndCloseIdempotent(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.Close(1)
	firstOffset := *sb.streams[1].closeAtOffset

	// Send data
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Close again - offset should not change
	sb.Close(1)
	assert.Equal(t, firstOffset, *sb.streams[1].closeAtOffset)
}

func TestSndCloseBeforeSend(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)

	// Send should include close flag
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseAfterPartialSend(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("0123456789"))

	// Send first 5 bytes
	data, _, isClose := sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, 5, len(data))
	assert.False(t, isClose)

	// Close after partial send
	sb.Close(1)
	assert.Equal(t, uint64(10), *sb.streams[1].closeAtOffset)

	// Next send should have close flag
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, []byte("56789"), data)
	assert.Equal(t, uint64(5), offset)
	assert.True(t, isClose)
}

func TestSndCloseAfterAllDataSent(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Close after all data sent
	sb.Close(1)
	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)

	// Should send empty packet with close flag
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.True(t, isClose)
}

func TestSndCloseEmptyStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Close without queuing any data
	sb.Close(1)
	assert.Equal(t, uint64(0), *sb.streams[1].closeAtOffset)

	// Should get empty packet with close flag
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseRetransmitKeepsFlag(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("testdata"))
	sb.Close(1)

	// Send with close flag
	data, _, isClose := sb.ReadyToSend(1, Data, nil, 1000, 100)
	assert.Equal(t, []byte("testdata"), data)
	assert.True(t, isClose)

	// Retransmit should preserve close flag
	data, offset, isClose, err := sb.ReadyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("testdata"), data)
	assert.Equal(t, uint64(0), offset)
	assert.True(t, isClose)
}

func TestSndCloseRetransmitSplitCorrectFlag(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("0123456789")) // 10 bytes
	sb.Close(1)

	// Send all at once with close flag
	sb.ReadyToSend(1, Data, nil, 1000, 100)

	// Retransmit with small MTU forcing split
	// Left packet should NOT have close
	data, offset, isClose, err := sb.ReadyToRetransmit(1, nil, 45, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose) // Left packet has NO close flag

	// Right packet SHOULD have close
	data, offset, isClose, err = sb.ReadyToRetransmit(1, nil, 45, 50, Data, 300)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
	assert.True(t, isClose) // Right packet has close flag
}

func TestSndCloseEmptyPacketRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Ack the data packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	sb.Close(1)

	// Send empty close packet
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.True(t, isClose)

	// Retransmit empty close packet
	data, offset, isClose, err := sb.ReadyToRetransmit(1, nil, 43, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.True(t, isClose)
}

func TestSndCheckStreamFullyAcked(t *testing.T) {
	sb := NewSendBuffer(1000)

	// No stream
	assert.False(t, sb.checkStreamFullyAcked(1))

	// Stream without close
	sb.QueueData(1, []byte("test"))
	assert.False(t, sb.checkStreamFullyAcked(1))

	// Close but data not sent
	sb.Close(1)
	assert.False(t, sb.checkStreamFullyAcked(1))

	// Data sent but not acked
	sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.False(t, sb.checkStreamFullyAcked(1))

	// Data acked
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.True(t, sb.checkStreamFullyAcked(1))
}

func TestSndCloseFlagOnDataPackets(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("0123456789")) // 10 bytes
	sb.Close(1)                           // closeAtOffset = 10

	// First packet (0-5) should NOT have close flag
	data, offset, isClose := sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.False(t, isClose)

	// Second packet (5-10) SHOULD have close flag
	data, offset, isClose = sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, uint64(5), offset)
	assert.True(t, isClose)
}