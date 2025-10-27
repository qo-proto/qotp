package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSndInsert(t *testing.T) {
	sb := NewSendBuffer(1000)
	
	// Basic insert
	n, status := sb.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)
	
	// Verify stream created correctly
	stream := sb.streams[1]
	assert.Equal(t, []byte("test"), stream.queuedData)  // Changed from userData
	assert.Equal(t, uint64(0), stream.bytesSentOffset)  // Changed from bytesSentUserOffset
	// Removed diffArrayToUserOffset assertion - field no longer exists
	
	// Test capacity limit
	sb2 := NewSendBuffer(3)
	nr, status := sb2.QueueData(1, []byte("test"))
	assert.Equal(t, InsertStatusSndFull, status)
	assert.Equal(t, 3, nr)
}

func TestSndAcknowledgeRangeBasic(t *testing.T) {
	sb := NewSendBuffer(1000)
	
	sb.QueueData(1, []byte("testdata"))
	sb.ReadyToSend(1, Data, nil, 1000, 100)
	stream := sb.streams[1]
	
	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      8,
	})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, uint64(100), sentTime)
	assert.Equal(t, 0, len(stream.queuedData))        // Changed from userData
	assert.Equal(t, uint64(8), stream.bytesSentOffset) // Now checking bytesSentOffset
	// Removed diffArrayToUserOffset assertion - field no longer exists
}

func TestSndAcknowledgeRangeNonExistentStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
	assert.Equal(t, AckNoStream, status)
	assert.Equal(t, uint64(0), sentTime)
}

func TestSndAcknowledgeRangeNonExistentRange(t *testing.T) {
	sb := NewSendBuffer(1000)

	stream := NewStreamBuffer()
	sb.streams[1] = stream

	status, sentTime := sb.AcknowledgeRange(&Ack{
		streamID: 1,
		offset:   0,
		len:      4,
	})
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
	
	// Ack middle packet first
	status, _ := sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, 0, len(stream.queuedData))  // All data was sent
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
	
	// Ack last packet
	status, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
	
	// Ack first packet - all packets now acked
	status, _ = sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, AckStatusOk, status)
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, uint64(12), stream.bytesSentOffset)
	assert.Equal(t, 0, stream.dataInFlightMap.Size())
}

func TestSndAcknowledgeComplexGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("01234567890123456789"))
	
	for i := 0; i < 5; i++ {
		sb.ReadyToSend(1, Data, nil, 43, 100)
	}
	
	stream := sb.streams[1]
	assert.Equal(t, 5, stream.dataInFlightMap.Size())
	
	// Ack in random order: 2, 4, 1, 3, 0
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 8, len: 4})
	assert.Equal(t, 0, len(stream.queuedData))  // All sent
	assert.Equal(t, 4, stream.dataInFlightMap.Size())
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 16, len: 4})
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, 3, stream.dataInFlightMap.Size())
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 4, len: 4})
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 12, len: 4})
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, uint64(20), stream.bytesSentOffset)
	assert.Equal(t, 0, stream.dataInFlightMap.Size())
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

// New close tests






func TestSndCloseIdempotent(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	firstOffset := *sb.streams[1].closeAtOffset

	// Send data
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Close again - offset should not change
	sb.Close(1)
	secondOffset := *sb.streams[1].closeAtOffset

	assert.Equal(t, firstOffset, secondOffset)
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
	offset := sb.GetOffsetAcked(1)
	assert.Equal(t, uint64(0), offset)

	// Send data
	sb.QueueData(1, []byte("01234567"))
	sb.ReadyToSend(1, Data, nil, 44, 100) // sends 5 bytes
	sb.ReadyToSend(1, Data, nil, 44, 100) // sends 3 bytes

	// Nothing acked yet, should return first in-flight offset
	offset = sb.GetOffsetAcked(1)
	assert.Equal(t, uint64(0), offset)

	// Ack first packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 5})

	// Should return next in-flight offset
	offset = sb.GetOffsetAcked(1)
	assert.Equal(t, uint64(5), offset)

	// Ack second packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 3})

	// All acked, should return bytes sent
	offset = sb.GetOffsetAcked(1)
	assert.Equal(t, uint64(8), offset)
}



func TestSndReadyToSend(t *testing.T) {
	sb := NewSendBuffer(1000)
	nowNano := uint64(100)

	// Insert data
	sb.QueueData(1, []byte("test1"))
	sb.QueueData(2, []byte("test2"))

	// Basic send
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 1000, nowNano)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)

	// Verify range tracking
	stream := sb.streams[1]
	rangePair, v, ok := stream.dataInFlightMap.First()
	assert.True(t, ok)
	assert.NotNil(t, rangePair)
	assert.Equal(t, uint16(5), rangePair.length())
	assert.Equal(t, nowNano, v.sentTimeNano)

	// Test MTU limiting with small MTU
	sb.QueueData(3, []byte("toolongdata"))
	data, offset, msgType = sb.ReadyToSend(3, Data, nil, 15, nowNano)
	assert.True(t, len(data) <= 15)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)

	// Test no data available
	data, offset, msgType = sb.ReadyToSend(4, Data, nil, 1000, nowNano)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeInvalid, msgType)
}

func TestSndReadyToRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Setup test data
	sb.QueueData(1, []byte("test1"))
	sb.QueueData(2, []byte("test2"))

	sb.ReadyToSend(1, Data, nil, 1000, 100) // Initial send at time 100
	sb.ReadyToSend(2, Data, nil, 1000, 100) // Initial send at time 100

	// Test basic retransmit
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)

	data, offset, msgType, err = sb.ReadyToRetransmit(2, nil, 1000, 100, Data, 200)
	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeInvalid, msgType)

	data, offset, msgType, err = sb.ReadyToRetransmit(1, nil, 1000, 99, Data, 399)
	assert.Nil(t, err)
	assert.Equal(t, []byte("test1"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)

	// Test MTU split scenario
	sb2 := NewSendBuffer(1000)
	sb2.QueueData(1, []byte("testdata"))
	sb2.ReadyToSend(1, Data, nil, 1000, 100)

	data, offset, msgType, err = sb2.ReadyToRetransmit(1, nil, 20, 99, Data, 200)
	assert.Nil(t, err)
	assert.True(t, len(data) <= 20)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)

	stream := sb2.streams[1]
	assert.True(t, stream.dataInFlightMap.Size() >= 1)
	node, _, ok := stream.dataInFlightMap.First()
	assert.True(t, ok)
	assert.Equal(t, uint64(0), node.offset())
}

func TestSndMultipleStreams(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("stream1"))
	sb.QueueData(2, []byte("stream2"))
	sb.QueueData(3, []byte("stream3"))

	data1, offset1, msgType1 := sb.ReadyToSend(1, Data, nil, 1000, 100)
	data2, offset2, msgType2 := sb.ReadyToSend(2, Data, nil, 1000, 200)
	data3, offset3, msgType3 := sb.ReadyToSend(3, Data, nil, 1000, 300)

	assert.Equal(t, []byte("stream1"), data1)
	assert.Equal(t, []byte("stream2"), data2)
	assert.Equal(t, []byte("stream3"), data3)
	assert.Equal(t, uint64(0), offset1)
	assert.Equal(t, uint64(0), offset2)
	assert.Equal(t, uint64(0), offset3)
	assert.Equal(t, MsgTypeData, msgType1)
	assert.Equal(t, MsgTypeData, msgType2)
	assert.Equal(t, MsgTypeData, msgType3)

	assert.Equal(t, 1, sb.streams[1].dataInFlightMap.Size())
	assert.Equal(t, 1, sb.streams[2].dataInFlightMap.Size())
	assert.Equal(t, 1, sb.streams[3].dataInFlightMap.Size())
}

func TestSndRetransmitWithGaps(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("0123456789"))
	
	sb.ReadyToSend(1, Data, nil, 44, 100)
	sb.ReadyToSend(1, Data, nil, 44, 100)
	
	stream := sb.streams[1]
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
	
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 5, len: 5})
	
	// After ACKing the second packet, we should have:
	// - No queued data (all was sent)
	// - 1 packet still in flight (offset 0, len 5)
	assert.Equal(t, 0, len(stream.queuedData))
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
	
	// Retransmit the first packet (still in flight)
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 44, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("01234"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType)
}

func TestSndCloseBeforeSend(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	stream := sb.streams[1]
	assert.NotNil(t, stream.closeAtOffset)
	assert.Equal(t, uint64(4), *stream.closeAtOffset)

	// Send should include close flag
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeClose, msgType)
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
}

func TestSndCloseAfterPartialSend(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("0123456789"))

	// Send first 5 bytes
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, 5, len(data))
	assert.Equal(t, MsgTypeData, msgType)

	// Close after partial send
	sb.Close(1)
	stream := sb.streams[1]
	assert.Equal(t, uint64(10), *stream.closeAtOffset)

	// Next send should have close flag
	data, offset, msgType = sb.ReadyToSend(1, Data, nil, 44, 100)
	assert.Equal(t, []byte("56789"), data)
	assert.Equal(t, uint64(5), offset)
	assert.Equal(t, MsgTypeClose, msgType)
}

func TestSndCloseAfterAllDataSent(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Close after all data sent
	sb.Close(1)
	stream := sb.streams[1]
	assert.Equal(t, uint64(4), *stream.closeAtOffset)

	// Should send empty packet with close flag
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.Equal(t, MsgTypeClose, msgType)
	assert.Equal(t, 2, stream.dataInFlightMap.Size())
}

func TestSndCloseEmptyStream(t *testing.T) {
	sb := NewSendBuffer(1000)

	// Close without queuing any data
	sb.Close(1)

	stream := sb.streams[1]
	assert.NotNil(t, stream.closeAtOffset)
	assert.Equal(t, uint64(0), *stream.closeAtOffset)

	// Try to send - should get empty packet with close flag
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeClose, msgType)
	assert.Equal(t, 1, stream.dataInFlightMap.Size())
}

func TestSndCloseMultipleSplits(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("012345678901234567890123456789")) // 30 bytes
	sb.Close(1)

	// Send all at once
	sb.ReadyToSend(1, Data, nil, 1000, 100)

	// Force 3 splits
	data1, offset1, msgType1, _ := sb.ReadyToRetransmit(1, nil, 49, 50, Data, 200)
	assert.Equal(t, MsgTypeData, msgType1)
	assert.Equal(t, uint64(0), offset1)

	data2, offset2, msgType2, _ := sb.ReadyToRetransmit(1, nil, 49, 50, Data, 300)
	assert.Equal(t, MsgTypeData, msgType2)
	assert.Equal(t, uint64(len(data1)), offset2)

	data3, offset3, msgType3, _ := sb.ReadyToRetransmit(1, nil, 49, 50, Data, 400)
	assert.Equal(t, MsgTypeClose, msgType3)
	assert.Equal(t, uint64(len(data1)+len(data2)), offset3)
	assert.Equal(t, 30, len(data1)+len(data2)+len(data3))
}

func TestSndQueueAfterClose(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("test"))
	sb.Close(1)

	// Queue more data after close
	n, status := sb.QueueData(1, []byte("more"))
	assert.Equal(t, InsertStatusOk, status)
	assert.Equal(t, 4, n)

	// closeAtOffset doesn't change
	assert.Equal(t, uint64(4), *sb.streams[1].closeAtOffset)

	// First send gets "test" with close flag
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte("test"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeClose, msgType)

	// Second send gets "more" WITH close flag
	data, offset, msgType = sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte("more"), data)
	assert.Equal(t, uint64(4), offset)
	assert.Equal(t, MsgTypeClose, msgType)
}

func TestSndCloseRetransmitKeepsFlag(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("testdata"))
	sb.Close(1)

	// Send with close flag
	data, _, msgType := sb.ReadyToSend(1, Data, nil, 1000, 100)
	assert.Equal(t, []byte("testdata"), data)
	assert.Equal(t, MsgTypeClose, msgType)

	// Retransmit should preserve close flag
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 1000, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte("testdata"), data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeClose, msgType)
}

func TestSndCloseRetransmitSplitCorrectFlag(t *testing.T) {
	sb := NewSendBuffer(1000)

	sb.QueueData(1, []byte("0123456789")) // 10 bytes
	sb.Close(1)

	// Send all at once
	sb.ReadyToSend(1, Data, nil, 1000, 100)

	// Retransmit with small MTU forcing split
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 45, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, 6, len(data))
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeData, msgType) // Not at close point yet

	// Retransmit remaining
	data, offset, msgType, err = sb.ReadyToRetransmit(1, nil, 45, 50, Data, 300)
	assert.Nil(t, err)
	assert.Equal(t, 4, len(data))
	assert.Equal(t, uint64(6), offset)
	assert.Equal(t, MsgTypeClose, msgType) // Ends at close point
}

func TestSndCloseEmptyPacketRetransmit(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueueData(1, []byte("test"))
	sb.ReadyToSend(1, Data, nil, 43, 100)

	// Ack the data packet
	sb.AcknowledgeRange(&Ack{streamID: 1, offset: 0, len: 4})

	sb.Close(1)

	// Send empty close packet
	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.Equal(t, MsgTypeClose, msgType)

	// Retransmit empty close packet
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 43, 50, Data, 200)
	assert.Nil(t, err)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(4), offset)
	assert.Equal(t, MsgTypeClose, msgType)
}

func TestSndPingTimeout(t *testing.T) {
	sb := NewSendBuffer(1000)
	sb.QueuePing(1)

	data, offset, msgType := sb.ReadyToSend(1, Data, nil, 43, 100)
	assert.Equal(t, []byte{}, data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypePing, msgType)

	stream := sb.streams[1]
	assert.Equal(t, 1, stream.dataInFlightMap.Size())

	// Timeout - should remove without retransmit
	data, offset, msgType, err := sb.ReadyToRetransmit(1, nil, 43, 50, Data, 200)
	assert.Nil(t, err)
	assert.Nil(t, data)
	assert.Equal(t, uint64(0), offset)
	assert.Equal(t, MsgTypeInvalid, msgType)
	assert.Equal(t, 0, stream.dataInFlightMap.Size())
}
