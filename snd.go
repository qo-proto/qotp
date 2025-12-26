package qotp

import (
	"errors"
	"sync"
)

type InsertStatus int

const (
	InsertStatusOk InsertStatus = iota
	InsertStatusSndFull
	InsertStatusNoData
)

type AckStatus int

const (
	AckStatusOk AckStatus = iota
	AckNotFound
	AckDup
)

type SendInfo struct {
	data         []byte
	sentTimeNano uint64
	sentNr       int
	pingRequest  bool
	closeRequest bool
}

// StreamBuffer represents a single stream's userData and metadata
type StreamBuffer struct {
	dataInFlightMap *LinkedMap[packetKey, *SendInfo]
	queuedData      []byte
	bytesSentOffset uint64
	pingRequest     bool
	closeAtOffset   *uint64
	closeSent       bool
}

type SendBuffer struct {
	streams  map[uint32]*StreamBuffer // Changed to LinkedHashMap
	capacity int                      //len(dataToSend) of all streams cannot become larger than capacity
	size     int                      //len(dataToSend) of all streams
	mu       sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		dataInFlightMap: NewLinkedMap[packetKey, *SendInfo](),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  make(map[uint32]*StreamBuffer),
		capacity: capacity,
	}
}

func (sb *SendBuffer) getOrCreateStream(streamID uint32) *StreamBuffer {
	// INTERNAL: caller must hold sb.mu
	stream := sb.streams[streamID]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamID] = stream
	}
	return stream
}

// QueueData stores the userData in the dataMap, does not send yet
func (sb *SendBuffer) QueueData(streamId uint32, userData []byte) (n int, status InsertStatus) {
	if len(userData) <= 0 {
		return 0, InsertStatusNoData
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Calculate how much userData we can insert
	remainingCapacitySnd := sb.capacity - sb.size
	if remainingCapacitySnd == 0 {
		return 0, InsertStatusSndFull
	}

	// We fill up the chunk up to the capacity of snd
	// chunk is then what we will queue, and we report
	// how much bytes we queued
	chunk := userData
	if len(userData) > remainingCapacitySnd {
		chunk = userData[:remainingCapacitySnd]
		status = InsertStatusSndFull
	} else {
		status = InsertStatusOk
	}
	n = len(chunk)

	stream := sb.getOrCreateStream(streamId)
	stream.queuedData = append(stream.queuedData, chunk...)
	sb.size += n

	return n, status
}

func (sb *SendBuffer) QueuePing(streamId uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamId)
	stream.pingRequest = true
}

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamID uint32, msgType CryptoMsgType, ack *Ack, mtu int, nowNano uint64) (
	packetData []byte, offset uint64, isClose bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0, false
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false
	}

	// CASE 1: Ping request
	if stream.pingRequest {
		stream.pingRequest = false
		key := createPacketKey(stream.bytesSentOffset, 0)
		stream.dataInFlightMap.Put(key, &SendInfo{data: []byte{}, sentNr: 1, sentTimeNano: nowNano, pingRequest: true, closeRequest: false})
		return []byte{}, 0, false
	}

	// CASE 2: No queued data
	if len(stream.queuedData) == 0 {
		if stream.closeAtOffset == nil || stream.bytesSentOffset < *stream.closeAtOffset {
			return nil, 0, false
		}

		if stream.closeSent {
			return nil, 0, false
		}

		closeKey := createPacketKey(stream.bytesSentOffset, 0)
		if stream.dataInFlightMap.Contains(closeKey) {
			return nil, 0, false
		}

		stream.closeSent = true
		stream.dataInFlightMap.Put(closeKey, &SendInfo{data: []byte{}, sentNr: 1, sentTimeNano: nowNano, pingRequest: false, closeRequest: true})
		return []byte{}, closeKey.offset(), true
	}

	// CASE 3: Has queued data
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, stream.bytesSentOffset)
		if overhead > mtu {
			return nil, 0, false
		}
		maxData = mtu - overhead
	}

	// Determine how much to send
	length := min(uint64(maxData), uint64(len(stream.queuedData)))

	// Extract data from queue
	packetData = stream.queuedData[:length]

	// Create key and SendInfo with actual data
	key := createPacketKey(stream.bytesSentOffset, uint16(length))

	// Check if this packet reaches the close offset
	isClose = false
	if stream.closeAtOffset != nil {
		packetEndOffset := stream.bytesSentOffset + length
		if packetEndOffset >= *stream.closeAtOffset {
			isClose = true
			stream.closeSent = true
		}
	}

	stream.dataInFlightMap.Put(key, &SendInfo{data: packetData, sentNr: 1, sentTimeNano: nowNano, pingRequest: false, closeRequest: isClose})

	// Remove sent data from queue
	stream.queuedData = stream.queuedData[length:]

	// Update sent offset
	stream.bytesSentOffset += length

	return packetData, key.offset(), isClose
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamID uint32, ack *Ack, mtu int, expectedRtoNano uint64, msgType CryptoMsgType, nowNano uint64) (
	data []byte, offset uint64, isClose bool, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(sb.streams) == 0 {
		return nil, 0, false, nil
	}

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false, nil
	}

	// Check oldest packet first
	packetKey, rtoData, ok := stream.dataInFlightMap.First()
	if !ok {
		return nil, 0, false, nil
	}

	expectedRtoBackoffNano, err := backoff(expectedRtoNano, rtoData.sentNr)
	if err != nil {
		return nil, 0, false, err
	}

	// Check if RTO expired
	if nowNano-rtoData.sentTimeNano <= expectedRtoBackoffNano {
		return nil, 0, false, nil
	}

	// Ping - just remove, no retransmit
	if rtoData.pingRequest {
		stream.dataInFlightMap.Remove(packetKey)
		return nil, 0, false, nil
	}

	// Get data directly from SendInfo
	data = rtoData.data
	length := len(data)

	// Calculate available space
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, packetKey.offset())
		if overhead > mtu {
			return nil, 0, false, errors.New("overhead larger than MTU")
		}
		maxData = mtu - overhead
	}

	if length <= maxData {
		// Update SendInfo in place
		rtoData.sentTimeNano = nowNano
		rtoData.sentNr++

		return data, packetKey.offset(), rtoData.closeRequest, nil

	}

	// Split packet
	leftData := data[:maxData]
	rightData := data[maxData:]

	// Create new packet for left part
	leftKey := createPacketKey(packetKey.offset(), uint16(maxData))
	stream.dataInFlightMap.Put(leftKey, &SendInfo{data: leftData, sentTimeNano: nowNano, sentNr: rtoData.sentNr + 1})

	// Update right part (remaining data)
	remainingOffset := packetKey.offset() + uint64(maxData)
	rightKey := createPacketKey(remainingOffset, uint16(len(rightData)))
	rtoData.data = rightData // Update data in existing SendInfo
	stream.dataInFlightMap.Replace(packetKey, rightKey, rtoData)

	return leftData, packetKey.offset(), false, nil

}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	//slog.Debug("ACK received", "stream", ack.streamID, "offset", ack.offset, "status", status)

	stream := sb.streams[ack.streamID]
	if stream == nil {
		return AckNotFound, 0
	}

	key := createPacketKey(ack.offset, ack.len)

	// Simply remove from map - no trimming needed!
	sendInfo, ok := stream.dataInFlightMap.Remove(key)
	if !ok {
		return AckDup, 0
	}

	// Update global size tracking
	sb.size -= len(sendInfo.data)

	return AckStatusOk, sendInfo.sentTimeNano
}

func (sb *SendBuffer) CheckStreamFullyAcked(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return false
	}

	closeOffset := stream.closeAtOffset
	if closeOffset == nil {
		return false
	}

	var ackedOffset uint64
	firstKey, _, ok := stream.dataInFlightMap.First()
	if ok {
		ackedOffset = firstKey.offset()
	} else {
		// No inflight data means everything sent has been acked
		ackedOffset = stream.bytesSentOffset
	}

	// !ok -> standalone fin needs also to be acked
	return !ok && ackedOffset >= *closeOffset
}

func (sb *SendBuffer) GetOffsetAcked(streamID uint32) (offset uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}

	// If there's inflight data, the acked offset is where inflight begins
	firstKey, _, ok := stream.dataInFlightMap.First()
	if ok {
		ackedOffset := firstKey.offset()
		return ackedOffset
	}

	// No inflight data means everything sent has been acked
	return stream.bytesSentOffset // Changed from bytesSentUserOffset
}

func (sb *SendBuffer) GetOffsetClosedAt(streamID uint32) (offset *uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil
	}

	return stream.closeAtOffset
}

func (sb *SendBuffer) Close(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamID)
	if stream.closeAtOffset == nil {
		// Calculate total offset: sent + queued
		offset := stream.bytesSentOffset + uint64(len(stream.queuedData))
		stream.closeAtOffset = &offset
	}
}

type packetKey uint64

func (p packetKey) offset() uint64 {
	return uint64(p) >> 16
}

func (p packetKey) length() uint16 {
	return uint16(p & 0xFFFF)
}

func createPacketKey(offset uint64, length uint16) packetKey {
	return packetKey((offset << 16) | uint64(length))
}

func (sb *SendBuffer) RemoveStream(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	delete(sb.streams, streamID)
}

func (sb *SendBuffer) GetInflightSize(streamID uint32) int {
    sb.mu.Lock()
    defer sb.mu.Unlock()
    stream := sb.streams[streamID]
    if stream == nil {
        return -1
    }
    return stream.dataInFlightMap.Size()
}

func (sb *SendBuffer) IsCloseSent(streamID uint32) bool {
    sb.mu.Lock()
    defer sb.mu.Unlock()
    stream := sb.streams[streamID]
    if stream == nil {
        return false
    }
    return stream.closeSent
}