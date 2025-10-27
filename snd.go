package qotp

import (
	"log/slog"
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
	AckNoStream
	AckDup
)

type SendInfo struct {
	data         []byte
	sentTimeNano uint64
	sentNr       int
	pingRequest  bool
}

func (s *SendInfo) debug() slog.Attr {
	if s == nil {
		return slog.String("meta", "n/a")
	}
	return slog.Group("meta",
		slog.Uint64("sentTimeNano:ms", s.sentTimeNano/msNano),
		slog.Int("sentNr", s.sentNr))
}

// StreamBuffer represents a single stream's userData and metadata
type StreamBuffer struct {
	dataInFlightMap *LinkedMap[packetKey, *SendInfo]
	queuedData      []byte
	bytesSentOffset uint64
	pingRequest     bool
	closeAtOffset   *uint64
}

type SendBuffer struct {
	streams  map[uint32]*StreamBuffer // Changed to LinkedHashMap
	capacity int                      //len(dataToSend) of all streams cannot become larger than capacity
	size     int                      //len(dataToSend) of all streams
	mu       *sync.Mutex
}

func NewStreamBuffer() *StreamBuffer {
	return &StreamBuffer{
		queuedData:      []byte{},
		dataInFlightMap: NewLinkedMap[packetKey, *SendInfo](),
	}
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  make(map[uint32]*StreamBuffer),
		capacity: capacity,
		mu:       &sync.Mutex{},
	}
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

	// Get or create stream buffer
	stream := sb.streams[streamId]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamId] = stream
	}

	// Store chunk
	stream.queuedData = append(stream.queuedData, chunk...)
	sb.size += n

	return n, status
}

func (sb *SendBuffer) QueuePing(streamId uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Get or create stream buffer
	stream := sb.streams[streamId]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamId] = stream
	}

	stream.pingRequest = true
}

// ReadyToSend gets data from dataToSend and creates an entry in dataInFlightMap
func (sb *SendBuffer) ReadyToSend(streamID uint32, msgType CryptoMsgType, ack *Ack, mtu int, nowNano uint64) (
	packetData []byte, offset uint64, messageType StreamMsgType) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if len(sb.streams) == 0 {
		return nil, 0, MsgTypeInvalid
	}
	
	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, MsgTypeInvalid
	}
	
	if stream.pingRequest {
		stream.pingRequest = false
		key := createPacketKey(stream.bytesSentOffset, 0)
		m := &SendInfo{
			data: []byte{},  // Empty for ping
			sentNr: 1, 
			sentTimeNano: nowNano, 
			pingRequest: true,
		}
		stream.dataInFlightMap.Put(key, m)
		return []byte{}, 0, MsgTypePing
	}
	
	// Check if all queued data has been sent
	if len(stream.queuedData) == 0 {
		if stream.closeAtOffset == nil || stream.bytesSentOffset < *stream.closeAtOffset {
			return nil, 0, MsgTypeInvalid
		}
		key := createPacketKey(stream.bytesSentOffset, 0)
		m := &SendInfo{
			data: []byte{},  // Empty for close
			sentNr: 1, 
			sentTimeNano: nowNano, 
			pingRequest: false,
		}
		stream.dataInFlightMap.Put(key, m)
		return []byte{}, key.offset(), MsgTypeClose
	}
	
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverhead(msgType, ack, stream.bytesSentOffset)
		maxData = mtu - overhead
	}
	
	// Determine how much to send
	length := min(uint64(maxData), uint64(len(stream.queuedData)))
	
	// Extract data from queue
	packetData = stream.queuedData[:length]
	
	// Create key and SendInfo with actual data
	key := createPacketKey(stream.bytesSentOffset, uint16(length))
	m := &SendInfo{
		data: packetData,  // Store the actual data
		sentNr: 1, 
		sentTimeNano: nowNano, 
		pingRequest: false,
	}
	stream.dataInFlightMap.Put(key, m)
	
	// Remove sent data from queue
	stream.queuedData = stream.queuedData[length:]
	
	// Update sent offset
	stream.bytesSentOffset += length
	
	if stream.closeAtOffset != nil && stream.bytesSentOffset >= *stream.closeAtOffset {
		messageType = MsgTypeClose
	}
	
	return packetData, key.offset(), messageType
}

// ReadyToRetransmit finds expired dataInFlightMap that need to be resent
func (sb *SendBuffer) ReadyToRetransmit(streamID uint32, ack *Ack, mtu int, expectedRtoNano uint64, msgType CryptoMsgType, nowNano uint64) (
	data []byte, offset uint64, messageType StreamMsgType, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	if len(sb.streams) == 0 {
		return nil, 0, MsgTypeInvalid, nil
	}
	
	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, MsgTypeInvalid, nil
	}
	
	// Check oldest packet first
	packetKey, rtoData, ok := stream.dataInFlightMap.First()
	if !ok {
		return nil, 0, MsgTypeInvalid, nil
	}
	
	expectedRtoBackoffNano, err := backoff(expectedRtoNano, rtoData.sentNr)
	if err != nil {
		return nil, 0, MsgTypeInvalid, err
	}
	
	actualRtoNano := nowNano - rtoData.sentTimeNano
	if actualRtoNano <= expectedRtoBackoffNano {
		return nil, 0, MsgTypeInvalid, nil
	}
	
	// Timeout
	if rtoData.pingRequest {
		// Just remove ping, no retransmit
		stream.dataInFlightMap.Remove(packetKey)
		return nil, 0, MsgTypeInvalid, nil
	}
	
	// Get data directly from SendInfo
	data = rtoData.data
	length := uint16(len(data))
	
	// Calculate available space
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverhead(msgType, ack, packetKey.offset())
		maxData = mtu - overhead
	}
	
	if length <= uint16(maxData) {
		// Resend entire packet
		slog.Debug("Resend", slog.Uint64("free-space", uint64(uint16(maxData)-length)))
		
		// Update SendInfo in place
		rtoData.sentTimeNano = nowNano
		rtoData.sentNr++
		
		packetEnd := packetKey.offset() + uint64(length)
		if stream.closeAtOffset != nil && packetEnd >= *stream.closeAtOffset {
			messageType = MsgTypeClose
		}
		return data, packetKey.offset(), messageType, nil
		
	} else {
		// Split packet
		leftData := data[:maxData]
		rightData := data[maxData:]
		
		// Create new packet for left part
		leftKey := createPacketKey(packetKey.offset(), uint16(maxData))
		leftInfo := &SendInfo{
			data:         leftData,
			sentTimeNano: nowNano,
			sentNr:       rtoData.sentNr + 1,
		}
		stream.dataInFlightMap.Put(leftKey, leftInfo)
		
		// Update right part (remaining data)
		remainingOffset := packetKey.offset() + uint64(maxData)
		rightKey := createPacketKey(remainingOffset, uint16(len(rightData)))
		rtoData.data = rightData  // Update data in existing SendInfo
		stream.dataInFlightMap.Replace(packetKey, rightKey, rtoData)
		
		slog.Debug("Resend/Split", 
			slog.Uint64("send", uint64(maxData)),
			slog.Uint64("remain", uint64(len(rightData))))
		
		return leftData, packetKey.offset(), MsgTypeData, nil
	}
}

// AcknowledgeRange handles acknowledgment of dataToSend
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	stream := sb.streams[ack.streamID]
	if stream == nil {
		slog.Debug("ACK: no stream", slog.Uint64("streamID", uint64(ack.streamID)))
		return AckNoStream, 0
	}
	
	key := createPacketKey(ack.offset, ack.len)
		
	// Simply remove from map - no trimming needed!
	sendInfo, ok := stream.dataInFlightMap.Remove(key)
	if !ok {
		slog.Debug("ACK: duplicate")
		return AckDup, 0
	}
	
	// Update global size tracking
	sb.size -= len(sendInfo.data)	
	return AckStatusOk, sendInfo.sentTimeNano
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
	return stream.bytesSentOffset  // Changed from bytesSentUserOffset
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
	
	// Get or create stream buffer
	stream := sb.streams[streamID]
	if stream == nil {
		stream = NewStreamBuffer()
		sb.streams[streamID] = stream
	}
	
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
