package qotp

import (
	"errors"
	"sync"
)

// =============================================================================
// Send buffer - Manages outgoing data with retransmission support
//
// Per-stream buffer tracks:
//   - queuedData: data waiting to be sent (not yet transmitted)
//   - dataInFlightMap: sent but not yet acknowledged (keyed by offset+length)
//
// Packet tracking uses packetKey (offset << 16 | length) for O(1) ACK lookup.
// Retransmission triggered when RTO expires on oldest in-flight packet.
// =============================================================================

const sndBufferCapacity = 16 * 1024 * 1024 // 16MB

// =============================================================================
// Status types
// =============================================================================

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

// =============================================================================
// Packet tracking
// =============================================================================

// packetKey encodes offset (48-bit) and length (16-bit) for O(1) map lookup.
type packetKey uint64

func createPacketKey(offset uint64, length uint16) packetKey {
	return packetKey((offset << 16) | uint64(length))
}

func (p packetKey) offset() uint64 {
	return uint64(p) >> 16
}

// sendPacket tracks an in-flight packet awaiting acknowledgment.
type sendPacket struct {
	data         []byte
	packetSize   uint16 // Encrypted packet size (for RTT measurement)
	sentTimeNano uint64
	sentCount    uint   // Number of transmission attempts
	isPing       bool
	isClose      bool
}

// =============================================================================
// Per-stream send buffer
// =============================================================================

type streamSendBuffer struct {
	inFlight        *LinkedMap[packetKey, *sendPacket]
	queuedData      []byte
	bytesSentOffset uint64  // Next offset to send
	pingRequested   bool    // Pending ping request
	closeAtOffset   *uint64 // Stream closes at this offset
	closeSent       bool    // FIN packet has been sent
}

func newStreamSendBuffer() *streamSendBuffer {
	return &streamSendBuffer{inFlight: NewLinkedMap[packetKey, *sendPacket]()}
}

// =============================================================================
// Connection-level send buffer (manages all streams)
// =============================================================================

type SendBuffer struct {
	streams  map[uint32]*streamSendBuffer
	capacity int
	size     int // Total queued bytes across all streams
	mu       sync.Mutex
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		streams:  make(map[uint32]*streamSendBuffer),
		capacity: capacity,
	}
}

func (sb *SendBuffer) getOrCreateStream(streamID uint32) *streamSendBuffer {
	// Caller must hold sb.mu
	if stream := sb.streams[streamID]; stream != nil {
		return stream
	}
	stream := newStreamSendBuffer()
	sb.streams[streamID] = stream
	return stream
}

// =============================================================================
// Queue data for sending
// =============================================================================

// QueueData adds data to the stream's send queue.
// Returns bytes queued and status (may be partial if buffer full).
func (sb *SendBuffer) QueueData(streamID uint32, userData []byte) (n int, status InsertStatus) {
	if len(userData) == 0 {
		return 0, InsertStatusNoData
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	remaining := sb.capacity - sb.size
	if remaining == 0 {
		return 0, InsertStatusSndFull
	}

	chunk := userData
	status = InsertStatusOk
	if len(userData) > remaining {
		chunk = userData[:remaining]
		status = InsertStatusSndFull
	}

	stream := sb.getOrCreateStream(streamID)
	stream.queuedData = append(stream.queuedData, chunk...)
	sb.size += len(chunk)

	return len(chunk), status
}

func (sb *SendBuffer) QueuePing(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.getOrCreateStream(streamID).pingRequested = true
}

// =============================================================================
// Send - Get next packet to transmit
// =============================================================================

// readyToSend returns the next packet to send for the stream.
// Returns nil if nothing to send. Moves data from queue to in-flight.
func (sb *SendBuffer) readyToSend(streamID uint32, msgType cryptoMsgType, ack *Ack, mtu int) (
	data []byte, offset uint64, isClose bool) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false
	}

	// Priority 1: Ping request
	if stream.pingRequested {
		stream.pingRequested = false
		key := createPacketKey(stream.bytesSentOffset, 0)
		stream.inFlight.Put(key, &sendPacket{isPing: true})
		return []byte{}, 0, false
	}

	// Priority 2: Queued data
	if len(stream.queuedData) > 0 {
		return sb.sendQueuedData(stream, msgType, ack, mtu)
	}

	// Priority 3: Standalone FIN (no more data, but need to send close)
	if stream.closeAtOffset != nil &&
		stream.bytesSentOffset >= *stream.closeAtOffset &&
		!stream.closeSent {

		closeKey := createPacketKey(stream.bytesSentOffset, 0)
		if stream.inFlight.Contains(closeKey) {
			return nil, 0, false
		}

		stream.closeSent = true
		stream.inFlight.Put(closeKey, &sendPacket{isClose: true})
		return []byte{}, closeKey.offset(), true
	}

	return nil, 0, false
}

func (sb *SendBuffer) sendQueuedData(stream *streamSendBuffer, msgType cryptoMsgType, ack *Ack, mtu int) (
	data []byte, offset uint64, isClose bool) {

	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, stream.bytesSentOffset)
		if overhead > mtu {
			return nil, 0, false
		}
		maxData = mtu - overhead
	}

	length := min(uint64(maxData), uint64(len(stream.queuedData)))
	data = stream.queuedData[:length]
	key := createPacketKey(stream.bytesSentOffset, uint16(length))

	// Check if this packet includes FIN
	if stream.closeAtOffset != nil {
		packetEnd := stream.bytesSentOffset + length
		if packetEnd >= *stream.closeAtOffset {
			isClose = true
			stream.closeSent = true
		}
	}

	stream.inFlight.Put(key, &sendPacket{data: data, isClose: isClose})
	stream.queuedData = stream.queuedData[length:]
	stream.bytesSentOffset += length

	return data, key.offset(), isClose
}

// =============================================================================
// Retransmit - Resend expired packets
// =============================================================================

// readyToRetransmit returns expired in-flight data for retransmission.
// May split packets if MTU decreased. Increments retry counter.
func (sb *SendBuffer) readyToRetransmit(
	streamID uint32, ack *Ack, mtu int,
	baseRTO uint64, msgType cryptoMsgType, nowNano uint64,
) (data []byte, offset uint64, isClose bool, err error) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false, nil
	}

	key, pkt, ok := stream.inFlight.First()
	if !ok {
		return nil, 0, false, nil
	}

	rtoWithBackoff, err := backoff(baseRTO, pkt.sentCount)
	if err != nil {
		return nil, 0, false, err
	}

	// Not expired yet
	if nowNano-pkt.sentTimeNano <= rtoWithBackoff {
		return nil, 0, false, nil
	}

	// Ping packets: just remove, don't retransmit
	if pkt.isPing {
		stream.inFlight.Remove(key)
		return nil, 0, false, nil
	}

	// Calculate max data for current MTU
	maxData := 0
	if msgType != InitSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, key.offset())
		if overhead > mtu {
			return nil, 0, false, errors.New("overhead larger than MTU")
		}
		maxData = mtu - overhead
	}

	// Fits in current MTU - just retransmit
	if len(pkt.data) <= maxData {
		pkt.sentTimeNano = nowNano
		pkt.sentCount++
		return pkt.data, key.offset(), pkt.isClose, nil
	}

	// Need to split packet (MTU decreased)
	return sb.splitAndRetransmit(stream, key, pkt, maxData, nowNano)
}

func (sb *SendBuffer) splitAndRetransmit(
	stream *streamSendBuffer, key packetKey, pkt *sendPacket,
	maxData int, nowNano uint64,
) ([]byte, uint64, bool, error) {

	leftData := pkt.data[:maxData]
	rightData := pkt.data[maxData:]

	// Left part: new entry
	leftKey := createPacketKey(key.offset(), uint16(maxData))
	stream.inFlight.Put(leftKey, &sendPacket{
		data:         leftData,
		sentTimeNano: nowNano,
		sentCount:    pkt.sentCount + 1,
	})

	// Right part: replace original
	rightKey := createPacketKey(key.offset()+uint64(maxData), uint16(len(rightData)))
	pkt.data = rightData
	stream.inFlight.Replace(key, rightKey, pkt)

	return leftData, key.offset(), false, nil
}

// =============================================================================
// Acknowledgment
// =============================================================================

// AcknowledgeRange processes an ACK for a sent packet.
// Returns timing info for RTT measurement.
func (sb *SendBuffer) AcknowledgeRange(ack *Ack) (status AckStatus, sentTimeNano uint64, packetSize uint16) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[ack.streamID]
	if stream == nil {
		return AckNotFound, 0, 0
	}

	key := createPacketKey(ack.offset, ack.len)
	pkt, ok := stream.inFlight.Remove(key)
	if !ok {
		return AckDup, 0, 0
	}

	sb.size -= len(pkt.data)
	return AckStatusOk, pkt.sentTimeNano, pkt.packetSize
}

// UpdatePacketSize records encrypted size after packet is built (for RTT measurement).
func (sb *SendBuffer) UpdatePacketSize(streamID uint32, offset uint64, length, packetSize uint16, nowNano uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return
	}

	key := createPacketKey(offset, length)
	if pkt, ok := stream.inFlight.Get(key); ok {
		pkt.packetSize = packetSize
		pkt.sentTimeNano = nowNano
	}
}

// =============================================================================
// Stream lifecycle
// =============================================================================

func (sb *SendBuffer) Close(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamID)
	if stream.closeAtOffset == nil {
		offset := stream.bytesSentOffset + uint64(len(stream.queuedData))
		stream.closeAtOffset = &offset
	}
}

func (sb *SendBuffer) RemoveStream(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	delete(sb.streams, streamID)
}

func (sb *SendBuffer) CheckStreamFullyAcked(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil || stream.closeAtOffset == nil {
		return false
	}

	// Must have no in-flight data AND sent up to close offset
	_, _, hasInFlight := stream.inFlight.First()
	return !hasInFlight && stream.bytesSentOffset >= *stream.closeAtOffset
}

func (sb *SendBuffer) GetOffsetAcked(streamID uint32) uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}

	// Acked offset is where in-flight begins (everything before is acked)
	if firstKey, _, ok := stream.inFlight.First(); ok {
		return firstKey.offset()
	}
	return stream.bytesSentOffset
}

func (sb *SendBuffer) GetOffsetClosedAt(streamID uint32) *uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if stream := sb.streams[streamID]; stream != nil {
		return stream.closeAtOffset
	}
	return nil
}