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

type insertStatus int

const (
	insertStatusOk insertStatus = iota
	insertStatusSndFull
	insertStatusNoData
)

type ackStatus int

const (
	ackStatusOk ackStatus = iota
	ackNotFound
	ackDup
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
	data           []byte
	packetSize     uint16 // Encrypted packet size (for RTT measurement)
	sentTimeNano   uint64
	sentCount      uint // Number of transmission attempts
	isPing         bool
	isClose        bool
	isKeyUpdate    bool
	isKeyUpdateAck bool
	needsReTx      bool
}

// =============================================================================
// Connection-level send buffer (manages all streams)
// =============================================================================

type sender struct {
	streams  map[uint32]*transmitBuffer
	capacity int
	size     int // Total queued bytes across all streams
	mu       sync.Mutex
}

func newSendBuffer(capacity int) *sender {
	return &sender{
		streams:  make(map[uint32]*transmitBuffer),
		capacity: capacity,
	}
}

func (sb *sender) getOrCreateStream(streamID uint32) *transmitBuffer {
	// Caller must hold sb.mu
	if stream := sb.streams[streamID]; stream != nil {
		return stream
	}
	stream := newStreamSendBuffer()
	sb.streams[streamID] = stream
	return stream
}

// =============================================================================
// Per-stream send buffer
// =============================================================================

type transmitBuffer struct {
	inFlight        *linkedMap[packetKey, *sendPacket]
	queuedData      []byte
	bytesSentOffset uint64  // Next offset to send
	pingRequested   bool    // Pending ping request
	closeAtOffset   *uint64 // Stream closes at this offset
	closeSent       bool    // FIN packet has been sent
}

func newStreamSendBuffer() *transmitBuffer {
	return &transmitBuffer{inFlight: newLinkedMap[packetKey, *sendPacket]()}
}

// =============================================================================
// Queue data for sending
// =============================================================================

// queueData adds data to the stream's send queue.
// Returns bytes queued and status (may be partial if buffer full).
func (sb *sender) queueData(streamID uint32, userData []byte) (n int, status insertStatus) {
	if len(userData) == 0 {
		return 0, insertStatusNoData
	}

	sb.mu.Lock()
	defer sb.mu.Unlock()

	remaining := sb.capacity - sb.size
	if remaining == 0 {
		return 0, insertStatusSndFull
	}

	chunk := userData
	status = insertStatusOk
	if len(userData) > remaining {
		chunk = userData[:remaining]
		status = insertStatusSndFull
	}

	stream := sb.getOrCreateStream(streamID)
	stream.queuedData = append(stream.queuedData, chunk...)
	sb.size += len(chunk)

	return len(chunk), status
}

func (sb *sender) queuePing(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.getOrCreateStream(streamID).pingRequested = true
}

// =============================================================================
// Send - Get next packet to transmit
// =============================================================================

// readyToSend returns the next packet to send for the stream.
// Returns nil if nothing to send. Moves data from queue to in-flight.
func (sb *sender) readyToSend(streamID uint32, msgType cryptoMsgType, ack *ack, mtu int, isKeyUpdate, isKeyUpdateAck bool) (
	data []byte, offset uint64, isClose bool) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false
	}

	// Priority 1: Ping request
	if stream.pingRequested && !(isKeyUpdate || isKeyUpdateAck) {
		stream.pingRequested = false
		key := createPacketKey(stream.bytesSentOffset, 0)
		//
		stream.inFlight.put(key, &sendPacket{isPing: true, isKeyUpdate: isKeyUpdate, isKeyUpdateAck: isKeyUpdateAck, needsReTx: false})
		return []byte{}, 0, false
	}

	// Priority 2: Queued data
	if len(stream.queuedData) > 0 {
		return sb.sendQueuedData(stream, msgType, ack, mtu, isKeyUpdate, isKeyUpdateAck)
	}

	// Priority 3: Standalone FIN (no more data, but need to send close)
	if stream.closeAtOffset != nil &&
		stream.bytesSentOffset >= *stream.closeAtOffset &&
		!stream.closeSent {

		closeKey := createPacketKey(stream.bytesSentOffset, 0)
		if stream.inFlight.contains(closeKey) {
			return nil, 0, false
		}

		stream.closeSent = true
		stream.inFlight.put(closeKey, &sendPacket{isClose: true, isKeyUpdate: isKeyUpdate, isKeyUpdateAck: isKeyUpdateAck, needsReTx: true})
		return []byte{}, closeKey.offset(), true
	}

	// Priority 4: KEY_UPDATE/KEY_UPDATE_ACK without data - needs tracking
	if isKeyUpdate || isKeyUpdateAck {
		key := createPacketKey(stream.bytesSentOffset, 0)
		if !stream.inFlight.contains(key) {
			stream.inFlight.put(key, &sendPacket{
				isKeyUpdate:    isKeyUpdate,
				isKeyUpdateAck: isKeyUpdateAck,
				needsReTx:      true,
				data:           []byte{},
			})
			return []byte{}, stream.bytesSentOffset, false
		}
	}

	return nil, 0, false
}

func (sb *sender) sendQueuedData(stream *transmitBuffer, msgType cryptoMsgType, ack *ack, mtu int, isKeyUpdate, isKeyUpdateAck bool) (
	data []byte, offset uint64, isClose bool) {

	maxData := 0
	if msgType != initSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, stream.bytesSentOffset, isKeyUpdate, isKeyUpdateAck)
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

	needsReTx := len(data) > 0 || isClose || isKeyUpdate || isKeyUpdateAck
	stream.inFlight.put(key, &sendPacket{data: data, isClose: isClose, isKeyUpdate: isKeyUpdate, isKeyUpdateAck: isKeyUpdateAck, needsReTx: needsReTx})
	stream.queuedData = stream.queuedData[length:]
	stream.bytesSentOffset += length

	return data, key.offset(), isClose
}

// =============================================================================
// Retransmit - Resend expired packets
// =============================================================================

// readyToRetransmit returns expired in-flight data for retransmission.
// May split packets if MTU decreased. Increments retry counter.
func (sb *sender) readyToRetransmit(
	streamID uint32, ack *ack, mtu int,
	baseRTO uint64, msgType cryptoMsgType,
	nowNano uint64) (data []byte, offset uint64, isClose, isKeyUpdate, isKeyUpdateAck bool, err error) {

	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return nil, 0, false, false, false, nil
	}

	key, pkt, ok := stream.inFlight.first()
	if !ok {
		return nil, 0, false, false, false, nil
	}

	rtoWithBackoff, err := backoff(baseRTO, pkt.sentCount)
	if err != nil {
		return nil, 0, false, false, false, err
	}

	// Not expired yet
	if nowNano-pkt.sentTimeNano <= rtoWithBackoff {
		return nil, 0, false, false, false, nil
	}

	// Ping packets: just remove, don't retransmit
	if !pkt.needsReTx {
		stream.inFlight.remove(key)
		return nil, 0, false, false, false, nil
	}

	// Calculate max data for current MTU
	maxData := 0
	if msgType != initSnd {
		overhead := calcCryptoOverheadWithData(msgType, ack, key.offset(), pkt.isKeyUpdate, pkt.isKeyUpdateAck)
		if overhead > mtu {
			return nil, 0, false, false, false, errors.New("overhead larger than MTU")
		}
		maxData = mtu - overhead
	}

	// Fits in current MTU - just retransmit
	if len(pkt.data) <= maxData {
		pkt.sentTimeNano = nowNano
		pkt.sentCount++
		return pkt.data, key.offset(), pkt.isClose, pkt.isKeyUpdate, pkt.isKeyUpdateAck, nil
	}

	// Need to split packet (MTU decreased)
	return sb.splitAndRetransmit(stream, key, pkt, maxData, nowNano)
}

func (sb *sender) splitAndRetransmit(
	stream *transmitBuffer, key packetKey, pkt *sendPacket,
	maxData int, nowNano uint64,
) ([]byte, uint64, bool, bool, bool, error) {

	leftData := pkt.data[:maxData]
	rightData := pkt.data[maxData:]

	// Left part: new entry
	leftKey := createPacketKey(key.offset(), uint16(maxData))
	stream.inFlight.put(leftKey, &sendPacket{
		data:           leftData,
		sentTimeNano:   nowNano,
		sentCount:      pkt.sentCount + 1,
		isKeyUpdate:    pkt.isKeyUpdate,
		isKeyUpdateAck: pkt.isKeyUpdateAck,
		needsReTx:      pkt.needsReTx,
	})

	// Right part: replace original
	rightKey := createPacketKey(key.offset()+uint64(maxData), uint16(len(rightData)))
	pkt.data = rightData
	stream.inFlight.replace(key, rightKey, pkt)

	return leftData, key.offset(), false, pkt.isKeyUpdate, pkt.isKeyUpdateAck, nil
}

// =============================================================================
// Acknowledgment
// =============================================================================

// acknowledgeRange processes an ACK for a sent packet.
// Returns timing info for RTT measurement.
func (sb *sender) acknowledgeRange(ack *ack) (status ackStatus, sentTimeNano uint64, packetSize uint16) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[ack.streamId]
	if stream == nil {
		return ackNotFound, 0, 0
	}

	key := createPacketKey(ack.offset, ack.len)
	pkt, ok := stream.inFlight.remove(key)
	if !ok {
		return ackDup, 0, 0
	}

	sb.size -= len(pkt.data)
	return ackStatusOk, pkt.sentTimeNano, pkt.packetSize
}

// updatePacketSize records encrypted size after packet is built (for RTT measurement).
func (sb *sender) updatePacketSize(streamID uint32, offset uint64, length, packetSize uint16, nowNano uint64) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return
	}

	key := createPacketKey(offset, length)
	if pkt, ok := stream.inFlight.get(key); ok {
		pkt.packetSize = packetSize
		pkt.sentTimeNano = nowNano
	}
}

// =============================================================================
// Stream lifecycle
// =============================================================================

func (sb *sender) close(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.getOrCreateStream(streamID)
	if stream.closeAtOffset == nil {
		offset := stream.bytesSentOffset + uint64(len(stream.queuedData))
		stream.closeAtOffset = &offset
	}
}

func (sb *sender) removeStream(streamID uint32) {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	delete(sb.streams, streamID)
}

func (sb *sender) checkStreamFullyAcked(streamID uint32) bool {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil || stream.closeAtOffset == nil {
		return false
	}

	// Must have no in-flight data AND sent up to close offset
	_, _, hasInFlight := stream.inFlight.first()
	return !hasInFlight && stream.bytesSentOffset >= *stream.closeAtOffset
}

func (sb *sender) ensureKeyFlagsTracked(streamID uint32, isKeyUpdate, isKeyUpdateAck bool) uint64 {
    sb.mu.Lock()
    defer sb.mu.Unlock()
    
    stream := sb.getOrCreateStream(streamID)
    
    if isKeyUpdate || isKeyUpdateAck {
        key := createPacketKey(stream.bytesSentOffset, 0)
        if !stream.inFlight.contains(key) {
            stream.inFlight.put(key, &sendPacket{
                isKeyUpdate:    isKeyUpdate,
                isKeyUpdateAck: isKeyUpdateAck,
                needsReTx:      true,
            })
        }
    }
    
    return stream.bytesSentOffset
}

func (sb *sender) getOffsetAcked(streamID uint32) uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	stream := sb.streams[streamID]
	if stream == nil {
		return 0
	}

	// Acked offset is where in-flight begins (everything before is acked)
	if firstKey, _, ok := stream.inFlight.first(); ok {
		return firstKey.offset()
	}
	return stream.bytesSentOffset
}

func (sb *sender) getOffsetClosedAt(streamID uint32) *uint64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if stream := sb.streams[streamID]; stream != nil {
		return stream.closeAtOffset
	}
	return nil
}
