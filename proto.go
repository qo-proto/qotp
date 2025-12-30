package qotp

import (
	"errors"
	"math/bits"
)

// =============================================================================
// Transport layer protocol encoding/decoding
//
// Payload format (after crypto layer decryption):
//   Byte 0:     Header (version + type + offset size flag)
//   [ACK]:      Optional ACK section (streamID, offset, len, rcvWnd)
//   [Data]:     Optional data section (streamID, offset, userData)
//
// Type encoding (bits 5-6):
//   00 = DATA with ACK
//   01 = DATA without ACK
//   10 = CLOSE with ACK
//   11 = CLOSE without ACK
//
// Offset sizes: 24-bit (≤16MB) or 48-bit (>16MB), signaled by bit 7
// =============================================================================

const (
	protoVersion     = 0
	typeFlag         = 5
	offset24or48Flag = 7
	minProtoSize     = 8
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	isClose      bool
	ack          *ack
	streamId     uint32
	streamOffset uint64
}

type ack struct {
	streamId uint32
	offset   uint64
	len      uint16
	rcvWnd   uint64
}

// =============================================================================
// Receive window encoding
//
// Logarithmic encoding: 8 substeps per power of 2
// Maps 0-255 to 0B-~896GB range
//
//	encoded | capacity
//	--------|----------
//	0       | 0B
//	1       | 128B
//	2       | 256B
//	10      | 512B
//	18      | 1KB
//	50      | 16KB
//	100     | 1MB
//	150     | 96MB
//	200     | 7GB
//	255     | ~896GB
//
// =============================================================================

func encodeRcvWindow(actualBytes uint64) uint8 {
	if actualBytes == 0 {
		return 0
	}
	if actualBytes <= 255 {
		return 1
	}

	highBit := bits.Len64(actualBytes) - 1
	lowerBits := (actualBytes >> (highBit - 3)) & 0x7

	encoded := (highBit-8)*8 + int(lowerBits) + 2
	if encoded > 255 {
		return 255
	}
	return uint8(encoded)
}

func decodeRcvWindow(encoded uint8) uint64 {
	if encoded == 0 {
		return 0
	}
	if encoded == 1 {
		return 128
	}

	adjusted := encoded - 2
	highBit := int(adjusted/8) + 8
	subStep := adjusted % 8

	base := uint64(1) << highBit
	increment := base / 8

	return base + uint64(subStep)*increment
}

// =============================================================================
// Encode
// =============================================================================

func encodeProto(p *payloadHeader, userData []byte) ([]byte, int) {
	hasAck := p.ack != nil
	// ACK-only packet: has ACK, no close, nil userData (not empty slice)
	isAckOnly := hasAck && !p.isClose && userData == nil

	header := buildHeader(p.isClose, hasAck, p.streamOffset, p.ack)
	isExtend := (header & (1 << offset24or48Flag)) != 0

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = header
	offset++

	if hasAck {
		offset += putUint32(encoded[offset:], p.ack.streamId)
		offset += putOffsetVarint(encoded[offset:], p.ack.offset, isExtend)
		offset += putUint16(encoded[offset:], p.ack.len)
		encoded[offset] = encodeRcvWindow(p.ack.rcvWnd)
		offset++
	}

	if isAckOnly {
		return encoded, offset
	}

	offset += putUint32(encoded[offset:], p.streamId)
	offset += putOffsetVarint(encoded[offset:], p.streamOffset, isExtend)
	offset += copy(encoded[offset:], userData)

	return encoded, offset
}

func buildHeader(isClose, hasAck bool, streamOffset uint64, ack *ack) uint8 {
	header := uint8(protoVersion)

	// Type flags (bits 5-6)
	switch {
	case isClose && hasAck:
		header |= 0b10 << typeFlag
	case isClose:
		header |= 0b11 << typeFlag
	case hasAck:
		header |= 0b00 << typeFlag
	default:
		header |= 0b01 << typeFlag
	}

	// Offset size flag (bit 7)
	needsExtend := streamOffset > 0xFFFFFF || (hasAck && ack.offset > 0xFFFFFF)
	if needsExtend {
		header |= 1 << offset24or48Flag
	}

	return header
}

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < minProtoSize {
		return nil, nil, errors.New("payload size below minimum")
	}

	header := data[0]
	version := header & 0b11111
	if version != protoVersion {
		return nil, nil, errors.New("unsupported protocol version")
	}

	typeFlag := (header >> typeFlag) & 0b11
	isExtend := (header & (1 << offset24or48Flag)) != 0
	hasAck := typeFlag == 0b00 || typeFlag == 0b10
	isClose := typeFlag == 0b10 || typeFlag == 0b11
	isAckOnly := hasAck && len(data) < 18

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	if len(data) < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	payload := &payloadHeader{isClose: isClose}
	offset := 1

	if hasAck {
		payload.ack = &ack{
			streamId: getUint32(data[offset:]),
		}
		offset += 4
		payload.ack.offset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		payload.ack.len = getUint16(data[offset:])
		offset += 2
		payload.ack.rcvWnd = decodeRcvWindow(data[offset])
		offset++
	}

	var userData []byte
	if !isAckOnly {
		payload.streamId = getUint32(data[offset:])
		offset += 4
		payload.streamOffset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)

		if len(data) > offset {
			userData = data[offset:]
		} else {
			userData = []byte{} // PING packet
		}
	}

	return payload, userData, nil
}

// =============================================================================
// Overhead calculation
// =============================================================================

func calcProtoOverhead(hasAck, isExtend, isAckOnly bool) int {
	overhead := 1 // header byte

	offsetBytes := 3 // 24-bit
	if isExtend {
		offsetBytes = 6 // 48-bit
	}

	if !isAckOnly {
		overhead += 4 + offsetBytes // streamID + offset
	}

	if hasAck {
		overhead += 4 + offsetBytes + 2 + 1 // streamID + offset + len + rcvWnd
	}

	return overhead
}