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
	ProtoVersion     = 0
	TypeFlag         = 5
	Offset24or48Flag = 7
	MinProtoSize     = 8
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	IsClose      bool
	Ack          *Ack
	StreamID     uint32
	StreamOffset uint64
}

type Ack struct {
	streamID uint32
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
	hasAck := p.Ack != nil
	// ACK-only packet: has ACK, no close, nil userData (not empty slice)
	isAckOnly := hasAck && !p.IsClose && userData == nil

	header := buildHeader(p.IsClose, hasAck, p.StreamOffset, p.Ack)
	isExtend := (header & (1 << Offset24or48Flag)) != 0

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = header
	offset++

	if hasAck {
		offset += PutUint32(encoded[offset:], p.Ack.streamID)
		offset += putOffsetVarint(encoded[offset:], p.Ack.offset, isExtend)
		offset += PutUint16(encoded[offset:], p.Ack.len)
		encoded[offset] = encodeRcvWindow(p.Ack.rcvWnd)
		offset++
	}

	if isAckOnly {
		return encoded, offset
	}

	offset += PutUint32(encoded[offset:], p.StreamID)
	offset += putOffsetVarint(encoded[offset:], p.StreamOffset, isExtend)
	offset += copy(encoded[offset:], userData)

	return encoded, offset
}

func buildHeader(isClose, hasAck bool, streamOffset uint64, ack *Ack) uint8 {
	header := uint8(ProtoVersion)

	// Type flags (bits 5-6)
	switch {
	case isClose && hasAck:
		header |= 0b10 << TypeFlag
	case isClose:
		header |= 0b11 << TypeFlag
	case hasAck:
		header |= 0b00 << TypeFlag
	default:
		header |= 0b01 << TypeFlag
	}

	// Offset size flag (bit 7)
	needsExtend := streamOffset > 0xFFFFFF || (hasAck && ack.offset > 0xFFFFFF)
	if needsExtend {
		header |= 1 << Offset24or48Flag
	}

	return header
}

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < MinProtoSize {
		return nil, nil, errors.New("payload size below minimum")
	}

	header := data[0]
	version := header & 0b11111
	if version != ProtoVersion {
		return nil, nil, errors.New("unsupported protocol version")
	}

	typeFlag := (header >> TypeFlag) & 0b11
	isExtend := (header & (1 << Offset24or48Flag)) != 0
	hasAck := typeFlag == 0b00 || typeFlag == 0b10
	isClose := typeFlag == 0b10 || typeFlag == 0b11
	isAckOnly := hasAck && len(data) < 18

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	if len(data) < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	payload := &payloadHeader{IsClose: isClose}
	offset := 1

	if hasAck {
		payload.Ack = &Ack{
			streamID: Uint32(data[offset:]),
		}
		offset += 4
		payload.Ack.offset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		payload.Ack.len = Uint16(data[offset:])
		offset += 2
		payload.Ack.rcvWnd = decodeRcvWindow(data[offset])
		offset++
	}

	var userData []byte
	if !isAckOnly {
		payload.StreamID = Uint32(data[offset:])
		offset += 4
		payload.StreamOffset = offsetVarint(data[offset:], isExtend)
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