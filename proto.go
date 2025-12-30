package qotp

import (
	"errors"
	"math/bits"
)

// =============================================================================
// Transport layer protocol encoding/decoding
//
// Header byte:
//   Bits 0-3: Protocol version (4 bits, currently 0)
//   Bits 4-7: Message type (4 bits)
// =============================================================================

const (
	protoVersion = 0
	typeShift    = 4
	minProtoSize = 8

	// Type values (bits 4-7)
	typeDataAck24    = 0b0000 // 0: DATA + ACK, 24-bit
	typeProbe24      = 0b0001 // 1: PROBE, 24-bit
	typeDataAck48    = 0b0010 // 2: DATA + ACK, 48-bit
	typeDataNoAck24  = 0b0100 // 4: DATA, 24-bit
	typeProbe48      = 0b0101 // 5: PROBE, 48-bit
	typeDataNoAck48  = 0b0110 // 6: DATA, 48-bit
	typeCloseAck24   = 0b1000 // 8: CLOSE + ACK, 24-bit
	typeCloseAck48   = 0b1010 // 10: CLOSE + ACK, 48-bit
	typeCloseNoAck24 = 0b1100 // 12: CLOSE, 24-bit
	typeCloseNoAck48 = 0b1110 // 14: CLOSE, 48-bit
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	isClose      bool
	isProbe      bool
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
	isExtend := p.streamOffset > 0xFFFFFF || (hasAck && p.ack.offset > 0xFFFFFF)
	isAckOnly := hasAck && !p.isClose && !p.isProbe && userData == nil

	// Build type from bits
	var ptype uint8
	if p.isProbe {
		ptype = 0b0001
		if isExtend {
			ptype |= 0b0100
		}
	} else {
		if p.isClose {
			ptype |= 0b1000
		}
		if !hasAck {
			ptype |= 0b0100
		}
		if isExtend {
			ptype |= 0b0010
		}
	}

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = protoVersion | (ptype << typeShift)
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

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < minProtoSize {
		return nil, nil, errors.New("payload size below minimum")
	}

	header := data[0]
	version := header & 0x0F
	if version != protoVersion {
		return nil, nil, errors.New("unsupported protocol version")
	}

	ptype := header >> typeShift
	isProbe := (ptype & 0b0001) != 0

	var isClose, hasAck, isExtend bool
	if isProbe {
		isExtend = (ptype & 0b0100) != 0
	} else {
		isClose = (ptype & 0b1000) != 0
		hasAck = (ptype & 0b0100) == 0
		isExtend = (ptype & 0b0010) != 0
	}

	isAckOnly := hasAck && !isClose && !isProbe && len(data) < 18

	overhead := calcProtoOverhead(hasAck, isExtend, isAckOnly)
	if len(data) < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	payload := &payloadHeader{isClose: isClose, isProbe: isProbe}
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
