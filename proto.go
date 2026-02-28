package qotp

import (
	"errors"
	"math/bits"
)

// =============================================================================
// Transport layer protocol encoding/decoding
//
// Header byte:
//   Bit 0:    hasAck
//   Bit 1:    extend (48-bit offsets)
//   Bit 2:    needsReTx
//   Bits 3-5: packet type (0=data, 1=mtuUpdate, 2=close, 3=keyUpdate,
//             4=keyUpdateAck, 5=close+KU, 6=close+KUAck, 7=close+KU+KUAck)
//   Bits 6-7: reserved
// =============================================================================

const (
	minProtoSize = 8

	// Header byte layout:
	//   Bit 0:   hasAck
	//   Bit 1:   extend (48-bit offsets)
	//   Bit 2:   needsReTx
	//   Bits 3-5: packet type (3 bits)
	//   Bits 6-7: reserved

	flagHasAck    = 1 << 0
	flagExtend    = 1 << 1
	flagNeedsReTx = 1 << 2

	// Packet type (bits 3-5)
	pktTypeShift = 3
	pktTypeMask  = 0x7 << pktTypeShift // 0b00111000

	pktData         = 0 // plain data
	pktMtuUpdate    = 1
	pktClose        = 2
	pktKeyUpdate    = 3
	pktKeyUpdateAck = 4
	pktKUBoth       = 5 // keyUpdate + keyUpdateAck
	pktCloseKU      = 6 // close + keyUpdate
	pktCloseKUAck   = 7 // close + keyUpdateAck
	// Note: close + keyUpdate + keyUpdateAck not encoded (not a valid state)
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	hasAck          bool
	isMtuUpdate     bool
	mtuUpdateValue  uint16 // max UDP payload when isMtuUpdate
	isClose         bool
	isKeyUpdate     bool
	isKeyUpdateAck  bool
	keyUpdatePub    []byte // 32 bytes when isKeyUpdate
	keyUpdatePubAck []byte // 32 bytes when isKeyUpdate
	needsReTx       bool
	ack             *ack
	streamId        uint32
	streamOffset    uint64
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
// Packet type encoding
// =============================================================================

func encodePktType(isMtuUpdate, isClose, isKeyUpdate, isKeyUpdateAck bool) uint8 {
	switch {
	case isMtuUpdate:
		return pktMtuUpdate
	case isClose && isKeyUpdate:
		return pktCloseKU
	case isClose && isKeyUpdateAck:
		return pktCloseKUAck
	case isClose:
		return pktClose
	case isKeyUpdate && isKeyUpdateAck:
		return pktKUBoth
	case isKeyUpdate:
		return pktKeyUpdate
	case isKeyUpdateAck:
		return pktKeyUpdateAck
	default:
		return pktData
	}
}

func decodePktType(pktType uint8) (isMtuUpdate, isClose, isKeyUpdate, isKeyUpdateAck bool) {
	switch pktType {
	case pktMtuUpdate:
		return true, false, false, false
	case pktClose:
		return false, true, false, false
	case pktKeyUpdate:
		return false, false, true, false
	case pktKeyUpdateAck:
		return false, false, false, true
	case pktKUBoth:
		return false, false, true, true
	case pktCloseKU:
		return false, true, true, false
	case pktCloseKUAck:
		return false, true, false, true
	default:
		return false, false, false, false
	}
}

// =============================================================================
// Encode
// =============================================================================

func encodeProto(p *payloadHeader, userData []byte) ([]byte, int) {
	isExtend := p.streamOffset > 0xFFFFFF || (p.ack != nil && p.ack.offset > 0xFFFFFF)

	pktType := encodePktType(p.isMtuUpdate, p.isClose, p.isKeyUpdate, p.isKeyUpdateAck)

	// Stream header (streamId+offset) included when:
	// - any control packet type, OR
	// - has user data, OR
	// - no ACK (for minimum packet size)
	hasStreamHeader := pktType != pktData || userData != nil || p.ack == nil

	// Build flags
	var flags uint8
	if p.ack != nil {
		flags |= flagHasAck
	}
	if isExtend {
		flags |= flagExtend
	}
	if p.needsReTx {
		flags |= flagNeedsReTx
	}
	flags |= pktType << pktTypeShift

	overhead := calcProtoOverheadWithStream(flags, hasStreamHeader)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = flags
	offset++

	if flags&flagHasAck != 0 {
		offset += putUint32(encoded[offset:], p.ack.streamId)
		offset += putOffsetVarint(encoded[offset:], p.ack.offset, isExtend)
		offset += putUint16(encoded[offset:], p.ack.len)
		encoded[offset] = encodeRcvWindow(p.ack.rcvWnd)
		offset++
	}

	if p.isMtuUpdate {
		offset += putUint16(encoded[offset:], p.mtuUpdateValue)
	}

	if p.isKeyUpdate {
		copy(encoded[offset:], p.keyUpdatePub)
		offset += pubKeySize
	}

	if p.isKeyUpdateAck {
		copy(encoded[offset:], p.keyUpdatePubAck)
		offset += pubKeySize
	}

	if hasStreamHeader {
		offset += putUint32(encoded[offset:], p.streamId)
		offset += putOffsetVarint(encoded[offset:], p.streamOffset, isExtend)
	}

	offset += copy(encoded[offset:], userData)
	return encoded, offset
}

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < 1 {
		return nil, nil, errors.New("payload too small")
	}

	flags := data[0]
	isExtend := flags&flagExtend != 0
	pktType := (flags & pktTypeMask) >> pktTypeShift
	isMtuUpdate, isClose, isKeyUpdate, isKeyUpdateAck := decodePktType(pktType)

	p := &payloadHeader{
		hasAck:         flags&flagHasAck != 0,
		isMtuUpdate:    isMtuUpdate,
		isClose:        isClose,
		isKeyUpdate:    isKeyUpdate,
		isKeyUpdateAck: isKeyUpdateAck,
		needsReTx:      flags&flagNeedsReTx != 0,
	}
	offset := 1

	if p.hasAck {
		if len(data) < offset+10 {
			return nil, nil, errors.New("payload too small for ack")
		}
		p.ack = &ack{
			streamId: getUint32(data[offset:]),
		}
		offset += 4
		p.ack.offset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		p.ack.len = getUint16(data[offset:])
		offset += 2
		p.ack.rcvWnd = decodeRcvWindow(data[offset])
		offset++
	}

	if p.isMtuUpdate {
		if len(data) < offset+2 {
			return nil, nil, errors.New("payload too small for mtuUpdate")
		}
		p.mtuUpdateValue = getUint16(data[offset:])
		offset += 2
	}

	if p.isKeyUpdate {
		if len(data) < offset+pubKeySize {
			return nil, nil, errors.New("payload too small for keyUpdate")
		}
		p.keyUpdatePub = data[offset : offset+pubKeySize]
		offset += pubKeySize
	}

	if p.isKeyUpdateAck {
		if len(data) < offset+pubKeySize {
			return nil, nil, errors.New("payload too small for keyUpdateAck")
		}
		p.keyUpdatePubAck = data[offset : offset+pubKeySize]
		offset += pubKeySize
	}

	hasStreamHeader := pktType != pktData || !p.hasAck || len(data) > offset

	if hasStreamHeader {
		streamHeaderSize := 4 + offsetSize(isExtend)
		if len(data) < offset+streamHeaderSize {
			return nil, nil, errors.New("payload too small for stream header")
		}
		p.streamId = getUint32(data[offset:])
		offset += 4
		p.streamOffset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
	}

	var userData []byte
	if hasStreamHeader {
		userData = data[offset:]
	}

	return p, userData, nil
}

// =============================================================================
// Overhead calculation
// =============================================================================

func calcProtoOverheadWithStream(flags uint8, hasStreamHeader bool) int {
	overhead := 1 // header

	isExtend := flags&flagExtend != 0
	offsetBytes := 3
	if isExtend {
		offsetBytes = 6
	}

	if flags&flagHasAck != 0 {
		overhead += 4 + offsetBytes + 2 + 1 // streamId + offset + len + rcvWnd
	}

	pktType := (flags & pktTypeMask) >> pktTypeShift
	isMtuUpdate, _, isKeyUpdate, isKeyUpdateAck := decodePktType(pktType)

	if isMtuUpdate {
		overhead += 2 // mtuUpdateValue
	}

	if isKeyUpdate {
		overhead += pubKeySize
	}

	if isKeyUpdateAck {
		overhead += pubKeySize
	}

	if hasStreamHeader {
		overhead += 4 + offsetBytes // streamId + offset
	}

	return overhead
}

func calcProtoOverhead(flags uint8) int {
	pktType := (flags & pktTypeMask) >> pktTypeShift
	// Stream header present if any control packet type or no ACK
	hasStreamHeader := pktType != pktData || flags&flagHasAck == 0
	return calcProtoOverheadWithStream(flags, hasStreamHeader)
}
