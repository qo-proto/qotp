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
	minProtoSize = 8

	// Flags (bits 0-6)
	flagHasAck       = 1 << 0
	flagExtend       = 1 << 1 // 48-bit offsets
	flagHasData      = 1 << 2 // stream data present
	flagProbe        = 1 << 3
	flagClose        = 1 << 4
	flagKeyUpdate    = 1 << 5
	flagKeyUpdateAck = 1 << 6
	flagNeedsReTx    = 1 << 7
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	hasAck          bool
	hasData         bool
	isProbe         bool
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
// Encode
// =============================================================================

func encodeProto(p *payloadHeader, userData []byte) ([]byte, int) {
	isExtend := p.streamOffset > 0xFFFFFF || (p.ack != nil && p.ack.offset > 0xFFFFFF)

	// Build flags
	var flags uint8
	if p.ack != nil {
		flags |= flagHasAck
	}
	if isExtend {
		flags |= flagExtend
	}
	if len(userData) > 0 || p.hasData {
		flags |= flagHasData
	}
	if p.isProbe {
		flags |= flagProbe
	}
	if p.isClose {
		flags |= flagClose
	}
	if p.isKeyUpdate {
		flags |= flagKeyUpdate
	}
	if p.isKeyUpdateAck {
		flags |= flagKeyUpdateAck
	}

	if len(userData) > 0 || p.hasData || p.isKeyUpdate || p.isKeyUpdateAck || p.isClose {
		flags |= flagNeedsReTx
	}

	overhead := calcProtoOverhead(flags)
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

	if flags&flagKeyUpdate != 0 {
		copy(encoded[offset:], p.keyUpdatePub)
		offset += pubKeySize
	}

	if flags&flagKeyUpdateAck != 0 {
		copy(encoded[offset:], p.keyUpdatePubAck)
		offset += pubKeySize
	}

	if flags&flagHasData != 0 || flags&flagProbe != 0 || flags&flagClose != 0 || flags&flagKeyUpdate != 0 || flags&flagKeyUpdateAck != 0 {
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
	overhead := calcProtoOverhead(flags)
	if len(data) < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	p := &payloadHeader{
		hasAck:         flags&flagHasAck != 0,
		hasData:        flags&flagHasData != 0,
		isProbe:        flags&flagProbe != 0,
		isClose:        flags&flagClose != 0,
		isKeyUpdate:    flags&flagKeyUpdate != 0,
		isKeyUpdateAck: flags&flagKeyUpdateAck != 0,
		needsReTx:      flags&flagNeedsReTx != 0,
	}
	offset := 1

	if p.hasAck {
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

	if p.isKeyUpdate {
		p.keyUpdatePub = data[offset : offset+pubKeySize]
		offset += pubKeySize
	}

	if p.isKeyUpdateAck {
		p.keyUpdatePubAck = data[offset : offset+pubKeySize]
		offset += pubKeySize
	}

	if p.hasData || p.isProbe || p.isClose || p.isKeyUpdate || p.isKeyUpdateAck {
		p.streamId = getUint32(data[offset:])
		offset += 4
		p.streamOffset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
	}

	var userData []byte
	if len(data) > offset {
		userData = data[offset:]
	}

	return p, userData, nil
}

// =============================================================================
// Overhead calculation
// =============================================================================

func calcProtoOverhead(flags uint8) int {
	overhead := 1 // header

	isExtend := flags&flagExtend != 0
	offsetBytes := 3
	if isExtend {
		offsetBytes = 6
	}

	if flags&flagHasAck != 0 {
		overhead += 4 + offsetBytes + 2 + 1 // streamId + offset + len + rcvWnd
	}

	if flags&flagKeyUpdate != 0 {
		overhead += pubKeySize
	}

	if flags&flagKeyUpdateAck != 0 {
		overhead += pubKeySize
	}

	if flags&flagHasData != 0 || flags&flagProbe != 0 || flags&flagClose != 0 || flags&flagKeyUpdate != 0 || flags&flagKeyUpdateAck != 0 {
		overhead += 4 + offsetBytes // streamId + offset
	}

	return overhead
}
