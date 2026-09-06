package qotp

import (
	"errors"
	"math/bits"
)

// =============================================================================
// Transport layer protocol encoding/decoding
//
// Header byte: one independent flag per field.
//   Bit 0: hasAck        ACK block present
//   Bit 1: hasStream     streamId + streamOffset (+ userData) present
//   Bit 2: extend        48-bit offsets instead of 24-bit
//   Bit 3: isClose
//   Bit 4: isKeyUpdate      32-byte pubkey present
//   Bit 5: isKeyUpdateAck   32-byte pubkey present
//   Bits 6-7: reserved
//
// Wire layout: [flags][maxPayload][ack?][keyPub?][keyPubAck?][streamId+offset?][data]
//
// Stream reliability rides the high bit of the wire streamId rather than a
// flag, so every packet of a best-effort stream carries it — a once-announced
// flag could be lost, and best-effort data is never retransmitted.
//
// maxPayload is unconditional so a path MTU change reaches the peer on the
// next packet, with no "already announced" state to keep.
// =============================================================================

const (
	// flags + maxPayload + streamId + 24-bit offset
	minProtoSize = 1 + 2 + 4 + 3

	flagHasAck       = 1 << 0
	flagHasStream    = 1 << 1
	flagExtend       = 1 << 2
	flagClose        = 1 << 3
	flagKeyUpdate    = 1 << 4
	flagKeyUpdateAck = 1 << 5

	streamUnreliableBit uint32 = 1 << 31
	maxStreamID         uint32 = streamUnreliableBit - 1
)

// =============================================================================
// Types
// =============================================================================

type payloadHeader struct {
	maxPayload      uint16 // sender's max UDP payload; always present
	isClose         bool
	isKeyUpdate     bool
	isKeyUpdateAck  bool
	keyUpdatePub    []byte // 32 bytes when isKeyUpdate
	keyUpdatePubAck []byte // 32 bytes when isKeyUpdateAck
	unreliable      bool   // best-effort stream: sender never retransmits its data
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

	// Stream header (streamId+offset) included when:
	// - any control flag set, OR
	// - has user data (empty userData = ping), OR
	// - no ACK (for minimum packet size)
	hasStreamHeader := p.isClose || p.isKeyUpdate || p.isKeyUpdateAck ||
		userData != nil || p.ack == nil

	var flags uint8
	if p.ack != nil {
		flags |= flagHasAck
	}
	if hasStreamHeader {
		flags |= flagHasStream
	}
	if isExtend {
		flags |= flagExtend
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

	overhead := calcProtoOverhead(flags)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = flags
	offset++
	offset += putUint16(encoded[offset:], p.maxPayload)

	if flags&flagHasAck != 0 {
		offset += putUint32(encoded[offset:], p.ack.streamId)
		offset += putOffsetVarint(encoded[offset:], p.ack.offset, isExtend)
		offset += putUint16(encoded[offset:], p.ack.len)
		encoded[offset] = encodeRcvWindow(p.ack.rcvWnd)
		offset++
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
		wireStreamId := p.streamId
		if p.unreliable {
			wireStreamId |= streamUnreliableBit
		}
		offset += putUint32(encoded[offset:], wireStreamId)
		offset += putOffsetVarint(encoded[offset:], p.streamOffset, isExtend)
	}

	offset += copy(encoded[offset:], userData)
	return encoded, offset
}

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < 3 {
		return nil, nil, errors.New("payload too small")
	}

	flags := data[0]
	isExtend := flags&flagExtend != 0

	p := &payloadHeader{
		maxPayload:     getUint16(data[1:]),
		isClose:        flags&flagClose != 0,
		isKeyUpdate:    flags&flagKeyUpdate != 0,
		isKeyUpdateAck: flags&flagKeyUpdateAck != 0,
	}
	offset := 3

	if flags&flagHasAck != 0 {
		ackSize := 4 + offsetSize(isExtend) + 2 + 1 // streamId + offset + len + rcvWnd
		if len(data) < offset+ackSize {
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

	var userData []byte
	if flags&flagHasStream != 0 {
		streamHeaderSize := 4 + offsetSize(isExtend)
		if len(data) < offset+streamHeaderSize {
			return nil, nil, errors.New("payload too small for stream header")
		}
		wireStreamId := getUint32(data[offset:])
		p.unreliable = wireStreamId&streamUnreliableBit != 0
		p.streamId = wireStreamId &^ streamUnreliableBit
		offset += 4
		p.streamOffset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		userData = data[offset:]
	} else if len(data) > offset {
		return nil, nil, errors.New("trailing bytes without stream header")
	}

	return p, userData, nil
}

// =============================================================================
// Overhead calculation
// =============================================================================

func calcProtoOverhead(flags uint8) int {
	overhead := 1 + 2 // flags byte + maxPayload

	offsetBytes := 3
	if flags&flagExtend != 0 {
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

	if flags&flagHasStream != 0 {
		overhead += 4 + offsetBytes // streamId + offset
	}

	return overhead
}
