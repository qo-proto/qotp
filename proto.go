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
//   Bit 4: keyUpdate        32-byte pubkey present
//   Bit 5: keyUpdateAck     32-byte pubkey present
//   Bits 6-7: reserved
//
// Wire layout: [flags][maxPayload][rcvWnd][ack?][keyPub?][keyPubAck?][streamId+offset?][data]
//
// Stream reliability rides the high bit of the wire streamId rather than a
// flag, so every packet of a best-effort stream carries it — a once-announced
// flag could be lost, and best-effort data is never retransmitted.
//
// maxPayload and rcvWnd are unconditional so a path MTU change or a receive
// buffer that drained reaches the peer on the next packet, with no "already
// announced" state to keep. rcvWnd in particular describes the whole
// connection's buffer, so it does not belong inside a per-stream ACK block:
// there it would travel only when that one stream was being acknowledged, and
// a sender blocked on a stale window has nothing to acknowledge.
// =============================================================================

const (
	// flags + maxPayload + rcvWnd + streamId + 24-bit offset
	minProtoSize = 1 + 2 + 1 + 4 + 3

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
	maxPayload uint16 // sender's max UDP payload; always present
	rcvWnd     uint64 // free space in the connection's receive buffer; always present
	isClose    bool
	// A key update is present exactly when its public key is. The wire flag
	// means "32 bytes follow", so the key's length is the only truth there is
	// -- a separate bool could disagree with it.
	keyUpdatePub    []byte // 32 bytes to announce a new ephemeral key
	keyUpdatePubAck []byte // 32 bytes to answer the peer's
	unreliable      bool   // best-effort stream: sender never retransmits its data
	ack             *ack
	streamId        uint32
	streamOffset    uint64
}

type ack struct {
	streamId uint32
	offset   uint64
	len      uint16
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

func encodeProto(p *payloadHeader, userData []byte) []byte {
	isExtend := p.streamOffset > 0xFFFFFF || (p.ack != nil && p.ack.offset > 0xFFFFFF)

	// Stream header (streamId+offset) included when:
	// - any control flag set, OR
	// - has user data (empty userData = ping), OR
	// - no ACK (for minimum packet size)
	hasKeyUpdate := len(p.keyUpdatePub) == pubKeySize
	hasKeyUpdateAck := len(p.keyUpdatePubAck) == pubKeySize
	hasStreamHeader := p.isClose || hasKeyUpdate || hasKeyUpdateAck ||
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
	if hasKeyUpdate {
		flags |= flagKeyUpdate
	}
	if hasKeyUpdateAck {
		flags |= flagKeyUpdateAck
	}

	overhead := calcProtoOverhead(flags)
	encoded := make([]byte, overhead+len(userData))
	offset := 0

	encoded[offset] = flags
	offset++
	offset += putUint16(encoded[offset:], p.maxPayload)
	encoded[offset] = encodeRcvWindow(p.rcvWnd)
	offset++

	if flags&flagHasAck != 0 {
		offset += putUint32(encoded[offset:], p.ack.streamId)
		offset += putOffsetVarint(encoded[offset:], p.ack.offset, isExtend)
		offset += putUint16(encoded[offset:], p.ack.len)
	}

	if hasKeyUpdate {
		offset += copy(encoded[offset:], p.keyUpdatePub)
	}

	if hasKeyUpdateAck {
		offset += copy(encoded[offset:], p.keyUpdatePubAck)
	}

	if hasStreamHeader {
		wireStreamId := p.streamId
		if p.unreliable {
			wireStreamId |= streamUnreliableBit
		}
		offset += putUint32(encoded[offset:], wireStreamId)
		offset += putOffsetVarint(encoded[offset:], p.streamOffset, isExtend)
	}

	copy(encoded[offset:], userData)
	return encoded
}

// =============================================================================
// Decode
// =============================================================================

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < 4 {
		return nil, nil, errors.New("payload too small")
	}

	flags := data[0]
	isExtend := flags&flagExtend != 0

	p := &payloadHeader{
		maxPayload: getUint16(data[1:]),
		rcvWnd:     decodeRcvWindow(data[3]),
		isClose:    flags&flagClose != 0,
	}
	offset := 4

	if flags&flagHasAck != 0 {
		ackSize := 4 + offsetSize(isExtend) + 2 // streamId + offset + len
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
	}

	if flags&flagKeyUpdate != 0 {
		if len(data) < offset+pubKeySize {
			return nil, nil, errors.New("payload too small for keyUpdate")
		}
		p.keyUpdatePub = data[offset : offset+pubKeySize]
		offset += pubKeySize
	}

	if flags&flagKeyUpdateAck != 0 {
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
	overhead := 1 + 2 + 1 // flags + maxPayload + rcvWnd

	offsetBytes := 3
	if flags&flagExtend != 0 {
		offsetBytes = 6
	}

	if flags&flagHasAck != 0 {
		overhead += 4 + offsetBytes + 2 // streamId + offset + len
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
