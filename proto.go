package qotp

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// =============================================================================
// Transport layer encoding
//
// [flags][maxPayload][rcvWnd][ack?][keyPub?][keyPubAck?][streamId+offset?][data]
//
// maxPayload and rcvWnd are on every packet so an MTU change or a drained
// buffer reaches the peer without "already announced" state; a sender
// blocked on a stale window has nothing to acknowledge, so rcvWnd cannot
// live in the ACK block. Stream reliability rides the high bit of the wire
// streamId so every packet of a best-effort stream carries it: a
// once-announced flag could be lost and would never be retransmitted.
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

type payloadHeader struct {
	maxPayload      uint16 // sender's max UDP payload
	rcvWnd          uint64 // free space in the sender's receive buffer
	isClose         bool
	keyUpdatePub    []byte // present exactly when 32 bytes long
	keyUpdatePubAck []byte
	unreliable      bool
	ack             *ack
	streamId        uint32
	streamOffset    uint64
}

type ack struct {
	streamId uint32
	offset   uint64
	len      uint16
}

// The receive window is encoded logarithmically in one byte, 8 steps per
// power of two: 1 = 128B, 18 = 1KB, 100 = 1MB, 255 = about 896GB.

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

func encodeProto(p *payloadHeader, userData []byte) []byte {
	isExtend := p.streamOffset > 0xFFFFFF || (p.ack != nil && p.ack.offset > 0xFFFFFF)

	// The stream header is present with any control flag, with user data
	// (empty for a ping), or when there is no ACK either
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
	binary.LittleEndian.PutUint16(encoded[offset:], p.maxPayload)
	offset += 2
	encoded[offset] = encodeRcvWindow(p.rcvWnd)
	offset++

	if flags&flagHasAck != 0 {
		binary.LittleEndian.PutUint32(encoded[offset:], p.ack.streamId)
		offset += 4
		offset += putOffsetVarint(encoded[offset:], p.ack.offset, isExtend)
		binary.LittleEndian.PutUint16(encoded[offset:], p.ack.len)
		offset += 2
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
		binary.LittleEndian.PutUint32(encoded[offset:], wireStreamId)
		offset += 4
		offset += putOffsetVarint(encoded[offset:], p.streamOffset, isExtend)
	}

	copy(encoded[offset:], userData)
	return encoded
}

func decodeProto(data []byte) (*payloadHeader, []byte, error) {
	if len(data) < 4 {
		return nil, nil, errors.New("payload too small")
	}

	flags := data[0]
	isExtend := flags&flagExtend != 0

	p := &payloadHeader{
		maxPayload: binary.LittleEndian.Uint16(data[1:]),
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
			streamId: binary.LittleEndian.Uint32(data[offset:]),
		}
		offset += 4
		p.ack.offset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		p.ack.len = binary.LittleEndian.Uint16(data[offset:])
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
		wireStreamId := binary.LittleEndian.Uint32(data[offset:])
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
