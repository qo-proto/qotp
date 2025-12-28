package qotp

import (
	"errors"
	"math/bits"
)

const (
	ProtoVersion     = 0
	TypeFlag         = 5
	Offset24or48Flag = 7
	MinProtoSize     = 8
)

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

/*
encoded | capacity
--------|----------
0       | 0B
1       | 128B
2       | 256B
3       | 288B
4       | 320B
5       | 352B
6       | 384B
10      | 512B
18      | 1KB
50      | 16KB
100     | 1MB
150     | 96MB
200     | 7GB
250     | 512GB
255     | ~896GB+ (max)
*/

func encodeRcvWindow(actualBytes uint64) uint8 {
	if actualBytes == 0 {
		return 0
	}
	if actualBytes <= 255 {
		return 1
	}

	highBit := bits.Len64(actualBytes) - 1
	lowerBits := (actualBytes >> (highBit - 3)) & 0x7 // 8 substeps

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

func encodeProto(p *payloadHeader, userData []byte) (encoded []byte, offset int) {
	isAck := p.Ack != nil
	isEmptyDataHeader := !p.IsClose && isAck && userData == nil

	// Build header byte
	header := uint8(ProtoVersion)
	switch {
	case p.IsClose && isAck:
		header |= 0b10 << TypeFlag
	case p.IsClose:
		header |= 0b11 << TypeFlag
	case isAck:
		header |= 0b00 << TypeFlag
	default:
		header |= 0b01 << TypeFlag
	}

	// Determine if 48-bit offset needed
	isExtend := p.StreamOffset > 0xffffff || (isAck && p.Ack.offset > 0xffffff)
	if isExtend {
		header |= 1 << Offset24or48Flag
	}

	// Allocate buffer
	overhead := calcProtoOverhead(isAck, isExtend, isEmptyDataHeader)
	userDataLen := len(userData)
	encoded = make([]byte, overhead+userDataLen)

	// Write header
	encoded[offset] = header
	offset++

	// Write ACK section if present
	if isAck {
		offset += PutUint32(encoded[offset:], p.Ack.streamID)
		offset += putOffsetVarint(encoded[offset:], p.Ack.offset, isExtend)
		offset += PutUint16(encoded[offset:], p.Ack.len)
		encoded[offset] = encodeRcvWindow(p.Ack.rcvWnd)
		offset++
	}

	if isEmptyDataHeader {
		return encoded, offset
	}

	// Write Data
	offset += PutUint32(encoded[offset:], p.StreamID)
	offset += putOffsetVarint(encoded[offset:], p.StreamOffset, isExtend)

	if userDataLen > 0 {
		offset += copy(encoded[offset:], userData)
	}

	return encoded, offset
}

func decodeProto(data []byte) (payload *payloadHeader, userData []byte, err error) {
	dataLen := len(data)
	if dataLen < MinProtoSize {
		return nil, nil, errors.New("payload size below minimum")
	}

	payload = &payloadHeader{}

	// Decode header byte
	header := data[0]
	version := header & 0b11111
	typeFlag := (header >> TypeFlag) & 0b11
	isExtend := (header & (1 << Offset24or48Flag)) != 0

	// Validate version
	if version != ProtoVersion {
		return nil, nil, errors.New("unsupported protocol version")
	}

	// Decode type flags
	isAck := typeFlag == 0b00 || typeFlag == 0b10
	payload.IsClose = typeFlag == 0b10 || typeFlag == 0b11
	isEmptyDataHeader := isAck && dataLen < 18

	offset := 1

	// Check overhead
	overhead := calcProtoOverhead(isAck, isExtend, isEmptyDataHeader)
	if dataLen < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	// Decode ACK if present
	if isAck {
		payload.Ack = &Ack{}
		payload.Ack.streamID = Uint32(data[offset:])
		offset += 4
		payload.Ack.offset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)
		payload.Ack.len = Uint16(data[offset:])
		offset += 2
		payload.Ack.rcvWnd = decodeRcvWindow(data[offset])
		offset++
	}

	// Decode Data
	if !isEmptyDataHeader {
		payload.StreamID = Uint32(data[offset:])
		offset += 4
		payload.StreamOffset = offsetVarint(data[offset:], isExtend)
		offset += offsetSize(isExtend)

		if dataLen > offset {
			userData = data[offset:]
		} else {
			userData = make([]byte, 0) //ping
		}
	} else {
		userData = nil
	}

	return payload, userData, nil
}

func calcProtoOverhead(isAck bool, isExtend bool, isEmptyDataHeader bool) int {
	overhead := 1 // 1 byte header, always

	extBytes := 3 // 24-bit base
	if isExtend {
		extBytes = 6 // 48-bit
	}

	if !isEmptyDataHeader {
		overhead += 4 + extBytes // streamID + offset
	}

	if isAck {
		overhead += 4 + extBytes + 2 + 1 // streamID + offset + len + rcvWnd
	}

	return overhead
}
