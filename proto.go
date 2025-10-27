package qotp

import (
	"errors"
	"log/slog"
	"math/bits"
)

const (
	ProtoVersion     = 0
	TypeFlag         = 4
	Offset24or48Flag = 6
	AckFlag          = 7
	MinProtoSize     = 8
)

type StreamMsgType uint8

const (
	MsgTypeData StreamMsgType = iota
	MsgTypePing
	MsgTypeClose
	MsgTypeReserved
	MsgTypeInvalid
)

type PayloadHeader struct {
	MsgType      StreamMsgType
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

func EncodeRcvWindow(actualBytes uint64) uint8 {
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

func DecodeRcvWindow(encoded uint8) uint64 {
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

func EncodePayload(p *PayloadHeader, userData []byte) (encoded []byte, offset int) {
	header := uint8(ProtoVersion) // bits 0-3

	// Determine type (bits 4-5)
	switch p.MsgType {
	case MsgTypePing:
		header |= 1 << TypeFlag // type = 01
	case MsgTypeClose:
		header |= 2 << TypeFlag // type = 10
		// case MsgTypeData: nothing to set (00)
	}

	// Determine if 48-bit offset needed
	isExtend := p.StreamOffset > 0xffffff
	if p.Ack != nil && p.Ack.offset > 0xffffff {
		isExtend = true
	}

	// Set flags
	isAck := p.Ack != nil
	if isExtend {
		header |= 1 << Offset24or48Flag
	}
	if isAck {
		header |= 1 << AckFlag
	}

	// Allocate buffer
	overhead := calcProtoOverhead(isAck, isExtend)
	userDataLen := len(userData)
	encoded = make([]byte, overhead+userDataLen)

	// Write header
	encoded[offset] = header
	offset++

	// Write ACK section if present
	if p.Ack != nil {
		offset += PutUint32(encoded[offset:], p.Ack.streamID)
		if isExtend {
			offset += PutUint48(encoded[offset:], p.Ack.offset)
		} else {
			offset += PutUint24(encoded[offset:], p.Ack.offset)
		}
		offset += PutUint16(encoded[offset:], p.Ack.len)
		encoded[offset] = EncodeRcvWindow(p.Ack.rcvWnd)
		offset++
	}

	// Write Data
	offset += PutUint32(encoded[offset:], p.StreamID)
	if isExtend {
		offset += PutUint48(encoded[offset:], p.StreamOffset)
	} else {
		offset += PutUint24(encoded[offset:], p.StreamOffset)
	}

	if userDataLen > 0 {
		offset += copy(encoded[offset:], userData)
	}

	return encoded, offset
}

func DecodePayload(data []byte) (payload *PayloadHeader, userData []byte, err error) {
	dataLen := len(data)
	if dataLen < MinProtoSize {
		slog.Error("payload size too low", "dataLen", dataLen, "MinProtoSize", MinProtoSize)
		return nil, nil, errors.New("payload Size below minimum of 8 bytes")
	}

	payload = &PayloadHeader{}

	// Decode header byte
	header := data[0]
	version := header & 0xF // bits 0-3
	typeFlag := (header >> TypeFlag) & 0x3
	switch typeFlag {
	case 0:
		payload.MsgType = MsgTypeData
	case 1:
		payload.MsgType = MsgTypePing
	case 2:
		payload.MsgType = MsgTypeClose
	case 3:
		return nil, nil, errors.New("type not supported")
	}
	isExtend := (header & (1 << Offset24or48Flag)) != 0 // bit 6
	isAck := (header & (1 << AckFlag)) != 0             // bit 7

	// Validate version
	if version != ProtoVersion {
		return nil, nil, errors.New("unsupported protocol version")
	}

	offset := 1

	// Check overhead
	overhead := calcProtoOverhead(isAck, isExtend)
	if dataLen < overhead {
		return nil, nil, errors.New("payload size below minimum")
	}

	// Decode ACK if present
	if isAck {
		payload.Ack = &Ack{}
		payload.Ack.streamID = Uint32(data[offset:])
		offset += 4
		if isExtend {
			payload.Ack.offset = Uint48(data[offset:])
			offset += 6
		} else {
			payload.Ack.offset = Uint24(data[offset:])
			offset += 3
		}
		payload.Ack.len = Uint16(data[offset:])
		offset += 2
		payload.Ack.rcvWnd = DecodeRcvWindow(data[offset])
		offset++
	}

	// Decode Data
	payload.StreamID = Uint32(data[offset:])
	offset += 4
	if isExtend {
		payload.StreamOffset = Uint48(data[offset:])
		offset += 6
	} else {
		payload.StreamOffset = Uint24(data[offset:])
		offset += 3
	}

	if dataLen > offset {
		userData = data[offset:dataLen]
	} else {
		userData = make([]byte, 0)
	}

	return payload, userData, nil
}

func calcProtoOverhead(isAck, isExtend bool) (overhead int) {
	overhead = 1 + 4 + 3 //header + 32bit + 24bit
	if isExtend {
		overhead += 3 //in total 6 bytes for 48bit, we already counted 24bit, so just add 3
	}
	if isAck {
		overhead += 4 + 3 + 2 + 1 //32bit + 24bit + 16bit + 8bit
		if isExtend {
			overhead += 3 //in total 6 bytes for 48bit, we already counted 24bit, so just add 3
		}
	}
	return overhead
}
