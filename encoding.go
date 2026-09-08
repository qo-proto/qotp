package qotp

import "encoding/binary"

// Wire integers are little-endian. Put functions return the bytes written.

func putUint16(b []byte, v uint16) int { binary.LittleEndian.PutUint16(b, v); return 2 }
func putUint32(b []byte, v uint32) int { binary.LittleEndian.PutUint32(b, v); return 4 }
func putUint64(b []byte, v uint64) int { binary.LittleEndian.PutUint64(b, v); return 8 }

func putUint24(b []byte, v uint64) int {
	b[0], b[1], b[2] = byte(v), byte(v>>8), byte(v>>16)
	return 3
}

func putUint48(b []byte, v uint64) int {
	putUint32(b, uint32(v))
	putUint16(b[4:], uint16(v>>32))
	return 6
}

func getUint16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func getUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func getUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func getUint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func getUint48(b []byte) uint64 {
	return uint64(getUint32(b)) | uint64(getUint16(b[4:]))<<32
}

// Stream offsets are 24-bit unless the extend flag selects 48-bit

func putOffsetVarint(b []byte, v uint64, isExtend bool) int {
	if isExtend {
		return putUint48(b, v)
	}
	return putUint24(b, v)
}

func offsetVarint(b []byte, isExtend bool) uint64 {
	if isExtend {
		return getUint48(b)
	}
	return getUint24(b)
}

func offsetSize(isExtend bool) int {
	if isExtend {
		return 6
	}
	return 3
}
