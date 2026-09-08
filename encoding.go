package qotp

import "encoding/binary"

// Wire integers are little-endian; encoding/binary covers 16, 32 and 64 bit.
// Stream offsets are 24-bit unless the extend flag selects 48-bit.

func putUint24(b []byte, v uint64) int {
	b[0], b[1], b[2] = byte(v), byte(v>>8), byte(v>>16)
	return 3
}

func putUint48(b []byte, v uint64) int {
	binary.LittleEndian.PutUint32(b, uint32(v))
	binary.LittleEndian.PutUint16(b[4:], uint16(v>>32))
	return 6
}

func getUint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func getUint48(b []byte) uint64 {
	return uint64(binary.LittleEndian.Uint32(b)) | uint64(binary.LittleEndian.Uint16(b[4:]))<<32
}

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
