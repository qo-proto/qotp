package qotp

// =============================================================================
// Little-endian integer encoding
//
// All integers are encoded in little-endian format for wire protocol.
// Returns number of bytes written for Put functions.
// =============================================================================

func PutUint16(b []byte, v uint16) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return 2
}

func PutUint24(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	return 3
}

func PutUint32(b []byte, v uint32) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return 4
}

func PutUint48(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	return 6
}

func PutUint64(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	return 8
}

func Uint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func Uint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func Uint48(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
}

func Uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// =============================================================================
// Variable-length offset encoding (24-bit or 48-bit)
//
// Used for stream offsets in transport layer. Saves 3 bytes per offset
// when values fit in 24 bits (< 16MB).
// =============================================================================

func putOffsetVarint(b []byte, v uint64, isExtend bool) int {
	if isExtend {
		return PutUint48(b, v)
	}
	return PutUint24(b, v)
}

func offsetVarint(b []byte, isExtend bool) uint64 {
	if isExtend {
		return Uint48(b)
	}
	return Uint24(b)
}

func offsetSize(isExtend bool) int {
	if isExtend {
		return 6
	}
	return 3
}