package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// UINT16 TESTS
// =============================================================================

func TestEncodingUint16_Zero(t *testing.T) {
	buf := make([]byte, 2)
	n := PutUint16(buf, 0)
	assert.Equal(t, 2, n)
	assert.Equal(t, uint16(0), Uint16(buf))
}

func TestEncodingUint16_Max(t *testing.T) {
	buf := make([]byte, 2)
	PutUint16(buf, 0xFFFF)
	assert.Equal(t, uint16(0xFFFF), Uint16(buf))
}

func TestEncodingUint16_LittleEndian(t *testing.T) {
	buf := make([]byte, 2)
	PutUint16(buf, 0x1234)
	assert.Equal(t, byte(0x34), buf[0], "low byte first")
	assert.Equal(t, byte(0x12), buf[1], "high byte second")
	assert.Equal(t, uint16(0x1234), Uint16(buf))
}

func TestEncodingUint16_One(t *testing.T) {
	buf := make([]byte, 2)
	PutUint16(buf, 1)
	assert.Equal(t, uint16(1), Uint16(buf))
}

func TestEncodingUint16_PowerOf2(t *testing.T) {
	buf := make([]byte, 2)
	PutUint16(buf, 256) // 2^8
	assert.Equal(t, uint16(256), Uint16(buf))
	assert.Equal(t, byte(0x00), buf[0])
	assert.Equal(t, byte(0x01), buf[1])
}

// =============================================================================
// UINT24 TESTS
// =============================================================================

func TestEncodingUint24_Zero(t *testing.T) {
	buf := make([]byte, 3)
	n := PutUint24(buf, 0)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0), Uint24(buf))
}

func TestEncodingUint24_Max(t *testing.T) {
	buf := make([]byte, 3)
	PutUint24(buf, 0xFFFFFF)
	assert.Equal(t, uint64(0xFFFFFF), Uint24(buf))
}

func TestEncodingUint24_LittleEndian(t *testing.T) {
	buf := make([]byte, 3)
	PutUint24(buf, 0x123456)
	assert.Equal(t, byte(0x56), buf[0])
	assert.Equal(t, byte(0x34), buf[1])
	assert.Equal(t, byte(0x12), buf[2])
	assert.Equal(t, uint64(0x123456), Uint24(buf))
}

func TestEncodingUint24_Truncation(t *testing.T) {
	buf := make([]byte, 3)
	// Value larger than 24-bit gets truncated
	PutUint24(buf, 0xFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFF), Uint24(buf))
}

func TestEncodingUint24_One(t *testing.T) {
	buf := make([]byte, 3)
	PutUint24(buf, 1)
	assert.Equal(t, uint64(1), Uint24(buf))
}

// =============================================================================
// UINT32 TESTS
// =============================================================================

func TestEncodingUint32_Zero(t *testing.T) {
	buf := make([]byte, 4)
	n := PutUint32(buf, 0)
	assert.Equal(t, 4, n)
	assert.Equal(t, uint32(0), Uint32(buf))
}

func TestEncodingUint32_Max(t *testing.T) {
	buf := make([]byte, 4)
	PutUint32(buf, 0xFFFFFFFF)
	assert.Equal(t, uint32(0xFFFFFFFF), Uint32(buf))
}

func TestEncodingUint32_LittleEndian(t *testing.T) {
	buf := make([]byte, 4)
	PutUint32(buf, 0x12345678)
	assert.Equal(t, byte(0x78), buf[0])
	assert.Equal(t, byte(0x56), buf[1])
	assert.Equal(t, byte(0x34), buf[2])
	assert.Equal(t, byte(0x12), buf[3])
	assert.Equal(t, uint32(0x12345678), Uint32(buf))
}

func TestEncodingUint32_One(t *testing.T) {
	buf := make([]byte, 4)
	PutUint32(buf, 1)
	assert.Equal(t, uint32(1), Uint32(buf))
}

func TestEncodingUint32_PowerOf2(t *testing.T) {
	buf := make([]byte, 4)
	PutUint32(buf, 1<<24) // 2^24 = 16777216
	assert.Equal(t, uint32(1<<24), Uint32(buf))
}

// =============================================================================
// UINT48 TESTS
// =============================================================================

func TestEncodingUint48_Zero(t *testing.T) {
	buf := make([]byte, 6)
	n := PutUint48(buf, 0)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0), Uint48(buf))
}

func TestEncodingUint48_Max(t *testing.T) {
	buf := make([]byte, 6)
	PutUint48(buf, 0xFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), Uint48(buf))
}

func TestEncodingUint48_LittleEndian(t *testing.T) {
	buf := make([]byte, 6)
	PutUint48(buf, 0x123456789ABC)
	assert.Equal(t, byte(0xBC), buf[0])
	assert.Equal(t, byte(0x9A), buf[1])
	assert.Equal(t, byte(0x78), buf[2])
	assert.Equal(t, byte(0x56), buf[3])
	assert.Equal(t, byte(0x34), buf[4])
	assert.Equal(t, byte(0x12), buf[5])
	assert.Equal(t, uint64(0x123456789ABC), Uint48(buf))
}

func TestEncodingUint48_Truncation(t *testing.T) {
	buf := make([]byte, 6)
	// Value larger than 48-bit gets truncated
	PutUint48(buf, 0xFFFFFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), Uint48(buf))
}

func TestEncodingUint48_One(t *testing.T) {
	buf := make([]byte, 6)
	PutUint48(buf, 1)
	assert.Equal(t, uint64(1), Uint48(buf))
}

func TestEncodingUint48_PowerOf2(t *testing.T) {
	buf := make([]byte, 6)
	PutUint48(buf, 1<<32) // 2^32
	assert.Equal(t, uint64(1<<32), Uint48(buf))
}

// =============================================================================
// UINT64 TESTS
// =============================================================================

func TestEncodingUint64_Zero(t *testing.T) {
	buf := make([]byte, 8)
	n := PutUint64(buf, 0)
	assert.Equal(t, 8, n)
	assert.Equal(t, uint64(0), Uint64(buf))
}

func TestEncodingUint64_Max(t *testing.T) {
	buf := make([]byte, 8)
	PutUint64(buf, 0xFFFFFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), Uint64(buf))
}

func TestEncodingUint64_LittleEndian(t *testing.T) {
	buf := make([]byte, 8)
	PutUint64(buf, 0x123456789ABCDEF0)
	assert.Equal(t, byte(0xF0), buf[0])
	assert.Equal(t, byte(0xDE), buf[1])
	assert.Equal(t, byte(0xBC), buf[2])
	assert.Equal(t, byte(0x9A), buf[3])
	assert.Equal(t, byte(0x78), buf[4])
	assert.Equal(t, byte(0x56), buf[5])
	assert.Equal(t, byte(0x34), buf[6])
	assert.Equal(t, byte(0x12), buf[7])
	assert.Equal(t, uint64(0x123456789ABCDEF0), Uint64(buf))
}

func TestEncodingUint64_One(t *testing.T) {
	buf := make([]byte, 8)
	PutUint64(buf, 1)
	assert.Equal(t, uint64(1), Uint64(buf))
}

func TestEncodingUint64_PowerOf2(t *testing.T) {
	buf := make([]byte, 8)
	PutUint64(buf, 1<<48) // 2^48
	assert.Equal(t, uint64(1<<48), Uint64(buf))
}

// =============================================================================
// OFFSET VARINT TESTS (24-bit / 48-bit variable encoding)
// =============================================================================

func TestEncodingOffsetVarint_24BitMode_Zero(t *testing.T) {
	buf := make([]byte, 6)
	n := putOffsetVarint(buf, 0, false)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0), offsetVarint(buf, false))
}

func TestEncodingOffsetVarint_24BitMode_Max(t *testing.T) {
	buf := make([]byte, 6)
	putOffsetVarint(buf, 0xFFFFFF, false)
	assert.Equal(t, uint64(0xFFFFFF), offsetVarint(buf, false))
}

func TestEncodingOffsetVarint_24BitMode_Value(t *testing.T) {
	buf := make([]byte, 6)
	n := putOffsetVarint(buf, 0x123456, false)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0x123456), offsetVarint(buf, false))
}

func TestEncodingOffsetVarint_48BitMode_Zero(t *testing.T) {
	buf := make([]byte, 6)
	n := putOffsetVarint(buf, 0, true)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0), offsetVarint(buf, true))
}

func TestEncodingOffsetVarint_48BitMode_Max(t *testing.T) {
	buf := make([]byte, 6)
	putOffsetVarint(buf, 0xFFFFFFFFFFFF, true)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), offsetVarint(buf, true))
}

func TestEncodingOffsetVarint_48BitMode_Value(t *testing.T) {
	buf := make([]byte, 6)
	n := putOffsetVarint(buf, 0x123456789ABC, true)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0x123456789ABC), offsetVarint(buf, true))
}

func TestEncodingOffsetVarint_48BitMode_BoundaryValue(t *testing.T) {
	buf := make([]byte, 6)
	// First value that doesn't fit in 24-bit
	putOffsetVarint(buf, 0xFFFFFF+1, true)
	assert.Equal(t, uint64(0x1000000), offsetVarint(buf, true))
}

func TestEncodingOffsetSize_24Bit(t *testing.T) {
	assert.Equal(t, 3, offsetSize(false))
}

func TestEncodingOffsetSize_48Bit(t *testing.T) {
	assert.Equal(t, 6, offsetSize(true))
}

// =============================================================================
// ROUNDTRIP TESTS
// =============================================================================

func TestEncodingRoundtrip_AllTypes(t *testing.T) {
	// Test that encoding then decoding produces original value
	buf := make([]byte, 8)

	testVal16 := uint16(0xABCD)
	PutUint16(buf, testVal16)
	assert.Equal(t, testVal16, Uint16(buf))

	testVal24 := uint64(0xABCDEF)
	PutUint24(buf, testVal24)
	assert.Equal(t, testVal24, Uint24(buf))

	testVal32 := uint32(0xABCDEF12)
	PutUint32(buf, testVal32)
	assert.Equal(t, testVal32, Uint32(buf))

	testVal48 := uint64(0xABCDEF123456)
	PutUint48(buf, testVal48)
	assert.Equal(t, testVal48, Uint48(buf))

	testVal64 := uint64(0xABCDEF1234567890)
	PutUint64(buf, testVal64)
	assert.Equal(t, testVal64, Uint64(buf))
}

func TestEncodingRoundtrip_OffsetVarint(t *testing.T) {
	buf := make([]byte, 6)

	// 24-bit mode
	val24 := uint64(0x123456)
	putOffsetVarint(buf, val24, false)
	assert.Equal(t, val24, offsetVarint(buf, false))

	// 48-bit mode
	val48 := uint64(0x123456789ABC)
	putOffsetVarint(buf, val48, true)
	assert.Equal(t, val48, offsetVarint(buf, true))
}