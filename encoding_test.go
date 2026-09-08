package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// UINT16 TESTS
// =============================================================================

func TestEncodingUint24_Zero(t *testing.T) {
	buf := make([]byte, 3)
	n := putUint24(buf, 0)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0), getUint24(buf))
}

func TestEncodingUint24_Max(t *testing.T) {
	buf := make([]byte, 3)
	putUint24(buf, 0xFFFFFF)
	assert.Equal(t, uint64(0xFFFFFF), getUint24(buf))
}

func TestEncodingUint24_LittleEndian(t *testing.T) {
	buf := make([]byte, 3)
	putUint24(buf, 0x123456)
	assert.Equal(t, byte(0x56), buf[0])
	assert.Equal(t, byte(0x34), buf[1])
	assert.Equal(t, byte(0x12), buf[2])
	assert.Equal(t, uint64(0x123456), getUint24(buf))
}

func TestEncodingUint24_Truncation(t *testing.T) {
	buf := make([]byte, 3)
	// Value larger than 24-bit gets truncated
	putUint24(buf, 0xFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFF), getUint24(buf))
}

func TestEncodingUint24_One(t *testing.T) {
	buf := make([]byte, 3)
	putUint24(buf, 1)
	assert.Equal(t, uint64(1), getUint24(buf))
}

// =============================================================================
// UINT32 TESTS
// =============================================================================

func TestEncodingUint48_Zero(t *testing.T) {
	buf := make([]byte, 6)
	n := putUint48(buf, 0)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0), getUint48(buf))
}

func TestEncodingUint48_Max(t *testing.T) {
	buf := make([]byte, 6)
	putUint48(buf, 0xFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), getUint48(buf))
}

func TestEncodingUint48_LittleEndian(t *testing.T) {
	buf := make([]byte, 6)
	putUint48(buf, 0x123456789ABC)
	assert.Equal(t, byte(0xBC), buf[0])
	assert.Equal(t, byte(0x9A), buf[1])
	assert.Equal(t, byte(0x78), buf[2])
	assert.Equal(t, byte(0x56), buf[3])
	assert.Equal(t, byte(0x34), buf[4])
	assert.Equal(t, byte(0x12), buf[5])
	assert.Equal(t, uint64(0x123456789ABC), getUint48(buf))
}

func TestEncodingUint48_Truncation(t *testing.T) {
	buf := make([]byte, 6)
	// Value larger than 48-bit gets truncated
	putUint48(buf, 0xFFFFFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), getUint48(buf))
}

func TestEncodingUint48_One(t *testing.T) {
	buf := make([]byte, 6)
	putUint48(buf, 1)
	assert.Equal(t, uint64(1), getUint48(buf))
}

func TestEncodingUint48_PowerOf2(t *testing.T) {
	buf := make([]byte, 6)
	putUint48(buf, 1<<32) // 2^32
	assert.Equal(t, uint64(1<<32), getUint48(buf))
}

// =============================================================================
// UINT64 TESTS
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
