package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodingUint16(t *testing.T) {
	buf := make([]byte, 2)

	// Zero
	n := PutUint16(buf, 0)
	assert.Equal(t, 2, n)
	assert.Equal(t, uint16(0), Uint16(buf))

	// Max value
	PutUint16(buf, 0xFFFF)
	assert.Equal(t, uint16(0xFFFF), Uint16(buf))

	// Specific value - verify little-endian
	PutUint16(buf, 0x1234)
	assert.Equal(t, byte(0x34), buf[0])
	assert.Equal(t, byte(0x12), buf[1])
	assert.Equal(t, uint16(0x1234), Uint16(buf))
}

func TestEncodingUint24(t *testing.T) {
	buf := make([]byte, 3)

	// Zero
	n := PutUint24(buf, 0)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0), Uint24(buf))

	// Max 24-bit value
	PutUint24(buf, 0xFFFFFF)
	assert.Equal(t, uint64(0xFFFFFF), Uint24(buf))

	// Specific value - verify little-endian
	PutUint24(buf, 0x123456)
	assert.Equal(t, byte(0x56), buf[0])
	assert.Equal(t, byte(0x34), buf[1])
	assert.Equal(t, byte(0x12), buf[2])
	assert.Equal(t, uint64(0x123456), Uint24(buf))
}

func TestEncodingUint32(t *testing.T) {
	buf := make([]byte, 4)

	// Zero
	n := PutUint32(buf, 0)
	assert.Equal(t, 4, n)
	assert.Equal(t, uint32(0), Uint32(buf))

	// Max value
	PutUint32(buf, 0xFFFFFFFF)
	assert.Equal(t, uint32(0xFFFFFFFF), Uint32(buf))

	// Specific value - verify little-endian
	PutUint32(buf, 0x12345678)
	assert.Equal(t, byte(0x78), buf[0])
	assert.Equal(t, byte(0x56), buf[1])
	assert.Equal(t, byte(0x34), buf[2])
	assert.Equal(t, byte(0x12), buf[3])
	assert.Equal(t, uint32(0x12345678), Uint32(buf))
}

func TestEncodingUint48(t *testing.T) {
	buf := make([]byte, 6)

	// Zero
	n := PutUint48(buf, 0)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0), Uint48(buf))

	// Max 48-bit value
	PutUint48(buf, 0xFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFF), Uint48(buf))

	// Specific value - verify little-endian
	PutUint48(buf, 0x123456789ABC)
	assert.Equal(t, byte(0xBC), buf[0])
	assert.Equal(t, byte(0x9A), buf[1])
	assert.Equal(t, byte(0x78), buf[2])
	assert.Equal(t, byte(0x56), buf[3])
	assert.Equal(t, byte(0x34), buf[4])
	assert.Equal(t, byte(0x12), buf[5])
	assert.Equal(t, uint64(0x123456789ABC), Uint48(buf))
}

func TestEncodingUint64(t *testing.T) {
	buf := make([]byte, 8)

	// Zero
	n := PutUint64(buf, 0)
	assert.Equal(t, 8, n)
	assert.Equal(t, uint64(0), Uint64(buf))

	// Max value
	PutUint64(buf, 0xFFFFFFFFFFFFFFFF)
	assert.Equal(t, uint64(0xFFFFFFFFFFFFFFFF), Uint64(buf))

	// Specific value - verify little-endian
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

func TestEncodingOffsetVarint(t *testing.T) {
	buf := make([]byte, 6)

	// 24-bit mode
	n := putOffsetVarint(buf, 0x123456, false)
	assert.Equal(t, 3, n)
	assert.Equal(t, uint64(0x123456), offsetVarint(buf, false))
	assert.Equal(t, 3, offsetSize(false))

	// 48-bit mode
	n = putOffsetVarint(buf, 0x123456789ABC, true)
	assert.Equal(t, 6, n)
	assert.Equal(t, uint64(0x123456789ABC), offsetVarint(buf, true))
	assert.Equal(t, 6, offsetSize(true))

	// Boundary: max 24-bit value in 24-bit mode
	putOffsetVarint(buf, 0xFFFFFF, false)
	assert.Equal(t, uint64(0xFFFFFF), offsetVarint(buf, false))

	// Boundary: value that needs 48-bit
	putOffsetVarint(buf, 0xFFFFFF+1, true)
	assert.Equal(t, uint64(0x1000000), offsetVarint(buf, true))
}
