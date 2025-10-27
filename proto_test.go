package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to encode payload and assert no error
func encodePayload(payload *PayloadHeader, data []byte) []byte {
	encoded, _ := EncodePayload(payload, data)
	return encoded
}

func mustDecodePayload(t *testing.T, encoded []byte) (*PayloadHeader, []byte) {
	decoded, data, err := DecodePayload(encoded)
	require.NoError(t, err)
	return decoded, data
}

func roundTrip(t *testing.T, payload *PayloadHeader, data []byte) (*PayloadHeader, []byte) {
	encoded := encodePayload(payload, data)
	return mustDecodePayload(t, encoded)
}

// Helper to assert payload equality
func assertPayloadEqual(t *testing.T, expected, actual *PayloadHeader) {
	assert.Equal(t, expected.StreamID, actual.StreamID)
	assert.Equal(t, expected.StreamOffset, actual.StreamOffset)
	assert.Equal(t, expected.MsgType, actual.MsgType)

	if expected.Ack == nil {
		assert.Nil(t, actual.Ack)
	} else {
		require.NotNil(t, actual.Ack)
		assert.Equal(t, expected.Ack.streamID, actual.Ack.streamID)
		assert.Equal(t, expected.Ack.offset, actual.Ack.offset)
		assert.Equal(t, expected.Ack.len, actual.Ack.len)

		encoded := EncodeRcvWindow(expected.Ack.rcvWnd)
		expectedDecoded := DecodeRcvWindow(encoded)
		assert.Equal(t, expectedDecoded, actual.Ack.rcvWnd)
	}
}

// =============================================================================
// Basic Payload Tests
// =============================================================================

func TestProtoMinimal(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     12345,
		StreamOffset: 0,
	}

	decoded, decodedData := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestProtoWithData(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 100,
	}
	originalData := []byte("test data")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// ACK Tests
// =============================================================================

func TestProtoWithAck24Bit(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 10, offset: 200, len: 300, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoWithAck48Bit(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     5,
		StreamOffset: 0x1000000,
		Ack:          &Ack{streamID: 50, offset: 0x1000000, len: 200, rcvWnd: 5000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoAckBoundary24Bit(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     4,
		StreamOffset: 0xFFFFFF,
		Ack:          &Ack{streamID: 40, offset: 0xFFFFFF, len: 100, rcvWnd: 4000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoAckMixed24And48Bit(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 0x1000000,
		Ack:          &Ack{streamID: 10, offset: 100, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// Close Flag Tests
// =============================================================================

func TestProtoCloseFlag(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeClose,
		StreamID:     1,
		StreamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProtoCloseFlagWithAck(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeClose,
		StreamID:     1,
		StreamOffset: 9999,
		Ack:          &Ack{streamID: 1, offset: 123456, len: 10, rcvWnd: 1000},
	}
	originalData := []byte("closing")

	decoded, decodedData := roundTrip(t, original, originalData)
	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// Ping Flag Tests
// =============================================================================

func TestProtoPingFlag(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypePing,
		StreamID:     1,
		StreamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assert.Equal(t, MsgTypePing, decoded.MsgType)
	assertPayloadEqual(t, original, decoded)
}

func TestProtoPingWithAck(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypePing,
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 1, offset: 50, len: 0, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assert.Equal(t, MsgTypePing, decoded.MsgType)
	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// Offset Size Tests
// =============================================================================

func TestProto24BitOffset(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 0xFFFFFF,
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

func TestProto48BitOffset(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 0x1000000,
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// Error Tests
// =============================================================================

func TestProtoErrorBelowMinSize(t *testing.T) {
	testCases := []int{0, 1, 7}
	for _, size := range testCases {
		data := make([]byte, size)
		_, _, err := DecodePayload(data)
		assert.Error(t, err)
	}
}

func TestProtoErrorInvalidVersion(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x1F // Invalid version

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestProtoErrorTypeNotSupported(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x30 // Version 0, Type=3 (11b)

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type not supported")
}

func TestProtoErrorInsufficientDataForAck(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x80 // ACK flag set, needs 18 bytes minimum

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")
}

func TestProtoErrorInsufficientDataForExtended(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x40 // Extended flag set, needs 11 bytes minimum

	_, _, err := DecodePayload(data)
	assert.Error(t, err)
}

// =============================================================================
// RcvWindow Tests
// =============================================================================

func TestProtoRcvWindowRoundTrip(t *testing.T) {
	testCases := []uint64{
		0, 512, 1024, 2048, 4096, 8192, 16384, 32768,
		65536, 131072, 262144, 524288, 1048576, 1073741824,
	}

	for _, input := range testCases {
		encoded := EncodeRcvWindow(input)
		decoded := DecodeRcvWindow(encoded)
		assert.LessOrEqual(t, input, decoded)
	}
}

func TestProtoRcvWindowEdgeCases(t *testing.T) {
	assert.Equal(t, uint8(0), EncodeRcvWindow(0))
	assert.Equal(t, uint8(1), EncodeRcvWindow(1))
	assert.Equal(t, uint8(1), EncodeRcvWindow(128))

	// Values 129-255 also encode to 1
	assert.Equal(t, uint8(1), EncodeRcvWindow(129))
	assert.Equal(t, uint8(1), EncodeRcvWindow(255))

	// First value that encodes to 2
	assert.Equal(t, uint8(2), EncodeRcvWindow(256))

	// Decode checks
	assert.Equal(t, uint64(0), DecodeRcvWindow(0))
	assert.Equal(t, uint64(128), DecodeRcvWindow(1))
	assert.Equal(t, uint64(256), DecodeRcvWindow(2))

	// Verify monotonic from 2 onwards
	prev := DecodeRcvWindow(2)
	for i := uint8(3); i <= 254; i++ {
		curr := DecodeRcvWindow(i)
		assert.Greater(t, curr, prev, "Should be monotonic at %d", i)
		prev = curr
	}
}

func TestProtoRcvWindowOverflow(t *testing.T) {
	// Values that would overflow uint8 without capping
	hugeValues := []uint64{
		1 << 50, // 1 PB
		1 << 60, // 1 EB
		1 << 63, // Max int64
	}

	for _, val := range hugeValues {
		encoded := EncodeRcvWindow(val)
		assert.Equal(t, uint8(255), encoded, "Should cap at 255")

		decoded := DecodeRcvWindow(255)
		// Decoded value (~896GB) is LESS than huge input values
		assert.Less(t, decoded, val, "Decoded max is ~896GB, less than input")
		assert.Greater(t, decoded, uint64(800_000_000_000)) // Sanity check: > 800GB
	}
}

func TestProtoRcvWindowMax(t *testing.T) {
	encoded := EncodeRcvWindow(1 << 63)
	assert.Equal(t, uint8(255), encoded)

	decoded := DecodeRcvWindow(255)
	assert.Greater(t, decoded, uint64(800_000_000_000)) // > 800GB
	assert.Less(t, decoded, uint64(900_000_000_000))    // < 900GB
}

// =============================================================================
// Additional Tests
// =============================================================================

func TestProtoAckZeroLength(t *testing.T) {
	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 100,
		Ack:          &Ack{streamID: 1, offset: 100, len: 0, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})
	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, uint16(0), decoded.Ack.len)
}

func TestProtoOverheadCalculation(t *testing.T) {
	assert.Equal(t, 8, calcProtoOverhead(false, false))   // No ACK, 24-bit
	assert.Equal(t, 11, calcProtoOverhead(false, true))   // No ACK, 48-bit
	assert.Equal(t, 18, calcProtoOverhead(true, false))   // ACK, 24-bit
	assert.Equal(t, 24, calcProtoOverhead(true, true))    // ACK, 48-bit
}

func TestProtoLargeData(t *testing.T) {
	largeData := make([]byte, 65000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 0,
	}

	decoded, decodedData := roundTrip(t, original, largeData)
	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, largeData, decodedData)
}

func TestProtoMessageTypeExclusive(t *testing.T) {
	// Test that message types work independently
	data := &PayloadHeader{
		MsgType:      MsgTypeData,
		StreamID:     1,
		StreamOffset: 0,
	}

	ping := &PayloadHeader{
		MsgType:      MsgTypePing,
		StreamID:     1,
		StreamOffset: 0,
	}

	close := &PayloadHeader{
		MsgType:      MsgTypeClose,
		StreamID:     1,
		StreamOffset: 0,
	}

	decodedData, _ := roundTrip(t, data, []byte{})
	assert.Equal(t, MsgTypeData, decodedData.MsgType)

	decodedPing, _ := roundTrip(t, ping, []byte{})
	assert.Equal(t, MsgTypePing, decodedPing.MsgType)

	decodedClose, _ := roundTrip(t, close, []byte{})
	assert.Equal(t, MsgTypeClose, decodedClose.MsgType)
}