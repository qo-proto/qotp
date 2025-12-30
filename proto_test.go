package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TEST HELPERS
// =============================================================================

func encodePayload(payload *payloadHeader, data []byte) []byte {
	encoded, _ := encodeProto(payload, data)
	return encoded
}

func mustDecodePayload(t *testing.T, encoded []byte) (*payloadHeader, []byte) {
	decoded, data, err := decodeProto(encoded)
	require.NoError(t, err)
	return decoded, data
}

func roundTrip(t *testing.T, payload *payloadHeader, data []byte) (*payloadHeader, []byte) {
	encoded := encodePayload(payload, data)
	return mustDecodePayload(t, encoded)
}

func assertPayloadEqual(t *testing.T, expected, actual *payloadHeader) {
	assert.Equal(t, expected.streamId, actual.streamId)
	assert.Equal(t, expected.streamOffset, actual.streamOffset)
	assert.Equal(t, expected.isClose, actual.isClose)

	if expected.ack == nil {
		assert.Nil(t, actual.ack)
	} else {
		require.NotNil(t, actual.ack)
		assert.Equal(t, expected.ack.streamId, actual.ack.streamId)
		assert.Equal(t, expected.ack.offset, actual.ack.offset)
		assert.Equal(t, expected.ack.len, actual.ack.len)

		encoded := encodeRcvWindow(expected.ack.rcvWnd)
		expectedDecoded := decodeRcvWindow(encoded)
		assert.Equal(t, expectedDecoded, actual.ack.rcvWnd)
	}
}

// =============================================================================
// TYPE 01: DATA WITHOUT ACK
// =============================================================================

func TestProto_DataNoAck_WithData(t *testing.T) {
	original := &payloadHeader{
		streamId:     12345,
		streamOffset: 100,
	}
	originalData := []byte("test data")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_DataNoAck_EmptyData(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
	}

	decoded, decodedData := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestProto_DataNoAck_ZeroStreamID(t *testing.T) {
	original := &payloadHeader{
		streamId:     0,
		streamOffset: 100,
	}
	originalData := []byte("data")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_DataNoAck_MaxStreamID(t *testing.T) {
	original := &payloadHeader{
		streamId:     0xFFFFFFFF,
		streamOffset: 100,
	}
	originalData := []byte("data")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// TYPE 00: DATA WITH ACK
// =============================================================================

func TestProto_DataWithAck_AndData(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 10, offset: 200, len: 300, rcvWnd: 1000},
	}
	originalData := []byte("payload")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_DataWithAck_EmptyData(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 1, offset: 50, len: 0, rcvWnd: 1000},
	}

	decoded, decodedData := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestProto_DataWithAck_AckOnly(t *testing.T) {
	original := &payloadHeader{
		ack: &ack{streamId: 10, offset: 200, len: 300, rcvWnd: 1000},
	}

	decoded, decodedData := roundTrip(t, original, nil)

	assertPayloadEqual(t, original, decoded)
	assert.Nil(t, decodedData)
}

func TestProto_DataWithAck_ZeroLen(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 1, offset: 100, len: 0, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, uint16(0), decoded.ack.len)
}

func TestProto_DataWithAck_MaxLen(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 1, offset: 100, len: 0xFFFF, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, uint16(0xFFFF), decoded.ack.len)
}

// =============================================================================
// TYPE 10: CLOSE WITH ACK
// =============================================================================

func TestProto_CloseWithAck(t *testing.T) {
	original := &payloadHeader{
		isClose:      true,
		streamId:     1,
		streamOffset: 9999,
		ack:          &ack{streamId: 1, offset: 123456, len: 10, rcvWnd: 1000},
	}
	originalData := []byte("closing")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_CloseWithAck_NoData(t *testing.T) {
	original := &payloadHeader{
		isClose:      true,
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 1, offset: 50, len: 10, rcvWnd: 500},
	}

	decoded, decodedData := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

// =============================================================================
// TYPE 11: CLOSE WITHOUT ACK
// =============================================================================

func TestProto_CloseNoAck(t *testing.T) {
	original := &payloadHeader{
		isClose:      true,
		streamId:     1,
		streamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_CloseNoAck_WithData(t *testing.T) {
	original := &payloadHeader{
		isClose:      true,
		streamId:     1,
		streamOffset: 100,
	}
	originalData := []byte("final data")

	decoded, decodedData := roundTrip(t, original, originalData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, originalData, decodedData)
}

// =============================================================================
// OFFSET SIZE TESTS (24-bit vs 48-bit)
// =============================================================================

func TestProto_Offset_24BitMax(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0xFFFFFF,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_Offset_48BitMin(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0x1000000,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_Offset_48BitWithAck(t *testing.T) {
	original := &payloadHeader{
		streamId:     5,
		streamOffset: 0x1000000,
		ack:          &ack{streamId: 50, offset: 0x1000000, len: 200, rcvWnd: 5000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_Offset_MixedData48BitAck24Bit(t *testing.T) {
	// Data needs 48-bit, ACK needs 24-bit - both use 48-bit encoding
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0x1000000,
		ack:          &ack{streamId: 10, offset: 100, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_Offset_MixedAck48BitData24Bit(t *testing.T) {
	// ACK needs 48-bit, Data needs 24-bit - both use 48-bit encoding
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 10, offset: 0x1000000, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

func TestProto_Offset_MaxValue(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0xFFFFFFFFFFFF, // max 48-bit
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
}

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestProto_Decode_EmptyBuffer(t *testing.T) {
	_, _, err := decodeProto([]byte{})
	assert.Error(t, err)
}

func TestProto_Decode_TooSmall_1Byte(t *testing.T) {
	_, _, err := decodeProto(make([]byte, 1))
	assert.Error(t, err)
}

func TestProto_Decode_TooSmall_7Bytes(t *testing.T) {
	_, _, err := decodeProto(make([]byte, 7))
	assert.Error(t, err)
}

func TestProto_Decode_InvalidVersion(t *testing.T) {
	data := make([]byte, 8)
	data[0] = 0x1F // version bits = 31

	_, _, err := decodeProto(data)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "version")
}

func TestProto_Decode_InsufficientDataForAck(t *testing.T) {
	data := make([]byte, 10)
	data[0] = 0x00 // Type 00 (ACK) needs >= 11 bytes

	_, _, err := decodeProto(data)

	assert.Error(t, err)
}

func TestProto_Decode_MinimumValidSize(t *testing.T) {
	// Minimum valid: 8 bytes for DATA without ACK
	data := make([]byte, 8)
	data[0] = 0b01 << typeFlag // Type 01 = DATA without ACK

	_, _, err := decodeProto(data)

	assert.NoError(t, err)
}

// =============================================================================
// RCVWINDOW ENCODING TESTS
// =============================================================================

func TestProto_RcvWindow_Zero(t *testing.T) {
	assert.Equal(t, uint8(0), encodeRcvWindow(0))
	assert.Equal(t, uint64(0), decodeRcvWindow(0))
}

func TestProto_RcvWindow_One(t *testing.T) {
	assert.Equal(t, uint8(1), encodeRcvWindow(1))
	assert.Equal(t, uint64(128), decodeRcvWindow(1))
}

func TestProto_RcvWindow_SmallValues(t *testing.T) {
	assert.Equal(t, uint8(1), encodeRcvWindow(128))
	assert.Equal(t, uint8(1), encodeRcvWindow(255))
	assert.Equal(t, uint8(2), encodeRcvWindow(256))
	assert.Equal(t, uint64(256), decodeRcvWindow(2))
}

func TestProto_RcvWindow_MonotonicallyIncreasing(t *testing.T) {
	prev := decodeRcvWindow(2)
	for i := uint8(3); i <= 254; i++ {
		curr := decodeRcvWindow(i)
		assert.Greater(t, curr, prev, "decodeRcvWindow should be monotonically increasing at %d", i)
		prev = curr
	}
}

func TestProto_RcvWindow_MaxValue(t *testing.T) {
	assert.Equal(t, uint8(255), encodeRcvWindow(1<<63))

	decoded := decodeRcvWindow(255)
	assert.Greater(t, decoded, uint64(800_000_000_000))
}

func TestProto_RcvWindow_RoundTrip(t *testing.T) {
	testValues := []uint64{0, 512, 1024, 65536, 1048576}

	for _, input := range testValues {
		encoded := encodeRcvWindow(input)
		decoded := decodeRcvWindow(encoded)
		assert.LessOrEqual(t, input, decoded, "round trip should preserve or increase value for %d", input)
	}
}

// =============================================================================
// OVERHEAD CALCULATION TESTS
// =============================================================================

func TestProto_Overhead_NoAck24Bit(t *testing.T) {
	assert.Equal(t, 8, calcProtoOverhead(false, false, false))
}

func TestProto_Overhead_NoAck48Bit(t *testing.T) {
	assert.Equal(t, 11, calcProtoOverhead(false, true, false))
}

func TestProto_Overhead_WithAck24Bit(t *testing.T) {
	assert.Equal(t, 18, calcProtoOverhead(true, false, false))
}

func TestProto_Overhead_WithAck48Bit(t *testing.T) {
	assert.Equal(t, 24, calcProtoOverhead(true, true, false))
}

func TestProto_Overhead_AckOnly24Bit(t *testing.T) {
	assert.Equal(t, 11, calcProtoOverhead(true, false, true))
}

func TestProto_Overhead_AckOnly48Bit(t *testing.T) {
	assert.Equal(t, 14, calcProtoOverhead(true, true, true))
}

// =============================================================================
// LARGE DATA TESTS
// =============================================================================

func TestProto_LargeData(t *testing.T) {
	largeData := make([]byte, 65000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
	}

	decoded, decodedData := roundTrip(t, original, largeData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, largeData, decodedData)
}

func TestProto_LargeData_WithAck(t *testing.T) {
	largeData := make([]byte, 65000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	original := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          &ack{streamId: 2, offset: 1000, len: 500, rcvWnd: 10000},
	}

	decoded, decodedData := roundTrip(t, original, largeData)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, largeData, decodedData)
}

// =============================================================================
// HEADER BUILDING TESTS
// =============================================================================

func TestProto_BuildHeader_DataNoAck(t *testing.T) {
	header := buildHeader(false, false, 100, nil)

	typeFlag := (header >> typeFlag) & 0b11
	assert.Equal(t, uint8(0b01), typeFlag)
}

func TestProto_BuildHeader_DataWithAck(t *testing.T) {
	header := buildHeader(false, true, 100, &ack{offset: 50})

	typeFlag := (header >> typeFlag) & 0b11
	assert.Equal(t, uint8(0b00), typeFlag)
}

func TestProto_BuildHeader_CloseNoAck(t *testing.T) {
	header := buildHeader(true, false, 100, nil)

	typeFlag := (header >> typeFlag) & 0b11
	assert.Equal(t, uint8(0b11), typeFlag)
}

func TestProto_BuildHeader_CloseWithAck(t *testing.T) {
	header := buildHeader(true, true, 100, &ack{offset: 50})

	typeFlag := (header >> typeFlag) & 0b11
	assert.Equal(t, uint8(0b10), typeFlag)
}

func TestProto_BuildHeader_ExtendFlag_24Bit(t *testing.T) {
	header := buildHeader(false, false, 0xFFFFFF, nil)

	isExtend := (header & (1 << offset24or48Flag)) != 0
	assert.False(t, isExtend)
}

func TestProto_BuildHeader_ExtendFlag_48Bit(t *testing.T) {
	header := buildHeader(false, false, 0x1000000, nil)

	isExtend := (header & (1 << offset24or48Flag)) != 0
	assert.True(t, isExtend)
}

func TestProto_BuildHeader_ExtendFlag_AckTriggersExtend(t *testing.T) {
	// Data offset is 24-bit, but ACK offset is 48-bit
	header := buildHeader(false, true, 100, &ack{offset: 0x1000000})

	isExtend := (header & (1 << offset24or48Flag)) != 0
	assert.True(t, isExtend)
}