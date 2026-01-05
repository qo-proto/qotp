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
	assert.Equal(t, expected.isProbe, actual.isProbe)
	assert.Equal(t, expected.isKeyUpdate, actual.isKeyUpdate)
	assert.Equal(t, expected.isKeyUpdateAck, actual.isKeyUpdateAck)

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

	if expected.isKeyUpdate {
		assert.Equal(t, expected.keyUpdatePub, actual.keyUpdatePub)
	}
	if expected.isKeyUpdateAck {
		assert.Equal(t, expected.keyUpdatePubAck, actual.keyUpdatePubAck)
	}
}

// =============================================================================
// TYPE: DATA WITHOUT ACK
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
// TYPE: DATA WITH ACK
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

	assert.NotNil(t, decoded.ack)
	assert.Equal(t, uint32(10), decoded.ack.streamId)
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
// TYPE: CLOSE WITH ACK
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
// TYPE: CLOSE WITHOUT ACK
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
// TYPE: PROBE
// =============================================================================

func TestProto_Probe_NoPadding(t *testing.T) {
	original := &payloadHeader{
		isProbe:      true,
		streamId:     1,
		streamOffset: 0,
	}

	decoded, decodedData := roundTrip(t, original, []byte{})

	assertPayloadEqual(t, original, decoded)
	assert.Empty(t, decodedData)
}

func TestProto_Probe_WithPadding(t *testing.T) {
	original := &payloadHeader{
		isProbe:      true,
		streamId:     1,
		streamOffset: 100,
	}
	padding := make([]byte, 1000)

	decoded, decodedData := roundTrip(t, original, padding)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, padding, decodedData)
}

func TestProto_Probe_48Bit(t *testing.T) {
	original := &payloadHeader{
		isProbe:      true,
		streamId:     1,
		streamOffset: 0x1000000,
	}
	padding := make([]byte, 100)

	decoded, decodedData := roundTrip(t, original, padding)

	assertPayloadEqual(t, original, decoded)
	assert.Equal(t, padding, decodedData)
}

func TestProto_Probe_NoAckEvenIfSet(t *testing.T) {
	// Probe can have ACK
	original := &payloadHeader{
		isProbe:      true,
		streamId:     1,
		streamOffset: 0,
		ack:          &ack{streamId: 2, offset: 100, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.isProbe)
	assert.NotNil(t, decoded.ack)
}

// =============================================================================
// KEY UPDATE TESTS
// =============================================================================

func TestProto_KeyUpdate_Basic(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	original := &payloadHeader{
		isKeyUpdate:  true,
		keyUpdatePub: pubKey,
		streamId:     1,
		streamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.isKeyUpdate)
	assert.Equal(t, pubKey, decoded.keyUpdatePub)
	assertPayloadEqual(t, original, decoded)
}

func TestProto_KeyUpdate_WithData(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	original := &payloadHeader{
		isKeyUpdate:  true,
		keyUpdatePub: pubKey,
		streamId:     1,
		streamOffset: 100,
	}
	originalData := []byte("data with key update")

	decoded, decodedData := roundTrip(t, original, originalData)

	assert.True(t, decoded.isKeyUpdate)
	assert.Equal(t, pubKey, decoded.keyUpdatePub)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_KeyUpdate_WithAck(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	original := &payloadHeader{
		isKeyUpdate:  true,
		keyUpdatePub: pubKey,
		streamId:     1,
		streamOffset: 100,
		ack:          &ack{streamId: 2, offset: 50, len: 10, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.isKeyUpdate)
	assert.NotNil(t, decoded.ack)
	assertPayloadEqual(t, original, decoded)
}

func TestProto_KeyUpdateAck_Basic(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i + 100)
	}

	original := &payloadHeader{
		isKeyUpdateAck:  true,
		keyUpdatePubAck: pubKey,
		streamId:        1,
		streamOffset:    100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.isKeyUpdateAck)
	assert.Equal(t, pubKey, decoded.keyUpdatePubAck)
	assertPayloadEqual(t, original, decoded)
}

func TestProto_KeyUpdateAck_WithData(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i + 100)
	}

	original := &payloadHeader{
		isKeyUpdateAck:  true,
		keyUpdatePubAck: pubKey,
		streamId:        1,
		streamOffset:    100,
	}
	originalData := []byte("data with key update ack")

	decoded, decodedData := roundTrip(t, original, originalData)

	assert.True(t, decoded.isKeyUpdateAck)
	assert.Equal(t, pubKey, decoded.keyUpdatePubAck)
	assert.Equal(t, originalData, decodedData)
}

func TestProto_KeyUpdateAndAck_Both(t *testing.T) {
	pubKey := make([]byte, pubKeySize)
	pubKeyAck := make([]byte, pubKeySize)
	for i := range pubKey {
		pubKey[i] = byte(i)
		pubKeyAck[i] = byte(i + 100)
	}

	original := &payloadHeader{
		isKeyUpdate:     true,
		keyUpdatePub:    pubKey,
		isKeyUpdateAck:  true,
		keyUpdatePubAck: pubKeyAck,
		streamId:        1,
		streamOffset:    100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.isKeyUpdate)
	assert.True(t, decoded.isKeyUpdateAck)
	assert.Equal(t, pubKey, decoded.keyUpdatePub)
	assert.Equal(t, pubKeyAck, decoded.keyUpdatePubAck)
}

// =============================================================================
// NEEDS RETX FLAG TESTS
// =============================================================================

func TestProto_NeedsReTx_WithData(t *testing.T) {
	original := &payloadHeader{
		streamId:     1,
		streamOffset: 100,
	}
	originalData := []byte("data")

	decoded, _ := roundTrip(t, original, originalData)

	assert.True(t, decoded.needsReTx)
}

func TestProto_NeedsReTx_WithClose(t *testing.T) {
	original := &payloadHeader{
		isClose:      true,
		streamId:     1,
		streamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.needsReTx)
}

func TestProto_NeedsReTx_WithKeyUpdate(t *testing.T) {
	pubKey := make([]byte, pubKeySize)

	original := &payloadHeader{
		isKeyUpdate:  true,
		keyUpdatePub: pubKey,
		streamId:     1,
		streamOffset: 100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.needsReTx)
}

func TestProto_NeedsReTx_WithKeyUpdateAck(t *testing.T) {
	pubKey := make([]byte, pubKeySize)

	original := &payloadHeader{
		isKeyUpdateAck:  true,
		keyUpdatePubAck: pubKey,
		streamId:        1,
		streamOffset:    100,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	assert.True(t, decoded.needsReTx)
}

func TestProto_NeedsReTx_AckOnly(t *testing.T) {
	original := &payloadHeader{
		ack: &ack{streamId: 1, offset: 100, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, nil)

	assert.False(t, decoded.needsReTx)
}

func TestProto_NeedsReTx_ProbeOnly(t *testing.T) {
	original := &payloadHeader{
		isProbe:      true,
		streamId:     1,
		streamOffset: 0,
	}

	decoded, _ := roundTrip(t, original, []byte{})

	// Probe sets needsReTx
	assert.True(t, decoded.needsReTx)
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

func TestProto_Decode_TooSmall_ForAck(t *testing.T) {
	data := make([]byte, 5)
	data[0] = flagHasAck // Has ACK but not enough bytes

	_, _, err := decodeProto(data)
	assert.Error(t, err)
}

func TestProto_Decode_TooSmall_ForKeyUpdate(t *testing.T) {
	data := make([]byte, 10)
	data[0] = flagKeyUpdate // Has key update but not enough bytes

	_, _, err := decodeProto(data)
	assert.Error(t, err)
}

func TestProto_Decode_MinimumValidSize_AckOnly(t *testing.T) {
	// ACK only: 1 + 4 + 3 + 2 + 1 = 11 bytes (24-bit offset)
	original := &payloadHeader{
		ack: &ack{streamId: 1, offset: 100, len: 50, rcvWnd: 1000},
	}

	decoded, _ := roundTrip(t, original, nil)

	assert.NotNil(t, decoded.ack)
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
	// No ACK means stream header is always included: 1 + 4 + 3 = 8
	var flags uint8 = 0
	assert.Equal(t, 8, calcProtoOverhead(flags))
}

func TestProto_Overhead_NoAck48Bit(t *testing.T) {
	// No ACK, extended: 1 + 4 + 6 = 11
	var flags uint8 = flagExtend
	assert.Equal(t, 11, calcProtoOverhead(flags))
}

func TestProto_Overhead_WithAck24Bit(t *testing.T) {
	// ACK only (no stream header): 1 + 4 + 3 + 2 + 1 = 11
	var flags uint8 = flagHasAck
	assert.Equal(t, 11, calcProtoOverhead(flags))
}

func TestProto_Overhead_WithAck48Bit(t *testing.T) {
	// ACK only, extended: 1 + 4 + 6 + 2 + 1 = 14
	var flags uint8 = flagHasAck | flagExtend
	assert.Equal(t, 14, calcProtoOverhead(flags))
}

func TestProto_Overhead_KeyUpdate(t *testing.T) {
	var flags uint8 = flagKeyUpdate
	// 1 (header) + 32 (pubkey) + 4 (streamId) + 3 (offset 24-bit) = 40
	assert.Equal(t, 40, calcProtoOverhead(flags))
}

func TestProto_Overhead_KeyUpdateAck(t *testing.T) {
	var flags uint8 = flagKeyUpdateAck
	// 1 (header) + 32 (pubkey) + 4 (streamId) + 3 (offset 24-bit) = 40
	assert.Equal(t, 40, calcProtoOverhead(flags))
}

func TestProto_Overhead_KeyUpdateAndAck(t *testing.T) {
	var flags uint8 = flagKeyUpdate | flagKeyUpdateAck
	// 1 (header) + 32 + 32 (both pubkeys) + 4 (streamId) + 3 (offset 24-bit) = 72
	assert.Equal(t, 72, calcProtoOverhead(flags))
}

func TestProto_Overhead_Close(t *testing.T) {
	var flags uint8 = flagClose
	// 1 (header) + 4 (streamId) + 3 (offset 24-bit) = 8
	assert.Equal(t, 8, calcProtoOverhead(flags))
}

func TestProto_Overhead_Probe(t *testing.T) {
	var flags uint8 = flagProbe
	// 1 (header) + 4 (streamId) + 3 (offset 24-bit) = 8
	assert.Equal(t, 8, calcProtoOverhead(flags))
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
// FLAG ENCODING TESTS
// =============================================================================

func TestProto_Flags_DataNoAck24(t *testing.T) {
	p := &payloadHeader{streamId: 1, streamOffset: 100}
	encoded, _ := encodeProto(p, []byte("data"))

	flags := encoded[0]
	assert.True(t, flags&flagHasAck == 0)
	assert.True(t, flags&flagExtend == 0)
}

func TestProto_Flags_DataWithAck24(t *testing.T) {
	p := &payloadHeader{streamId: 1, streamOffset: 100, ack: &ack{offset: 50}}
	encoded, _ := encodeProto(p, []byte("data"))

	flags := encoded[0]
	assert.True(t, flags&flagHasAck != 0)
	assert.True(t, flags&flagExtend == 0)
}

func TestProto_Flags_DataNoAck48(t *testing.T) {
	p := &payloadHeader{streamId: 1, streamOffset: 0x1000000}
	encoded, _ := encodeProto(p, []byte("data"))

	flags := encoded[0]
	assert.True(t, flags&flagHasAck == 0)
	assert.True(t, flags&flagExtend != 0)
}

func TestProto_Flags_DataWithAck48(t *testing.T) {
	p := &payloadHeader{streamId: 1, streamOffset: 0x1000000, ack: &ack{offset: 50}}
	encoded, _ := encodeProto(p, []byte("data"))

	flags := encoded[0]
	assert.True(t, flags&flagHasAck != 0)
	assert.True(t, flags&flagExtend != 0)
}

func TestProto_Flags_CloseNoAck24(t *testing.T) {
	p := &payloadHeader{isClose: true, streamId: 1, streamOffset: 100}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagClose != 0)
	assert.True(t, flags&flagHasAck == 0)
	assert.True(t, flags&flagExtend == 0)
}

func TestProto_Flags_CloseWithAck24(t *testing.T) {
	p := &payloadHeader{isClose: true, streamId: 1, streamOffset: 100, ack: &ack{offset: 50}}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagClose != 0)
	assert.True(t, flags&flagHasAck != 0)
}

func TestProto_Flags_Probe24(t *testing.T) {
	p := &payloadHeader{isProbe: true, streamId: 1, streamOffset: 100}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagProbe != 0)
	assert.True(t, flags&flagExtend == 0)
}

func TestProto_Flags_Probe48(t *testing.T) {
	p := &payloadHeader{isProbe: true, streamId: 1, streamOffset: 0x1000000}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagProbe != 0)
	assert.True(t, flags&flagExtend != 0)
}

func TestProto_Flags_KeyUpdate(t *testing.T) {
	p := &payloadHeader{isKeyUpdate: true, keyUpdatePub: make([]byte, pubKeySize), streamId: 1, streamOffset: 100}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagKeyUpdate != 0)
}

func TestProto_Flags_KeyUpdateAck(t *testing.T) {
	p := &payloadHeader{isKeyUpdateAck: true, keyUpdatePubAck: make([]byte, pubKeySize), streamId: 1, streamOffset: 100}
	encoded, _ := encodeProto(p, []byte{})

	flags := encoded[0]
	assert.True(t, flags&flagKeyUpdateAck != 0)
}

func TestProto_Flags_AckTriggersExtend(t *testing.T) {
	// Data offset is 24-bit, but ACK offset is 48-bit
	p := &payloadHeader{streamId: 1, streamOffset: 100, ack: &ack{offset: 0x1000000}}
	encoded, _ := encodeProto(p, []byte("data"))

	flags := encoded[0]
	assert.True(t, flags&flagExtend != 0)
}

// =============================================================================
// STREAM HEADER PRESENCE TESTS
// =============================================================================

func TestProto_StreamHeader_NoAckMeansStreamHeader(t *testing.T) {
	// When there's no ACK, stream header is always included (for minimum packet size)
	original := &payloadHeader{
		streamId:     42,
		streamOffset: 123,
	}

	decoded, userData := roundTrip(t, original, nil)

	assert.Equal(t, uint32(42), decoded.streamId)
	assert.Equal(t, uint64(123), decoded.streamOffset)
	assert.NotNil(t, userData) // empty slice, not nil
	assert.Empty(t, userData)
}

func TestProto_StreamHeader_AckOnlyNoStreamHeader(t *testing.T) {
	// ACK-only packets don't include stream header
	original := &payloadHeader{
		ack: &ack{streamId: 10, offset: 200, len: 50, rcvWnd: 1000},
	}

	decoded, userData := roundTrip(t, original, nil)

	assert.NotNil(t, decoded.ack)
	assert.Nil(t, userData) // nil means no stream header was parsed
}

func TestProto_StreamHeader_AckWithDataHasStreamHeader(t *testing.T) {
	// ACK with data includes stream header
	original := &payloadHeader{
		streamId:     5,
		streamOffset: 50,
		ack:          &ack{streamId: 10, offset: 200, len: 50, rcvWnd: 1000},
	}

	decoded, userData := roundTrip(t, original, []byte("test"))

	assert.NotNil(t, decoded.ack)
	assert.Equal(t, uint32(5), decoded.streamId)
	assert.Equal(t, []byte("test"), userData)
}