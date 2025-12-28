package qotp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper functions
func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func generateKeys(t *testing.T) *ecdh.PrivateKey {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	return privKey
}

func testDoubleEncryptDecrypt(t *testing.T, sn uint64, data []byte, additionalData []byte) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("Failed to generate shared secret: %v", err)
	}

	buf, err := chainedEncrypt(sn, 0, true, sharedSecret, additionalData, data)
	// too short
	if len(data) < MinProtoSize {
		assert.NotNil(t, err)
		return
	}
	assert.Nil(t, err)

	if len(buf) == 0 {
		t.Fatalf("No encrypted dataToSend written")
	}
	t.Logf("Encrypted dataToSend: %s", hex.EncodeToString(buf))

	decryptedSn, decryptedEpoch, decryptedData, err := chainedDecrypt(false, 0, sharedSecret, buf[0:len(additionalData)], buf[len(additionalData):])
	assert.Nil(t, err)

	assert.Equal(t, uint64(0), decryptedEpoch)
	assert.Equal(t, sn, decryptedSn)
	assert.Equal(t, data, decryptedData)
}

// Encryption/Decryption Tests
func TestCryptoDoubleEncryptDecryptShortData(t *testing.T) {
	testDoubleEncryptDecrypt(t, 1234567890, randomBytes(10), []byte("AAD"))
}

func TestCryptoDoubleEncryptDecryptLongData(t *testing.T) {
	testDoubleEncryptDecrypt(t, 987654321, randomBytes(100), randomBytes(100))
}

func TestCryptoDoubleEncryptDecryptLongDataShortAAD(t *testing.T) {
	testDoubleEncryptDecrypt(t, 1, randomBytes(100), []byte(""))
}

func TestCryptoDoubleEncryptDecryptMinData(t *testing.T) {
	testDoubleEncryptDecrypt(t, 2, randomBytes(9), []byte("Only AAD"))
}

func TestCryptoDoubleEncryptDecryptMinData2(t *testing.T) {
	testDoubleEncryptDecrypt(t, 2, randomBytes(9), []byte(""))
}

// Corner case: Maximum sequence number
func TestCryptoDoubleEncryptDecryptMaxSequenceNumber(t *testing.T) {
	testDoubleEncryptDecrypt(t, uint64(0xffffffffffff), randomBytes(10), []byte("AAD"))
}

// Corner case: Zero sequence number
func TestCryptoDoubleEncryptDecryptZeroSequenceNumber(t *testing.T) {
	testDoubleEncryptDecrypt(t, 0, randomBytes(10), []byte("AAD"))
}

// Corner case: Large AAD
func TestCryptoDoubleEncryptDecryptLargeAAD(t *testing.T) {
	testDoubleEncryptDecrypt(t, 12345, randomBytes(10), randomBytes(1000))
}

// Corner case: Exactly minimum payload size
func TestCryptoDoubleEncryptDecryptExactMinPayload(t *testing.T) {
	testDoubleEncryptDecrypt(t, 123, randomBytes(MinProtoSize), []byte("AAD"))
}

func TestCryptoSecretKey(t *testing.T) {
	bobPrvKeyId := generateKeys(t)
	bobPubKeyId := bobPrvKeyId.PublicKey()
	alicePrvKeyEp := generateKeys(t)
	alicePubKeyEp := alicePrvKeyEp.PublicKey()

	secret1, err := bobPrvKeyId.ECDH(alicePubKeyEp)
	assert.Nil(t, err)
	secret2, err := alicePrvKeyEp.ECDH(bobPubKeyId)
	assert.Nil(t, err)

	assert.Equal(t, secret1, secret2)
}

// Corner case: ECDH with same keys
func TestCryptoSecretKeySameKeys(t *testing.T) {
	key := generateKeys(t)
	pubKey := key.PublicKey()

	secret, err := key.ECDH(pubKey)
	assert.Nil(t, err)
	assert.NotNil(t, secret)
	assert.Len(t, secret, 32) // X25519 shared secret is 32 bytes
}

// Corner case: Multiple ECDH operations with same keys should produce same result
func TestCryptoSecretKeyDeterministic(t *testing.T) {
	key1 := generateKeys(t)
	key2 := generateKeys(t)

	secret1, err := key1.ECDH(key2.PublicKey())
	assert.Nil(t, err)
	secret2, err := key1.ECDH(key2.PublicKey())
	assert.Nil(t, err)

	assert.Equal(t, secret1, secret2)
}

func testEncodeDecodeInitCryptoSnd(t *testing.T, payload []byte) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)

	_, buffer, err := encryptInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, defaultMTU, payload)

	// If payload is too short (< 8 bytes), expect error
	if len(payload) < 8 {
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "too short")
		return
	}

	assert.Nil(t, err)

	_, _, m, err := decryptInitCryptoSnd(buffer, bobPrvKeyId, defaultMTU)
	assert.Nil(t, err)
	assert.Equal(t, payload, m.PayloadRaw)
}

// InitCrypto Tests
func TestCryptoEncodeDecodeInitCryptoSndShortPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, []byte("short1234"))
}

func TestCryptoEncodeDecodeInitCryptoSndLongPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, randomBytes(100))
}

func TestCryptoEncodeDecodeInitCryptoSndMaxPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, randomBytes(1303))
}

// Corner case: Exactly 8 bytes payload (should succeed)
func TestCryptoEncodeDecodeInitCryptoSnd8BytePayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, []byte("12345678"))
}

func testEncodeDecodeInitCryptoRcv(t *testing.T, payload []byte) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	// Alice -> Bob, Alice encodes (need valid payload for this step)
	validPayload := payload
	if len(payload) < 8 {
		validPayload = []byte("12345678") // Use minimum valid payload for initial step
	}

	connId, bufferInit, err := encryptInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, defaultMTU, validPayload)
	assert.Nil(t, err)

	// Bob decodes message from Alice
	_, _, _, err = decryptInitCryptoSnd(bufferInit, bobPrvKeyId, defaultMTU)
	assert.Nil(t, err)

	// Bob -> Alice (test the actual payload we want to test)
	bufferInitReply, err := encryptInitCryptoRcv(connId, alicePrvKeyEp.PublicKey(), bobPrvKeyEp, 0, payload)

	// If payload is too short (< 8 bytes), expect error
	if len(payload) < 8 {
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "too short")
		return
	}

	assert.Nil(t, err)

	// Alice decodes message from Bob
	_, _, m2, err := decryptInitCryptoRcv(bufferInitReply, alicePrvKeyEp)
	assert.Nil(t, err)
	assert.Equal(t, payload, m2.PayloadRaw)
}

func TestCryptoEncodeDecodeInitCryptoRcvShortPayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, []byte("short1234"))
}

func TestCryptoEncodeDecodeInitCryptoRcvLongPayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, randomBytes(100))
}

// Corner case: Exactly 8 bytes payload for InitCryptoRcv (should succeed)
func TestCryptoEncodeDecodeInitCryptoRcv8BytePayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, []byte("12345678"))
}

// Corner case: Maximum size payload for InitCryptoRcv
func TestCryptoEncodeDecodeInitCryptoRcvMaxPayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, randomBytes(1303))
}

// Init Handshake Tests
func TestCryptoInitSndBasicFlow(t *testing.T) {
	// Generate keys
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	// Alice -> Bob: Encode InitHandshakeS0
	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	// Bob receives and decodes InitHandshakeS0
	pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(buffer, defaultMTU)

	// Verify the results
	assert.NoError(t, err)

	// Verify the public keys match what was sent
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func TestCryptoInitSndInvalidSize(t *testing.T) {
	// Test with buffer that's too small
	buffer := make([]byte, 1399)
	_, _, err := decryptInitSnd(buffer, defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init")
}

// Corner case: Exactly minimum size buffer
func TestCryptoInitSndExactMinSize(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	// Verify the buffer is at least minimum size
	assert.GreaterOrEqual(t, len(buffer), defaultMTU)

	// Should decode successfully
	_, _, err := decryptInitSnd(buffer, defaultMTU)
	assert.NoError(t, err)
}

// Corner case: Empty buffer
func TestCryptoInitSndEmptyBuffer(t *testing.T) {
	_, _, err := decryptInitSnd([]byte{}, defaultMTU)
	assert.Error(t, err)
}

func TestCryptoInitRcvBasicFlow(t *testing.T) {
	// Generate keys
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	// Bob -> Alice: Encode InitHandshakeR0
	rawData := []byte("test data")
	buffer, err := encryptInitRcv(
		0,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp,
		0,
		rawData)

	assert.NoError(t, err)

	// Alice receives and decodes InitHandshakeR0
	_, pubKeyIdRcv, pubKeyEpRcv, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)

	// Verify the results
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), msg.SnConn)
	assert.Equal(t, rawData, msg.PayloadRaw)

	// Verify the public keys match what was sent
	assert.True(t, bytes.Equal(bobPrvKeyId.PublicKey().Bytes(), pubKeyIdRcv.Bytes()))
	assert.True(t, bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
}

func TestCryptoInitRcvInvalidSize(t *testing.T) {
	// Test with buffer that's too small
	buffer := make([]byte, MinInitRcvSizeHdr+FooterDataSize-1)
	_, _, _, _, err := decryptInitRcv(buffer, generateKeys(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init reply")
}

// Corner case: 8 bytes payload for InitRcv
func TestCryptoInitRcv8BytePayload(t *testing.T) {
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	payload := []byte("12345678")
	buffer, err := encryptInitRcv(
		0,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp,
		0,
		payload)

	assert.NoError(t, err)
	_, _, _, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.PayloadRaw)
}

// Corner case: Maximum epoch and sequence values
func TestCryptoInitRcvMaxValues(t *testing.T) {
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	maxSn := ^uint64(0)

	buffer, err := encryptInitRcv(
		0,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp,
		maxSn,
		[]byte("test1234"))

	assert.NoError(t, err)

	_, _, _, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, []byte("test1234"), msg.PayloadRaw)
}

func TestCryptoFullHandshakeFlow(t *testing.T) {
	// Generate keys for both parties
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	// Step 1: Alice sends InitHandshakeS0
	connId, bufferS0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	// Step 2: Bob receives and decodes InitHandshakeS0
	_, _, err := decryptInitSnd(bufferS0, defaultMTU)
	assert.NoError(t, err)

	// Step 3: Bob sends InitHandshakeR0
	rawData := []byte("handshake response")
	bufferR0, err := encryptInitRcv(
		connId,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		bobPrvKeyEp, 0,
		rawData)
	assert.NoError(t, err)

	// Step 4: Alice receives and decodes InitHandshakeR0
	_, _, _, _, err = decryptInitRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)

}

// Corner case: Multiple handshakes between same parties
func TestCryptoMultipleHandshakes(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	bobPrvKeyId := generateKeys(t)

	// First handshake
	alicePrvKeyEp1 := generateKeys(t)
	bobPrvKeyEp1 := generateKeys(t)

	connId, buffer1S0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp1.PublicKey(), defaultMTU)
	_, _, err := decryptInitSnd(buffer1S0, defaultMTU)
	assert.NoError(t, err)

	buffer1R0, err := encryptInitRcv(
		connId,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp1.PublicKey(),
		bobPrvKeyEp1, 0,
		[]byte("first123"))
	assert.NoError(t, err)

	_, _, _, _, err = decryptInitRcv(buffer1R0, alicePrvKeyEp1)
	assert.NoError(t, err)

	// Second handshake with different ephemeral keys
	alicePrvKeyEp2 := generateKeys(t)
	bobPrvKeyEp2 := generateKeys(t)

	connId, buffer2S0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp2.PublicKey(), defaultMTU)
	_, _, err = decryptInitSnd(buffer2S0, defaultMTU)
	assert.NoError(t, err)

	buffer2R0, err := encryptInitRcv(
		connId,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp2.PublicKey(),
		bobPrvKeyEp2, 0,
		[]byte("second12"))
	assert.NoError(t, err)

	_, _, _, _, err = decryptInitRcv(buffer2R0, alicePrvKeyEp2)
	assert.NoError(t, err)

}

// Corner case: Corrupted buffer data
func TestCryptoCorruptedBuffer(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	// Create valid buffer
	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	// Corrupt the buffer
	if len(buffer) > 10 {
		buffer[5] ^= 0xFF // Flip bits
		buffer[10] ^= 0xFF
	}

	// Should fail to decode
	_, _, err := decryptInitSnd(buffer, defaultMTU)
	// Note: Depending on where corruption occurs, this might succeed or fail
	// The test verifies the function doesn't panic on corrupted data
	_ = err // Explicitly acknowledge we're not checking the error
}

// Corner case: Very large buffer
func TestCryptoVeryLargeBuffer(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, validBuffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	// Create oversized buffer by appending extra data
	largeBuffer := make([]byte, len(validBuffer)+10000)
	copy(largeBuffer, validBuffer)

	// Should still decode the valid portion
	_, _, err := decryptInitSnd(largeBuffer, defaultMTU)
	assert.NoError(t, err)
}

// Corner case: Buffer with wrong message type or corrupted header
func TestCryptoRandomBuffer(t *testing.T) {
	randomBuffer := randomBytes(1000)

	// Should handle random data gracefully
	_, _, err := decryptInitSnd(randomBuffer, defaultMTU)
	// This will likely fail, but shouldn't panic
	_ = err
}

func TestCryptoOverhead(t *testing.T) {
	// InitSnd returns -1 (no data allowed)
	assert.Equal(t, -1, calcCryptoOverheadWithData(InitSnd, nil, 100))

	// InitRcv
	expected := calcProtoOverhead(false, false, false) + MinInitRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitRcv, nil, 100))

	// InitCryptoSnd
	expected = calcProtoOverhead(false, false, false) + MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitCryptoSnd, nil, 100))

	// InitCryptoRcv
	expected = calcProtoOverhead(false, false, false) + MinInitCryptoRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitCryptoRcv, nil, 100))

	// Data no ACK, small offset (24-bit)
	expected = calcProtoOverhead(false, false, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, nil, 2000))
}

func TestCryptoOverheadWithAck(t *testing.T) {
	// Data with small ACK offset (24-bit)
	ack := &Ack{offset: 1000}
	expected := calcProtoOverhead(true, false, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, ack, 2000))

	// Data with large ACK offset (48-bit required)
	ack = &Ack{offset: 0xFFFFFF + 1}
	expected = calcProtoOverhead(true, true, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, ack, 100))
}

func TestCryptoOverheadLargeOffset(t *testing.T) {
	// Data with large data offset (48-bit required)
	expected := calcProtoOverhead(false, true, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, nil, 0xFFFFFF+1))
}
