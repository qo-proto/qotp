package qotp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// TEST HELPERS
// =============================================================================

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func generateTestKey(t *testing.T) *ecdh.PrivateKey {
	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return privKey
}

// =============================================================================
// CHAINED ENCRYPT/DECRYPT TESTS
// =============================================================================

func TestCryptoChainedEncryptDecrypt_ShortData(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(1234567890, true, sharedSecret, aad, data)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf)

	decrypted, err := chainedDecrypt(false, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_LongData(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(1000)
	aad := randomBytes(100)

	buf, err := chainedEncrypt(987654321, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_EmptyAAD(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte{}

	buf, err := chainedEncrypt(1, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{sharedSecret}, buf[:0], buf)
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_MaxSequenceNumber(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")
	maxSn := uint64(0xffffffffffff) // 48-bit max

	buf, err := chainedEncrypt(maxSn, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_ZeroSequenceNumber(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_WrongSharedSecret(t *testing.T) {
	sharedSecret := randomBytes(32)
	wrongSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	_, err = chainedDecrypt(false, [][]byte{wrongSecret}, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

func TestCryptoChainedDecrypt_WrongDirection(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	// Encrypt as sender (isSender=true)
	buf, err := chainedEncrypt(100, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Decrypt as sender instead of receiver - should fail due to direction bit
	_, err = chainedDecrypt(true, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

func TestCryptoChainedDecrypt_CorruptedMAC(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Corrupt the last byte (MAC)
	buf[len(buf)-1] ^= 0xFF

	_, err = chainedDecrypt(false, [][]byte{sharedSecret}, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

// =============================================================================
// MULTI-KEY DECRYPTION TESTS (Key Rotation Support)
// =============================================================================

func TestCryptoChainedDecrypt_MultipleSecrets_FirstMatches(t *testing.T) {
	secret1 := randomBytes(32)
	secret2 := randomBytes(32)
	secret3 := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, secret1, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{secret1, secret2, secret3}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_MultipleSecrets_SecondMatches(t *testing.T) {
	secret1 := randomBytes(32)
	secret2 := randomBytes(32)
	secret3 := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, secret2, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{secret1, secret2, secret3}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_MultipleSecrets_ThirdMatches(t *testing.T) {
	secret1 := randomBytes(32)
	secret2 := randomBytes(32)
	secret3 := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, secret3, aad, data)
	assert.NoError(t, err)

	decrypted, err := chainedDecrypt(false, [][]byte{secret1, secret2, secret3}, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_MultipleSecrets_NoneMatch(t *testing.T) {
	secret1 := randomBytes(32)
	secret2 := randomBytes(32)
	secretActual := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, true, secretActual, aad, data)
	assert.NoError(t, err)

	_, err = chainedDecrypt(false, [][]byte{secret1, secret2}, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

// =============================================================================
// INIT SND TESTS
// =============================================================================

func TestCryptoInitSnd_BasicFlow(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)

	connId, buffer, err := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), testMaxPayload)
	assert.NoError(t, err)
	assert.Equal(t, conservativeMTU, len(buffer))
	assert.NotZero(t, connId)

	pubKeyIdSnd, pubKeyEpSnd, senderMaxPayload, err := decryptInitSnd(buffer)
	assert.NoError(t, err)
	assert.Equal(t, uint16(testMaxPayload), senderMaxPayload)
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func TestCryptoInitSnd_NilPubKeyId(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)

	_, _, err := encryptInitSnd(nil, alicePrvKeyEp.PublicKey(), testMaxPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoInitSnd_NilPubKeyEp(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)

	_, _, err := encryptInitSnd(alicePrvKeyId.PublicKey(), nil, testMaxPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitSnd_TooSmall(t *testing.T) {
	buffer := make([]byte, conservativeMTU-1)
	_, _, _, err := decryptInitSnd(buffer)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init")
}

func TestCryptoDecryptInitSnd_EmptyBuffer(t *testing.T) {
	_, _, _, err := decryptInitSnd([]byte{})
	assert.Error(t, err)
}

// =============================================================================
// INIT RCV TESTS
// =============================================================================

func TestCryptoInitRcv_BasicFlow(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	rawData := []byte("test data")
	buffer, err := encryptPacket(
		initRcv,
		12345,
		bobPrvKeyEp,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		nil,
		0,
		false,
		rawData,
	)
	assert.NoError(t, err)

	sharedSecret, pubKeyIdRcv, pubKeyEpRcv, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.NotNil(t, sharedSecret)
	assert.NotNil(t, pubKeyIdRcv)
	assert.NotNil(t, pubKeyEpRcv)
	assert.Equal(t, rawData, msg)
}

func TestCryptoInitRcv_NilKeys(t *testing.T) {
	_, err := encryptPacket(
		initRcv,
		12345,
		nil,
		nil,
		nil,
		nil,
		0,
		false,
		[]byte("test"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitRcv_TooSmall(t *testing.T) {
	buffer := make([]byte, minInitRcvSizeHdr+footerDataSize-1)
	_, _, _, _, err := decryptInitRcv(buffer, generateTestKey(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum")
}

// =============================================================================
// INIT CRYPTO SND TESTS
// =============================================================================

func TestCryptoInitCryptoSnd_BasicFlow(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)

	rawData := []byte("init crypto data")
	connId, buffer, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		rawData,
	)
	assert.NoError(t, err)
	assert.NotZero(t, connId)
	assert.Equal(t, conservativeMTU, len(buffer))

	pubKeyIdSnd, pubKeyEpSnd, msg, err := decryptInitCryptoSnd(buffer, bobPrvKeyId)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
	assert.Equal(t, rawData, msg)
}

func TestCryptoInitCryptoSnd_NilKeys(t *testing.T) {
	_, _, err := encryptInitCryptoSnd(nil, nil, nil, 0, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoInitCryptoSnd_PayloadTooLarge(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)

	// Payload larger than MTU allows
	largeData := make([]byte, testMaxPayload)

	_, _, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		largeData,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestCryptoDecryptInitCryptoSnd_TooSmall(t *testing.T) {
	buffer := make([]byte, conservativeMTU-1)
	_, _, _, err := decryptInitCryptoSnd(buffer, generateTestKey(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum")
}

// =============================================================================
// INIT CRYPTO RCV TESTS
// =============================================================================

func TestCryptoInitCryptoRcv_BasicFlow(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	rawData := []byte("init crypto response")
	buffer, err := encryptPacket(
		initCryptoRcv,
		12345,
		bobPrvKeyEp,
		nil,
		alicePrvKeyEp.PublicKey(),
		nil,
		0,
		false,
		rawData,
	)
	assert.NoError(t, err)

	sharedSecret, pubKeyEpRcv, msg, err := decryptInitCryptoRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.NotNil(t, sharedSecret)
	assert.NotNil(t, pubKeyEpRcv)
	assert.Equal(t, rawData, msg)
}

func TestCryptoInitCryptoRcv_NilKeys(t *testing.T) {
	_, err := encryptPacket(
		initCryptoRcv,
		12345,
		nil,
		nil,
		nil,
		nil,
		0,
		false,
		[]byte("test"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitCryptoRcv_TooSmall(t *testing.T) {
	buffer := make([]byte, minInitCryptoRcvSizeHdr+footerDataSize-1)
	_, _, _, err := decryptInitCryptoRcv(buffer, generateTestKey(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum")
}

// =============================================================================
// DATA PACKET TESTS
// =============================================================================

func TestCryptoData_BasicFlow(t *testing.T) {
	sharedSecret := randomBytes(32)
	payload := []byte("test data payload")

	encData, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		sharedSecret,
		0,
		true,
		payload,
	)
	assert.NoError(t, err)

	msg, err := decryptData(encData, false, [][]byte{sharedSecret})
	assert.NoError(t, err)
	assert.Equal(t, payload, msg)
}

func TestCryptoData_NilSharedSecret(t *testing.T) {
	_, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		nil,
		0,
		true,
		[]byte("test"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoData_MultipleKeys(t *testing.T) {
	prevSecret := randomBytes(32)
	curSecret := randomBytes(32)
	payload := []byte("test with key rotation")

	// Encrypt with previous secret (simulating delayed packet)
	encData, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		prevSecret,
		50,
		true,
		payload,
	)
	assert.NoError(t, err)

	// Decrypt with current and previous secrets
	msg, err := decryptData(encData, false, [][]byte{curSecret, prevSecret})
	assert.NoError(t, err)
	assert.Equal(t, payload, msg)
}

func TestCryptoDecryptData_TooSmall(t *testing.T) {
	sharedSecret := randomBytes(32)
	buffer := make([]byte, minDataSizeHdr+footerDataSize-1)

	_, err := decryptData(buffer, false, [][]byte{sharedSecret})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum")
}

func TestCryptoDecryptData_WrongSecret(t *testing.T) {
	sharedSecret := randomBytes(32)
	wrongSecret := randomBytes(32)
	payload := []byte("test data")

	encData, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		sharedSecret,
		0,
		true,
		payload,
	)
	assert.NoError(t, err)

	_, err = decryptData(encData, false, [][]byte{wrongSecret})
	assert.Error(t, err)
}

// =============================================================================
// ENCRYPT PACKET ERROR TESTS
// =============================================================================

func TestCryptoEncryptPacket_UnsupportedMsgType(t *testing.T) {
	_, err := encryptPacket(
		cryptoMsgType(99),
		0,
		nil,
		nil,
		nil,
		nil,
		0,
		false,
		[]byte("test1234"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

// =============================================================================
// FULL HANDSHAKE FLOW TESTS
// =============================================================================

func TestCryptoFullHandshake_NoCrypto(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	// Step 1: Alice sends InitSnd
	connId, bufferS0, err := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), testMaxPayload)
	assert.NoError(t, err)

	// Step 2: Bob receives InitSnd
	_, pubKeyEpSnd, senderMaxPayload, err := decryptInitSnd(bufferS0)
	assert.NoError(t, err)
	assert.Equal(t, uint16(testMaxPayload), senderMaxPayload)

	// Step 3: Bob sends InitRcv
	rawData := []byte("handshake response")
	bufferR0, err := encryptPacket(
		initRcv,
		connId,
		bobPrvKeyEp,
		bobPrvKeyId.PublicKey(),
		pubKeyEpSnd,
		nil,
		0,
		false,
		rawData,
	)
	assert.NoError(t, err)

	// Step 4: Alice receives InitRcv
	_, _, _, msg, err := decryptInitRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, rawData, msg)
}

func TestCryptoFullHandshake_WithCrypto(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	// Step 1: Alice sends InitCryptoSnd
	initPayload := []byte("init data")
	connId, bufferS0, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		initPayload,
	)
	assert.NoError(t, err)

	// Step 2: Bob receives InitCryptoSnd
	_, pubKeyEpSnd, msg, err := decryptInitCryptoSnd(bufferS0, bobPrvKeyId)
	assert.NoError(t, err)
	assert.Equal(t, initPayload, msg)

	// Step 3: Bob sends InitCryptoRcv
	responsePayload := []byte("response")
	bufferR0, err := encryptPacket(
		initCryptoRcv,
		connId,
		bobPrvKeyEp,
		nil,
		pubKeyEpSnd,
		nil,
		0,
		false,
		responsePayload,
	)
	assert.NoError(t, err)

	// Step 4: Alice receives InitCryptoRcv
	_, _, msg, err = decryptInitCryptoRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, responsePayload, msg)
}

// =============================================================================
// CRYPTO OVERHEAD TESTS
// =============================================================================

func TestCryptoOverhead_InitSnd(t *testing.T) {
	assert.Equal(t, -1, calcCryptoOverheadWithData(initSnd, nil, 100))
}

func TestCryptoOverhead_InitRcv(t *testing.T) {
	// calcCryptoOverheadWithData always sizes with the stream header present
	expected := calcProtoOverhead(flagHasStream) + minInitRcvSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initRcv, nil, 100))
}

func TestCryptoOverhead_InitCryptoSnd(t *testing.T) {
	expected := calcProtoOverhead(flagHasStream) + minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initCryptoSnd, nil, 100))
}

func TestCryptoOverhead_InitCryptoRcv(t *testing.T) {
	expected := calcProtoOverhead(flagHasStream) + minInitCryptoRcvSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initCryptoRcv, nil, 100))
}

func TestCryptoOverhead_Data(t *testing.T) {
	expected := calcProtoOverhead(flagHasStream) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, nil, 100))
}

func TestCryptoOverhead_DataWithAck(t *testing.T) {
	ack := &ack{offset: 1000}
	expected := calcProtoOverhead(flagHasStream|flagHasAck) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, ack, 100))
}

func TestCryptoOverhead_DataWithLargeAckOffset(t *testing.T) {
	ack := &ack{offset: 0xFFFFFF + 1}
	expected := calcProtoOverhead(flagHasStream|flagHasAck|flagExtend) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, ack, 100))
}

func TestCryptoOverhead_DataWithLargeOffset(t *testing.T) {
	expected := calcProtoOverhead(flagHasStream|flagExtend) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, nil, 0xFFFFFF+1))
}

// =============================================================================
// DECODE HEX PUB KEY TESTS
// =============================================================================

func TestCryptoDecodeHexPubKey_Valid(t *testing.T) {
	key := generateTestKey(t)
	hexStr := hex.EncodeToString(key.PublicKey().Bytes())

	pubKey, err := decodeHexPubKey(hexStr)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(key.PublicKey().Bytes(), pubKey.Bytes()))
}

func TestCryptoDecodeHexPubKey_With0xPrefix(t *testing.T) {
	key := generateTestKey(t)
	hexStr := "0x" + hex.EncodeToString(key.PublicKey().Bytes())

	pubKey, err := decodeHexPubKey(hexStr)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(key.PublicKey().Bytes(), pubKey.Bytes()))
}

func TestCryptoDecodeHexPubKey_InvalidHex(t *testing.T) {
	_, err := decodeHexPubKey("not-valid-hex!")
	assert.Error(t, err)
}

func TestCryptoDecodeHexPubKey_WrongLength(t *testing.T) {
	_, err := decodeHexPubKey("abcd") // Too short for X25519
	assert.Error(t, err)
}

func TestCryptoDecodeHexPubKey_Empty(t *testing.T) {
	_, err := decodeHexPubKey("")
	assert.Error(t, err)
}