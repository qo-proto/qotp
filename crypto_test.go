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

// DecryptWithSecrets is the offline/debugging entry point: round-trip every
// message type through it, including the InitCryptoSnd padding strip.
func TestCryptoDecryptWithSecrets_RoundTrip(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)
	payload := randomBytes(minProtoSize)

	// InitSnd: unencrypted, returns empty
	_, buf, err := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), 1400)
	assert.NoError(t, err)
	out, err := DecryptWithSecrets(buf, false, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, out)

	// InitCryptoSnd: needs sharedSecretId = ECDH(alice ep, bob id)
	_, buf, err = encryptInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, payload)
	assert.NoError(t, err)
	ssId, _ := alicePrvKeyEp.ECDH(bobPrvKeyId.PublicKey())
	out, err = DecryptWithSecrets(buf, false, nil, ssId)
	assert.NoError(t, err)
	assert.Equal(t, payload, out, "InitCryptoSnd payload (padding must be stripped)")

	// InitRcv: encrypted to alice's ephemeral, secret = ECDH(bob ep, alice ep)
	buf, err = encryptPacket(initRcv, 42, bobPrvKeyEp, bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), nil, 0, false, payload)
	assert.NoError(t, err)
	ss, _ := bobPrvKeyEp.ECDH(alicePrvKeyEp.PublicKey())
	out, err = DecryptWithSecrets(buf, false, ss, nil)
	assert.NoError(t, err)
	assert.Equal(t, payload, out, "InitRcv payload")

	// InitCryptoRcv
	buf, err = encryptPacket(initCryptoRcv, 42, bobPrvKeyEp, bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), nil, 0, false, payload)
	assert.NoError(t, err)
	out, err = DecryptWithSecrets(buf, false, ss, nil)
	assert.NoError(t, err)
	assert.Equal(t, payload, out, "InitCryptoRcv payload")

	// Data, both nonce directions. chainedDecrypt inverts the direction bit,
	// so a packet encrypted with isSender=X is read back with isSender=!X.
	for _, isSender := range []bool{true, false} {
		buf, err = encryptPacket(data, 42, bobPrvKeyEp, bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), ss, 7, isSender, payload)
		assert.NoError(t, err)
		out, err = DecryptWithSecrets(buf, !isSender, ss, nil)
		assert.NoError(t, err)
		assert.Equal(t, payload, out, "Data payload isSender=%v", isSender)
	}

	// Missing-secret errors still name the right parameter
	buf, _ = encryptPacket(data, 42, bobPrvKeyEp, bobPrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), ss, 7, false, payload)
	_, err = DecryptWithSecrets(buf, true, nil, nil)
	assert.ErrorContains(t, err, "sharedSecret required for Data")
}

// A crafted InitCryptoSnd whose padding header claims a filler longer than the
// payload must be rejected, not panic. InitCryptoSnd is sealed to the
// receiver's *public* identity key, so the plaintext is attacker-chosen: this
// was a remote, pre-connection crash reachable with a single datagram.
func TestCryptoInitCryptoSnd_FillerLenOverflow(t *testing.T) {
	bobPrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	alicePrvKeyId := generateTestKey(t)

	secret, err := alicePrvKeyEp.ECDH(bobPrvKeyId.PublicKey())
	assert.NoError(t, err)

	header := make([]byte, minInitCryptoSndSizeHdr)
	header[0] = (uint8(initCryptoSnd) << 5) | cryptoVersion
	copy(header[headerSize:], alicePrvKeyEp.PublicKey().Bytes())
	copy(header[headerSize+pubKeySize:], alicePrvKeyId.PublicKey().Bytes())

	for _, fillerLen := range []uint16{0xFFFF, 1200, 1144} {
		padded := make([]byte, conservativeMTU-(minInitCryptoSndSizeHdr+footerDataSize))
		putUint16(padded, fillerLen)

		encData, err := chainedEncrypt(0, true, secret, header, padded)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, len(encData), conservativeMTU)

		_, _, _, err = decryptInitCryptoSnd(encData, bobPrvKeyId)
		if int(fillerLen)+msgInitFillLenSize > len(padded) {
			assert.ErrorContains(t, err, "invalid filler length", "fillerLen=%d", fillerLen)
		} else {
			assert.NoError(t, err, "fillerLen=%d is in range and must be accepted", fillerLen)
		}
	}
}

// The same packet through the real Listen() entry point.
func TestCryptoInitCryptoSnd_FillerLenOverflowViaListen(t *testing.T) {
	pair := NewConnPair("127.0.0.1:9000", "127.0.0.1:9001")
	l, err := Listen(WithNetworkConn(pair.Conn1), WithSeed([32]byte{9}))
	assert.NoError(t, err)

	alicePrvKeyEp := generateTestKey(t)
	alicePrvKeyId := generateTestKey(t)
	secret, err := alicePrvKeyEp.ECDH(l.prvKeyId.PublicKey()) // public key only
	assert.NoError(t, err)

	header := make([]byte, minInitCryptoSndSizeHdr)
	header[0] = (uint8(initCryptoSnd) << 5) | cryptoVersion
	copy(header[headerSize:], alicePrvKeyEp.PublicKey().Bytes())
	copy(header[headerSize+pubKeySize:], alicePrvKeyId.PublicKey().Bytes())

	padded := make([]byte, conservativeMTU-(minInitCryptoSndSizeHdr+footerDataSize))
	putUint16(padded, 0xFFFF)
	encData, err := chainedEncrypt(0, true, secret, header, padded)
	assert.NoError(t, err)

	pair.Conn1.readQueue = append(pair.Conn1.readQueue, packetData{
		data: encData, remoteAddr: "127.0.0.1:9001", arrivalTime: 0,
	})

	_, err = l.Listen(1000, 0)
	assert.ErrorContains(t, err, "invalid filler length")
}

// chainedDecrypt takes its XChaCha20 nonce from the first 24 bytes of the
// sealed payload, so it needs snSize+24 bytes, not the snSize+macSize the
// per-type guards used to promise. Exactly-sized buffers (no spare capacity to
// mask the reslice) across the boundary must error, never panic.
func TestCryptoDecrypt_ShortEncryptedPayload(t *testing.T) {
	prv := generateTestKey(t)
	pub := prv.PublicKey().Bytes()
	minEnc := snSize + 24

	for _, msgType := range []cryptoMsgType{initRcv, initCryptoRcv, data} {
		for _, encLen := range []int{0, 1, footerDataSize, minEnc - 1, minEnc} {
			size := aadLen(msgType) + encLen
			buf := make([]byte, size, size) // exact capacity: no reslice slack
			buf[0] = (uint8(msgType) << 5) | cryptoVersion
			if size >= headerSize+connIdSize+2*pubKeySize {
				copy(buf[headerSize+connIdSize:], pub)
				copy(buf[headerSize+connIdSize+pubKeySize:], pub)
			} else if size >= headerSize+connIdSize+pubKeySize {
				copy(buf[headerSize+connIdSize:], pub)
			}

			var err error
			switch msgType {
			case initRcv:
				_, _, _, _, err = decryptInitRcv(buf, prv)
			case initCryptoRcv:
				_, _, _, err = decryptInitCryptoRcv(buf, prv)
			case data:
				_, err = decryptData(buf, false, [][]byte{make([]byte, 32)})
			}
			assert.Error(t, err, "msgType=%d encLen=%d must be rejected", msgType, encLen)
		}
	}
}

// DecryptWithSecrets is handed caller-allocated (exactly sized) buffers, so it
// has no spare capacity to hide a short read behind.
func TestCryptoDecryptWithSecrets_ShortPacket(t *testing.T) {
	prv := generateTestKey(t)
	pub := prv.PublicKey().Bytes()

	for _, encLen := range []int{footerDataSize, snSize + 23} {
		size := aadLen(initRcv) + encLen
		buf := make([]byte, size, size)
		buf[0] = (uint8(initRcv) << 5) | cryptoVersion
		copy(buf[headerSize+connIdSize:], pub)
		copy(buf[headerSize+connIdSize+pubKeySize:], pub)

		_, err := DecryptWithSecrets(buf, false, make([]byte, 32), nil)
		assert.Error(t, err, "encLen=%d must be rejected", encLen)
	}
}
