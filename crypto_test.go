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

	buf, err := chainedEncrypt(1234567890, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)
	assert.NotEmpty(t, buf)

	sn, epoch, decrypted, err := chainedDecrypt(false, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(1234567890), sn)
	assert.Equal(t, uint64(0), epoch)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_LongData(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(1000)
	aad := randomBytes(100)

	buf, err := chainedEncrypt(987654321, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	sn, epoch, decrypted, err := chainedDecrypt(false, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(987654321), sn)
	assert.Equal(t, uint64(0), epoch)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_EmptyAAD(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte{}

	buf, err := chainedEncrypt(1, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	sn, _, decrypted, err := chainedDecrypt(false, 0, sharedSecret, buf[:0], buf)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), sn)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_MaxSequenceNumber(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")
	maxSn := uint64(0xffffffffffff) // 48-bit max

	buf, err := chainedEncrypt(maxSn, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	sn, _, decrypted, err := chainedDecrypt(false, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, maxSn, sn)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_ZeroSequenceNumber(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(0, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	sn, _, decrypted, err := chainedDecrypt(false, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), sn)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedEncryptDecrypt_WithEpoch(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, 5, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	sn, epoch, decrypted, err := chainedDecrypt(false, 5, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(100), sn)
	assert.Equal(t, uint64(5), epoch)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_EpochWindowMinus1(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	// Encrypt with epoch 5
	buf, err := chainedEncrypt(100, 5, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Decrypt expecting epoch 6 - should still work (tries epoch-1)
	sn, epoch, decrypted, err := chainedDecrypt(false, 6, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(100), sn)
	assert.Equal(t, uint64(5), epoch)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_EpochWindowPlus1(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	// Encrypt with epoch 5
	buf, err := chainedEncrypt(100, 5, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Decrypt expecting epoch 4 - should still work (tries epoch+1)
	sn, epoch, decrypted, err := chainedDecrypt(false, 4, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.NoError(t, err)
	assert.Equal(t, uint64(100), sn)
	assert.Equal(t, uint64(5), epoch)
	assert.Equal(t, data, decrypted)
}

func TestCryptoChainedDecrypt_EpochTooFar(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	// Encrypt with epoch 5
	buf, err := chainedEncrypt(100, 5, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Decrypt expecting epoch 10 - should fail (only tries ±1)
	_, _, _, err = chainedDecrypt(false, 10, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

func TestCryptoChainedDecrypt_WrongSharedSecret(t *testing.T) {
	sharedSecret := randomBytes(32)
	wrongSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	_, _, _, err = chainedDecrypt(false, 0, wrongSecret, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

func TestCryptoChainedDecrypt_WrongDirection(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	// Encrypt as sender (isSender=true)
	buf, err := chainedEncrypt(100, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Decrypt as sender instead of receiver - should fail due to direction bit
	_, _, _, err = chainedDecrypt(true, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

func TestCryptoChainedDecrypt_CorruptedMAC(t *testing.T) {
	sharedSecret := randomBytes(32)
	data := randomBytes(minProtoSize)
	aad := []byte("AAD")

	buf, err := chainedEncrypt(100, 0, true, sharedSecret, aad, data)
	assert.NoError(t, err)

	// Corrupt the last byte (MAC)
	buf[len(buf)-1] ^= 0xFF

	_, _, _, err = chainedDecrypt(false, 0, sharedSecret, buf[:len(aad)], buf[len(aad):])
	assert.Error(t, err)
}

// =============================================================================
// INIT SND TESTS
// =============================================================================

func TestCryptoInitSnd_BasicFlow(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)

	connId, buffer, err := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)
	assert.NoError(t, err)
	assert.Equal(t, defaultMTU, len(buffer))
	assert.NotZero(t, connId)

	pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(buffer, defaultMTU)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func TestCryptoInitSnd_NilPubKeyId(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)

	_, _, err := encryptInitSnd(nil, alicePrvKeyEp.PublicKey(), defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoInitSnd_NilPubKeyEp(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)

	_, _, err := encryptInitSnd(alicePrvKeyId.PublicKey(), nil, defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitSnd_TooSmall(t *testing.T) {
	buffer := make([]byte, defaultMTU-1)
	_, _, err := decryptInitSnd(buffer, defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init")
}

func TestCryptoDecryptInitSnd_EmptyBuffer(t *testing.T) {
	_, _, err := decryptInitSnd([]byte{}, defaultMTU)
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
		0,
		false,
		rawData,
	)
	assert.NoError(t, err)

	sharedSecret, pubKeyIdRcv, pubKeyEpRcv, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.NotNil(t, sharedSecret)
	assert.Equal(t, uint64(0), msg.snConn)
	assert.Equal(t, rawData, msg.payloadRaw)
	assert.True(t, bytes.Equal(bobPrvKeyId.PublicKey().Bytes(), pubKeyIdRcv.Bytes()))
	assert.True(t, bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
}

func TestCryptoInitRcv_NilKeys(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	// Missing pubKeyIdSnd
	_, err := encryptPacket(
		initRcv,
		0,
		bobPrvKeyEp,
		nil, // pubKeyIdSnd
		alicePrvKeyEp.PublicKey(),
		nil,
		0,
		0,
		false,
		[]byte("test1234"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitRcv_TooSmall(t *testing.T) {
	buffer := make([]byte, minInitRcvSizeHdr+footerDataSize-1)
	_, _, _, _, err := decryptInitRcv(buffer, generateTestKey(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init reply")
}

func TestCryptoInitRcv_MinPayload(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	payload := []byte("12345678") // 8 bytes - min proto size
	buffer, err := encryptPacket(
		initRcv,
		0,
		bobPrvKeyEp,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		nil,
		0,
		0,
		false,
		payload,
	)
	assert.NoError(t, err)

	_, _, _, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.payloadRaw)
}

// =============================================================================
// INIT CRYPTO SND TESTS
// =============================================================================

func TestCryptoInitCryptoSnd_BasicFlow(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)

	payload := []byte("test payload data")
	connId, buffer, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		defaultMTU,
		payload,
	)
	assert.NoError(t, err)
	assert.Equal(t, defaultMTU, len(buffer))
	assert.NotZero(t, connId)

	pubKeyIdSnd, pubKeyEpSnd, msg, err := decryptInitCryptoSnd(buffer, bobPrvKeyId, defaultMTU)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.payloadRaw)
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func TestCryptoInitCryptoSnd_NilKeys(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)

	_, _, err := encryptInitCryptoSnd(
		nil, // pubKeyIdRcv
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		defaultMTU,
		[]byte("test1234"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoInitCryptoSnd_PayloadTooLarge(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)

	// Payload larger than MTU allows
	largePayload := randomBytes(defaultMTU)
	_, _, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		defaultMTU,
		largePayload,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestCryptoInitCryptoSnd_MaxPayload(t *testing.T) {
	alicePrvKeyId := generateTestKey(t)
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyId := generateTestKey(t)

	// Calculate max payload size
	maxPayload := defaultMTU - minInitCryptoSndSizeHdr - footerDataSize - msgInitFillLenSize
	payload := randomBytes(maxPayload)

	_, buffer, err := encryptInitCryptoSnd(
		bobPrvKeyId.PublicKey(),
		alicePrvKeyId.PublicKey(),
		alicePrvKeyEp,
		0,
		defaultMTU,
		payload,
	)
	assert.NoError(t, err)
	assert.Equal(t, defaultMTU, len(buffer))

	_, _, msg, err := decryptInitCryptoSnd(buffer, bobPrvKeyId, defaultMTU)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.payloadRaw)
}

func TestCryptoDecryptInitCryptoSnd_TooSmall(t *testing.T) {
	bobPrvKeyId := generateTestKey(t)
	buffer := make([]byte, defaultMTU-1)

	_, _, _, err := decryptInitCryptoSnd(buffer, bobPrvKeyId, defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init")
}

// =============================================================================
// INIT CRYPTO RCV TESTS
// =============================================================================

func TestCryptoInitCryptoRcv_BasicFlow(t *testing.T) {
	alicePrvKeyEp := generateTestKey(t)
	bobPrvKeyEp := generateTestKey(t)

	payload := []byte("response data")
	buffer, err := encryptPacket(
		initCryptoRcv,
		12345,
		bobPrvKeyEp,
		nil,
		alicePrvKeyEp.PublicKey(),
		nil,
		0,
		0,
		false,
		payload,
	)
	assert.NoError(t, err)

	sharedSecret, pubKeyEpRcv, msg, err := decryptInitCryptoRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.NotNil(t, sharedSecret)
	assert.Equal(t, payload, msg.payloadRaw)
	assert.True(t, bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
}

func TestCryptoInitCryptoRcv_NilKeys(t *testing.T) {
	bobPrvKeyEp := generateTestKey(t)

	_, err := encryptPacket(
		initCryptoRcv,
		0,
		bobPrvKeyEp,
		nil,
		nil, // pubKeyEpRcv
		nil,
		0,
		0,
		false,
		[]byte("test1234"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoDecryptInitCryptoRcv_TooSmall(t *testing.T) {
	buffer := make([]byte, minInitCryptoRcvSizeHdr+footerDataSize-1)
	_, _, _, err := decryptInitCryptoRcv(buffer, generateTestKey(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init reply")
}

// =============================================================================
// DATA MESSAGE TESTS
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
		0,
		true,
		payload,
	)
	assert.NoError(t, err)
	assert.NotNil(t, encData)

	msg, err := decryptData(encData, false, 0, sharedSecret)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.payloadRaw)
}

func TestCryptoData_NilSharedSecret(t *testing.T) {
	_, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		nil, // sharedSecret
		0,
		0,
		true,
		[]byte("test1234"),
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestCryptoData_WithEpoch(t *testing.T) {
	sharedSecret := randomBytes(32)
	payload := []byte("test data")

	encData, err := encryptPacket(
		data,
		12345,
		nil,
		nil,
		nil,
		sharedSecret,
		100,
		5,
		true,
		payload,
	)
	assert.NoError(t, err)

	msg, err := decryptData(encData, false, 5, sharedSecret)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.payloadRaw)
	assert.Equal(t, uint64(5), msg.currentEpochCrypt)
}

func TestCryptoDecryptData_TooSmall(t *testing.T) {
	sharedSecret := randomBytes(32)
	buffer := make([]byte, minDataSizeHdr+footerDataSize-1)

	_, err := decryptData(buffer, false, 0, sharedSecret)
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
		0,
		true,
		payload,
	)
	assert.NoError(t, err)

	_, err = decryptData(encData, false, 0, wrongSecret)
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
	connId, bufferS0, err := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)
	assert.NoError(t, err)

	// Step 2: Bob receives InitSnd
	_, pubKeyEpSnd, err := decryptInitSnd(bufferS0, defaultMTU)
	assert.NoError(t, err)

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
		0,
		false,
		rawData,
	)
	assert.NoError(t, err)

	// Step 4: Alice receives InitRcv
	_, _, _, msg, err := decryptInitRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, rawData, msg.payloadRaw)
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
		defaultMTU,
		initPayload,
	)
	assert.NoError(t, err)

	// Step 2: Bob receives InitCryptoSnd
	_, pubKeyEpSnd, msg, err := decryptInitCryptoSnd(bufferS0, bobPrvKeyId, defaultMTU)
	assert.NoError(t, err)
	assert.Equal(t, initPayload, msg.payloadRaw)

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
		0,
		false,
		responsePayload,
	)
	assert.NoError(t, err)

	// Step 4: Alice receives InitCryptoRcv
	_, _, msg, err = decryptInitCryptoRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, responsePayload, msg.payloadRaw)
}

// =============================================================================
// CRYPTO OVERHEAD TESTS
// =============================================================================

func TestCryptoOverhead_InitSnd(t *testing.T) {
	assert.Equal(t, -1, calcCryptoOverheadWithData(initSnd, nil, 100))
}

func TestCryptoOverhead_InitRcv(t *testing.T) {
	expected := calcProtoOverhead(false, false, false) + minInitRcvSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initRcv, nil, 100))
}

func TestCryptoOverhead_InitCryptoSnd(t *testing.T) {
	expected := calcProtoOverhead(false, false, false) + minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initCryptoSnd, nil, 100))
}

func TestCryptoOverhead_InitCryptoRcv(t *testing.T) {
	expected := calcProtoOverhead(false, false, false) + minInitCryptoRcvSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(initCryptoRcv, nil, 100))
}

func TestCryptoOverhead_Data(t *testing.T) {
	expected := calcProtoOverhead(false, false, false) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, nil, 100))
}

func TestCryptoOverhead_DataWithAck(t *testing.T) {
	ack := &ack{offset: 1000}
	expected := calcProtoOverhead(true, false, false) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, ack, 100))
}

func TestCryptoOverhead_DataWithLargeAckOffset(t *testing.T) {
	ack := &ack{offset: 0xFFFFFF + 1}
	expected := calcProtoOverhead(true, true, false) + minDataSizeHdr + footerDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(data, ack, 100))
}

func TestCryptoOverhead_DataWithLargeOffset(t *testing.T) {
	expected := calcProtoOverhead(false, true, false) + minDataSizeHdr + footerDataSize
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