package qotp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
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
	_, _ = rand.Read(sharedSecret)

	buf, err := chainedEncrypt(sn, 0, true, sharedSecret, additionalData, data)
	if len(data) < MinProtoSize {
		assert.NotNil(t, err)
		return
	}
	assert.Nil(t, err)

	if len(buf) == 0 {
		t.Fatalf("No encrypted data written")
	}
	t.Logf("Encrypted data: %s", hex.EncodeToString(buf))

	decryptedSn, decryptedEpoch, decryptedData, err := chainedDecrypt(false, 0, sharedSecret, buf[0:len(additionalData)], buf[len(additionalData):])
	assert.Nil(t, err)
	assert.Equal(t, uint64(0), decryptedEpoch)
	assert.Equal(t, sn, decryptedSn)
	assert.Equal(t, data, decryptedData)
}

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

func TestCryptoDoubleEncryptDecryptMaxSequenceNumber(t *testing.T) {
	testDoubleEncryptDecrypt(t, uint64(0xffffffffffff), randomBytes(10), []byte("AAD"))
}

func TestCryptoDoubleEncryptDecryptZeroSequenceNumber(t *testing.T) {
	testDoubleEncryptDecrypt(t, 0, randomBytes(10), []byte("AAD"))
}

func TestCryptoDoubleEncryptDecryptLargeAAD(t *testing.T) {
	testDoubleEncryptDecrypt(t, 12345, randomBytes(10), randomBytes(1000))
}

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

func TestCryptoSecretKeySameKeys(t *testing.T) {
	key := generateKeys(t)
	pubKey := key.PublicKey()

	secret, err := key.ECDH(pubKey)
	assert.Nil(t, err)
	assert.NotNil(t, secret)
	assert.Len(t, secret, 32)
}

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

func TestCryptoEncodeDecodeInitCryptoSndShortPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, []byte("short1234"))
}

func TestCryptoEncodeDecodeInitCryptoSndLongPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, randomBytes(100))
}

func TestCryptoEncodeDecodeInitCryptoSndMaxPayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, randomBytes(1303))
}

func TestCryptoEncodeDecodeInitCryptoSnd8BytePayload(t *testing.T) {
	testEncodeDecodeInitCryptoSnd(t, []byte("12345678"))
}

func testEncodeDecodeInitCryptoRcv(t *testing.T, payload []byte) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	validPayload := payload
	if len(payload) < 8 {
		validPayload = []byte("12345678")
	}

	connId, bufferInit, err := encryptInitCryptoSnd(bobPrvKeyId.PublicKey(), alicePrvKeyId.PublicKey(), alicePrvKeyEp, 0, defaultMTU, validPayload)
	assert.Nil(t, err)

	_, _, _, err = decryptInitCryptoSnd(bufferInit, bobPrvKeyId, defaultMTU)
	assert.Nil(t, err)

	// Use encryptPacket for InitCryptoRcv
	bufferInitReply, err := encryptPacket(
		InitCryptoRcv,
		connId,
		bobPrvKeyEp,
		nil, // pubKeyIdSnd not needed for InitCryptoRcv
		alicePrvKeyEp.PublicKey(),
		nil, // sharedSecret computed internally
		0,
		0,
		false,
		payload,
	)

	if len(payload) < 8 {
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "too short")
		return
	}
	assert.Nil(t, err)

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

func TestCryptoEncodeDecodeInitCryptoRcv8BytePayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, []byte("12345678"))
}

func TestCryptoEncodeDecodeInitCryptoRcvMaxPayload(t *testing.T) {
	testEncodeDecodeInitCryptoRcv(t, randomBytes(1303))
}

func TestCryptoInitSndBasicFlow(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)
	pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(buffer, defaultMTU)

	assert.NoError(t, err)
	assert.True(t, bytes.Equal(alicePrvKeyId.PublicKey().Bytes(), pubKeyIdSnd.Bytes()))
	assert.True(t, bytes.Equal(alicePrvKeyEp.PublicKey().Bytes(), pubKeyEpSnd.Bytes()))
}

func TestCryptoInitSndInvalidSize(t *testing.T) {
	buffer := make([]byte, 1399)
	_, _, err := decryptInitSnd(buffer, defaultMTU)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init")
}

func TestCryptoInitSndExactMinSize(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)
	assert.GreaterOrEqual(t, len(buffer), defaultMTU)

	_, _, err := decryptInitSnd(buffer, defaultMTU)
	assert.NoError(t, err)
}

func TestCryptoInitSndEmptyBuffer(t *testing.T) {
	_, _, err := decryptInitSnd([]byte{}, defaultMTU)
	assert.Error(t, err)
}

func TestCryptoInitRcvBasicFlow(t *testing.T) {
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	rawData := []byte("test data")
	// Use encryptPacket for InitRcv
	buffer, err := encryptPacket(
		InitRcv,
		0,
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

	_, pubKeyIdRcv, pubKeyEpRcv, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)

	assert.NoError(t, err)
	assert.Equal(t, uint64(0), msg.SnConn)
	assert.Equal(t, rawData, msg.PayloadRaw)
	assert.True(t, bytes.Equal(bobPrvKeyId.PublicKey().Bytes(), pubKeyIdRcv.Bytes()))
	assert.True(t, bytes.Equal(bobPrvKeyEp.PublicKey().Bytes(), pubKeyEpRcv.Bytes()))
}

func TestCryptoInitRcvInvalidSize(t *testing.T) {
	buffer := make([]byte, MinInitRcvSizeHdr+FooterDataSize-1)
	_, _, _, _, err := decryptInitRcv(buffer, generateKeys(t))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "size is below minimum init reply")
}

func TestCryptoInitRcv8BytePayload(t *testing.T) {
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	payload := []byte("12345678")
	buffer, err := encryptPacket(
		InitRcv,
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
	assert.Equal(t, payload, msg.PayloadRaw)
}

func TestCryptoInitRcvMaxValues(t *testing.T) {
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	maxSn := ^uint64(0)
	buffer, err := encryptPacket(
		InitRcv,
		0,
		bobPrvKeyEp,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp.PublicKey(),
		nil,
		maxSn,
		0,
		false,
		[]byte("test1234"),
	)
	assert.NoError(t, err)

	_, _, _, msg, err := decryptInitRcv(buffer, alicePrvKeyEp)
	assert.NoError(t, err)
	assert.Equal(t, []byte("test1234"), msg.PayloadRaw)
}

func TestCryptoFullHandshakeFlow(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)
	bobPrvKeyId := generateKeys(t)
	bobPrvKeyEp := generateKeys(t)

	connId, bufferS0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	_, _, err := decryptInitSnd(bufferS0, defaultMTU)
	assert.NoError(t, err)

	rawData := []byte("handshake response")
	bufferR0, err := encryptPacket(
		InitRcv,
		connId,
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

	_, _, _, _, err = decryptInitRcv(bufferR0, alicePrvKeyEp)
	assert.NoError(t, err)
}

func TestCryptoMultipleHandshakes(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	bobPrvKeyId := generateKeys(t)

	// First handshake
	alicePrvKeyEp1 := generateKeys(t)
	bobPrvKeyEp1 := generateKeys(t)

	connId, buffer1S0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp1.PublicKey(), defaultMTU)
	_, _, err := decryptInitSnd(buffer1S0, defaultMTU)
	assert.NoError(t, err)

	buffer1R0, err := encryptPacket(
		InitRcv,
		connId,
		bobPrvKeyEp1,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp1.PublicKey(),
		nil,
		0,
		0,
		false,
		[]byte("first123"),
	)
	assert.NoError(t, err)

	_, _, _, _, err = decryptInitRcv(buffer1R0, alicePrvKeyEp1)
	assert.NoError(t, err)

	// Second handshake
	alicePrvKeyEp2 := generateKeys(t)
	bobPrvKeyEp2 := generateKeys(t)

	connId, buffer2S0, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp2.PublicKey(), defaultMTU)
	_, _, err = decryptInitSnd(buffer2S0, defaultMTU)
	assert.NoError(t, err)

	buffer2R0, err := encryptPacket(
		InitRcv,
		connId,
		bobPrvKeyEp2,
		bobPrvKeyId.PublicKey(),
		alicePrvKeyEp2.PublicKey(),
		nil,
		0,
		0,
		false,
		[]byte("second12"),
	)
	assert.NoError(t, err)

	_, _, _, _, err = decryptInitRcv(buffer2R0, alicePrvKeyEp2)
	assert.NoError(t, err)
}

func TestCryptoCorruptedBuffer(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, buffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	if len(buffer) > 10 {
		buffer[5] ^= 0xFF
		buffer[10] ^= 0xFF
	}

	_, _, err := decryptInitSnd(buffer, defaultMTU)
	_ = err // May or may not error depending on corruption location
}

func TestCryptoVeryLargeBuffer(t *testing.T) {
	alicePrvKeyId := generateKeys(t)
	alicePrvKeyEp := generateKeys(t)

	_, validBuffer, _ := encryptInitSnd(alicePrvKeyId.PublicKey(), alicePrvKeyEp.PublicKey(), defaultMTU)

	largeBuffer := make([]byte, len(validBuffer)+10000)
	copy(largeBuffer, validBuffer)

	_, _, err := decryptInitSnd(largeBuffer, defaultMTU)
	assert.NoError(t, err)
}

func TestCryptoRandomBuffer(t *testing.T) {
	randomBuffer := randomBytes(1000)
	_, _, err := decryptInitSnd(randomBuffer, defaultMTU)
	_ = err // Should handle gracefully without panic
}

func TestCryptoOverhead(t *testing.T) {
	assert.Equal(t, -1, calcCryptoOverheadWithData(InitSnd, nil, 100))

	expected := calcProtoOverhead(false, false, false) + MinInitRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitRcv, nil, 100))

	expected = calcProtoOverhead(false, false, false) + MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitCryptoSnd, nil, 100))

	expected = calcProtoOverhead(false, false, false) + MinInitCryptoRcvSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(InitCryptoRcv, nil, 100))

	expected = calcProtoOverhead(false, false, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, nil, 2000))
}

func TestCryptoOverheadWithAck(t *testing.T) {
	ack := &Ack{offset: 1000}
	expected := calcProtoOverhead(true, false, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, ack, 2000))

	ack = &Ack{offset: 0xFFFFFF + 1}
	expected = calcProtoOverhead(true, true, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, ack, 100))
}

func TestCryptoOverheadLargeOffset(t *testing.T) {
	expected := calcProtoOverhead(false, true, false) + MinDataSizeHdr + FooterDataSize
	assert.Equal(t, expected, calcCryptoOverheadWithData(Data, nil, 0xFFFFFF+1))
}

// Test encryptPacket for Data messages
func TestCryptoEncryptPacketData(t *testing.T) {
	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	payload := []byte("test data payload")
	encData, err := encryptPacket(
		Data,
		12345,
		nil,
		nil,
		nil,
		sharedSecret,
		0,
		0,
		true, // sender encrypts with isSender=true
		payload,
	)
	assert.NoError(t, err)
	assert.NotNil(t, encData)

	// Receiver decrypts with isSender=false (opposite of sender)
	msg, err := decryptData(encData, false, 0, sharedSecret)
	assert.NoError(t, err)
	assert.Equal(t, payload, msg.PayloadRaw)
}