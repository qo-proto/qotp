package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type CryptoMsgType int8

const (
	InitSnd CryptoMsgType = iota
	InitRcv
	InitCryptoSnd
	InitCryptoRcv
	Data
)

const (
	CryptoVersion = 0
	MacSize       = 16
	SnSize        = 6 // Sequence number Size is 48bit / 6 bytes
	//MinPayloadSize is the minimum payload Size in bytes. We need at least 8 bytes as
	// 8 + the MAC Size (16 bytes) is 24 bytes, which is used as the input for
	// sealing with chacha20poly1305.NewX().

	PubKeySize         = 32
	HeaderSize         = 1
	ConnIdSize         = 8
	MsgInitFillLenSize = 2

	//MinInitSndSize          = minMtu
	MinInitRcvSizeHdr       = HeaderSize + ConnIdSize + (2 * PubKeySize)
	MinInitCryptoSndSizeHdr = HeaderSize + (2 * PubKeySize)
	MinInitCryptoRcvSizeHdr = HeaderSize + ConnIdSize + PubKeySize
	MinDataSizeHdr          = HeaderSize + ConnIdSize
	FooterDataSize          = SnSize + MacSize

	MinPacketSize = MinDataSizeHdr + FooterDataSize + MinProtoSize
)

type Message struct {
	SnConn            uint64
	currentEpochCrypt uint64
	PayloadRaw        []byte
}

// ************************************* Encoder *************************************

func encryptInitSnd(pubKeyIdSnd *ecdh.PublicKey, pubKeyEpSnd *ecdh.PublicKey, mtu int) (
	connId uint64, encData []byte) {

	if pubKeyIdSnd == nil || pubKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size
	headerCryptoDataBuffer := make([]byte, mtu)

	headerCryptoDataBuffer[0] = (uint8(InitSnd) << 5) | CryptoVersion

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerCryptoDataBuffer[HeaderSize:], pubKeyEpSnd.Bytes())

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerCryptoDataBuffer[HeaderSize+PubKeySize:], pubKeyIdSnd.Bytes())

	return Uint64(headerCryptoDataBuffer[HeaderSize:]), headerCryptoDataBuffer
}

func encryptInitRcv(connId uint64,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size, INIT_HANDSHAKE_R0 has 3 public keys
	headerWithKeys := make([]byte, MinInitRcvSizeHdr)

	headerWithKeys[0] = (uint8(InitRcv) << 5) | CryptoVersion

	PutUint64(headerWithKeys[HeaderSize:], connId)

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderSize+ConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+ConnIdSize+PubKeySize:], pubKeyIdSnd.Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, 0, false, sharedSecret, headerWithKeys, packetData)
}

func encryptInitCryptoSnd(
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	mtu int,
	packetData []byte) (connId uint64, encData []byte, err error) {

	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_S0 has 3 public keys
	headerWithKeys := make([]byte, MinInitCryptoSndSizeHdr)

	headerWithKeys[0] = (uint8(InitCryptoSnd) << 5) | CryptoVersion

	// Directly copy the isSender's public key to the buffer following the connection ID
	copy(headerWithKeys[HeaderSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+PubKeySize:], pubKeyIdSnd.Bytes())

	// Encrypt and write dataToSend
	fillLen := mtu - (MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize + len(packetData))

	if fillLen < 0 {
		return 0, nil, errors.New("packet dataToSend cannot be larger than MTU")
	}

	// Create payload with filler length and filler if needed
	paddedPacketData := make([]byte, len(packetData)+MsgInitFillLenSize+fillLen)

	// Add filler length, this is also encrypted
	PutUint16(paddedPacketData, uint16(fillLen))

	// After the filler, copy the dataToSend
	copy(paddedPacketData[2+fillLen:], packetData)

	// Perform ECDH for initial encryption
	nonForwardSecretKey, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)

	if err != nil {
		return 0, nil, err
	}

	encData, err = chainedEncrypt(snCrypto, 0, true, nonForwardSecretKey, headerWithKeys, paddedPacketData)
	return Uint64(headerWithKeys[HeaderSize:]), encData, err
}

func encryptInitCryptoRcv(
	connId uint64,
	pubKeyEpRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if pubKeyEpRcv == nil || prvKeyEpSnd == nil {
		panic("handshake keys cannot be nil")
	}

	// Create the buffer with the correct size, INIT_WITH_CRYPTO_R0 has 2 public keys
	headerWithKeys := make([]byte, MinInitCryptoRcvSizeHdr)

	headerWithKeys[0] = (uint8(InitCryptoRcv) << 5) | CryptoVersion

	PutUint64(headerWithKeys[HeaderSize:], connId)

	// Directly copy the ephemeral public key to the buffer following the isSender's public key
	copy(headerWithKeys[HeaderSize+ConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())

	// Perform ECDH for initial encryption
	sharedSecret, err := prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, err
	}

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, 0, false, sharedSecret, headerWithKeys, packetData)
}

func encryptData(
	connId uint64,
	isSender bool,
	sharedSecret []byte,
	snCrypto uint64,
	epochCrypto uint64,
	packetData []byte) (encData []byte, err error) {

	if sharedSecret == nil {
		panic("pubKeyEpSnd/pubKeyEpRcv keys cannot be nil")
	}

	// Create the buffer with the correct size, DATA_0 has no public key
	headerBuffer := make([]byte, HeaderSize+ConnIdSize)

	headerBuffer[0] = (uint8(Data) << 5) | CryptoVersion
	PutUint64(headerBuffer[HeaderSize:], connId)

	// Encrypt and write dataToSend
	return chainedEncrypt(snCrypto, epochCrypto, isSender, sharedSecret, headerBuffer, packetData)
}

func chainedEncrypt(snCrypt uint64, epochConn uint64, isSender bool, sharedSecret []byte,
	headerAndCrypto []byte, packetData []byte) (encData []byte, err error) {
	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	PutUint48(nonceDet, epochConn)
	PutUint48(nonceDet[6:], snCrypt)

	if !isSender {
		// set first (highest) bit to 0
		nonceDet[0] = nonceDet[0] &^ 0x80 // bit clear
	} else {
		// set first (highest) bit to 1
		nonceDet[0] = nonceDet[0] | 0x80 // bit set
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonceDet, packetData, headerAndCrypto)

	encData = make([]byte, len(headerAndCrypto)+SnSize+len(sealed))
	copy(encData, headerAndCrypto)

	aeadSn, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	nonceRand := sealed[0:24]
	encSn := aeadSn.Seal(nil, nonceRand, nonceDet[6:12], nil)
	copy(encData[len(headerAndCrypto):], encSn[:SnSize])
	copy(encData[len(headerAndCrypto)+SnSize:], sealed)

	// Write the full message in one operation
	return encData, nil
}

// ************************************* Decoder *************************************

func decryptInitSnd(encData []byte, mtu int) (
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	err error) {

	if len(encData) < mtu {
		return nil, nil, errors.New("size is below minimum init")
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize : HeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, err
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+PubKeySize : HeaderSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, err
	}

	return pubKeyIdSnd, pubKeyEpSnd, nil
}

func decryptInitRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize : HeaderSize+ConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubKeyIdRcv, err = ecdh.X25519().NewPublicKey(
		encData[HeaderSize+ConnIdSize+PubKeySize : HeaderSize+ConnIdSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)

	if err != nil {
		return nil, nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:MinInitRcvSizeHdr],
		encData[MinInitRcvSizeHdr:],
		false, // Live decryption
	)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return sharedSecret, pubKeyIdRcv, pubKeyEpRcv, &Message{
		PayloadRaw:        packetData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil

}

func decryptInitCryptoSnd(
	encData []byte,
	prvKeyIdRcv *ecdh.PrivateKey,
	mtu int) (
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpSnd *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < mtu {
		return nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize : HeaderSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+PubKeySize : HeaderSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, nil, err
	}

	nonForwardSecretKey, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)

	if err != nil {
		return nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		false,
		0,
		nonForwardSecretKey,
		encData[0:HeaderSize+(2*PubKeySize)],
		encData[HeaderSize+(2*PubKeySize):],
		false, // Live decryption
	)
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract actual dataToSend - Remove filler_length and filler
	fillerLen := Uint16(packetData)
	actualData := packetData[2+int(fillerLen):]

	return pubKeyIdSnd, pubKeyEpSnd, &Message{
		PayloadRaw:        actualData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

// decryptInitCryptoRcv is decoded by the isSender
func decryptInitCryptoRcv(
	encData []byte,
	prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte,
	pubKeyEpRcv *ecdh.PublicKey,
	m *Message,
	err error) {

	if len(encData) < MinInitCryptoRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize : HeaderSize+ConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, err
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		true,
		0,
		sharedSecret,
		encData[0:HeaderSize+ConnIdSize+PubKeySize],
		encData[HeaderSize+ConnIdSize+PubKeySize:],
		false, // Live decryption
	)
	if err != nil {
		return nil, nil, nil, err
	}

	return sharedSecret, pubKeyEpRcv, &Message{
		PayloadRaw:        packetData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

func decryptData(
	encData []byte,
	isSender bool,
	epochCrypt uint64,
	sharedSecret []byte) (*Message, error) {

	if len(encData) < MinDataSizeHdr+FooterDataSize {
		return nil, errors.New("size is below minimum")
	}

	snConn, currentEpochCrypt, packetData, err := chainedDecrypt(
		isSender,
		epochCrypt,
		sharedSecret,
		encData[0:HeaderSize+ConnIdSize],
		encData[HeaderSize+ConnIdSize:],
		false, // This is a live decryption, not offline
	)
	if err != nil {
		return nil, err
	}

	return &Message{
		PayloadRaw:        packetData,
		SnConn:            snConn,
		currentEpochCrypt: currentEpochCrypt,
	}, nil
}

func chainedDecrypt(isSender bool, epochCrypt uint64, sharedSecret []byte, header []byte, encData []byte, isOfflineDecrypt bool) (
	snConn uint64, currentEpochCrypt uint64, packetData []byte, err error) {
	snConnBytes := make([]byte, SnSize)

	encryptedSN := encData[:SnSize]
	ciphertextWithNonce := encData[SnSize:]
	snConnBytes, err = openNoVerify(sharedSecret, ciphertextWithNonce, encryptedSN, snConnBytes)
	if err != nil {
	}
	snConn = Uint48(snConnBytes)

	nonceDet := make([]byte, chacha20poly1305.NonceSize)

	epochs := []uint64{epochCrypt}
	// Only try previous epoch if > 0
	if epochCrypt > 0 {
		epochs = append(epochs, epochCrypt-1)
	}
	epochs = append(epochs, epochCrypt+1)

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, 0, nil, err
	}
	PutUint48(nonceDet[6:], snConn)

	for _, epochTry := range epochs {
		PutUint48(nonceDet, epochTry)
		// The logic for the sender bit is inverted between live decryption and offline pcap decryption.
		// isOfflineDecrypt allows us to handle both cases correctly.
		if isOfflineDecrypt {
			if isSender {
				nonceDet[0] = nonceDet[0] | 0x80 // bit set
			} else {
				nonceDet[0] = nonceDet[0] &^ 0x80 // bit clear
			}
		} else {
			// Live decryption logic
			if isSender {
				nonceDet[0] = nonceDet[0] &^ 0x80 // bit clear
			} else {
				nonceDet[0] = nonceDet[0] | 0x80 // bit set
			}
		}

		packetData, err = aead.Open(nil, nonceDet, ciphertextWithNonce, header)
		if err == nil {
			//TODO if we are at epochCrypt + 1 -> make this the new epochCrypt
			return snConn, epochTry, packetData, nil
		}
	}
	return 0, 0, nil, err
}

// DecryptDataForPcap is a helper function for external tools (like pcap decryptors)
// to decrypt a QOTP data packet payload.
func DecryptDataForPcap(encryptedPortion []byte, isSenderOnInit bool, epoch uint64, sharedSecret []byte, connId uint64) ([]byte, error) {
	// Reconstruct the AAD (header) as it was during encryption for a Data packet.
	header := make([]byte, HeaderSize+ConnIdSize)
	header[0] = (uint8(Data) << 5) | CryptoVersion
	PutUint64(header[HeaderSize:], connId)

	// For offline decryption, we must call chainedDecrypt directly with the offline flag.
	_, _, payload, err := chainedDecrypt(isSenderOnInit, epoch, sharedSecret, header, encryptedPortion, true)
	if err != nil {
		return nil, err
	}
	// The payload of a data packet is another QOTP-formatted payload.
	// We return this inner raw payload for dissection.
	return payload, nil
}

// inspired by: https://github.com/golang/crypto/blob/master/chacha20poly1305/chacha20poly1305_generic.go
func openNoVerify(sharedSecret []byte, nonce []byte, encoded []byte, snSer []byte) ([]byte, error) {
	// The nonce for the SN is the first 24 bytes of the main ciphertext (which is passed as 'nonce' here).
	snNonce := nonce[:chacha20poly1305.NonceSizeX]
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, snNonce)
	if err != nil {
		return nil, err
	}
	s.SetCounter(1) // Per the spec, skip the first 32 bytes of the keystream for SN encryption.

	// Decrypt the ciphertext
	s.XORKeyStream(snSer, encoded)

	return snSer, nil
}

func decodeHexPubKey(pubKeyHex string) (pubKey *ecdh.PublicKey, err error) {
	b, err := decodeHex(pubKeyHex)
	if err != nil {
		return nil, err
	}

	pubKey, err = ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func generateKey() (*ecdh.PrivateKey, error) {
	prvKey1, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return prvKey1, nil
}

func calcCryptoOverhead(msgType CryptoMsgType, ack *Ack, offset uint64) (overhead int) {
	hasAck := ack != nil
	needsExtension := (hasAck && ack.offset > 0xFFFFFF) || offset > 0xFFFFFF

	overhead = calcProtoOverhead(hasAck, needsExtension)

	switch msgType {
	case InitSnd:
		return -1 //we cannot send data, this is unencrypted
	case InitRcv:
		overhead += MinInitRcvSizeHdr + FooterDataSize
	case InitCryptoSnd:
		overhead += MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	case InitCryptoRcv:
		overhead += MinInitCryptoRcvSizeHdr + FooterDataSize
	case Data:
		overhead += MinDataSizeHdr + FooterDataSize
	}

	return overhead
}
