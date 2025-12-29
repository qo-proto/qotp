package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type cryptoMsgType int8

const (
	InitSnd cryptoMsgType = iota
	InitRcv
	InitCryptoSnd
	InitCryptoRcv
	Data
)

const (
	CryptoVersion = 0
	MacSize       = 16
	SnSize        = 6

	PubKeySize         = 32
	HeaderSize         = 1
	ConnIdSize         = 8
	MsgInitFillLenSize = 2

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

// ======================== Encrypt ========================

func encryptInitSnd(pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, mtu int) (connId uint64, encData []byte, err error) {
	if pubKeyIdSnd == nil || pubKeyEpSnd == nil {
		return 0, nil, errors.New("handshake keys cannot be nil")
	}
	encData = make([]byte, mtu)
	encData[0] = (uint8(InitSnd) << 5) | CryptoVersion
	copy(encData[HeaderSize:], pubKeyEpSnd.Bytes())
	copy(encData[HeaderSize+PubKeySize:], pubKeyIdSnd.Bytes())
	return Uint64(encData[HeaderSize:]), encData, nil
}

func encryptInitCryptoSnd(
	pubKeyIdRcv, pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	mtu int,
	packetData []byte,
) (connId uint64, encData []byte, err error) {
	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		return 0, nil, errors.New("handshake keys cannot be nil")
	}

	header := make([]byte, MinInitCryptoSndSizeHdr)
	header[0] = (uint8(InitCryptoSnd) << 5) | CryptoVersion
	copy(header[HeaderSize:], prvKeyEpSnd.PublicKey().Bytes())
	copy(header[HeaderSize+PubKeySize:], pubKeyIdSnd.Bytes())

	fillLen := mtu - (MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize + len(packetData))
	if fillLen < 0 {
		return 0, nil, errors.New("packet data too large for MTU")
	}
	padded := make([]byte, len(packetData)+MsgInitFillLenSize+fillLen)
	PutUint16(padded, uint16(fillLen))
	copy(padded[2+fillLen:], packetData)

	secret, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return 0, nil, err
	}
	encData, err = chainedEncrypt(snCrypto, 0, true, secret, header, padded)
	return Uint64(header[HeaderSize:]), encData, err
}

func encryptPacket(
	msgType cryptoMsgType,
	connId uint64,
	prvKeyEpSnd *ecdh.PrivateKey,
	pubKeyIdSnd *ecdh.PublicKey,
	pubKeyEpRcv *ecdh.PublicKey,
	sharedSecret []byte,
	snCrypto, epochCrypto uint64,
	isSender bool,
	packetData []byte,
) ([]byte, error) {
	var header []byte
	var secret []byte

	switch msgType {
	case InitRcv:
		if pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
			return nil, errors.New("handshake keys cannot be nil")
		}
		header = make([]byte, MinInitRcvSizeHdr)
		header[0] = (uint8(InitRcv) << 5) | CryptoVersion
		PutUint64(header[HeaderSize:], connId)
		copy(header[HeaderSize+ConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())
		copy(header[HeaderSize+ConnIdSize+PubKeySize:], pubKeyIdSnd.Bytes())
		var err error
		secret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
		if err != nil {
			return nil, err
		}

	case InitCryptoRcv:
		if pubKeyEpRcv == nil || prvKeyEpSnd == nil {
			return nil, errors.New("handshake keys cannot be nil")
		}
		header = make([]byte, MinInitCryptoRcvSizeHdr)
		header[0] = (uint8(InitCryptoRcv) << 5) | CryptoVersion
		PutUint64(header[HeaderSize:], connId)
		copy(header[HeaderSize+ConnIdSize:], prvKeyEpSnd.PublicKey().Bytes())
		var err error
		secret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
		if err != nil {
			return nil, err
		}

	case Data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret cannot be nil")
		}
		header = make([]byte, HeaderSize+ConnIdSize)
		header[0] = (uint8(Data) << 5) | CryptoVersion
		PutUint64(header[HeaderSize:], connId)
		secret = sharedSecret
		// Data uses epochCrypto, init messages use 0
		return chainedEncrypt(snCrypto, epochCrypto, isSender, secret, header, packetData)

	default:
		return nil, errors.New("unsupported message type")
	}

	return chainedEncrypt(snCrypto, 0, false, secret, header, packetData)
}

func chainedEncrypt(snCrypt, epochConn uint64, isSender bool, sharedSecret, header, packetData []byte) ([]byte, error) {
	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	PutUint48(nonceDet, epochConn)
	PutUint48(nonceDet[6:], snCrypt)

	if isSender {
		nonceDet[0] |= 0x80
	} else {
		nonceDet[0] &^= 0x80
	}

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonceDet, packetData, header)

	aeadSn, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	encData := make([]byte, len(header)+SnSize+len(sealed))
	copy(encData, header)

	encSn := aeadSn.Seal(nil, sealed[0:24], nonceDet[6:12], nil)
	copy(encData[len(header):], encSn[:SnSize])
	copy(encData[len(header)+SnSize:], sealed)

	return encData, nil
}

// ======================== Decrypt ========================

func decryptInitSnd(encData []byte, mtu int) (pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, err error) {
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
	sharedSecret []byte, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, m *Message, err error) {
	if len(encData) < MinInitRcvSizeHdr+FooterDataSize {
		return nil, nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize : HeaderSize+ConnIdSize+PubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pubKeyIdRcv, err = ecdh.X25519().NewPublicKey(encData[HeaderSize+ConnIdSize+PubKeySize : HeaderSize+ConnIdSize+(2*PubKeySize)])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	headerLen := HeaderSize + ConnIdSize + (2 * PubKeySize)
	snConn, epochCrypt, packetData, err := chainedDecrypt(true, 0, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return sharedSecret, pubKeyIdRcv, pubKeyEpRcv, &Message{PayloadRaw: packetData, SnConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

func decryptInitCryptoSnd(encData []byte, prvKeyIdRcv *ecdh.PrivateKey, mtu int) (
	pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, m *Message, err error) {
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

	secret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, nil, nil, err
	}

	headerLen := HeaderSize + (2 * PubKeySize)
	snConn, epochCrypt, packetData, err := chainedDecrypt(false, 0, secret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	fillerLen := Uint16(packetData)
	actualData := packetData[2+int(fillerLen):]

	return pubKeyIdSnd, pubKeyEpSnd, &Message{PayloadRaw: actualData, SnConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

func decryptInitCryptoRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte, pubKeyEpRcv *ecdh.PublicKey, m *Message, err error) {
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

	headerLen := HeaderSize + ConnIdSize + PubKeySize
	snConn, epochCrypt, packetData, err := chainedDecrypt(true, 0, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	return sharedSecret, pubKeyEpRcv, &Message{PayloadRaw: packetData, SnConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

func decryptData(encData []byte, isSender bool, epochCrypt uint64, sharedSecret []byte) (*Message, error) {
	if len(encData) < MinDataSizeHdr+FooterDataSize {
		return nil, errors.New("size is below minimum")
	}

	headerLen := HeaderSize + ConnIdSize
	snConn, currentEpoch, packetData, err := chainedDecrypt(isSender, epochCrypt, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, err
	}

	return &Message{PayloadRaw: packetData, SnConn: snConn, currentEpochCrypt: currentEpoch}, nil
}

func chainedDecrypt(isSender bool, epochCrypt uint64, sharedSecret, header, encData []byte) (
	snConn, currentEpochCrypt uint64, packetData []byte, err error) {

	encSn := encData[:SnSize]
	encData = encData[SnSize:]
	nonceRand := encData[:24]

	snConnBytes := make([]byte, SnSize)
	snConnBytes, err = openNoVerify(sharedSecret, nonceRand, encSn, snConnBytes)
	if err != nil {
		return 0, 0, nil, err
	}
	snConn = Uint48(snConnBytes)

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, 0, nil, err
	}

	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	PutUint48(nonceDet[6:], snConn)

	// Try current epoch, then adjacent epochs
	epochs := []uint64{epochCrypt}
	if epochCrypt > 0 {
		epochs = append(epochs, epochCrypt-1)
	}
	epochs = append(epochs, epochCrypt+1)

	for _, epoch := range epochs {
		PutUint48(nonceDet, epoch)
		if isSender {
			nonceDet[0] &^= 0x80
		} else {
			nonceDet[0] |= 0x80
		}

		packetData, err = aead.Open(nil, nonceDet, encData, header)
		if err == nil {
			return snConn, epoch, packetData, nil
		}
	}
	return 0, 0, nil, err
}

func openNoVerify(sharedSecret, nonce, encoded, snSer []byte) ([]byte, error) {
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	s.SetCounter(1)
	s.XORKeyStream(snSer, encoded)
	return snSer, nil
}

func decodeHexPubKey(pubKeyHex string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(pubKeyHex, "0x"))
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func generateKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func calcCryptoOverheadWithData(msgType cryptoMsgType, ack *Ack, offset uint64) int {
	hasAck := ack != nil
	needsExtension := (hasAck && ack.offset > 0xFFFFFF) || offset > 0xFFFFFF
	overhead := calcProtoOverhead(hasAck, needsExtension, false)

	switch msgType {
	case InitSnd:
		return -1
	case InitRcv:
		return overhead + MinInitRcvSizeHdr + FooterDataSize
	case InitCryptoSnd:
		return overhead + MinInitCryptoSndSizeHdr + FooterDataSize + MsgInitFillLenSize
	case InitCryptoRcv:
		return overhead + MinInitCryptoRcvSizeHdr + FooterDataSize
	case Data:
		return overhead + MinDataSizeHdr + FooterDataSize
	}
	return overhead
}