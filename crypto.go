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

// =============================================================================
// Types and constants
// =============================================================================

type cryptoMsgType int8

const (
	initSnd       cryptoMsgType = iota // Unencrypted handshake initiation
	initRcv                            // Encrypted handshake response (PFS)
	initCryptoSnd                      // Encrypted 0-RTT initiation (no PFS for first msg)
	initCryptoRcv                      // Encrypted 0-RTT response (PFS)
	data                               // Regular encrypted data
)

const (
	cryptoVersion = 0
	macSize       = 16 // Poly1305 tag size
	snSize        = 6  // 48-bit sequence number

	pubKeySize         = 32 // X25519 public key
	headerSize         = 1  // Message type + version
	connIdSize         = 8
	msgInitFillLenSize = 2 // Padding length field for InitCryptoSnd

	// Minimum header sizes (before encrypted payload)
	minInitRcvSizeHdr       = headerSize + connIdSize + (2 * pubKeySize) // 73 bytes
	minInitCryptoSndSizeHdr = headerSize + (2 * pubKeySize)              // 65 bytes
	minInitCryptoRcvSizeHdr = headerSize + connIdSize + pubKeySize       // 41 bytes
	minDataSizeHdr          = headerSize + connIdSize                    // 9 bytes

	// Footer: encrypted sequence number + MAC
	footerDataSize = snSize + macSize // 22 bytes

	minPacketSize = minDataSizeHdr + footerDataSize + minProtoSize // 39 bytes
)

// msg represents a decrypted QOTP message.
type msg struct {
	snConn            uint64
	currentEpochCrypt uint64
	payloadRaw        []byte
}

// =============================================================================
// Encryption
// =============================================================================

// encryptInitSnd creates an unencrypted InitSnd packet.
// Padded to MTU to prevent amplification attacks.
// Returns connId derived from first 8 bytes of pubKeyEpSnd.
func encryptInitSnd(pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, mtu int) (connId uint64, encData []byte, err error) {
	if pubKeyIdSnd == nil || pubKeyEpSnd == nil {
		return 0, nil, errors.New("handshake keys cannot be nil")
	}
	encData = make([]byte, mtu)
	encData[0] = (uint8(initSnd) << 5) | cryptoVersion
	copy(encData[headerSize:], pubKeyEpSnd.Bytes())
	copy(encData[headerSize+pubKeySize:], pubKeyIdSnd.Bytes())
	return getUint64(encData[headerSize:]), encData, nil
}

// encryptInitCryptoSnd creates an encrypted 0-RTT initiation packet.
// Encrypted with ECDH(prvKeyEpSnd, pubKeyIdRcv) - no perfect forward secrecy.
// Padded to MTU to prevent amplification attacks.
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

	header := make([]byte, minInitCryptoSndSizeHdr)
	header[0] = (uint8(initCryptoSnd) << 5) | cryptoVersion
	copy(header[headerSize:], prvKeyEpSnd.PublicKey().Bytes())
	copy(header[headerSize+pubKeySize:], pubKeyIdSnd.Bytes())

	// Pad to MTU: [fillLen (2 bytes)][filler (fillLen bytes)][packetData]
	fillLen := mtu - (minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize + len(packetData))
	if fillLen < 0 {
		return 0, nil, errors.New("packet data too large for MTU")
	}
	padded := make([]byte, len(packetData)+msgInitFillLenSize+fillLen)
	putUint16(padded, uint16(fillLen))
	copy(padded[2+fillLen:], packetData)

	secret, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return 0, nil, err
	}
	encData, err = chainedEncrypt(snCrypto, 0, true, secret, header, padded)
	return getUint64(header[headerSize:]), encData, err
}

// encryptPacket encrypts InitRcv, InitCryptoRcv, or Data messages.
// InitRcv/InitCryptoRcv: uses ECDH(prvKeyEpSnd, pubKeyEpRcv) for PFS.
// Data: uses pre-established sharedSecret.
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
	case initRcv:
		if pubKeyIdSnd == nil || pubKeyEpRcv == nil || prvKeyEpSnd == nil {
			return nil, errors.New("handshake keys cannot be nil")
		}
		header = make([]byte, minInitRcvSizeHdr)
		header[0] = (uint8(initRcv) << 5) | cryptoVersion
		putUint64(header[headerSize:], connId)
		copy(header[headerSize+connIdSize:], prvKeyEpSnd.PublicKey().Bytes())
		copy(header[headerSize+connIdSize+pubKeySize:], pubKeyIdSnd.Bytes())
		var err error
		secret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
		if err != nil {
			return nil, err
		}

	case initCryptoRcv:
		if pubKeyEpRcv == nil || prvKeyEpSnd == nil {
			return nil, errors.New("handshake keys cannot be nil")
		}
		header = make([]byte, minInitCryptoRcvSizeHdr)
		header[0] = (uint8(initCryptoRcv) << 5) | cryptoVersion
		putUint64(header[headerSize:], connId)
		copy(header[headerSize+connIdSize:], prvKeyEpSnd.PublicKey().Bytes())
		var err error
		secret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
		if err != nil {
			return nil, err
		}

	case data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret cannot be nil")
		}
		header = make([]byte, headerSize+connIdSize)
		header[0] = (uint8(data) << 5) | cryptoVersion
		putUint64(header[headerSize:], connId)
		secret = sharedSecret
		// Data messages use epochCrypto; init messages always use epoch 0
		return chainedEncrypt(snCrypto, epochCrypto, isSender, secret, header, packetData)

	default:
		return nil, errors.New("unsupported message type")
	}

	// Init messages always use epoch 0 and isSender=false for nonce direction
	return chainedEncrypt(snCrypto, 0, false, secret, header, packetData)
}

// chainedEncrypt implements double encryption:
// 1. Encrypt payload with ChaCha20-Poly1305 using deterministic nonce
// 2. Encrypt sequence number with XChaCha20-Poly1305 using random nonce (from step 1)
//
// Nonce structure (12 bytes): [epoch (6 bytes)][snCrypto (6 bytes)]
// Bit 0 of epoch: 1=sender, 0=receiver (prevents nonce collision)
func chainedEncrypt(snCrypt, epochConn uint64, isSender bool, sharedSecret, header, packetData []byte) ([]byte, error) {
	// Build deterministic nonce
	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	putUint48(nonceDet, epochConn)
	putUint48(nonceDet[6:], snCrypt)

	// Set direction bit to prevent nonce collision between peers
	if isSender {
		nonceDet[0] |= 0x80
	} else {
		nonceDet[0] &^= 0x80
	}

	// First layer: encrypt payload
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonceDet, packetData, header)

	// Second layer: encrypt sequence number using first 24 bytes of ciphertext as nonce
	aeadSn, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, err
	}

	// Output: [header][encryptedSn (6 bytes)][sealed payload + MAC]
	encData := make([]byte, len(header)+snSize+len(sealed))
	copy(encData, header)

	encSn := aeadSn.Seal(nil, sealed[0:24], nonceDet[6:12], nil)
	copy(encData[len(header):], encSn[:snSize])
	copy(encData[len(header)+snSize:], sealed)

	return encData, nil
}

// =============================================================================
// Decryption
// =============================================================================

// decryptInitSnd extracts public keys from an unencrypted InitSnd packet.
// Validates packet size against MTU to prevent amplification attacks.
func decryptInitSnd(encData []byte, mtu int) (pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, err error) {
	if len(encData) < mtu {
		return nil, nil, errors.New("size is below minimum init")
	}
	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize : headerSize+pubKeySize])
	if err != nil {
		return nil, nil, err
	}
	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize+pubKeySize : headerSize+(2*pubKeySize)])
	if err != nil {
		return nil, nil, err
	}
	return pubKeyIdSnd, pubKeyEpSnd, nil
}

// decryptInitRcv decrypts an InitRcv handshake response.
// Derives shared secret from ECDH(prvKeyEpSnd, pubKeyEpRcv).
func decryptInitRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, m *msg, err error) {
	if len(encData) < minInitRcvSizeHdr+footerDataSize {
		return nil, nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[headerSize+connIdSize : headerSize+connIdSize+pubKeySize])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pubKeyIdRcv, err = ecdh.X25519().NewPublicKey(encData[headerSize+connIdSize+pubKeySize : headerSize+connIdSize+(2*pubKeySize)])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	headerLen := headerSize + connIdSize + (2 * pubKeySize)
	snConn, epochCrypt, packetData, err := chainedDecrypt(true, 0, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return sharedSecret, pubKeyIdRcv, pubKeyEpRcv, &msg{payloadRaw: packetData, snConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

// decryptInitCryptoSnd decrypts a 0-RTT initiation packet.
// Uses receiver's identity key for decryption (no PFS for this message).
func decryptInitCryptoSnd(encData []byte, prvKeyIdRcv *ecdh.PrivateKey, mtu int) (
	pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, m *msg, err error) {
	if len(encData) < mtu {
		return nil, nil, nil, errors.New("size is below minimum init")
	}

	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize : headerSize+pubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}
	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize+pubKeySize : headerSize+(2*pubKeySize)])
	if err != nil {
		return nil, nil, nil, err
	}

	secret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, nil, nil, err
	}

	headerLen := headerSize + (2 * pubKeySize)
	snConn, epochCrypt, packetData, err := chainedDecrypt(false, 0, secret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	// Remove padding: [fillLen (2 bytes)][filler][actualData]
	fillerLen := getUint16(packetData)
	actualData := packetData[2+int(fillerLen):]

	return pubKeyIdSnd, pubKeyEpSnd, &msg{payloadRaw: actualData, snConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

// decryptInitCryptoRcv decrypts a 0-RTT response packet.
// Derives shared secret from ECDH(prvKeyEpSnd, pubKeyEpRcv) for PFS.
func decryptInitCryptoRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte, pubKeyEpRcv *ecdh.PublicKey, m *msg, err error) {
	if len(encData) < minInitCryptoRcvSizeHdr+footerDataSize {
		return nil, nil, nil, errors.New("size is below minimum init reply")
	}

	pubKeyEpRcv, err = ecdh.X25519().NewPublicKey(encData[headerSize+connIdSize : headerSize+connIdSize+pubKeySize])
	if err != nil {
		return nil, nil, nil, err
	}

	sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	if err != nil {
		return nil, nil, nil, err
	}

	headerLen := headerSize + connIdSize + pubKeySize
	snConn, epochCrypt, packetData, err := chainedDecrypt(true, 0, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	return sharedSecret, pubKeyEpRcv, &msg{payloadRaw: packetData, snConn: snConn, currentEpochCrypt: epochCrypt}, nil
}

// decryptData decrypts a regular Data packet using the established shared secret.
func decryptData(encData []byte, isSender bool, epochCrypt uint64, sharedSecret []byte) (*msg, error) {
	if len(encData) < minDataSizeHdr+footerDataSize {
		return nil, errors.New("size is below minimum")
	}

	headerLen := headerSize + connIdSize
	snConn, currentEpoch, packetData, err := chainedDecrypt(isSender, epochCrypt, sharedSecret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, err
	}

	return &msg{payloadRaw: packetData, snConn: snConn, currentEpochCrypt: currentEpoch}, nil
}

// chainedDecrypt reverses the double encryption from chainedEncrypt.
// Tries current epoch ±1 to handle packets arriving during epoch rollover.
func chainedDecrypt(isSender bool, epochCrypt uint64, sharedSecret, header, encData []byte) (
	snConn, currentEpochCrypt uint64, packetData []byte, err error) {

	// Extract encrypted sequence number and ciphertext
	encSn := encData[:snSize]
	encData = encData[snSize:]
	nonceRand := encData[:24]

	// Decrypt sequence number (no MAC verification - MAC is on payload)
	snConnBytes := make([]byte, snSize)
	snConnBytes, err = decryptSnWithoutMAC(sharedSecret, nonceRand, encSn, snConnBytes)
	if err != nil {
		return 0, 0, nil, err
	}
	snConn = getUint48(snConnBytes)

	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return 0, 0, nil, err
	}

	nonceDet := make([]byte, chacha20poly1305.NonceSize)
	putUint48(nonceDet[6:], snConn)

	// Try current epoch, then ±1 to handle reordering near epoch boundaries
	epochs := []uint64{epochCrypt}
	if epochCrypt > 0 {
		epochs = append(epochs, epochCrypt-1)
	}
	epochs = append(epochs, epochCrypt+1)

	for _, epoch := range epochs {
		putUint48(nonceDet, epoch)
		// Receiver uses opposite direction bit from sender
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

// =============================================================================
// Helpers
// =============================================================================

// decryptSnWithoutMAC decrypts the sequence number without MAC verification.
// The MAC is verified on the payload in chainedDecrypt.
func decryptSnWithoutMAC(sharedSecret, nonce, encoded, snSer []byte) ([]byte, error) {
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	if err != nil {
		return nil, err
	}
	s.SetCounter(1) // Skip first block (used for Poly1305 key in AEAD)
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

// calcCryptoOverheadWithData returns the crypto layer overhead for a given message type.
// Returns -1 for InitSnd (no payload allowed).
func calcCryptoOverheadWithData(msgType cryptoMsgType, ack *ack, offset uint64) int {
	hasAck := ack != nil
	needsExtension := (hasAck && ack.offset > 0xFFFFFF) || offset > 0xFFFFFF
	overhead := calcProtoOverhead(hasAck, needsExtension, false)

	switch msgType {
	case initRcv:
		return overhead + minInitRcvSizeHdr + footerDataSize
	case initCryptoSnd:
		return overhead + minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize
	case initCryptoRcv:
		return overhead + minInitCryptoRcvSizeHdr + footerDataSize
	case data:
		return overhead + minDataSizeHdr + footerDataSize
	default: // InitSnd cannot carry payload
		return -1
	}
}
