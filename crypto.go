package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

	minPacketSize = minDataSizeHdr + footerDataSize + minProtoSize // 42 bytes
)

// =============================================================================
// Encryption
// =============================================================================

// encryptInitSnd creates an unencrypted InitSnd packet.
// Padded to conservativeMTU to prevent amplification attacks.
// Embeds localMaxPayload so the receiver can negotiate MTU at handshake time.
// Returns connId derived from first 8 bytes of pubKeyEpSnd.
func encryptInitSnd(pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, localMaxPayload int) (connId uint64, encData []byte, err error) {
	if pubKeyIdSnd == nil || pubKeyEpSnd == nil {
		return 0, nil, errors.New("handshake keys cannot be nil")
	}
	encData = make([]byte, conservativeMTU)
	encData[0] = (uint8(initSnd) << 5) | cryptoVersion
	copy(encData[headerSize:], pubKeyEpSnd.Bytes())
	copy(encData[headerSize+pubKeySize:], pubKeyIdSnd.Bytes())
	putUint16(encData[headerSize+2*pubKeySize:], uint16(localMaxPayload))
	return getUint64(encData[headerSize:]), encData, nil
}

// encryptInitCryptoSnd creates an encrypted 0-RTT initiation packet.
// Encrypted with ECDH(prvKeyEpSnd, pubKeyIdRcv) - no perfect forward secrecy.
// Padded to conservativeMTU to prevent amplification attacks.
func encryptInitCryptoSnd(
	pubKeyIdRcv, pubKeyIdSnd *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	snCrypto uint64,
	packetData []byte,
) (connId uint64, encData []byte, err error) {
	if pubKeyIdRcv == nil || pubKeyIdSnd == nil || prvKeyEpSnd == nil {
		return 0, nil, errors.New("handshake keys cannot be nil")
	}

	header := make([]byte, minInitCryptoSndSizeHdr)
	header[0] = (uint8(initCryptoSnd) << 5) | cryptoVersion
	copy(header[headerSize:], prvKeyEpSnd.PublicKey().Bytes())
	copy(header[headerSize+pubKeySize:], pubKeyIdSnd.Bytes())

	// Pad to conservativeMTU: [fillLen (2 bytes)][filler (fillLen bytes)][packetData]
	fillLen := conservativeMTU - (minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize + len(packetData))
	if fillLen < 0 {
		return 0, nil, errors.New("packet data too large for MTU")
	}
	padded := make([]byte, len(packetData)+msgInitFillLenSize+fillLen)
	putUint16(padded, uint16(fillLen))
	copy(padded[msgInitFillLenSize+fillLen:], packetData)

	secret, err := prvKeyEpSnd.ECDH(pubKeyIdRcv)
	if err != nil {
		return 0, nil, err
	}
	encData, err = chainedEncrypt(snCrypto, true, secret, header, padded)
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
	snCrypto uint64,
	isSender bool,
	packetData []byte,
) ([]byte, error) {
	var header []byte
	var err error

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
		sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	case initCryptoRcv:
		if pubKeyEpRcv == nil || prvKeyEpSnd == nil {
			return nil, errors.New("handshake keys cannot be nil")
		}
		header = make([]byte, minInitCryptoRcvSizeHdr)
		header[0] = (uint8(initCryptoRcv) << 5) | cryptoVersion
		putUint64(header[headerSize:], connId)
		copy(header[headerSize+connIdSize:], prvKeyEpSnd.PublicKey().Bytes())
		sharedSecret, err = prvKeyEpSnd.ECDH(pubKeyEpRcv)
	case data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret cannot be nil")
		}
		header = make([]byte, headerSize+connIdSize)
		header[0] = (uint8(data) << 5) | cryptoVersion
		putUint64(header[headerSize:], connId)
		// Data messages set the nonce direction bit by role; init messages use isSender=false
		return chainedEncrypt(snCrypto, isSender, sharedSecret, header, packetData)
	default:
		return nil, errors.New("unsupported message type")
	}

	if err != nil {
		return nil, err
	}

	// Init messages always use epoch 0 and isSender=false for nonce direction
	return chainedEncrypt(snCrypto, false, sharedSecret, header, packetData)
}

// chainedEncrypt implements double encryption:
// 1. Encrypt payload with ChaCha20-Poly1305 using deterministic nonce
// 2. Encrypt sequence number with XChaCha20-Poly1305 using random nonce (from step 1)
//
// Nonce structure (12 bytes): [zero padding (6 bytes)][snCrypto (6 bytes)]
// Bit 7 (MSB) of byte 0: 1=sender, 0=receiver (prevents nonce collision).
// Nonce reuse is prevented by key rotation before the sequence number overflows.
func chainedEncrypt(snCrypt uint64, isSender bool, sharedSecret []byte, header, packetData []byte) ([]byte, error) {
	// Build deterministic nonce
	nonceDet := make([]byte, chacha20poly1305.NonceSize)
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

	encSn := aeadSn.Seal(nil, sealed[:chacha20poly1305.NonceSizeX], nonceDet[6:12], nil)
	copy(encData[len(header):], encSn[:snSize])
	copy(encData[len(header)+snSize:], sealed)

	return encData, nil
}

// =============================================================================
// Decryption
// =============================================================================

// aadLen returns the plaintext header length for a message type: the AEAD's
// additional data, and where the encrypted part starts. -1 for InitSnd.
func aadLen(msgType cryptoMsgType) int {
	switch msgType {
	case initRcv:
		return minInitRcvSizeHdr
	case initCryptoSnd:
		return minInitCryptoSndSizeHdr
	case initCryptoRcv:
		return minInitCryptoRcvSizeHdr
	case data:
		return minDataSizeHdr
	}
	return -1
}

// decryptInitSnd extracts public keys and sender's maxPayload from an unencrypted InitSnd packet.
// Validates packet size against conservativeMTU to prevent amplification attacks.
func decryptInitSnd(encData []byte) (pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, senderMaxPayload uint16, err error) {
	if len(encData) < conservativeMTU {
		return nil, nil, 0, errors.New("size is below minimum init")
	}
	pubKeyEpSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize : headerSize+pubKeySize])
	if err != nil {
		return nil, nil, 0, err
	}
	pubKeyIdSnd, err = ecdh.X25519().NewPublicKey(encData[headerSize+pubKeySize : headerSize+(2*pubKeySize)])
	if err != nil {
		return nil, nil, 0, err
	}
	senderMaxPayload = getUint16(encData[headerSize+2*pubKeySize:])
	return pubKeyIdSnd, pubKeyEpSnd, senderMaxPayload, nil
}

// decryptInitRcv decrypts an InitRcv handshake response.
// Derives shared secret from ECDH(prvKeyEpSnd, pubKeyEpRcv).
func decryptInitRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte, pubKeyIdRcv, pubKeyEpRcv *ecdh.PublicKey, payload []byte, err error) {
	if len(encData) < aadLen(initRcv)+footerDataSize+minProtoSize {
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

	headerLen := aadLen(initRcv)
	packetData, _, err := chainedDecrypt(true, [][]byte{sharedSecret}, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return sharedSecret, pubKeyIdRcv, pubKeyEpRcv, packetData, nil
}

// decryptInitCryptoSnd decrypts a 0-RTT initiation packet.
// Uses receiver's identity key for decryption (no PFS for this message).
func decryptInitCryptoSnd(encData []byte, prvKeyIdRcv *ecdh.PrivateKey) (
	pubKeyIdSnd, pubKeyEpSnd *ecdh.PublicKey, payload []byte, err error) {
	if len(encData) < conservativeMTU {
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

	noPFsharedSecret, err := prvKeyIdRcv.ECDH(pubKeyEpSnd)
	if err != nil {
		return nil, nil, nil, err
	}

	headerLen := aadLen(initCryptoSnd)
	packetData, _, err := chainedDecrypt(false, [][]byte{noPFsharedSecret}, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	// Padding is [fillLen][filler][data]. fillLen is attacker-chosen: this
	// message is sealed to the receiver's *public* identity key, so decrypting
	// says nothing about who sent it. The length read itself is in bounds —
	// chainedDecrypt guarantees at least minProtoSize of plaintext.
	fillerLen := int(getUint16(packetData))
	if msgInitFillLenSize+fillerLen > len(packetData) {
		return nil, nil, nil, errors.New("invalid filler length")
	}
	return pubKeyIdSnd, pubKeyEpSnd, packetData[msgInitFillLenSize+fillerLen:], nil
}

// decryptInitCryptoRcv decrypts a 0-RTT response packet.
// Derives shared secret from ECDH(prvKeyEpSnd, pubKeyEpRcv) for PFS.
func decryptInitCryptoRcv(encData []byte, prvKeyEpSnd *ecdh.PrivateKey) (
	sharedSecret []byte, pubKeyEpRcv *ecdh.PublicKey, payload []byte, err error) {
	if len(encData) < aadLen(initCryptoRcv)+footerDataSize+minProtoSize {
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

	headerLen := aadLen(initCryptoRcv)
	packetData, _, err := chainedDecrypt(true, [][]byte{sharedSecret}, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, nil, nil, err
	}

	return sharedSecret, pubKeyEpRcv, packetData, nil
}

// decryptData decrypts a regular Data packet using the established shared
// secret, returning the payload and the packet's sequence number.
func decryptData(encData []byte, isSender bool, sharedSecret [][]byte) ([]byte, uint64, error) {
	if len(encData) < aadLen(data)+footerDataSize+minProtoSize {
		return nil, 0, errors.New("size is below minimum")
	}

	headerLen := aadLen(data)
	return chainedDecrypt(isSender, sharedSecret, encData[:headerLen], encData[headerLen:])
}

// chainedDecrypt reverses the double encryption from chainedEncrypt.
// Tries all provided secrets (cur, plus prev/next during key rotation).
// Returns the packet's sequence number as well: it is per-connection and rises
// with every packet the peer sends, which is the only ordering the receiver
// gets (see conn.rcvSnHigh).
func chainedDecrypt(isSender bool, sharedSecrets [][]byte, header, encData []byte) ([]byte, uint64, error) {
	// The sequence-number layer takes its nonce from the front of the sealed
	// payload, so that much must be present. Asserted here because callers
	// only guarantee their own header fits.
	if minEnc := snSize + chacha20poly1305.NonceSizeX; len(encData) < minEnc {
		return nil, 0, fmt.Errorf("encrypted payload too small: need %d bytes, got %d", minEnc, len(encData))
	}

	encSn := encData[:snSize]
	encData = encData[snSize:]
	nonceRand := encData[:chacha20poly1305.NonceSizeX]

	for _, sharedSecret := range sharedSecrets {
		// A wrong secret yields garbage, not an error; Open below rejects it.
		snConn, err := decryptSnWithoutMAC(sharedSecret, nonceRand, encSn)
		if err != nil {
			continue
		}

		aead, err := chacha20poly1305.New(sharedSecret)
		if err != nil {
			continue
		}

		nonceDet := make([]byte, chacha20poly1305.NonceSize)
		putUint48(nonceDet[6:], snConn)

		if isSender {
			nonceDet[0] &^= 0x80
		} else {
			nonceDet[0] |= 0x80
		}

		if packetData, err := aead.Open(nil, nonceDet, encData, header); err == nil {
			return packetData, snConn, nil
		}
	}
	return nil, 0, errors.New("no matching secret found")
}

// =============================================================================
// Helpers
// =============================================================================

// decryptSnWithoutMAC decrypts the sequence number without MAC verification.
// The MAC is verified on the payload in chainedDecrypt.
func decryptSnWithoutMAC(sharedSecret, nonce, encoded []byte) (uint64, error) {
	s, err := chacha20.NewUnauthenticatedCipher(sharedSecret, nonce)
	if err != nil {
		return 0, err
	}
	s.SetCounter(1) // Skip first block (used for Poly1305 key in AEAD)
	var snSer [snSize]byte
	s.XORKeyStream(snSer[:], encoded)
	return getUint48(snSer[:]), nil
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
// Key update pubkeys are not included here: the caller reserves their space by
// reducing the MTU handed to the sender (see flushStream).
// Returns -1 for InitSnd (no payload allowed).
func calcCryptoOverheadWithData(msgType cryptoMsgType, ack *ack, offset uint64) int {
	var flags uint8 = flagHasStream // this path always sizes with stream header
	if ack != nil {
		flags |= flagHasAck
	}
	if (ack != nil && ack.offset > 0xFFFFFF) || offset > 0xFFFFFF {
		flags |= flagExtend
	}

	overhead := calcProtoOverhead(flags)

	switch msgType {
	case initRcv:
		return overhead + minInitRcvSizeHdr + footerDataSize
	case initCryptoSnd:
		return overhead + minInitCryptoSndSizeHdr + footerDataSize + msgInitFillLenSize
	case initCryptoRcv:
		return overhead + minInitCryptoRcvSizeHdr + footerDataSize
	case data:
		return overhead + minDataSizeHdr + footerDataSize
	default:
		return -1
	}
}

// =============================================================================
// Offline decryption (debugging)
//
// WithKeyLogWriter logs the per-connection secrets; DecryptWithSecrets turns
// those plus a captured packet back into plaintext.
// =============================================================================

// DecryptWithSecrets decrypts one captured packet, auto-detecting its type.
// Secrets come from a WithKeyLogWriter key log:
//   - Data, InitRcv, InitCryptoRcv: sharedSecret (ECDH of ephemeral keys)
//   - InitCryptoSnd:                sharedSecretId (ECDH with identity key)
//   - InitSnd:                      unencrypted, returns empty
//
// Debugging only; the live path is conn.decode, which also tracks key rotation.
func DecryptWithSecrets(encData []byte, isSenderOnInit bool, sharedSecret, sharedSecretId []byte) ([]byte, error) {
	if len(encData) < minPacketSize {
		return nil, fmt.Errorf("packet too small: need %d bytes, got %d", minPacketSize, len(encData))
	}

	header := encData[0]
	if version := header & 0x1F; version != cryptoVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}
	msgType := cryptoMsgType(header >> 5)

	var isSender bool
	var secret []byte

	switch msgType {
	case initSnd:
		return []byte{}, nil // unencrypted handshake initiation

	case data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for Data")
		}
		isSender, secret = isSenderOnInit, sharedSecret

	case initRcv, initCryptoRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitRcv/InitCryptoRcv")
		}
		isSender, secret = true, sharedSecret

	case initCryptoSnd:
		if sharedSecretId == nil {
			return nil, errors.New("sharedSecretId required for InitCryptoSnd")
		}
		isSender, secret = false, sharedSecretId

	default:
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}

	headerLen := aadLen(msgType)
	if minSize := headerLen + footerDataSize + minProtoSize; len(encData) < minSize {
		return nil, fmt.Errorf("packet too small for %v: need %d, got %d", msgType, minSize, len(encData))
	}

	packetData, _, err := chainedDecrypt(isSender, [][]byte{secret}, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// InitCryptoSnd has padding that must be stripped
	if msgType == initCryptoSnd {
		fillerLen := getUint16(packetData)
		if msgInitFillLenSize+int(fillerLen) > len(packetData) {
			return nil, errors.New("invalid filler length")
		}
		return packetData[msgInitFillLenSize+int(fillerLen):], nil
	}

	return packetData, nil
}
