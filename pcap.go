package qotp

import (
	"errors"
	"fmt"
)

// DecryptPcap decrypts a captured QOTP packet for offline analysis.
// Auto-detects message type from header. Requires appropriate shared secret:
//   - Data, InitRcv, InitCryptoRcv: sharedSecret (ECDH of ephemeral keys)
//   - InitCryptoSnd: sharedSecretId (ECDH with identity key)
//   - InitSnd: no decryption needed (returns empty)
func DecryptPcap(encData []byte, isSenderOnInit bool, epoch uint64, sharedSecret, sharedSecretId []byte) ([]byte, error) {
	if len(encData) < MinPacketSize {
		return nil, fmt.Errorf("packet too small: need %d bytes, got %d", MinPacketSize, len(encData))
	}

	header := encData[0]
	if version := header & 0x1F; version != CryptoVersion {
		return nil, fmt.Errorf("unsupported protocol version: %d", version)
	}

	msgType := cryptoMsgType(header >> 5)

	// Determine decryption parameters based on message type
	var headerLen, minSize int
	var isSender bool
	var secret []byte

	switch msgType {
	case InitSnd:
		// Unencrypted handshake initiation
		return []byte{}, nil

	case Data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for Data")
		}
		headerLen = HeaderSize + ConnIdSize
		minSize = MinDataSizeHdr + FooterDataSize
		isSender = isSenderOnInit
		secret = sharedSecret

	case InitRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitRcv")
		}
		headerLen = HeaderSize + ConnIdSize + 2*PubKeySize
		minSize = MinInitRcvSizeHdr + FooterDataSize
		isSender = true
		secret = sharedSecret

	case InitCryptoRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitCryptoRcv")
		}
		headerLen = HeaderSize + ConnIdSize + PubKeySize
		minSize = MinInitCryptoRcvSizeHdr + FooterDataSize
		isSender = true
		secret = sharedSecret

	case InitCryptoSnd:
		if sharedSecretId == nil {
			return nil, errors.New("sharedSecretId required for InitCryptoSnd")
		}
		headerLen = HeaderSize + 2*PubKeySize
		minSize = MinInitCryptoSndSizeHdr + FooterDataSize
		isSender = false
		secret = sharedSecretId

	default:
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}

	if len(encData) < minSize {
		return nil, fmt.Errorf("packet too small for %v: need %d, got %d", msgType, minSize, len(encData))
	}

	_, _, packetData, err := chainedDecrypt(isSender, epoch, secret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// InitCryptoSnd has padding that must be stripped
	if msgType == InitCryptoSnd {
		fillerLen := Uint16(packetData)
		if len(packetData) < 2+int(fillerLen) {
			return nil, errors.New("invalid filler length")
		}
		return packetData[2+fillerLen:], nil
	}

	return packetData, nil
}
