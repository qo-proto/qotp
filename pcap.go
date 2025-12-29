package qotp

import (
	"errors"
	"fmt"
	"io"
)

// logKey writes the session key to the key log in a format Wireshark can understand.
func logKey(w io.Writer, connId uint64, secret, secretId []byte) {
	fmt.Fprintf(w, "QOTP_SHARED_SECRET %x %x\n", connId, secret)
	fmt.Fprintf(w, "QOTP_SHARED_SECRET_ID %x %x\n", connId, secretId)
}

// DecryptPcap decrypts any QOTP packet type by auto-detecting the message type.
func DecryptPcap(encData []byte, isSenderOnInit bool, epoch uint64, sharedSecret, sharedSecretId []byte) ([]byte, error) {
	if len(encData) < MinPacketSize {
		return nil, fmt.Errorf("packet too small: needs at least %v bytes", MinPacketSize)
	}

	header := encData[0]
	if version := header & 0x1F; version != CryptoVersion {
		return nil, errors.New("unsupported protocol version")
	}

	msgType := cryptoMsgType(header >> 5)

	var headerLen, minSize int
	var isSender bool
	var secret []byte

	switch msgType {
	case InitSnd:
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
		headerLen = HeaderSize + ConnIdSize + (2 * PubKeySize)
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
		headerLen = HeaderSize + (2 * PubKeySize)
		minSize = MinInitCryptoSndSizeHdr + FooterDataSize
		isSender = false
		secret = sharedSecretId

	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}

	if len(encData) < minSize {
		return nil, fmt.Errorf("packet too small for %v", msgType)
	}

	_, _, packetData, err := chainedDecrypt(isSender, epoch, secret, encData[:headerLen], encData[headerLen:])
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// InitCryptoSnd has padding
	if msgType == InitCryptoSnd {
		fillerLen := Uint16(packetData)
		if len(packetData) < 2+int(fillerLen) {
			return nil, errors.New("invalid filler length")
		}
		return packetData[2+int(fillerLen):], nil
	}

	return packetData, nil
}
