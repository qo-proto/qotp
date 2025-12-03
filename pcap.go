package qotp

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
)

// DecryptPcap decrypts any QOTP packet type by auto-detecting the message type.
// Pass nil for unused secrets based on what you're decrypting.
func DecryptPcap(encData []byte, isSenderOnInit bool, epoch uint64, sharedSecret []byte, sharedSecretId []byte) ([]byte, error) {
	slog.Debug("DecryptPcap called",
		"encDataLen", len(encData),
		"encDataHex", hex.EncodeToString(encData),
		"epoch", epoch,
		"isSenderOnInit", isSenderOnInit,
		"sharedSecretHex", hex.EncodeToString(sharedSecret),
		"sharedSecretIdHex", hex.EncodeToString(sharedSecretId))

	if len(encData) < MinPacketSize {
		return nil, fmt.Errorf("packet too small: needs at least %v bytes", MinPacketSize)
	}

	header := encData[0]
	version := header & 0x1F
	if version != CryptoVersion {
		return nil, errors.New("unsupported protocol version")
	}

	msgType := CryptoMsgType(header >> 5)
	slog.Debug("DecryptPcap detected message type",
		"msgType", msgType,
		"header", fmt.Sprintf("0x%02x", header))

	switch msgType {
	case InitSnd:
		slog.Debug("InitSnd packet - no decryption needed")
		return []byte{}, nil

	case InitCryptoSnd:
		if sharedSecretId == nil {
			return nil, errors.New("sharedSecretId required for InitCryptoSnd")
		}
		return decryptPcapInitCryptoSnd(encData, sharedSecretId)

	case InitRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitRcv")
		}
		return decryptPcapInitRcv(encData, sharedSecret)

	case InitCryptoRcv:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for InitCryptoRcv")
		}
		return decryptPcapInitCryptoRcv(encData, sharedSecret)

	case Data:
		if sharedSecret == nil {
			return nil, errors.New("sharedSecret required for Data")
		}

		return decryptPcapData(encData, epoch, isSenderOnInit, sharedSecret)

	default:
		return nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}

// decryptPcapData decrypts a QOTP Data packet for Wireshark/pcap analysis.
// This uses sharedSecret which is the ephemeral shared secret (PFS).
func decryptPcapData(encData []byte, epoch uint64, isSenderOnInit bool, sharedSecret []byte) ([]byte, error) {
	if len(encData) < MinDataSizeHdr+FooterDataSize {
		return nil, errors.New("packet too small for Data")
	}

	// Header is: [1 byte header][8 bytes connId]
	header := encData[0 : HeaderSize+ConnIdSize]
	encryptedPortion := encData[HeaderSize+ConnIdSize:]

	_, _, packetData, err := chainedDecrypt(
		isSenderOnInit,
		epoch,
		sharedSecret,
		header,
		encryptedPortion,
	)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return packetData, nil
}

// decryptPcapInitCryptoSnd decrypts InitCryptoSnd packets using the identity shared secret (non-PFS).
// This uses sharedSecretId which is computed as ECDH(prvKeyEpSnd, pubKeyIdRcv).
func decryptPcapInitCryptoSnd(encData []byte, sharedSecretId []byte) ([]byte, error) {
	if len(encData) < MinInitCryptoSndSizeHdr+FooterDataSize {
		return nil, errors.New("packet too small for InitCryptoSnd")
	}

	// Header is: [1 byte header][32 bytes pubKeyEpSnd][32 bytes pubKeyIdSnd]
	header := encData[0 : HeaderSize+(2*PubKeySize)]
	encryptedPortion := encData[HeaderSize+(2*PubKeySize):]

	_, _, packetData, err := chainedDecrypt(
		false, // InitCryptoSnd uses isSender=false
		0,     // epoch is always 0 for init messages
		sharedSecretId,
		header,
		encryptedPortion,
	)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Remove padding: first 2 bytes are filler length
	fillerLen := Uint16(packetData)
	if len(packetData) < 2+int(fillerLen) {
		return nil, errors.New("invalid filler length")
	}
	actualData := packetData[2+int(fillerLen):]

	return actualData, nil
}

// decryptPcapInitRcv decrypts InitRcv packets using the ephemeral shared secret (PFS).
// This uses sharedSecret which is computed as ECDH(prvKeyEpSnd, pubKeyEpRcv).
func decryptPcapInitRcv(encData []byte, sharedSecret []byte) ([]byte, error) {
	if len(encData) < MinInitRcvSizeHdr+FooterDataSize {
		return nil, errors.New("packet too small for InitRcv")
	}

	// Header is: [1 byte header][8 bytes connId][32 bytes pubKeyEpRcv][32 bytes pubKeyIdRcv]
	header := encData[0 : HeaderSize+ConnIdSize+(2*PubKeySize)]
	encryptedPortion := encData[HeaderSize+ConnIdSize+(2*PubKeySize):]

	_, _, packetData, err := chainedDecrypt(
		true, // InitRcv uses isSender=true
		0,    // epoch is always 0 for init messages
		sharedSecret,
		header,
		encryptedPortion,
	)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return packetData, nil
}

// decryptPcapInitCryptoRcv decrypts InitCryptoRcv packets using the ephemeral shared secret (PFS).
// This uses sharedSecret which is computed as ECDH(prvKeyEpSnd, pubKeyEpRcv).
func decryptPcapInitCryptoRcv(encData []byte, sharedSecret []byte) ([]byte, error) {
	if len(encData) < MinInitCryptoRcvSizeHdr+FooterDataSize {
		return nil, errors.New("packet too small for InitCryptoRcv")
	}

	// Header is: [1 byte header][8 bytes connId][32 bytes pubKeyEpRcv]
	header := encData[0 : HeaderSize+ConnIdSize+PubKeySize]
	encryptedPortion := encData[HeaderSize+ConnIdSize+PubKeySize:]

	_, _, packetData, err := chainedDecrypt(
		true, // InitCryptoRcv uses isSender=true
		0,    // epoch is always 0 for init messages
		sharedSecret,
		header,
		encryptedPortion,
	)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return packetData, nil
}