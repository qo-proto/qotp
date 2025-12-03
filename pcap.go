package qotp

import (
	"errors"
	"fmt"
)

// DecryptDataForPcap decrypts a QOTP Data packet for Wireshark/pcap analysis.
// This uses sharedSecret which is the ephemeral shared secret (PFS).
func DecryptDataForPcap(encData []byte, isSenderOnInit bool, epoch uint64, sharedSecret []byte) ([]byte, error) {
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

// DecryptInitCryptoSndForPcap decrypts InitCryptoSnd packets using the identity shared secret (non-PFS).
// This uses sharedSecretId which is computed as ECDH(prvKeyEpSnd, pubKeyIdRcv).
func DecryptInitCryptoSndForPcap(encData []byte, sharedSecretId []byte) ([]byte, error) {
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

// DecryptInitRcvForPcap decrypts InitRcv packets using the ephemeral shared secret (PFS).
// This uses sharedSecret which is computed as ECDH(prvKeyEpSnd, pubKeyEpRcv).
func DecryptInitRcvForPcap(encData []byte, sharedSecret []byte) ([]byte, error) {
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

// DecryptInitCryptoRcvForPcap decrypts InitCryptoRcv packets using the ephemeral shared secret (PFS).
// This uses sharedSecret which is computed as ECDH(prvKeyEpSnd, pubKeyEpRcv).
func DecryptInitCryptoRcvForPcap(encData []byte, sharedSecret []byte) ([]byte, error) {
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