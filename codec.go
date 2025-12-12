package qotp

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"

	"net/netip"
	"strings"
)

func (conn *Conn) encode(p *PayloadHeader, userData []byte, msgType CryptoMsgType) (encData []byte, err error) {
	// Create payload early for cases that need it
	var packetData []byte

	// Handle message encoding based on connection state
	switch msgType {
	case InitSnd:
		_, encData = encryptInitSnd(
			conn.listener.prvKeyId.PublicKey(),
			conn.prvKeyEpSnd.PublicKey(),
			conn.listener.mtu,
		)
		conn.isInitSentOnSnd = true
	case InitCryptoSnd:
		packetData, _ = EncodePayload(p, userData)
		_, encData, err = encryptInitCryptoSnd(
			conn.pubKeyIdRcv,
			conn.listener.prvKeyId.PublicKey(),
			conn.prvKeyEpSnd,
			conn.snCrypto,
			conn.listener.mtu,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case InitCryptoRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptInitCryptoRcv(
			conn.connId,
			conn.pubKeyEpRcv,
			conn.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case InitRcv:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptInitRcv(
			conn.connId,
			conn.listener.prvKeyId.PublicKey(),
			conn.pubKeyEpRcv,
			conn.prvKeyEpSnd,
			conn.snCrypto,
			packetData,
		)
		if err != nil {
			return nil, err
		}
		conn.isInitSentOnSnd = true
	case Data:
		packetData, _ = EncodePayload(p, userData)
		encData, err = encryptData(
			conn.connId,
			conn.isSenderOnInit,
			conn.sharedSecret,
			conn.snCrypto,
			conn.epochCryptoSnd,
			packetData,
		)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown message type")
	}

	//update state ofter encode of packet
	conn.snCrypto++
	//rollover
	if conn.snCrypto > (1<<48)-1 {
		if conn.epochCryptoSnd+1 > (1<<47)-1 {
			//47, as the last bit is used for sender / receiver differentiation
			//quic has key rotation (via bitflip), qotp does not.
			return nil, errors.New("exhausted 2^95 sn number, cannot continue, you just " +
				"sent ~5 billion ZettaBytes.\nNow you need to reconnect manually. This " +
				"is roughly 28 million times all the data humanity has ever created.")
		}
		conn.epochCryptoSnd++
		conn.snCrypto = 0
	}
	return encData, nil
}

func (l *Listener) decode(encData []byte, rAddr netip.AddrPort) (
	conn *Conn, userData []byte, msgType CryptoMsgType, err error) {
	// Read the header byte and connId
	if len(encData) < MinPacketSize {
		return nil, nil, 0, fmt.Errorf("header needs to be at least %v bytes", MinPacketSize)
	}

	header := encData[0]
	version := header & 0x1F // Extract bits 0-4 (mask 0001 1111)
	if version != CryptoVersion {
		return nil, nil, 0, errors.New("unsupported version version")
	}
	msgType = CryptoMsgType(header >> 5)

	connId := Uint64(encData[HeaderSize : ConnIdSize+HeaderSize])

	switch msgType {
	case InitSnd:
		// Decode S0 message
		pubKeyIdSnd, pubKeyEpSnd, err := decryptInitSnd(encData, l.mtu)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
		}
		conn := l.connMap.Get(connId)
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, rAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, false)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
		}
		conn.sharedSecret = sharedSecret
		return conn, []byte{}, InitSnd, nil
	case InitRcv:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, 0, errors.New("connection not found for InitRcv")
		}

		// Decode R0 message
		sharedSecret, pubKeyIdRcv, pubKeyEpRcv, message, err := decryptInitRcv(
			encData,
			conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitRcv: %w", err)
		}

		conn.pubKeyIdRcv = pubKeyIdRcv
		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		// Log keys for 0-RTT connections (where pubKeyEpRcv wasn't available at newConn time)
		if err := l.logKeysIfEnabled(conn, sharedSecret); err != nil {
			return nil, nil, 0, err
		}

		slog.Debug(" Decode/InitRcv", gId(), l.debug())
		return conn, message.PayloadRaw, InitRcv, nil
	case InitCryptoSnd:
		// Decode crypto S0 message
		pubKeyIdSnd, pubKeyEpSnd, message, err := decryptInitCryptoSnd(
			encData, l.prvKeyId, l.mtu)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
		}
		//we might have received this a multiple times due to retransmission in the first packet
		//however the other side send us this, so we are expected to drop the old keys
		conn := l.connMap.Get(connId)

		var prvKeyEpRcv *ecdh.PrivateKey
		if conn == nil {
			prvKeyEpRcv, err = generateKey()
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to generate keys: %w", err)
			}
			conn, err = l.newConn(connId, rAddr, prvKeyEpRcv, pubKeyIdSnd, pubKeyEpSnd, false, true)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to create connection: %w", err)
			}
			l.connMap.Put(connId, conn)
		} else {
			prvKeyEpRcv = conn.prvKeyEpSnd
		}

		sharedSecret, err := prvKeyEpRcv.ECDH(pubKeyEpSnd)

		conn.sharedSecret = sharedSecret
		return conn, message.PayloadRaw, InitCryptoSnd, nil
	case InitCryptoRcv:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, 0, errors.New("connection not found for InitWithCryptoR0")
		}

		// Decode crypto R0 message
		sharedSecret, pubKeyEpRcv, message, err := decryptInitCryptoRcv(encData, conn.prvKeyEpSnd)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
		}

		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.sharedSecret = sharedSecret

		// Log keys for 0-RTT connections (client side receives InitCryptoRcv)
		if err := l.logKeysIfEnabled(conn, sharedSecret); err != nil {
			return nil, nil, 0, err
		}

		slog.Debug(" Decode/InitCryptoRcv", gId(), l.debug())
		return conn, message.PayloadRaw, InitCryptoRcv, nil
	case Data:
		connId := Uint64(encData[HeaderSize : HeaderSize+ConnIdSize])
		conn := l.connMap.Get(connId)
		if conn == nil {
			return nil, nil, 0, errors.New("connection not found for DataMessage")
		}

		// Decode Data message
		message, err := decryptData(encData, conn.isSenderOnInit, conn.epochCryptoRcv, conn.sharedSecret)
		if err != nil {
			return nil, nil, 0, err
		}

		//we decoded conn.epochCrypto + 1, that means we can safely move forward with the epoch
		if message.currentEpochCrypt > conn.epochCryptoRcv {
			conn.epochCryptoRcv = message.currentEpochCrypt
		}

		return conn, message.PayloadRaw, Data, nil
	default:
		return nil, nil, 0, fmt.Errorf("unknown message type: %v", msgType)
	}
}

func decodeHex(pubKeyHex string) ([]byte, error) {
	if strings.HasPrefix(pubKeyHex, "0x") {
		pubKeyHex = strings.Replace(pubKeyHex, "0x", "", 1)
	}

	return hex.DecodeString(pubKeyHex)
}

// //////////////////////////////////////////
func PutUint16(b []byte, v uint16) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	return 2
}

func PutUint24(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	return 3
}

func PutUint32(b []byte, v uint32) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	return 4
}

func PutUint48(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	return 6
}

func PutUint64(b []byte, v uint64) int {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
	return 8
}

func Uint16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func Uint24(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16
}

func Uint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func Uint48(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40
}

func Uint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func putOffsetVarint(buf []byte, offset uint64, isExtend bool) int {
	if isExtend {
		return PutUint48(buf, offset)
	}
	return PutUint24(buf, offset)
}

func offsetVarint(buf []byte, isExtend bool) uint64 {
	if isExtend {
		return Uint48(buf)
	}
	return Uint24(buf)
}

func offsetSize(isExtend bool) int {
	if isExtend {
		return 6
	}
	return 3
}

// logKeysIfEnabled logs both shared secrets if keyLogWriter is enabled
func (l *Listener) logKeysIfEnabled(conn *Conn, sharedSecret []byte) error {
	if l.keyLogWriter == nil {
		return nil
	}

	var sharedSecretId []byte
	var err error
	if conn.pubKeyIdRcv != nil {
		sharedSecretId, err = conn.prvKeyEpSnd.ECDH(conn.pubKeyIdRcv)
		if err != nil {
			return fmt.Errorf("failed to derive sharedSecretId: %w", err)
		}
	}
	logKey(l.keyLogWriter, conn.connId, sharedSecret, sharedSecretId)
	return nil
}
