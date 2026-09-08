package qotp

import (
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"strings"
)

// Dial opens a connection with in-band key exchange: 1-RTT
func (l *Listener) Dial(remoteAddr netip.AddrPort) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := binary.LittleEndian.Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, nil, nil, true, false)
}

// DialWithCrypto opens a connection to a known identity key: 0-RTT data, but
// no forward secrecy for the first message
func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := binary.LittleEndian.Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, true)
}

func (l *Listener) DialString(remoteAddrString string) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}
	return l.Dial(remoteAddr)
}

func (l *Listener) DialStringWithCrypto(remoteAddrString string, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}
	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialStringWithCryptoString(remoteAddrString string, pubKeyIdRcvHex string) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	b, err := hex.DecodeString(strings.TrimPrefix(pubKeyIdRcvHex, "0x"))
	if err != nil {
		return nil, err
	}
	pubKeyIdRcv, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}
