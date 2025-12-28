package qotp

import (
	"crypto/ecdh"
	"net/netip"
)

func (l *Listener) DialString(remoteAddrString string) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.Dial(remoteAddr)
}

func (l *Listener) DialStringWithCryptoString(remoteAddrString string, pubKeyIdRcvHex string) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	pubKeyIdRcv, err := decodeHexPubKey(pubKeyIdRcvHex)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialStringWithCrypto(remoteAddrString string, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, true)
}

func (l *Listener) Dial(remoteAddr netip.AddrPort) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, nil, nil, true, false)
}
