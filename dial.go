package qotp

import (
	"crypto/ecdh"
	"net/netip"
)

func (l *Listener) DialString(remoteAddrString string) (*Conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.Dial(remoteAddr)
}

func (l *Listener) DialStringWithCryptoString(remoteAddrString string, pubKeyIdRcvHex string) (*Conn, error) {
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

func (l *Listener) DialStringWithCrypto(remoteAddrString string, pubKeyIdRcv *ecdh.PublicKey) (*Conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}

	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*Conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, true)
}

func (l *Listener) Dial(remoteAddr netip.AddrPort) (*Conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, nil, nil, true, false)
}
