package qotp

import (
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
)

// Dial opens a connection to addr ("host:port") with in-band key exchange:
// one round trip before data flows
func (l *Listener) Dial(addr string) (*Conn, error) {
	remoteAddr, err := resolve(addr)
	if err != nil {
		return nil, err
	}
	return l.dial(remoteAddr, nil, false)
}

// DialWithCrypto opens a connection to a peer whose identity key is known:
// data flows at once, but the first packet has no forward secrecy
func (l *Listener) DialWithCrypto(addr string, pubKeyIdRcv *ecdh.PublicKey) (*Conn, error) {
	remoteAddr, err := resolve(addr)
	if err != nil {
		return nil, err
	}
	return l.dial(remoteAddr, pubKeyIdRcv, true)
}

// PubKeyFromHex parses an identity key as printed by a peer, with or
// without a 0x prefix
func PubKeyFromHex(s string) (*ecdh.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(b)
}

func resolve(addr string) (netip.AddrPort, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := udpAddr.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, errors.New("invalid address: " + addr)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

func (l *Listener) dial(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey, withCrypto bool) (*Conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}
	connId := binary.LittleEndian.Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, withCrypto)
}
