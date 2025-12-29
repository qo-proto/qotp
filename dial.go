package qotp

import (
	"crypto/ecdh"
	"net/netip"
)

// =============================================================================
// Dial functions
//
// Two modes:
// - Without crypto (Dial, DialString): In-band key exchange, 1-RTT
// - With crypto (DialWithCrypto, ...): Out-of-band keys, 0-RTT but no PFS on first message
// =============================================================================

// Dial creates a new outbound connection without pre-shared keys.
// Uses in-band key exchange (InitSnd/InitRcv flow).
func (l *Listener) Dial(remoteAddr netip.AddrPort) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, nil, nil, true, false)
}

// DialWithCrypto creates a new outbound connection with pre-shared identity key.
// Enables 0-RTT data but first message lacks perfect forward secrecy.
func (l *Listener) DialWithCrypto(remoteAddr netip.AddrPort, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	prvKeyEp, err := generateKey()
	if err != nil {
		return nil, err
	}

	connId := Uint64(prvKeyEp.PublicKey().Bytes())
	return l.newConn(connId, remoteAddr, prvKeyEp, pubKeyIdRcv, nil, true, true)
}

// =============================================================================
// String address convenience wrappers
// =============================================================================

// DialString parses address and calls Dial.
func (l *Listener) DialString(remoteAddrString string) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}
	return l.Dial(remoteAddr)
}

// DialStringWithCrypto parses address and calls DialWithCrypto.
func (l *Listener) DialStringWithCrypto(remoteAddrString string, pubKeyIdRcv *ecdh.PublicKey) (*conn, error) {
	remoteAddr, err := netip.ParseAddrPort(remoteAddrString)
	if err != nil {
		return nil, err
	}
	return l.DialWithCrypto(remoteAddr, pubKeyIdRcv)
}

// DialStringWithCryptoString parses address and hex key, then calls DialWithCrypto.
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