package qotp

import (
	"encoding/hex"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// DIAL STRING TESTS
// =============================================================================

func TestDialString_InvalidAddress(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialString("not-valid-address")
	assert.Error(t, err)
}

func TestDialString_MissingPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialString("127.0.0.1")
	assert.Error(t, err)
}

func TestDialString_InvalidPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialString("127.0.0.1:99999")
	assert.Error(t, err)
}

func TestDialString_EmptyAddress(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialString("")
	assert.Error(t, err)
}

func TestDialString_ValidIPv4(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialString("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isSenderOnInit)
	assert.False(t, conn.isWithCryptoOnInit)
}

func TestDialString_ValidIPv6(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialString("[::1]:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.remoteAddr.Addr().Is6())
}

// =============================================================================
// DIAL WITH NETIP.ADDRPORT TESTS
// =============================================================================

func TestDial_ValidAddrPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:9000")
	conn, err := l.Dial(addr)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, addr, conn.remoteAddr)
}

func TestDial_ZeroPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	conn, err := l.Dial(addr)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestDial_MaxPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:65535")
	conn, err := l.Dial(addr)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestDial_AddsToConnMap(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	assert.Equal(t, 0, l.connMap.size())

	_, err = l.DialString("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.Equal(t, 1, l.connMap.size())

	_, err = l.DialString("127.0.0.1:9001")
	assert.NoError(t, err)
	assert.Equal(t, 2, l.connMap.size())
}

// =============================================================================
// DIAL WITH CRYPTO TESTS
// =============================================================================

func TestDialWithCrypto_ValidKey(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialStringWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isSenderOnInit)
	assert.True(t, conn.isWithCryptoOnInit)
	assert.Equal(t, prvIdBob.PublicKey(), conn.pubKeyIdRcv)
}

func TestDialWithCrypto_NilKey(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	// nil key is accepted at dial time; error happens during encode
	conn, err := l.DialStringWithCrypto("127.0.0.1:9000", nil)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Nil(t, conn.pubKeyIdRcv)
}

func TestDialWithCrypto_AddrPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	addr := netip.MustParseAddrPort("127.0.0.1:9000")
	conn, err := l.DialWithCrypto(addr, prvIdBob.PublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isWithCryptoOnInit)
}

// =============================================================================
// DIAL STRING WITH CRYPTO STRING TESTS
// =============================================================================

func TestDialStringWithCryptoString_InvalidAddress(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialStringWithCryptoString("not-valid", "0x1234")
	assert.Error(t, err)
}

func TestDialStringWithCryptoString_InvalidHex(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialStringWithCryptoString("127.0.0.1:8080", "not-hex!")
	assert.Error(t, err)
}

func TestDialStringWithCryptoString_HexTooShort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialStringWithCryptoString("127.0.0.1:8080", "0x1234")
	assert.Error(t, err)
}

func TestDialStringWithCryptoString_HexTooLong(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	// 33 bytes = 66 hex chars
	longHex := hex.EncodeToString(make([]byte, 33))
	_, err = l.DialStringWithCryptoString("127.0.0.1:8080", longHex)
	assert.Error(t, err)
}

func TestDialStringWithCryptoString_ValidHex(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	validHex := hex.EncodeToString(prvIdBob.PublicKey().Bytes())
	conn, err := l.DialStringWithCryptoString("127.0.0.1:8080", validHex)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isWithCryptoOnInit)
}

func TestDialStringWithCryptoString_ValidHexWith0xPrefix(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	validHex := "0x" + hex.EncodeToString(prvIdBob.PublicKey().Bytes())
	conn, err := l.DialStringWithCryptoString("127.0.0.1:8080", validHex)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestDialStringWithCryptoString_EmptyHex(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.DialStringWithCryptoString("127.0.0.1:8080", "")
	assert.Error(t, err)
}

// =============================================================================
// CONNECTION STATE TESTS
// =============================================================================

func TestDial_SetsCorrectState(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialString("127.0.0.1:9000")
	assert.NoError(t, err)

	assert.True(t, conn.isSenderOnInit, "dial should set isSenderOnInit=true")
	assert.False(t, conn.isWithCryptoOnInit, "dial without crypto should set isWithCryptoOnInit=false")
	assert.False(t, conn.isHandshakeDoneOnRcv, "new connection should not have handshake done")
	assert.False(t, conn.isInitSentOnSnd, "new connection should not have init sent")
	assert.NotNil(t, conn.prvKeyEpSnd, "dial should generate ephemeral key")
	assert.NotNil(t, conn.snd, "dial should create send buffer")
	assert.NotNil(t, conn.rcv, "dial should create receive buffer")
	assert.NotNil(t, conn.streams, "dial should create streams map")
	assert.Equal(t, l, conn.listener, "connection should reference listener")
}

func TestDialWithCrypto_SetsCorrectState(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialStringWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)

	assert.True(t, conn.isSenderOnInit, "dial should set isSenderOnInit=true")
	assert.True(t, conn.isWithCryptoOnInit, "dial with crypto should set isWithCryptoOnInit=true")
	assert.Equal(t, prvIdBob.PublicKey(), conn.pubKeyIdRcv, "dial with crypto should set pubKeyIdRcv")
}

func TestDial_GeneratesUniqueConnId(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn1, err := l.DialString("127.0.0.1:9000")
	assert.NoError(t, err)

	conn2, err := l.DialString("127.0.0.1:9001")
	assert.NoError(t, err)

	assert.NotEqual(t, conn1.connId, conn2.connId, "each dial should generate unique connId")
}