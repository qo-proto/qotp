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

	_, err = l.Dial("not-valid-address")
	assert.Error(t, err)
}

func TestDialString_MissingPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.Dial("127.0.0.1")
	assert.Error(t, err)
}

func TestDialString_InvalidPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.Dial("127.0.0.1:99999")
	assert.Error(t, err)
}

func TestDialString_EmptyAddress(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	_, err = l.Dial("")
	assert.Error(t, err)
}

func TestDialString_ValidIPv4(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.Dial("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, initSnd, conn.initMsgType)
}

func TestDialString_ValidIPv6(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.Dial("[::1]:9000")
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

	conn, err := l.Dial("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, netip.MustParseAddrPort("127.0.0.1:9000"), conn.remoteAddr)
}

func TestDial_ZeroPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.Dial("127.0.0.1:0")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestDial_MaxPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.Dial("127.0.0.1:65535")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestDial_AddsToConnMap(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	assert.Equal(t, 0, l.connMap.size())

	_, err = l.Dial("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.Equal(t, 1, l.connMap.size())

	_, err = l.Dial("127.0.0.1:9001")
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

	conn, err := l.DialWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, initCryptoSnd, conn.initMsgType)
	assert.Equal(t, prvIdBob.PublicKey(), conn.pubKeyIdRcv)
}

func TestDialWithCrypto_NilKey(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	// nil key is accepted at dial time; error happens during encode
	conn, err := l.DialWithCrypto("127.0.0.1:9000", nil)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Nil(t, conn.pubKeyIdRcv)
}

func TestDialWithCrypto_AddrPort(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, initCryptoSnd, conn.initMsgType)
}

// =============================================================================
// DIAL STRING WITH CRYPTO STRING TESTS
// =============================================================================

func TestDial_SetsCorrectState(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.Dial("127.0.0.1:9000")
	assert.NoError(t, err)

	assert.Equal(t, initSnd, conn.initMsgType, "dial without crypto should use initSnd")
	assert.Equal(t, phaseCreated, conn.phase, "new connection should have phaseCreated")
	assert.NotNil(t, conn.sndKeys.prvKeyEp, "dial should generate ephemeral key")
	assert.NotNil(t, conn.snd, "dial should create send buffer")
	assert.NotNil(t, conn.rcv, "dial should create receive buffer")
	assert.NotNil(t, conn.streams, "dial should create streams map")
	assert.Equal(t, l, conn.listener, "connection should reference listener")
}

func TestDialWithCrypto_SetsCorrectState(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn, err := l.DialWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)

	assert.Equal(t, initCryptoSnd, conn.initMsgType, "dial with crypto should use initCryptoSnd")
	assert.Equal(t, prvIdBob.PublicKey(), conn.pubKeyIdRcv, "dial with crypto should set pubKeyIdRcv")
}

func TestDial_GeneratesUniqueConnId(t *testing.T) {
	l, err := Listen(WithSeed(seed1))
	assert.NoError(t, err)
	defer l.Close()

	conn1, err := l.Dial("127.0.0.1:9000")
	assert.NoError(t, err)

	conn2, err := l.Dial("127.0.0.1:9001")
	assert.NoError(t, err)

	assert.NotEqual(t, conn1.connId, conn2.connId, "each dial should generate unique connId")
}

func TestPubKeyFromHex(t *testing.T) {
	key := generateTestKey(t)
	hexStr := hex.EncodeToString(key.PublicKey().Bytes())

	for _, in := range []string{hexStr, "0x" + hexStr} {
		pubKey, err := PubKeyFromHex(in)
		assert.NoError(t, err)
		assert.Equal(t, key.PublicKey().Bytes(), pubKey.Bytes())
	}
	for _, bad := range []string{"", "not-hex!", "0x1234", hexStr + "00"} {
		_, err := PubKeyFromHex(bad)
		assert.Error(t, err, bad)
	}
}
