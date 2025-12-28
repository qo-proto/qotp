package qotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDialInvalidAddress(t *testing.T) {
	l, _ := Listen(WithSeed(seed1))
	defer l.Close()

	_, err := l.DialString("not-valid-address")
	assert.Error(t, err)

	_, err = l.DialStringWithCryptoString("not-valid", "0x1234")
	assert.Error(t, err)
}

func TestDialInvalidHexKey(t *testing.T) {
	l, _ := Listen(WithSeed(seed1))
	defer l.Close()

	_, err := l.DialStringWithCryptoString("127.0.0.1:8080", "not-hex")
	assert.Error(t, err)

	_, err = l.DialStringWithCryptoString("127.0.0.1:8080", "0x1234") // too short
	assert.Error(t, err)
}

func TestDialCreatesConnection(t *testing.T) {
	l, _ := Listen(WithSeed(seed1))
	defer l.Close()

	conn, err := l.DialString("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isSenderOnInit)
	assert.False(t, conn.isWithCryptoOnInit)
	assert.Equal(t, 1, l.connMap.Size())
}

func TestDialWithCryptoCreatesConnection(t *testing.T) {
	l, _ := Listen(WithSeed(seed1))
	defer l.Close()

	conn, err := l.DialStringWithCrypto("127.0.0.1:9000", prvIdBob.PublicKey())
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.True(t, conn.isSenderOnInit)
	assert.True(t, conn.isWithCryptoOnInit)
	assert.Equal(t, prvIdBob.PublicKey(), conn.pubKeyIdRcv)
}
