package qotp

import (
	"crypto/ecdh"
	"fmt"
	"testing"
	"github.com/stretchr/testify/assert"
)

var (
	testPrvSeed1   = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testPrvSeed2   = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	testPrvKey1, _ = ecdh.X25519().NewPrivateKey(testPrvSeed1[:])
	testPrvKey2, _ = ecdh.X25519().NewPrivateKey(testPrvSeed2[:])

	hexPubKey1 = fmt.Sprintf("0x%x", testPrvKey1.PublicKey().Bytes())
	hexPubKey2 = fmt.Sprintf("0x%x", testPrvKey2.PublicKey().Bytes())
)

func TestNewListener(t *testing.T) {
	// Test case 1: Create a new listener with a valid address
	listener, err := Listen(WithListenAddr("127.0.0.1:8080"), WithSeed(testPrvSeed1))
	defer func() {
		err := listener.Close()
		assert.Nil(t, err)
	}()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	_, err = Listen(WithListenAddr("127.0.0.1:99999"), WithSeed(testPrvSeed1))
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	defer func() {
		err := listener.Close()
		assert.Nil(t, err)
	}()
	assert.Nil(t, err)
	conn, err := listener.DialWithCryptoString("127.0.0.1:9081", hexPubKey1)
	assert.Nil(t, err)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, err = listener.DialWithCryptoString("127.0.0.1:99999", hexPubKey1)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	// Test case 2: Close a listener with multi-streams
	listener.DialWithCryptoString("127.0.0.1:9081", hexPubKey1)
	err = listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}
