package qotp

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// testDecode mirrors Listen() header parsing logic for testing
func testDecodeConn(l *Listener, encData []byte, rAddr netip.AddrPort) (*conn, []byte, cryptoMsgType, error) {
	if len(encData) < MinPacketSize {
		return nil, nil, 0, fmt.Errorf("packet too small: %d bytes", len(encData))
	}

	header := encData[0]
	if version := header & 0x1F; version != CryptoVersion {
		return nil, nil, 0, errors.New("unsupported version")
	}
	msgType := cryptoMsgType(header >> 5)

	c, payload, err := decodePacket(l, encData, rAddr, msgType)
	return c, payload, msgType, err
}

var (
	seed1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed2 = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	seed3 = [32]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	seed4 = [32]byte{4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	prvIdAlice, _ = ecdh.X25519().NewPrivateKey(seed1[:])
	prvIdBob, _   = ecdh.X25519().NewPrivateKey(seed2[:])
	prvEpAlice, _ = ecdh.X25519().NewPrivateKey(seed3[:])
	prvEpBob, _   = ecdh.X25519().NewPrivateKey(seed4[:])
)

func createTestConn(isSender, withCrypto, handshakeDone bool) *conn {
	c := &conn{
		isSenderOnInit:       isSender,
		isWithCryptoOnInit:   withCrypto,
		isHandshakeDoneOnRcv: handshakeDone,
		snCrypto:             0,
		pubKeyIdRcv:          prvIdBob.PublicKey(),
		prvKeyEpSnd:          prvEpAlice,
		listener:             &Listener{prvKeyId: prvIdAlice, mtu: defaultMTU},
		snd:                  NewSendBuffer(sndBufferCapacity),
		rcv:                  NewReceiveBuffer(1000),
		streams:              NewLinkedMap[uint32, *Stream](),
		sharedSecret:         bytes.Repeat([]byte{1}, 32),
	}

	if !isSender {
		c.pubKeyIdRcv = prvIdAlice.PublicKey()
		c.pubKeyEpRcv = prvEpAlice.PublicKey()
	}

	if handshakeDone {
		c.pubKeyEpRcv = prvEpBob.PublicKey()
	}

	return c
}

func createTestListeners() (*Listener, *Listener) {
	lAlice := &Listener{
		connMap:  NewLinkedMap[uint64, *conn](),
		prvKeyId: prvIdAlice,
		mtu:      defaultMTU,
	}
	lBob := &Listener{
		connMap:  NewLinkedMap[uint64, *conn](),
		prvKeyId: prvIdBob,
		mtu:      defaultMTU,
	}
	return lAlice, lBob
}

func createTestData(size int) []byte {
	testData := make([]byte, size)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	return testData
}

func getTestRemoteAddr() netip.AddrPort {
	a, _ := netip.ParseAddr("127.0.0.1")
	return netip.AddrPortFrom(a, 8080)
}

// =============================================================================
// MSG TYPE TESTS
// =============================================================================

func TestConnMsgType(t *testing.T) {
	tests := []struct {
		name          string
		isSender      bool
		withCrypto    bool
		handshakeDone bool
		expected      cryptoMsgType
	}{
		{"sender + crypto", true, true, false, InitCryptoSnd},
		{"receiver + crypto", false, true, false, InitCryptoRcv},
		{"sender + no crypto", true, false, false, InitSnd},
		{"receiver + no crypto", false, false, false, InitRcv},
		{"handshake done", true, false, true, Data},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := createTestConn(tt.isSender, tt.withCrypto, tt.handshakeDone)
			assert.Equal(t, tt.expected, c.msgType())
		})
	}
}

// =============================================================================
// ENCODE TESTS
// =============================================================================

func TestConnEncodeClosedStates(t *testing.T) {
	// Stream closed - encode still works
	c := createTestConn(true, false, true)
	stream := c.Stream(1)
	stream.Close()

	p := &payloadHeader{}
	output, err := c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)

	// Connection closed - encode still works
	c = createTestConn(true, false, true)
	c.closeAllStreams()

	p = &payloadHeader{}
	output, err = c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncodeUnknownMsgType(t *testing.T) {
	c := createTestConn(true, false, true)

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), cryptoMsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

// =============================================================================
// SEQUENCE NUMBER TESTS
// =============================================================================

func TestConnSequenceNumberRollover(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 48) - 2
	c.epochCryptoSnd = 0

	p := &payloadHeader{}

	// First encode: snCrypto goes to max
	_, err := c.encode(p, []byte("test"), Data)
	assert.NoError(t, err)
	assert.Equal(t, uint64((1<<48)-1), c.snCrypto)

	// Second encode: rollover to 0, epoch increments
	_, err = c.encode(p, []byte("test"), Data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.snCrypto)
	assert.Equal(t, uint64(1), c.epochCryptoSnd)
}

func TestConnSequenceNumberExhaustion(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 48) - 1
	c.epochCryptoSnd = (1 << 47) - 1

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), Data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

// =============================================================================
// ENCODE/DECODE ROUNDTRIP TESTS
// =============================================================================

func TestConnEncodeDecodeRoundtripEmpty(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity)
	connAlice.rcv = NewReceiveBuffer(12000)

	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	testData := createTestData(0)

	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, payload, msgType, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	if msgType == InitCryptoRcv {
		p, u, err := decodeProto(payload)
		assert.NoError(t, err)
		s, err := connBob.processIncomingPayload(p, u, 0)
		assert.NoError(t, err)
		assert.NotNil(t, s)
	}
}

func TestConnEncodeDecodeRoundtripData(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connAlice.snd = NewSendBuffer(rcvBufferCapacity)
	connAlice.rcv = NewReceiveBuffer(12000)

	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.Put(connId, connAlice)
	connAlice.connId = connId

	// 1295 bytes is max payload for InitCryptoSnd
	testData := createTestData(1295)

	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, payload, _, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := connBob.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

// =============================================================================
// FULL HANDSHAKE TEST
// =============================================================================

func TestConnFullHandshake(t *testing.T) {
	lAlice, lBob := createTestListeners()
	remoteAddr := getTestRemoteAddr()

	// Alice's initial connection
	connAlice := &conn{
		connId:         Uint64(prvEpAlice.PublicKey().Bytes()),
		isSenderOnInit: true,
		snCrypto:       0,
		prvKeyEpSnd:    prvEpAlice,
		listener:       lAlice,
		rcv:            NewReceiveBuffer(1000),
		snd:            NewSendBuffer(1000),
		streams:        NewLinkedMap[uint32, *Stream](),
	}
	lAlice.connMap.Put(connAlice.connId, connAlice)

	// Step 1: Alice encodes InitSnd
	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, nil, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	// Step 2: Bob receives and decodes InitSnd
	connBob, _, msgTypeS0, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	assert.NotNil(t, connBob)
	assert.Equal(t, InitSnd, msgTypeS0)

	// Step 3: Bob responds with InitRcv
	testData := []byte("handshake response")
	p = &payloadHeader{}
	encodedR0, err := connBob.encode(p, testData, connBob.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encodedR0)

	// Step 4: Alice receives and decodes InitRcv
	c, payload, msgType, err := testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	assert.Equal(t, InitRcv, msgType)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := c.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)

	// Step 5: Setup for Data message flow after handshake
	connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

	connAlice.isHandshakeDoneOnRcv = true
	connAlice.pubKeyIdRcv = prvIdBob.PublicKey()
	connAlice.pubKeyEpRcv = prvEpBob.PublicKey()
	connAlice.sharedSecret = seed1[:]
	lAlice.connMap.Put(connId, connAlice)

	connBob.isHandshakeDoneOnRcv = true
	connBob.sharedSecret = seed1[:]
	lBob.connMap.Put(connId, connBob)

	// Step 6: Alice sends Data message
	dataMsg := []byte("data message")
	p = &payloadHeader{}
	encoded, err = connAlice.encode(p, dataMsg, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	// Step 7: Bob receives and decodes Data message
	c, payload, msgType, err = testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	assert.NotNil(t, c)
	assert.Equal(t, Data, msgType)

	p, u, err = decodeProto(payload)
	assert.NoError(t, err)
	s, err = c.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb = s.conn.rcv.RemoveOldestInOrder(s.streamID)
	assert.Equal(t, dataMsg, rb)
}

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestConnDecodeErrors(t *testing.T) {
	c := createTestConn(true, false, true)

	// Unknown message type
	_, err := c.decode([]byte{}, cryptoMsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected message type")
}