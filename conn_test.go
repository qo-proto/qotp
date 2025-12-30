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

// =============================================================================
// TEST HELPERS
// =============================================================================

// testDecodeConn mirrors Listen() header parsing logic for testing
func testDecodeConn(l *Listener, encData []byte, rAddr netip.AddrPort) (*conn, []byte, cryptoMsgType, error) {
	if len(encData) < minPacketSize {
		return nil, nil, 0, fmt.Errorf("packet too small: %d bytes", len(encData))
	}

	header := encData[0]
	if version := header & 0x1F; version != cryptoVersion {
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
		snd:                  newSendBuffer(sndBufferCapacity),
		rcv:                  newReceiveBuffer(1000),
		streams:              newLinkedMap[uint32, *Stream](),
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
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: prvIdAlice,
		mtu:      defaultMTU,
	}
	lBob := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
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

func TestConnMsgType_SenderWithCrypto(t *testing.T) {
	c := createTestConn(true, true, false)
	assert.Equal(t, initCryptoSnd, c.msgType())
}

func TestConnMsgType_ReceiverWithCrypto(t *testing.T) {
	c := createTestConn(false, true, false)
	assert.Equal(t, initCryptoRcv, c.msgType())
}

func TestConnMsgType_SenderNoCrypto(t *testing.T) {
	c := createTestConn(true, false, false)
	assert.Equal(t, initSnd, c.msgType())
}

func TestConnMsgType_ReceiverNoCrypto(t *testing.T) {
	c := createTestConn(false, false, false)
	assert.Equal(t, initRcv, c.msgType())
}

func TestConnMsgType_HandshakeDone(t *testing.T) {
	c := createTestConn(true, false, true)
	assert.Equal(t, data, c.msgType())
}

func TestConnMsgType_HandshakeDoneOverridesCrypto(t *testing.T) {
	c := createTestConn(true, true, true)
	assert.Equal(t, data, c.msgType(), "handshake done should always return Data")
}

// =============================================================================
// ENCODE TESTS
// =============================================================================

func TestConnEncode_StreamClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	stream := c.Stream(1)
	stream.Close()

	p := &payloadHeader{}
	output, err := c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_AllStreamsClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	c.closeAllStreams()

	p := &payloadHeader{}
	output, err := c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_UnknownMsgType(t *testing.T) {
	c := createTestConn(true, false, true)

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), cryptoMsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

func TestConnEncode_EmptyPayload(t *testing.T) {
	c := createTestConn(true, false, true)

	p := &payloadHeader{}
	output, err := c.encode(p, []byte{}, c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_NilPayload(t *testing.T) {
	c := createTestConn(true, false, true)

	p := &payloadHeader{}
	output, err := c.encode(p, nil, c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_InitSndNoPayload(t *testing.T) {
	c := createTestConn(true, false, false)

	p := &payloadHeader{}
	output, err := c.encode(p, nil, initSnd)
	assert.NoError(t, err)
	assert.NotNil(t, output)
	assert.True(t, c.isInitSentOnSnd, "isInitSentOnSnd should be set after encoding init message")
}

func TestConnEncode_InitCryptoSnd_PayloadTooLarge(t *testing.T) {
	c := createTestConn(true, true, false)

	// Create payload larger than MTU allows
	largePayload := createTestData(defaultMTU + 100)

	p := &payloadHeader{}
	_, err := c.encode(p, largePayload, initCryptoSnd)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

// =============================================================================
// SEQUENCE NUMBER TESTS
// =============================================================================

func TestConnSequenceNumber_Increment(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = 0

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), c.snCrypto)
}

func TestConnSequenceNumber_Rollover(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 48) - 2
	c.epochCryptoSnd = 0

	p := &payloadHeader{}

	// First encode: snCrypto goes to max
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64((1<<48)-1), c.snCrypto)

	// Second encode: rollover to 0, epoch increments
	_, err = c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.snCrypto)
	assert.Equal(t, uint64(1), c.epochCryptoSnd)
}

func TestConnSequenceNumber_Exhaustion(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 48) - 1
	c.epochCryptoSnd = (1 << 47) - 1

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exhausted")
}

func TestConnSequenceNumber_MultipleRollovers(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 48) - 1
	c.epochCryptoSnd = 5

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.snCrypto)
	assert.Equal(t, uint64(6), c.epochCryptoSnd)
}

// =============================================================================
// ENCODE/DECODE ROUNDTRIP TESTS
// =============================================================================

func TestConnEncodeDecodeRoundtrip_EmptyPayload(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connAlice.snd = newSendBuffer(rcvBufferCapacity)
	connAlice.rcv = newReceiveBuffer(12000)

	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.put(connId, connAlice)
	connAlice.connId = connId

	testData := createTestData(0)

	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, payload, msgType, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	if msgType == initCryptoRcv {
		p, u, err := decodeProto(payload)
		assert.NoError(t, err)
		s, err := connBob.processIncomingPayload(p, u, 0)
		assert.NoError(t, err)
		assert.NotNil(t, s)
	}
}

func TestConnEncodeDecodeRoundtrip_MaxPayload(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connAlice.snd = newSendBuffer(rcvBufferCapacity)
	connAlice.rcv = newReceiveBuffer(12000)

	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.put(connId, connAlice)
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
	rb := s.conn.rcv.removeOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)
}

func TestConnEncodeDecodeRoundtrip_SingleByte(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connAlice.snd = newSendBuffer(rcvBufferCapacity)
	connAlice.rcv = newReceiveBuffer(12000)

	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.put(connId, connAlice)
	connAlice.connId = connId

	testData := []byte{0xFF}

	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)

	connBob, payload, _, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := connBob.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb := s.conn.rcv.removeOldestInOrder(s.streamID)
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
		connId:         getUint64(prvEpAlice.PublicKey().Bytes()),
		isSenderOnInit: true,
		snCrypto:       0,
		prvKeyEpSnd:    prvEpAlice,
		listener:       lAlice,
		rcv:            newReceiveBuffer(1000),
		snd:            newSendBuffer(1000),
		streams:        newLinkedMap[uint32, *Stream](),
	}
	lAlice.connMap.put(connAlice.connId, connAlice)

	// Step 1: Alice encodes InitSnd
	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, nil, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	// Step 2: Bob receives and decodes InitSnd
	connBob, _, msgTypeS0, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	assert.NotNil(t, connBob)
	assert.Equal(t, initSnd, msgTypeS0)

	// Step 3: Bob responds with InitRcv
	testData := []byte("handshake response")
	p = &payloadHeader{}
	encodedR0, err := connBob.encode(p, testData, connBob.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encodedR0)

	// Step 4: Alice receives and decodes InitRcv
	c, payload, msgType, err := testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	assert.Equal(t, initRcv, msgType)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := c.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb := s.conn.rcv.removeOldestInOrder(s.streamID)
	assert.Equal(t, testData, rb)

	// Step 5: Setup for Data message flow after handshake
	connId := binary.LittleEndian.Uint64(prvIdAlice.PublicKey().Bytes()) ^ binary.LittleEndian.Uint64(prvIdBob.PublicKey().Bytes())

	connAlice.isHandshakeDoneOnRcv = true
	connAlice.pubKeyIdRcv = prvIdBob.PublicKey()
	connAlice.pubKeyEpRcv = prvEpBob.PublicKey()
	connAlice.sharedSecret = seed1[:]
	lAlice.connMap.put(connId, connAlice)

	connBob.isHandshakeDoneOnRcv = true
	connBob.sharedSecret = seed1[:]
	lBob.connMap.put(connId, connBob)

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
	assert.Equal(t, data, msgType)

	p, u, err = decodeProto(payload)
	assert.NoError(t, err)
	s, err = c.processIncomingPayload(p, u, 0)
	assert.NoError(t, err)
	rb = s.conn.rcv.removeOldestInOrder(s.streamID)
	assert.Equal(t, dataMsg, rb)
}

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestConnDecode_UnknownMsgType(t *testing.T) {
	c := createTestConn(true, false, true)

	_, err := c.decode([]byte{}, cryptoMsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected message type")
}

func TestConnDecode_PacketTooSmall(t *testing.T) {
	l, _ := createTestListeners()

	// Packet smaller than MinPacketSize
	tinyPacket := []byte{0x00, 0x01, 0x02}
	_, _, _, err := testDecodeConn(l, tinyPacket, getTestRemoteAddr())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "packet too small")
}

func TestConnDecode_UnsupportedVersion(t *testing.T) {
	l, _ := createTestListeners()

	// Create packet with wrong version (bits 0-4)
	badVersionPacket := make([]byte, minPacketSize)
	badVersionPacket[0] = 0x1F // Version 31 (max), not CryptoVersion

	_, _, _, err := testDecodeConn(l, badVersionPacket, getTestRemoteAddr())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestConnDecode_ConnectionNotFound(t *testing.T) {
	l, _ := createTestListeners()

	// Create a Data packet for a connection that doesn't exist
	c := createTestConn(true, false, true)
	c.connId = 12345
	p := &payloadHeader{}
	encoded, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)

	// Try to decode without registering the connection
	_, _, _, err = testDecodeConn(l, encoded, getTestRemoteAddr())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection not found")
}

func TestConnDecode_CorruptedMac(t *testing.T) {
	lAlice, lBob := createTestListeners()

	connAlice := createTestConn(true, true, false)
	connId := binary.LittleEndian.Uint64(prvEpAlice.PublicKey().Bytes())
	lAlice.connMap.put(connId, connAlice)
	connAlice.connId = connId

	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, []byte("test"), connAlice.msgType())
	assert.NoError(t, err)

	// Corrupt the last byte (part of MAC)
	encoded[len(encoded)-1] ^= 0xFF

	_, _, _, err = testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.Error(t, err)
}

// =============================================================================
// PROCESS INCOMING PAYLOAD TESTS
// =============================================================================

func TestConnProcessIncomingPayload_NilAck(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          nil,
	}

	s, err := c.processIncomingPayload(p, []byte("data"), 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, uint32(1), s.streamID)
}

func TestConnProcessIncomingPayload_WithAck(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)
	c.snd = newSendBuffer(1000)

	// Queue some data that will be acknowledged
	c.snd.queueData(1, []byte("test"))

	ack := &ack{
		streamId: 1,
		offset:   0,
		len:      4,
		rcvWnd:   1000,
	}

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          ack,
	}

	s, err := c.processIncomingPayload(p, []byte("response"), 1000)
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestConnProcessIncomingPayload_CloseFlag(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		isClose:      true,
		ack:          nil,
	}

	s, err := c.processIncomingPayload(p, []byte("final"), 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestConnProcessIncomingPayload_EmptyPing(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          nil,
	}

	// Empty slice (not nil) represents PING
	s, err := c.processIncomingPayload(p, []byte{}, 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestConnProcessIncomingPayload_FinishedStream(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	// Mark stream as finished
	c.rcv.close(1, 0)
	c.rcv.removeStream(1)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          nil,
	}

	s, err := c.processIncomingPayload(p, []byte("late data"), 0)
	assert.NoError(t, err)
	assert.Nil(t, s, "should return nil for finished stream")
}

// =============================================================================
// STREAM MANAGEMENT TESTS
// =============================================================================

func TestConnStream_GetOrCreate(t *testing.T) {
	c := createTestConn(true, false, true)

	s1 := c.Stream(1)
	assert.NotNil(t, s1)
	assert.Equal(t, uint32(1), s1.streamID)

	s1Again := c.Stream(1)
	assert.Equal(t, s1, s1Again, "should return same stream instance")
}

func TestConnStream_MultipleStreams(t *testing.T) {
	c := createTestConn(true, false, true)

	s1 := c.Stream(1)
	s2 := c.Stream(2)
	s3 := c.Stream(3)

	assert.NotEqual(t, s1, s2)
	assert.NotEqual(t, s2, s3)
	assert.Equal(t, uint32(1), s1.streamID)
	assert.Equal(t, uint32(2), s2.streamID)
	assert.Equal(t, uint32(3), s3.streamID)
}

func TestConnStream_FinishedStreamReturnsNil(t *testing.T) {
	c := createTestConn(true, false, true)

	// Create and finish stream
	c.Stream(1)
	c.rcv.close(1, 0)
	c.rcv.removeStream(1)

	s := c.Stream(1)
	assert.Nil(t, s, "should return nil for finished stream")
}

func TestConnHasActiveStreams_NoStreams(t *testing.T) {
	c := createTestConn(true, false, true)

	assert.False(t, c.HasActiveStreams())
}

func TestConnHasActiveStreams_WithActiveStream(t *testing.T) {
	c := createTestConn(true, false, true)
	c.Stream(1)

	assert.True(t, c.HasActiveStreams())
}

func TestConnHasActiveStreams_AllClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	s := c.Stream(1)
	s.rcvClosed = true
	s.sndClosed = true

	assert.False(t, c.HasActiveStreams())
}

func TestConnHasActiveStreams_PartiallyClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	s := c.Stream(1)
	s.rcvClosed = true
	s.sndClosed = false

	assert.True(t, c.HasActiveStreams(), "stream with only rcv closed should still be active")
}

func TestConnCloseAllStreams(t *testing.T) {
	c := createTestConn(true, false, true)
	c.Stream(1)
	c.Stream(2)
	c.Stream(3)

	c.closeAllStreams()

	// Verify all streams have Close() called (queued for close)
	for _, s := range c.streams.iterator(nil) {
		assert.True(t, s.IsCloseRequested(), "all streams should be close-requested")
	}
}

func TestConnCleanupStream(t *testing.T) {
	c := createTestConn(true, false, true)
	c.listener.currentStreamID = new(uint32)
	*c.listener.currentStreamID = 1

	c.Stream(1)
	c.Stream(2)

	c.cleanupStream(1)

	_, exists := c.streams.get(1)
	assert.False(t, exists, "stream 1 should be removed")

	_, exists = c.streams.get(2)
	assert.True(t, exists, "stream 2 should still exist")
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

func TestConnEncode_NilSharedSecretForData(t *testing.T) {
	c := createTestConn(true, false, true)
	c.sharedSecret = nil

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestConnEncode_NilPubKeyEpRcvForInitRcv(t *testing.T) {
	c := createTestConn(false, false, false)
	c.pubKeyEpRcv = nil

	p := &payloadHeader{}
	_, err := c.encode(p, []byte("test"), initRcv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestConnDecode_InitRcv_TooSmall(t *testing.T) {
	c := createTestConn(true, false, false)

	// Packet smaller than MinInitRcvSizeHdr + FooterDataSize
	smallPacket := make([]byte, minInitRcvSizeHdr-1)

	_, err := c.decode(smallPacket, initRcv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt InitRcv")
}

func TestConnDecode_InitCryptoRcv_TooSmall(t *testing.T) {
	c := createTestConn(true, true, false)

	// Packet smaller than MinInitCryptoRcvSizeHdr + FooterDataSize
	smallPacket := make([]byte, minInitCryptoRcvSizeHdr-1)

	_, err := c.decode(smallPacket, initCryptoRcv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt InitCryptoRcv")
}

func TestConnDecode_Data_TooSmall(t *testing.T) {
	c := createTestConn(true, false, true)

	// Packet smaller than MinDataSizeHdr + FooterDataSize
	smallPacket := make([]byte, minDataSizeHdr-1)

	_, err := c.decode(smallPacket, data)
	assert.Error(t, err)
}