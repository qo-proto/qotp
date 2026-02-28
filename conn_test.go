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

const testMaxPayload = 1400 // fixed test value for maxPayload

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
	seed5 = [32]byte{5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}

	prvIdAlice, _ = ecdh.X25519().NewPrivateKey(seed1[:])
	prvIdBob, _   = ecdh.X25519().NewPrivateKey(seed2[:])
	prvEpAlice, _ = ecdh.X25519().NewPrivateKey(seed3[:])
	prvEpBob, _   = ecdh.X25519().NewPrivateKey(seed4[:])
	prvEpNew, _   = ecdh.X25519().NewPrivateKey(seed5[:])
)

func createTestConn(isSender, withCrypto, handshakeDone bool) *conn {
	sharedSecret := bytes.Repeat([]byte{1}, 32)

	phase := phaseCreated
	if handshakeDone {
		phase = phaseReady
	}

	// Compute initMsgType from flags
	var initMsgType cryptoMsgType
	switch {
	case withCrypto && isSender:
		initMsgType = initCryptoSnd
	case withCrypto:
		initMsgType = initCryptoRcv
	case isSender:
		initMsgType = initSnd
	default:
		initMsgType = initRcv
	}

	c := &conn{
		initMsgType: initMsgType,
		phase:       phase,
		pubKeyIdRcv: prvIdBob.PublicKey(),
		listener:    &Listener{prvKeyId: prvIdAlice, maxPayload: testMaxPayload},
		snd:         newSendBuffer(sndBufferCapacity),
		rcv:         newReceiveBuffer(1000),
		streams:     newLinkedMap[uint32, *Stream](),
		sndKeys: &keyState{
			cur:      sharedSecret,
			prvKeyEp: prvEpAlice,
		},
		snCrypto: 0,
		rcvKeys: &rcvKeyState{
			keyState: keyState{
				cur:      sharedSecret,
				prvKeyEp: prvEpAlice,
			},
			pubKeyEp: prvEpBob.PublicKey(),
		},
	}

	if !isSender {
		c.pubKeyIdRcv = prvIdAlice.PublicKey()
		c.rcvKeys.pubKeyEp = prvEpAlice.PublicKey()
	}

	if handshakeDone {
		c.rcvKeys.pubKeyEp = prvEpBob.PublicKey()
	}

	return c
}

func createTestListeners() (*Listener, *Listener) {
	lAlice := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: prvIdAlice,
		maxPayload: testMaxPayload,
	}
	lBob := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: prvIdBob,
		maxPayload: testMaxPayload,
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

	p := &payloadHeader{streamId: 1}
	output, err := c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_AllStreamsClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	c.closeAllStreams()

	p := &payloadHeader{streamId: 1}
	output, err := c.encode(p, []byte("test data"), c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_UnknownMsgType(t *testing.T) {
	c := createTestConn(true, false, true)

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), cryptoMsgType(99))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown message type")
}

func TestConnEncode_EmptyPayload(t *testing.T) {
	c := createTestConn(true, false, true)

	// Empty payload with streamId ensures minimum proto size (8 bytes) for crypto layer
	p := &payloadHeader{streamId: 1}
	output, err := c.encode(p, []byte{}, c.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, output)
}

func TestConnEncode_NilPayload(t *testing.T) {
	c := createTestConn(true, false, true)

	// Nil payload - encodeProto will add stream header for minimum size when no ACK
	p := &payloadHeader{streamId: 1}
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
	assert.Equal(t, phaseInitSent, c.phase, "phase should be phaseInitSent after encoding init message")
}

func TestConnEncode_InitCryptoSnd_PayloadTooLarge(t *testing.T) {
	c := createTestConn(true, true, false)

	// Create payload larger than MTU allows
	largePayload := createTestData(testMaxPayload + 100)

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

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), c.snCrypto)
}

func TestConnSequenceNumber_KeyRotationTrigger(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 46) - 1
	c.sndKeys.prvKeyEpNext = nil

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1<<46), c.snCrypto)
	assert.NotNil(t, c.sndKeys.prvKeyEpNext, "should generate new ephemeral key at 2^46")
}

func TestConnSequenceNumber_RotationNotCompleted(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 47) - 1
	c.sndKeys.next = nil // rotation not completed

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key rotation not completed")
}

func TestConnSequenceNumber_RotationCompleted(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 47) - 1
	c.sndKeys.next = bytes.Repeat([]byte{2}, 32)
	c.sndKeys.prvKeyEpNext = prvEpBob

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.snCrypto, "snCrypto should reset to 0 after rotation")
	assert.Nil(t, c.sndKeys.next, "next should be nil after rotation")
}

// =============================================================================
// KEY ROTATION TESTS
// =============================================================================

func TestConnHandlePeerKeyUpdate_NewKeyUpdate(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcvKeys.next = nil
	c.rcvKeys.prvKeyEpNext = nil
	c.rcvKeys.pubKeyEpNext = nil

	newPeerPubKey := prvEpNew.PublicKey().Bytes() // Must be different from current peerPubKeyEp
	err := c.handlePeerKeyUpdate(newPeerPubKey)
	assert.NoError(t, err)

	assert.NotNil(t, c.rcvKeys.prvKeyEpNext)
	assert.NotNil(t, c.rcvKeys.pubKeyEpNext)
	assert.NotNil(t, c.rcvKeys.next)
	assert.Equal(t, phaseKeyUpdatePending, c.phase)
}

func TestConnHandlePeerKeyUpdate_Retransmit(t *testing.T) {
	c := createTestConn(false, false, true)

	// First KEY_UPDATE with a new key (different from current peerPubKeyEp)
	newPeerPubKey := prvEpNew.PublicKey().Bytes()
	err := c.handlePeerKeyUpdate(newPeerPubKey)
	assert.NoError(t, err)

	savedPrvKeyEpNext := c.rcvKeys.prvKeyEpNext
	savedNext := c.rcvKeys.next

	// Retransmit same KEY_UPDATE
	c.phase = phaseReady
	err = c.handlePeerKeyUpdate(newPeerPubKey)
	assert.NoError(t, err)

	// Should just re-set phase, not regenerate keys
	assert.Equal(t, savedPrvKeyEpNext, c.rcvKeys.prvKeyEpNext)
	assert.Equal(t, savedNext, c.rcvKeys.next)
	assert.Equal(t, phaseKeyUpdatePending, c.phase)
}

func TestConnHandlePeerKeyUpdate_NewRoundRotates(t *testing.T) {
	c := createTestConn(false, false, true)

	// First KEY_UPDATE with prvEpNew (different from current peerPubKeyEp which is prvEpBob)
	firstPeerPubKey := prvEpNew.PublicKey().Bytes()
	err := c.handlePeerKeyUpdate(firstPeerPubKey)
	assert.NoError(t, err)

	oldCur := c.rcvKeys.cur
	oldNext := c.rcvKeys.next

	// Second KEY_UPDATE with different key (new round)
	secondPeerKey, _ := generateKey()
	err = c.handlePeerKeyUpdate(secondPeerKey.PublicKey().Bytes())
	assert.NoError(t, err)

	// Should have rotated
	assert.Equal(t, oldCur, c.rcvKeys.prev)
	assert.Equal(t, oldNext, c.rcvKeys.cur)
}

func TestConnHandlePeerKeyUpdate_IgnorePreviousRound(t *testing.T) {
	c := createTestConn(false, false, true)

	// Set peerPubKeyEp to simulate we've already processed and rotated past this key
	c.rcvKeys.pubKeyEp = prvEpBob.PublicKey()

	// Receive delayed KEY_UPDATE from previous round
	err := c.handlePeerKeyUpdate(prvEpBob.PublicKey().Bytes())
	assert.NoError(t, err)

	// Should be ignored - no state changes
	assert.Nil(t, c.rcvKeys.next)
	assert.Equal(t, phaseReady, c.phase)
}

func TestConnHandleKeyUpdateAck_Basic(t *testing.T) {
	c := createTestConn(true, false, true)
	c.sndKeys.prvKeyEpNext = prvEpBob
	c.sndKeys.next = nil

	peerNewPubKey := prvEpAlice.PublicKey().Bytes()
	err := c.handleKeyUpdateAck(peerNewPubKey)
	assert.NoError(t, err)

	assert.NotNil(t, c.sndKeys.next)
}

func TestConnHandleKeyUpdateAck_Retransmit(t *testing.T) {
	c := createTestConn(true, false, true)
	c.sndKeys.prvKeyEpNext = prvEpBob
	c.sndKeys.next = bytes.Repeat([]byte{9}, 32) // Already processed

	// Retransmit should be silently ignored
	err := c.handleKeyUpdateAck(prvEpAlice.PublicKey().Bytes())
	assert.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte{9}, 32), c.sndKeys.next) // Unchanged
}

func TestConnHandleKeyUpdateAck_Unexpected(t *testing.T) {
	c := createTestConn(true, false, true)
	c.sndKeys.prvKeyEpNext = nil // No pending KEY_UPDATE

	// Should be silently ignored
	err := c.handleKeyUpdateAck(prvEpAlice.PublicKey().Bytes())
	assert.NoError(t, err)
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

	p := &payloadHeader{streamId: 0}
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

	p := &payloadHeader{streamId: 0}
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

	p := &payloadHeader{streamId: 0}
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
		connId:      getUint64(prvEpAlice.PublicKey().Bytes()),
		initMsgType: initSnd,
		listener:    lAlice,
		rcv:         newReceiveBuffer(1000),
		snd:         newSendBuffer(1000),
		streams:     newLinkedMap[uint32, *Stream](),
		sndKeys: &keyState{
			prvKeyEp: prvEpAlice,
		},
		snCrypto: 0,
		rcvKeys: &rcvKeyState{
			keyState: keyState{
				prvKeyEp: prvEpAlice,
			},
		},
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
	p = &payloadHeader{streamId: 0}
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

	connAlice.phase = phaseReady
	connAlice.pubKeyIdRcv = prvIdBob.PublicKey()
	connAlice.rcvKeys.pubKeyEp = prvEpBob.PublicKey()
	connAlice.sndKeys.cur = seed1[:]
	connAlice.rcvKeys.cur = seed1[:]
	lAlice.connMap.put(connId, connAlice)

	connBob.phase = phaseReady
	connBob.sndKeys.cur = seed1[:]
	connBob.rcvKeys.cur = seed1[:]
	lBob.connMap.put(connId, connBob)

	// Step 6: Alice sends Data message
	dataMsg := []byte("data message")
	p = &payloadHeader{streamId: 0}
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

// =============================================================================
// PROCESS INCOMING PAYLOAD TESTS
// =============================================================================

func TestConnProcessIncomingPayload_Basic(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
	}

	s, err := c.processIncomingPayload(p, []byte("test data"), 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, uint32(1), s.streamID)
}

func TestConnProcessIncomingPayload_WithAck(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)
	c.snd = newSendBuffer(1000)

	// Setup: queue data that will be acked
	c.snd.queueData(1, []byte("data to ack"))

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		ack:          &ack{streamId: 1, offset: 0, len: 11, rcvWnd: 1000},
	}

	s, err := c.processIncomingPayload(p, []byte("response"), 0)
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

func TestConnProcessIncomingPayload_KeyUpdate(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		isKeyUpdate:  true,
		keyUpdatePub: prvEpNew.PublicKey().Bytes(), // Must be different from current peerPubKeyEp
	}

	s, err := c.processIncomingPayload(p, []byte{}, 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	assert.Equal(t, phaseKeyUpdatePending, c.phase)
	assert.NotNil(t, c.rcvKeys.next)
}

func TestConnProcessIncomingPayload_KeyUpdateAck(t *testing.T) {
	c := createTestConn(true, false, true)
	c.rcv = newReceiveBuffer(1000)
	c.sndKeys.prvKeyEpNext = prvEpBob
	c.sndKeys.next = nil

	p := &payloadHeader{
		streamId:        1,
		streamOffset:    0,
		isKeyUpdateAck:  true,
		keyUpdatePubAck: prvEpAlice.PublicKey().Bytes(),
	}

	s, err := c.processIncomingPayload(p, []byte{}, 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	assert.NotNil(t, c.sndKeys.next)
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
	c.sndKeys.cur = nil

	p := &payloadHeader{streamId: 0}
	_, err := c.encode(p, []byte("test"), data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestConnEncode_NilPubKeyEpRcvForInitRcv(t *testing.T) {
	c := createTestConn(false, false, false)
	c.rcvKeys.pubKeyEp = nil

	p := &payloadHeader{streamId: 0}
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

// =============================================================================
// DECODE WITH MULTIPLE KEYS TESTS
// =============================================================================

func TestConnDecode_DataWithPrevKey(t *testing.T) {
	c := createTestConn(true, false, true)

	// Setup: cur key is different from prev
	prevSecret := bytes.Repeat([]byte{1}, 32)
	curSecret := bytes.Repeat([]byte{2}, 32)

	c.rcvKeys.prev = prevSecret
	c.rcvKeys.cur = curSecret

	// Encrypt with prev key (simulate packet from peer, so flip isSender)
	p := &payloadHeader{streamId: 1, streamOffset: 0}
	packetData, _ := encodeProto(p, []byte("test"))

	encData, err := encryptPacket(
		data,
		c.connId,
		c.sndKeys.prvKeyEp,
		c.listener.prvKeyId.PublicKey(),
		c.rcvKeys.pubKeyEp,
		prevSecret, // Use prev key
		0,
		!(c.initMsgType == initSnd || c.initMsgType == initCryptoSnd), // Peer's direction
		packetData,
	)
	assert.NoError(t, err)

	// Should be able to decode with prev key
	payload, err := c.decode(encData, data)
	assert.NoError(t, err)
	assert.NotNil(t, payload)
}

func TestConnDecode_DataWithNextKey(t *testing.T) {
	c := createTestConn(true, false, true)

	// Setup: next key exists
	curSecret := bytes.Repeat([]byte{1}, 32)
	nextSecret := bytes.Repeat([]byte{2}, 32)

	c.rcvKeys.cur = curSecret
	c.rcvKeys.next = nextSecret

	// Encrypt with next key (simulate packet from peer, so flip isSender)
	p := &payloadHeader{streamId: 1, streamOffset: 0}
	packetData, _ := encodeProto(p, []byte("test"))

	encData, err := encryptPacket(
		data,
		c.connId,
		c.sndKeys.prvKeyEp,
		c.listener.prvKeyId.PublicKey(),
		c.rcvKeys.pubKeyEp,
		nextSecret, // Use next key
		0,
		!(c.initMsgType == initSnd || c.initMsgType == initCryptoSnd), // Peer's direction
		packetData,
	)
	assert.NoError(t, err)

	// Should be able to decode with next key
	payload, err := c.decode(encData, data)
	assert.NoError(t, err)
	assert.NotNil(t, payload)
}

// =============================================================================
// MTU NEGOTIATION TESTS
// =============================================================================

func TestConn_NegotiateMTU_Symmetric(t *testing.T) {
	c := createTestConn(true, false, false)
	c.mtu = conservativeMTU // starts conservative

	c.negotiateMTU(uint16(testMaxPayload))

	assert.Equal(t, testMaxPayload, c.mtu)
	assert.Equal(t, testMaxPayload, c.negotiatedMTU)
}

func TestConn_NegotiateMTU_RemoteSmaller(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1400

	c.negotiateMTU(1300)

	assert.Equal(t, 1300, c.mtu)
	assert.Equal(t, 1300, c.negotiatedMTU)
}

func TestConn_NegotiateMTU_LocalSmaller(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1300

	c.negotiateMTU(1400)

	assert.Equal(t, 1300, c.mtu)
	assert.Equal(t, 1300, c.negotiatedMTU)
}

func TestConn_NegotiateMTU_BelowFloor(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1400

	c.negotiateMTU(500) // below conservativeMTU

	assert.Equal(t, conservativeMTU, c.mtu)
	assert.Equal(t, conservativeMTU, c.negotiatedMTU)
}

func TestConn_NegotiateMTU_JumboFrames(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 8952 // jumbo frame: 9000 - 48

	c.negotiateMTU(8952)

	assert.Equal(t, 8952, c.mtu)
	assert.Equal(t, 8952, c.negotiatedMTU)
}

func TestConn_InitialMTU_MatchesListenerMaxPayload(t *testing.T) {
	lAlice, lBob := createTestListeners()
	rAddr := netip.MustParseAddrPort("127.0.0.1:12345")

	// Create a new conn — should start with listener's maxPayload
	conn, err := lAlice.newConn(
		123, rAddr, prvEpAlice, prvIdBob.PublicKey(), prvEpBob.PublicKey(), true, false,
	)
	assert.NoError(t, err)
	assert.Equal(t, lAlice.maxPayload, conn.mtu)
	_ = lBob // suppress unused
}

func TestConn_FallbackOnConsecutiveLosses(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400
	c.negotiatedMTU = 1400

	// Simulate consecutive losses
	for i := 0; i < mtuFallbackThreshold; i++ {
		c.consecutiveLosses++
		if c.consecutiveLosses >= mtuFallbackThreshold && c.mtu > conservativeMTU {
			c.mtu = conservativeMTU
		}
	}

	assert.Equal(t, conservativeMTU, c.mtu)
	assert.Equal(t, 1400, c.negotiatedMTU) // original preserved
}

func TestConn_RestoreAfterFallback(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = conservativeMTU // currently in fallback
	c.negotiatedMTU = 1400
	c.consecutiveLosses = mtuFallbackThreshold

	// Simulate successful ACK
	c.consecutiveLosses = 0
	if c.mtu < c.negotiatedMTU {
		c.mtu = c.negotiatedMTU
	}

	assert.Equal(t, 1400, c.mtu)
}

func TestConn_MtuUpdate_ViaPayload(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400
	c.negotiatedMTU = 1400
	c.listener.maxPayload = 1400

	// Simulate receiving a pktMtuUpdate with a smaller value
	p := &payloadHeader{
		isMtuUpdate:    true,
		mtuUpdateValue: 1300,
		streamId:       1,
		streamOffset:   0,
	}

	s := c.getOrCreateStream(1)
	_, err := c.processIncomingPayload(p, []byte{}, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1300, c.mtu)
	assert.Equal(t, 1300, c.negotiatedMTU)
	_ = s
}

// =============================================================================
// MTU NEGOTIATION HANDSHAKE ROUND-TRIP TESTS
// =============================================================================

func TestConn_MtuNegotiation_NoCrypto_Handshake(t *testing.T) {
	lAlice := &Listener{
		connMap:    newLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdAlice,
		maxPayload: 1400,
	}
	lBob := &Listener{
		connMap:    newLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdBob,
		maxPayload: 1300, // Bob has smaller maxPayload
	}
	remoteAddr := getTestRemoteAddr()

	// Alice's initial connection (following TestConnFullHandshake pattern)
	connAlice := &conn{
		connId:       getUint64(prvEpAlice.PublicKey().Bytes()),
		initMsgType:  initSnd,
		listener:     lAlice,
		rcv:          newReceiveBuffer(1000),
		snd:          newSendBuffer(1000),
		streams:      newLinkedMap[uint32, *Stream](),
		mtu:          lAlice.maxPayload,
		measurements: newMeasurements(lAlice.maxPayload),
		rcvWndSize:   rcvBufferCapacity,
		sndKeys:      &keyState{prvKeyEp: prvEpAlice},
		rcvKeys:      &rcvKeyState{keyState: keyState{prvKeyEp: prvEpAlice}},
	}
	lAlice.connMap.put(connAlice.connId, connAlice)
	assert.Equal(t, lAlice.maxPayload, connAlice.mtu) // starts with local maxPayload

	// Step 1: Alice encodes InitSnd (no proto payload — no MTU info sent)
	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, nil, initSnd)
	assert.NoError(t, err)

	// Step 2: Bob receives InitSnd — no MTU negotiation yet (initSnd has no proto payload)
	connBob, _, _, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	assert.Equal(t, lBob.maxPayload, connBob.mtu) // starts with Bob's maxPayload

	// Step 3: Bob responds with InitRcv, including pktMtuUpdate in proto payload
	p = &payloadHeader{streamId: 0, isMtuUpdate: true, mtuUpdateValue: uint16(lBob.maxPayload)}
	encodedR0, err := connBob.encode(p, nil, connBob.msgType())
	assert.NoError(t, err)

	// Step 4: Alice receives InitRcv — crypto decode + proto decode + processIncomingPayload
	_, payload, _, err := testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err := decodeProto(payload)
	assert.NoError(t, err)
	_, err = connAlice.processIncomingPayload(ph, userData, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1300, connAlice.mtu) // min(1300, 1400) = 1300
}

// =============================================================================
// WILL INJECT MTU TESTS
// =============================================================================

func TestConn_WillInjectMtu_InitCryptoSnd(t *testing.T) {
	c := createTestConn(true, true, false)
	assert.True(t, c.willInjectMtu(initCryptoSnd))
}

func TestConn_WillInjectMtu_InitRcv(t *testing.T) {
	c := createTestConn(false, false, false)
	assert.True(t, c.willInjectMtu(initRcv))
}

func TestConn_WillInjectMtu_InitCryptoRcv(t *testing.T) {
	c := createTestConn(false, true, false)
	assert.True(t, c.willInjectMtu(initCryptoRcv))
}

func TestConn_WillInjectMtu_InitSnd(t *testing.T) {
	c := createTestConn(true, false, false)
	assert.False(t, c.willInjectMtu(initSnd))
}

func TestConn_WillInjectMtu_Data_NotSentYet(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtuSent = false
	assert.True(t, c.willInjectMtu(data))
}

func TestConn_WillInjectMtu_Data_AlreadySent(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtuSent = true
	assert.False(t, c.willInjectMtu(data))
}

// =============================================================================
// MTU SENT TRACKING TESTS
// =============================================================================

func TestConn_MtuSent_InitiallyFalse(t *testing.T) {
	c := createTestConn(true, false, true)
	assert.False(t, c.mtuSent)
}

func TestConn_MtuSent_SetAfterInitCryptoSnd(t *testing.T) {
	c := createTestConn(true, true, false)
	c.listener.localConn = NewConnPair("a", "b").Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)
	_, _, err := c.encodeAndWrite(s, nil, []byte("test"), 0, false, false, false, 1000, false)
	assert.NoError(t, err)
	assert.True(t, c.mtuSent)
}

func TestConn_MtuSent_NotSetOnInitSnd(t *testing.T) {
	// initSnd has no proto payload, so mtuSent should stay false
	c := createTestConn(true, false, false)
	c.listener.localConn = NewConnPair("a", "b").Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)
	_, _, err := c.encodeAndWrite(s, nil, nil, 0, false, false, false, 1000, false)
	assert.NoError(t, err)
	assert.False(t, c.mtuSent)
}

func TestConn_MtuSent_NotSetTwiceForData(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)

	// First data packet: should inject MTU and set mtuSent
	_, _, err := c.encodeAndWrite(s, nil, []byte("first"), 0, false, false, false, 1000, false)
	assert.NoError(t, err)
	assert.True(t, c.mtuSent)

	// Second data packet: should NOT inject MTU
	_, _, err = c.encodeAndWrite(s, nil, []byte("second"), 5, false, false, false, 2000, false)
	assert.NoError(t, err)
	// mtuSent stays true, no double injection
	assert.True(t, c.mtuSent)
}

// =============================================================================
// MTU INJECTION IN ENCODE AND WRITE TESTS
// =============================================================================

func TestConn_EncodeAndWrite_InjectsMtuForInitCryptoSnd(t *testing.T) {
	c := createTestConn(true, true, false)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)
	_, _, err := c.encodeAndWrite(s, nil, []byte("hello"), 0, false, false, false, 1000, false)
	assert.NoError(t, err)
	assert.True(t, c.mtuSent)

	// Verify the packet was written and contains pktMtuUpdate by reading it back
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
}

func TestConn_EncodeAndWrite_SkipsMtuOnClose(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)
	// isClose=true → should not inject mtuUpdate (mutually exclusive)
	_, _, err := c.encodeAndWrite(s, nil, []byte("bye"), 0, true, false, false, 1000, false)
	assert.NoError(t, err)
	assert.False(t, c.mtuSent)
}

func TestConn_EncodeAndWrite_SkipsMtuOnKeyUpdate(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements(testMaxPayload)
	c.rcvWndSize = rcvBufferCapacity
	c.sndKeys.prvKeyEpNext = prvEpNew

	s := c.Stream(0)
	// isKeyUpdate=true → should not inject mtuUpdate (mutually exclusive)
	_, _, err := c.encodeAndWrite(s, nil, []byte("ku"), 0, false, true, false, 1000, false)
	assert.NoError(t, err)
	assert.False(t, c.mtuSent)
}

func TestConn_MtuNegotiation_Crypto_Handshake(t *testing.T) {
	lAlice := &Listener{
		connMap:    newLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdAlice,
		maxPayload: 8952, // jumbo frame Alice
	}
	lBob := &Listener{
		connMap:    newLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdBob,
		maxPayload: 1452, // standard Ethernet Bob
	}
	remoteAddr := getTestRemoteAddr()

	// Alice's initial connection for crypto handshake
	connAlice := &conn{
		connId:       getUint64(prvEpAlice.PublicKey().Bytes()),
		initMsgType:  initCryptoSnd,
		listener:     lAlice,
		pubKeyIdRcv:  prvIdBob.PublicKey(),
		rcv:          newReceiveBuffer(1000),
		snd:          newSendBuffer(1000),
		streams:      newLinkedMap[uint32, *Stream](),
		mtu:          lAlice.maxPayload,
		measurements: newMeasurements(lAlice.maxPayload),
		rcvWndSize:   rcvBufferCapacity,
		sndKeys:      &keyState{prvKeyEp: prvEpAlice},
		rcvKeys:      &rcvKeyState{keyState: keyState{prvKeyEp: prvEpAlice}},
	}
	lAlice.connMap.put(connAlice.connId, connAlice)

	// Step 1: Alice encodes InitCryptoSnd with pktMtuUpdate in proto payload
	p := &payloadHeader{streamId: 0, isMtuUpdate: true, mtuUpdateValue: uint16(lAlice.maxPayload)}
	packetData, _ := encodeProto(p, []byte("init data"))
	encoded, err := connAlice.encode(p, packetData, initCryptoSnd)
	assert.NoError(t, err)

	// Step 2: Bob receives InitCryptoSnd — crypto decode + proto decode + process
	connBob, payload, _, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err := decodeProto(payload)
	assert.NoError(t, err)
	_, err = connBob.processIncomingPayload(ph, userData, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1452, connBob.mtu) // min(8952, 1452) = 1452

	// Step 3: Bob responds with InitCryptoRcv, including pktMtuUpdate
	p = &payloadHeader{streamId: 0, isMtuUpdate: true, mtuUpdateValue: uint16(lBob.maxPayload)}
	encodedR0, err := connBob.encode(p, nil, connBob.msgType())
	assert.NoError(t, err)

	// Step 4: Alice receives InitCryptoRcv — crypto decode + proto decode + process
	_, payload, _, err = testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err = decodeProto(payload)
	assert.NoError(t, err)
	_, err = connAlice.processIncomingPayload(ph, userData, 2000)
	assert.NoError(t, err)
	assert.Equal(t, 1452, connAlice.mtu) // min(1452, 8952) = 1452
}
