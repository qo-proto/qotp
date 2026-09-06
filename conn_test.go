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

	c, payload, _, err := decodePacket(l, encData, rAddr, msgType)
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
		streams:     newSharedLinkedMap[uint32, *Stream](),
		sndKeys: &keyState{
			secrets:  secrets{cur: sharedSecret},
			prvKeyEp: prvEpAlice,
		},
		snCrypto: 0,
		rcvKeys: &rcvKeyState{
			secrets:  secrets{cur: sharedSecret},
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
		connMap:    newSharedLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdAlice,
		maxPayload: testMaxPayload,
	}
	lBob := &Listener{
		connMap:    newSharedLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdBob,
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

func TestConnSequenceNumber_KeyRotationTrigger_PastThreshold(t *testing.T) {
	// A missed trigger (e.g. transient keygen failure at exactly 2^46) must
	// retry on later packets, not be skipped forever.
	c := createTestConn(true, false, true)
	c.snCrypto = (1 << 46) + 5
	c.sndKeys.prvKeyEpNext = nil

	p := &payloadHeader{streamId: 1}
	_, err := c.encode(p, []byte("test"), data)
	assert.NoError(t, err)
	assert.NotNil(t, c.sndKeys.prvKeyEpNext, "rotation initiation must self-heal past 2^46")
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
	assert.True(t, c.kuAckDue)
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
	assert.True(t, c.kuAckDue)
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
	lAlice.connMap.getOrPut(connId, connAlice)
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
		s, err := connBob.processIncomingPayload(p, u, 0, 0)
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
	lAlice.connMap.getOrPut(connId, connAlice)
	connAlice.connId = connId

	// max payload for InitCryptoSnd at conservativeMTU=1232
	// (1232 - 65 hdr - 22 footer - 2 fillLen - 11 proto = 1132)
	testData := createTestData(1132)

	p := &payloadHeader{streamId: 0}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)
	assert.NotNil(t, encoded)

	connBob, payload, _, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := connBob.processIncomingPayload(p, u, 0, 0)
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
	lAlice.connMap.getOrPut(connId, connAlice)
	connAlice.connId = connId

	testData := []byte{0xFF}

	p := &payloadHeader{streamId: 0}
	encoded, err := connAlice.encode(p, testData, connAlice.msgType())
	assert.NoError(t, err)

	connBob, payload, _, err := testDecodeConn(lBob, encoded, getTestRemoteAddr())
	assert.NoError(t, err)

	p, u, err := decodeProto(payload)
	assert.NoError(t, err)
	s, err := connBob.processIncomingPayload(p, u, 0, 0)
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
		streams:     newSharedLinkedMap[uint32, *Stream](),
		sndKeys: &keyState{
			prvKeyEp: prvEpAlice,
		},
		snCrypto: 0,
		rcvKeys:  &rcvKeyState{},
	}
	lAlice.connMap.getOrPut(connAlice.connId, connAlice)

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
	s, err := c.processIncomingPayload(p, u, 0, 0)
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
	lAlice.connMap.getOrPut(connId, connAlice)

	connBob.phase = phaseReady
	connBob.sndKeys.cur = seed1[:]
	connBob.rcvKeys.cur = seed1[:]
	lBob.connMap.getOrPut(connId, connBob)

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
	s, err = c.processIncomingPayload(p, u, 0, 0)
	assert.NoError(t, err)
	rb = s.conn.rcv.removeOldestInOrder(s.streamID)
	assert.Equal(t, dataMsg, rb)
}

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestConnDecode_UnknownMsgType(t *testing.T) {
	c := createTestConn(true, false, true)

	_, _, err := c.decode([]byte{}, cryptoMsgType(99))
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

	s, err := c.processIncomingPayload(p, []byte("test data"), 0, 0)
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
		ack:          &ack{streamId: 1, offset: 0, len: 11},
	}

	s, err := c.processIncomingPayload(p, []byte("response"), 0, 0)
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

	s, err := c.processIncomingPayload(p, []byte("late data"), 0, 0)
	assert.NoError(t, err)
	assert.Nil(t, s, "should return nil for finished stream")
}

func TestConnProcessIncomingPayload_KeyUpdate(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)

	p := &payloadHeader{
		streamId:     1,
		streamOffset: 0,
		keyUpdatePub: prvEpNew.PublicKey().Bytes(), // Must be different from current peerPubKeyEp
	}

	s, err := c.processIncomingPayload(p, []byte{}, 0, 0)
	assert.NoError(t, err)
	assert.NotNil(t, s)
	assert.True(t, c.kuAckDue)
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
		keyUpdatePubAck: prvEpAlice.PublicKey().Bytes(),
	}

	s, err := c.processIncomingPayload(p, []byte{}, 0, 0)
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
	s.rcvClosed.Store(true)
	s.sndClosed.Store(true)

	assert.False(t, c.HasActiveStreams())
}

func TestConnHasActiveStreams_PartiallyClosed(t *testing.T) {
	c := createTestConn(true, false, true)
	s := c.Stream(1)
	s.rcvClosed.Store(true)
	s.sndClosed.Store(false)

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

	_, _, err := c.decode(smallPacket, initRcv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt InitRcv")
}

func TestConnDecode_InitCryptoRcv_TooSmall(t *testing.T) {
	c := createTestConn(true, true, false)

	// Packet smaller than MinInitCryptoRcvSizeHdr + FooterDataSize
	smallPacket := make([]byte, minInitCryptoRcvSizeHdr-1)

	_, _, err := c.decode(smallPacket, initCryptoRcv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt InitCryptoRcv")
}

func TestConnDecode_Data_TooSmall(t *testing.T) {
	c := createTestConn(true, false, true)

	// Packet smaller than MinDataSizeHdr + FooterDataSize
	smallPacket := make([]byte, minDataSizeHdr-1)

	_, _, err := c.decode(smallPacket, data)
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
	packetData := encodeProto(p, []byte("test"))

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
	payload, _, err := c.decode(encData, data)
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
	packetData := encodeProto(p, []byte("test"))

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
	payload, _, err := c.decode(encData, data)
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
}

func TestConn_NegotiateMTU_RemoteSmaller(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1400

	c.negotiateMTU(1300)

	assert.Equal(t, 1300, c.mtu)
}

func TestConn_NegotiateMTU_LocalSmaller(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1300

	c.negotiateMTU(1400)

	assert.Equal(t, 1300, c.mtu)
}

func TestConn_NegotiateMTU_BelowFloor(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 1400

	c.negotiateMTU(500) // below conservativeMTU

	assert.Equal(t, conservativeMTU, c.mtu)
}

func TestConn_NegotiateMTU_JumboFrames(t *testing.T) {
	c := createTestConn(true, false, false)
	c.listener.maxPayload = 8952 // jumbo frame: 9000 - 48

	c.negotiateMTU(8952)

	assert.Equal(t, 8952, c.mtu)
}

func TestConn_InitialMTU_StartsAtConservativeMTU(t *testing.T) {
	lAlice, lBob := createTestListeners()
	rAddr := netip.MustParseAddrPort("127.0.0.1:12345")

	// New conn starts at conservativeMTU; negotiateMTU upgrades it after handshake
	conn, err := lAlice.newConn(
		123, rAddr, prvEpAlice, prvIdBob.PublicKey(), prvEpBob.PublicKey(), true, false,
	)
	assert.NoError(t, err)
	assert.Equal(t, conservativeMTU, conn.mtu)
	_ = lBob // suppress unused
}

// Ordinary congestion loss must not move the MTU. Inferring an MTU problem
// from loss made it oscillate many times a second on a lossy path.
func TestConn_MTU_LossAloneDoesNotLowerIt(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400

	// A full-size packet gets through: that is what confirms the path.
	c.observeMTU(&sendPacket{wireLen: 1400, sentCount: 0})
	assert.Equal(t, 1400, c.mtuConfirmed)
	assert.Equal(t, 1400, c.mtu)

	// Retransmits that still carry the working size say nothing about the MTU,
	// however many there are.
	for i := uint(1); i < maxRetry; i++ {
		c.observeMTU(&sendPacket{wireLen: 1400, sentCount: i})
	}
	assert.Equal(t, 1400, c.mtu, "loss at the working size must not downgrade")
	assert.False(t, c.mtuDowngraded)
}

// A packet that only got through once shrunk, on a size never seen to work,
// is what an MTU black hole looks like, and is the one thing that lowers it.
func TestConn_MTU_DowngradesWhenOnlySmallGetsThrough(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400 // raised on the peer's word, unconfirmed

	c.observeMTU(&sendPacket{wireLen: conservativeMTU, sentCount: maxRetry - mtuProbeLastAttempts})

	assert.Equal(t, conservativeMTU, c.mtu)
	assert.True(t, c.mtuDowngraded)
}

// Once the working size is confirmed, a probe succeeding is just loss. Without
// this a burst of losses on one packet downgrades a path already proven to
// carry the larger size — seen on a 2% loss link with no MTU problem at all.
func TestConn_MTU_ConfirmedSizeSurvivesProbeSuccess(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400
	c.observeMTU(&sendPacket{wireLen: 1400, sentCount: 0}) // proven to work

	c.observeMTU(&sendPacket{wireLen: conservativeMTU, sentCount: maxRetry - mtuProbeLastAttempts})

	assert.Equal(t, 1400, c.mtu, "a confirmed size must survive loss")
	assert.False(t, c.mtuDowngraded)
}

// The downgrade lasts for the life of the connection: the peer re-advertising
// its interface MTU on every packet says nothing about the path in between.
func TestConn_MTU_DowngradeIsSticky(t *testing.T) {
	c := createTestConn(true, false, true)
	c.listener.maxPayload = 1400
	c.mtu = 1400
	c.observeMTU(&sendPacket{wireLen: conservativeMTU, sentCount: maxRetry - mtuProbeLastAttempts})
	assert.True(t, c.mtuDowngraded)

	for i := 0; i < 10; i++ {
		c.negotiateMTU(1400)
	}
	assert.Equal(t, conservativeMTU, c.mtu, "advertisements must not undo a downgrade")
}

func TestConn_MtuUpdate_ViaPayload(t *testing.T) {
	c := createTestConn(true, false, true)
	c.mtu = 1400
	c.listener.maxPayload = 1400

	// Simulate receiving a the MTU update field with a smaller value
	p := &payloadHeader{
		maxPayload:   1300,
		streamId:     1,
		streamOffset: 0,
	}

	s := c.getOrCreateStream(1)
	_, err := c.processIncomingPayload(p, []byte{}, 0, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1300, c.mtu)
	_ = s
}

// =============================================================================
// MTU NEGOTIATION HANDSHAKE ROUND-TRIP TESTS
// =============================================================================

func TestConn_MtuNegotiation_NoCrypto_Handshake(t *testing.T) {
	lAlice := &Listener{
		connMap:    newSharedLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdAlice,
		maxPayload: 1400,
	}
	lBob := &Listener{
		connMap:    newSharedLinkedMap[uint64, *conn](),
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
		streams:      newSharedLinkedMap[uint32, *Stream](),
		mtu:          conservativeMTU,
		measurements: newMeasurements(),
		rcvWndSize:   rcvBufferCapacity,
		sndKeys:      &keyState{prvKeyEp: prvEpAlice},
		rcvKeys:      &rcvKeyState{},
	}
	lAlice.connMap.getOrPut(connAlice.connId, connAlice)
	assert.Equal(t, conservativeMTU, connAlice.mtu) // starts at conservativeMTU; negotiateMTU upgrades it

	// Step 1: Alice encodes InitSnd — embeds localMaxPayload=1400 in fixed header
	p := &payloadHeader{}
	encoded, err := connAlice.encode(p, nil, initSnd)
	assert.NoError(t, err)

	// Step 2: Bob receives InitSnd — negotiates MTU immediately from embedded sender maxPayload
	// min(Bob=1300, Alice=1400) = 1300
	connBob, _, _, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	assert.Equal(t, lBob.maxPayload, connBob.mtu) // min(1300, 1400) = 1300 = Bob's maxPayload

	// Step 3: Bob responds with InitRcv, including the MTU update field in proto payload
	p = &payloadHeader{streamId: 0, maxPayload: uint16(lBob.maxPayload)}
	encodedR0, err := connBob.encode(p, nil, connBob.msgType())
	assert.NoError(t, err)

	// Step 4: Alice receives InitRcv — crypto decode + proto decode + processIncomingPayload
	_, payload, _, err := testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err := decodeProto(payload)
	assert.NoError(t, err)
	_, err = connAlice.processIncomingPayload(ph, userData, 0, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1300, connAlice.mtu) // min(1300, 1400) = 1300
}

// =============================================================================
// WILL INJECT MTU TESTS
// =============================================================================
// maxPayload rides every packet now, including the kinds the old flag-based
// scheme deliberately skipped (close, key update) and ACK-only packets, which
// previously could not carry it at all.
func TestConn_MaxPayload_OnEveryPacketKind(t *testing.T) {
	pub := make([]byte, pubKeySize)
	cases := map[string]*payloadHeader{
		"data":      {streamId: 1, streamOffset: 5, maxPayload: 1400},
		"close":     {streamId: 1, isClose: true, maxPayload: 1400},
		"keyUpdate": {streamId: 1, keyUpdatePub: pub, maxPayload: 1400},
		"kuAck":     {streamId: 1, keyUpdatePubAck: pub, maxPayload: 1400},
		"ackOnly":   {ack: &ack{streamId: 1, offset: 2, len: 3}, maxPayload: 1400},
	}
	for name, p := range cases {
		enc := encodeProto(p, nil)
		got, _, err := decodeProto(enc)
		assert.NoError(t, err, name)
		assert.Equal(t, uint16(1400), got.maxPayload, name)
	}

	// An ACK-only packet must stay ACK-only: maxPayload no longer drags a
	// stream header along with it.
	enc := encodeProto(cases["ackOnly"], nil)
	assert.True(t, enc[0]&flagHasStream == 0, "ACK-only packet must not carry a stream header")
}

// A local interface change now reaches the peer, because every packet carries
// the current value instead of a once-only announcement.
func TestConn_MaxPayload_ChangePropagates(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity

	s := c.Stream(0)
	_, _, err := c.encodeAndWrite(s, nil, []byte("one"), 0, false, 1000, false)
	assert.NoError(t, err)

	// Interface changes (RefreshMaxPayload updates the listener) — the very
	// next packet advertises the new value; there is no latch to reset.
	c.listener.maxPayload = 1300
	_, _, err = c.encodeAndWrite(s, nil, []byte("two"), 3, false, 2000, false)
	assert.NoError(t, err)
	assert.Equal(t, 2, connPair.nrOutgoingPacketsSender())
}

func TestConn_ProcessIncomingPayload_AckOnlyNoPhantomStream(t *testing.T) {
	c := createTestConn(true, false, true)
	c.rcvWndSize = rcvBufferCapacity

	// Send something so the ACK references a real send stream (7)
	s := c.getOrCreateStream(7)
	c.snd.queueData(7, []byte("data"))
	c.snd.readyToSend(7, data, nil, 1000, true)
	c.snd.markSent(7, 0, 4, 44, 1_000_000_000, 0, 0, 0)

	// An ACK-only packet: no stream header, so streamId defaults to 0
	p := &payloadHeader{ack: &ack{streamId: 7, offset: 0, len: 4}}
	got, err := c.processIncomingPayload(p, nil, 0, 2_000_000_000)
	assert.NoError(t, err)
	assert.Nil(t, got, "ack-only packet returns no stream")

	// Stream 0 must not have been conjured into existence
	_, exists := c.streams.get(0)
	assert.False(t, exists, "ack-only packet must not create a phantom stream 0")
	_ = s
}

func TestConn_MtuNegotiation_Crypto_Handshake(t *testing.T) {
	lAlice := &Listener{
		connMap:    newSharedLinkedMap[uint64, *conn](),
		prvKeyId:   prvIdAlice,
		maxPayload: 8952, // jumbo frame Alice
	}
	lBob := &Listener{
		connMap:    newSharedLinkedMap[uint64, *conn](),
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
		streams:      newSharedLinkedMap[uint32, *Stream](),
		mtu:          conservativeMTU,
		measurements: newMeasurements(),
		rcvWndSize:   rcvBufferCapacity,
		sndKeys:      &keyState{prvKeyEp: prvEpAlice},
		rcvKeys:      &rcvKeyState{},
	}
	lAlice.connMap.getOrPut(connAlice.connId, connAlice)

	// Step 1: Alice encodes InitCryptoSnd with the MTU update field in proto payload
	p := &payloadHeader{streamId: 0, maxPayload: uint16(lAlice.maxPayload)}
	packetData := encodeProto(p, []byte("init data"))
	encoded, err := connAlice.encode(p, packetData, initCryptoSnd)
	assert.NoError(t, err)

	// Step 2: Bob receives InitCryptoSnd — crypto decode + proto decode + process
	connBob, payload, _, err := testDecodeConn(lBob, encoded, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err := decodeProto(payload)
	assert.NoError(t, err)
	_, err = connBob.processIncomingPayload(ph, userData, 0, 1000)
	assert.NoError(t, err)
	assert.Equal(t, 1452, connBob.mtu) // min(8952, 1452) = 1452

	// Step 3: Bob responds with InitCryptoRcv, including the MTU update field
	p = &payloadHeader{streamId: 0, maxPayload: uint16(lBob.maxPayload)}
	encodedR0, err := connBob.encode(p, nil, connBob.msgType())
	assert.NoError(t, err)

	// Step 4: Alice receives InitCryptoRcv — crypto decode + proto decode + process
	_, payload, _, err = testDecodeConn(lAlice, encodedR0, remoteAddr)
	assert.NoError(t, err)
	ph, userData, err = decodeProto(payload)
	assert.NoError(t, err)
	_, err = connAlice.processIncomingPayload(ph, userData, 0, 2000)
	assert.NoError(t, err)
	assert.Equal(t, 1452, connAlice.mtu) // min(1452, 8952) = 1452
}

// =============================================================================
// RETRANSMISSION BYPASSES RWND
// =============================================================================

// TestConn_FlushStream_RetransmitBypassesRwnd verifies that retransmissions
// are sent even when the receive window is zero. This prevents a deadlock where
// a lost packet creates a gap in the receiver's reassembly buffer, the receiver's
// buffer fills with out-of-order data (rwnd→0), and the sender can never
// retransmit the missing packet because it's blocked by rwnd.
func TestConn_FlushStream_RetransmitBypassesRwnd(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c := createTestConn(true, false, true)
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()

	// Simulate rwnd-blocked: receiver has zero window
	c.rcvWndSize = 0
	c.dataInFlight = testMaxPayload // exceeds rcvWndSize → isBlockedByRwnd=true

	s := c.Stream(0)

	// Queue some data first to create the stream entry in the send buffer,
	// then manually inject an in-flight packet with expired RTO to simulate
	// a packet that was sent long ago and never ACKed (lost on the wire).
	c.snd.queueData(s.streamID, []byte("new-data-blocked"))

	retransmitData := []byte("lost-packet-data")
	pktKey := createPacketKey(0, uint16(len(retransmitData)))
	c.snd.mu.Lock()
	c.snd.streams[s.streamID].inFlight[0].put(pktKey, &sendPacket{
		data:         retransmitData,
		sentTimeNano: 0, // sent at time 0
		sentCount:    0,
		needsReTx:    true,
	})
	c.snd.mu.Unlock()

	// Call flushStream at a time well past the RTO (200ms+)
	nowNano := uint64(500 * msNano)
	dataSent, _, err := c.flushStream(s, nowNano)
	assert.NoError(t, err)
	assert.Greater(t, dataSent, 0, "retransmit should succeed despite rwnd=0")
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender(), "one packet should be written")

	// Drain the retransmitted packet
	connPair.dropSender(0)

	// Now flushStream again — no more retransmits pending, new data blocked by rwnd
	dataSent, _, err = c.flushStream(s, nowNano)
	assert.NoError(t, err)
	assert.Equal(t, 0, dataSent, "new data should be blocked by rwnd=0")
}

// TestConn_FlushStream_NewDataBlockedByRwnd verifies that new data (non-retransmit)
// is still properly blocked when the receive window is zero. Going silent is
// not the right response though: the window arrives only in an ACK, so the
// sender probes for one (see TestConn_FlushStream_RwndBlocked_ProbesForWindowUpdate).
func TestConn_FlushStream_NewDataBlockedByRwnd(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c := createTestConn(true, false, true)
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()

	// Simulate rwnd-blocked
	c.rcvWndSize = 0
	c.dataInFlight = testMaxPayload

	s := c.Stream(0)

	// Queue only new data (no in-flight retransmits)
	c.snd.queueData(s.streamID, []byte("should-not-send"))

	nowNano := uint64(500 * msNano)
	dataSent, _, err := c.flushStream(s, nowNano)
	assert.NoError(t, err)
	assert.Equal(t, 0, dataSent, "new data must be blocked by rwnd=0")
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender(), "only a window probe, carrying no data")
}

// =============================================================================
// FLUSHSTREAM KEY UPDATE TESTS (state-driven KU send and RTO-paced resend)
// =============================================================================

func newKuTestConn(connPair *ConnPair) (*conn, *Stream) {
	c := createTestConn(true, false, true)
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity

	// Rotation pending: initiated but not yet acked
	c.sndKeys.prvKeyEpNext = prvEpNew
	return c, c.Stream(0)
}

func TestConn_FlushStream_KeyUpdate_IdleResendRTOPaced(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newKuTestConn(connPair)

	// First flush: idle connection, pending KU → KU-only packet goes out
	_, _, err := c.flushStream(s, uint64(1*secondNano))
	assert.NoError(t, err)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	assert.Equal(t, uint64(1*secondNano), c.kuLastSentNano, "KU send must be stamped")

	// Within RTO (default 200ms): no resend
	_, _, err = c.flushStream(s, uint64(1*secondNano+50*msNano))
	assert.NoError(t, err)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender(), "within RTO: no KU resend")

	// Past RTO: resend
	_, _, err = c.flushStream(s, uint64(1*secondNano+250*msNano))
	assert.NoError(t, err)
	assert.Equal(t, 2, connPair.nrOutgoingPacketsSender(), "past RTO: KU resent")
}

func TestConn_FlushStream_KeyUpdate_RetryExceeded(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newKuTestConn(connPair)

	// Initial send + maxRetry re-sends, each one RTO apart
	now := uint64(1 * secondNano)
	for i := 0; i < int(maxRetry)+1; i++ {
		_, _, err := c.flushStream(s, now)
		assert.NoError(t, err)
		now += 300 * msNano // beyond RTO each round
	}

	_, _, err := c.flushStream(s, now)
	assert.Error(t, err, "key update must give up after maxRetry unanswered re-sends")
	assert.Contains(t, err.Error(), "key update")
}

func TestConn_FlushStream_KeyUpdate_AttachedOncePerRTO(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newKuTestConn(connPair)

	// First data packet carries the KU
	c.snd.queueData(s.streamID, []byte("hello"))
	_, _, err := c.flushStream(s, uint64(1*secondNano))
	assert.NoError(t, err)
	assert.Equal(t, uint64(1*secondNano), c.kuLastSentNano)

	// Second data packet within the RTO must NOT carry it again
	// (kuLastSentNano is only stamped when the KU is actually attached)
	c.snd.queueData(s.streamID, []byte("hello"))
	_, _, err = c.flushStream(s, uint64(1*secondNano+50*msNano))
	assert.NoError(t, err)
	assert.Equal(t, 2, connPair.nrOutgoingPacketsSender())
	assert.Equal(t, uint64(1*secondNano), c.kuLastSentNano, "KU must not re-attach within RTO")
}

// =============================================================================
// KARN'S ALGORITHM TESTS (no RTT/bw samples from retransmitted packets)
// =============================================================================

func TestConn_Karn_NoMeasurementFromRetransmit(t *testing.T) {
	c := createTestConn(true, false, true)
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity

	// A packet that was sent, then retransmitted
	c.snd.queueData(0, []byte("test"))
	c.snd.readyToSend(0, data, nil, 1000, true)
	c.snd.markSent(0, 0, 4, 44, 1_000_000_000, 0, 0, 0)
	c.snd.readyToRetransmit(0, nil, 1000, 1000, 50, data, 2_000_000_000)

	// Its ACK is ambiguous (original or retransmit?) - must not be measured
	p := &payloadHeader{ack: &ack{streamId: 0, offset: 0, len: 4}}
	_, err := c.processIncomingPayload(p, nil, 0, 3_000_000_000)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.srtt, "no RTT sample from retransmitted packet")
}

func TestConn_Karn_MeasurementFromFreshPacket(t *testing.T) {
	c := createTestConn(true, false, true)
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity

	// A packet sent exactly once
	c.snd.queueData(0, []byte("test"))
	c.snd.readyToSend(0, data, nil, 1000, true)
	c.snd.markSent(0, 0, 4, 44, 1_000_000_000, 0, 0, 0)

	p := &payloadHeader{ack: &ack{streamId: 0, offset: 0, len: 4}}
	_, err := c.processIncomingPayload(p, nil, 0, 1_100_000_000)
	assert.NoError(t, err)
	assert.Equal(t, uint64(100_000_000), c.srtt, "fresh packet yields an RTT sample")
}

// =============================================================================
// FLUSHSTREAM HANDSHAKE RESEND TESTS (untracked init packets, ~5s give-up)
// =============================================================================

func newInitTestConn(connPair *ConnPair) (*conn, *Stream) {
	c := createTestConn(true, false, false) // phaseCreated, initSnd
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity
	return c, c.Stream(0)
}

func TestConn_FlushStream_InitResend_RTOPaced(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newInitTestConn(connPair)

	// First flush sends the init and moves to phaseInitSent
	_, _, err := c.flushStream(s, uint64(1*secondNano))
	assert.NoError(t, err)
	assert.Equal(t, phaseInitSent, c.phase)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	assert.Equal(t, uint64(1*secondNano), c.initLastSentNano)

	// Within RTO: no re-send
	_, _, err = c.flushStream(s, uint64(1*secondNano+50*msNano))
	assert.NoError(t, err)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender(), "within RTO: no init re-send")

	// Past RTO: re-send
	_, _, err = c.flushStream(s, uint64(1*secondNano+250*msNano))
	assert.NoError(t, err)
	assert.Equal(t, 2, connPair.nrOutgoingPacketsSender(), "past RTO: init re-sent")
}

func TestConn_FlushStream_InitResend_GiveUp(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newInitTestConn(connPair)

	now := uint64(1 * secondNano)
	_, _, err := c.flushStream(s, now) // initial send
	assert.NoError(t, err)

	// maxRetry re-sends with doubling backoff (200ms..2s cap), then error
	for i := 0; i < int(maxRetry); i++ {
		now += 2500 * msNano // beyond the max backoff step
		_, _, err = c.flushStream(s, now)
		assert.NoError(t, err)
	}
	assert.Equal(t, int(maxRetry)+1, connPair.nrOutgoingPacketsSender())

	now += 2500 * msNano
	_, _, err = c.flushStream(s, now)
	assert.Error(t, err, "handshake must give up after maxRetry re-sends")
}

func TestConn_FlushStream_KeyUpdate_CompletedStopsSending(t *testing.T) {
	connPair := NewConnPair("a", "b")
	c, s := newKuTestConn(connPair)

	_, _, err := c.flushStream(s, uint64(1*secondNano))
	assert.NoError(t, err)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())

	// KUAck processed: next secret established, so nothing left to announce
	c.sndKeys.next = bytes.Repeat([]byte{7}, 32)

	_, _, err = c.flushStream(s, uint64(2*secondNano))
	assert.NoError(t, err)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender(), "completed rotation must stop KU sends")
}

// The high bit of the wire streamId carries reliability, so it cannot also be
// an identifier — an id that would collide is refused rather than silently
// aliasing onto another stream.
func TestConn_GetOrCreateStream_RejectsReservedStreamID(t *testing.T) {
	c := createTestConn(true, false, true)

	assert.NotNil(t, c.getOrCreateStream(maxStreamID), "the whole usable range is available")
	assert.NotNil(t, c.getOrCreateStream(0))
	assert.Nil(t, c.getOrCreateStream(streamUnreliableBit), "reserved bit set")
	assert.Nil(t, c.getOrCreateStream(0xFFFFFFFF), "reserved bit set")
}

// Under the old scheme the FIN of a best-effort stream advertised "reliable"
// (needsReTx was OR'd with isClose), so a stream whose only packet was a FIN
// left the receiver unmarked. Now the FIN carries the stream's own property.
func TestUnreliableMarkerOnCloseOnlyStream(t *testing.T) {
	c := createTestConn(true, false, true)
	s := c.Stream(3)
	s.SetReliable(false)

	p := &payloadHeader{streamId: 3, streamOffset: 0, isClose: true, unreliable: !s.reliable}
	_, err := c.processIncomingPayload(p, []byte{}, 0, 1000)
	assert.NoError(t, err)

	c.rcv.mu.Lock()
	marked := c.rcv.streams[3] != nil && c.rcv.streams[3].unreliable
	c.rcv.mu.Unlock()
	assert.True(t, marked, "a FIN-only best-effort stream must still be marked")
}

// Packets that bypass the pacing gate (ACKs) must not push nextWriteTime
// arbitrarily far out. Before the cap, acknowledging a bulk transfer ran the
// receiver's next send seconds into the future and stalled its own data.
func TestConn_PacingDebtIsBounded(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity
	s := c.Stream(0)

	nowNano := uint64(1000)
	for i := 0; i < 2000; i++ {
		a := &ack{streamId: 0, offset: uint64(i), len: 1}
		_, _, err := c.sendControlPacket(s, a, nowNano)
		assert.NoError(t, err)
	}

	debt := c.nextWriteTime - nowNano
	limit := maxBurstPackets * c.calcPacing(uint64(c.mtu))
	assert.LessOrEqual(t, debt, limit,
		"2000 bypassing ACKs pushed nextWriteTime %dms into the future", debt/uint64(msNano))
	assert.Less(t, debt, uint64(secondNano), "debt must not reach seconds")
}

// A receiver-only connection gets no RTT sample on its own, because nothing it
// sends is ever ACKed. The first control packet carries a stream header and is
// tracked so the peer's ACK for it becomes that sample.
func TestConn_AckProbe_YieldsRttSample(t *testing.T) {
	c := createTestConn(true, false, true)
	connPair := NewConnPair("a", "b")
	c.listener.localConn = connPair.Conn1
	c.remoteAddr = getTestRemoteAddr()
	c.mtu = testMaxPayload
	c.measurements = newMeasurements()
	c.rcvWndSize = rcvBufferCapacity
	s := c.Stream(0)

	assert.Equal(t, uint64(0), c.srtt, "receiver-only: no sample yet")
	_, _, err := c.sendControlPacket(s, &ack{streamId: 0, offset: 0, len: 1}, 1000)
	assert.NoError(t, err)

	// The probe is tracked, so the peer's ACK for it can be matched.
	c.snd.mu.Lock()
	_, tracked := c.snd.streams[0].inFlightGet(createPacketKey(0, 0))
	c.snd.mu.Unlock()
	assert.True(t, tracked, "probe must be recorded in flight")

	// Peer ACKs the probe: that is the RTT sample.
	_, err = c.processIncomingPayload(&payloadHeader{ack: &ack{streamId: 0, offset: 0, len: 0}}, nil, 0, 1000+5*uint64(msNano))
	assert.NoError(t, err)
	assert.Positive(t, c.srtt, "the probe's ACK must produce an RTT sample")

	// Once a sample exists the probe stops: no more stream headers on ACKs.
	c.snd.mu.Lock()
	c.snd.streams[0].inFlight[0].remove(createPacketKey(0, 0))
	c.snd.mu.Unlock()
	_, _, err = c.sendControlPacket(s, &ack{streamId: 0, offset: 1, len: 1}, 2000)
	assert.NoError(t, err)
	c.snd.mu.Lock()
	_, again := c.snd.streams[0].inFlightGet(createPacketKey(0, 0))
	c.snd.mu.Unlock()
	assert.False(t, again, "probe must not repeat once srtt is known")
}

// packetKey is offset+length, so every zero-payload packet at one offset shares
// a key. A pending FIN or ping owns it; the probe must stand down for both, or
// their ACKs get misattributed to each other.
func TestConn_AckProbe_StandsDownOnKeyCollision(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(c *conn)
	}{
		{"close pending", func(c *conn) { c.snd.close(0) }},
		{"ping pending", func(c *conn) { c.snd.queuePing(0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := createTestConn(true, false, true)
			connPair := NewConnPair("a", "b")
			c.listener.localConn = connPair.Conn1
			c.remoteAddr = getTestRemoteAddr()
			c.mtu = testMaxPayload
			c.measurements = newMeasurements()
			c.rcvWndSize = rcvBufferCapacity
			s := c.Stream(0)
			tc.setup(c)

			assert.False(t, c.snd.trackProbe(0), "probe must not claim an occupied key")
			_, _, err := c.sendControlPacket(s, &ack{streamId: 0, offset: 0, len: 1}, 1000)
			assert.NoError(t, err)
		})
	}
}

// Only one probe may be outstanding, for the same key-collision reason.
func TestConn_AckProbe_OnlyOneOutstanding(t *testing.T) {
	c := createTestConn(true, false, true)
	assert.True(t, c.snd.trackProbe(0), "first probe is recorded")
	assert.False(t, c.snd.trackProbe(0), "second probe must not overwrite the first")
}

// =============================================================================
// RECEIVE-WINDOW PROBE
// =============================================================================

// countingConn records how many datagrams were written.
type countingConn struct {
	writes int
}

func (w *countingConn) ReadFromUDPAddrPort([]byte, uint64, uint64) (int, netip.AddrPort, netip.Addr, uint64, error) {
	return 0, netip.AddrPort{}, netip.Addr{}, 0, nil
}

func (w *countingConn) WriteToUDPAddrPort(b []byte, _ netip.AddrPort, _ netip.Addr, _ uint64) (uint64, error) {
	w.writes++
	return 0, nil
}
func (w *countingConn) TimeoutReadNow() error   { return nil }
func (w *countingConn) Close() error            { return nil }
func (w *countingConn) LocalAddrString() string { return "counting" }

// A sender blocked on the receive window has nothing to send, so the peer has
// nothing to acknowledge, so no ACK arrives -- and the window is only ever
// learned from an ACK. Without a probe the connection is deadlocked until some
// unrelated packet times out. Measured on a real path: 200ms with sent=0,
// acksIn=0 and pacing idle, escaped only by a third-generation retransmit.
func TestConn_FlushStream_RwndBlocked_ProbesForWindowUpdate(t *testing.T) {
	c := createTestConn(true, false, true)
	w := &countingConn{}
	c.listener.localConn = w
	s := c.getOrCreateStream(1)

	c.snd.queueData(1, make([]byte, 64*1024)) // plenty to send
	c.srtt, c.rttvar = 100*msNano, msNano     // established RTT, not cold start
	c.rcvWndSize = 1000                       // peer's buffer is nearly full
	c.dataInFlight = 5000                     // + mtu exceeds it: blocked

	// Nothing is in flight to time out, so a retransmit cannot rescue this.
	assert.False(t, c.snd.hasInFlight(s.streamID))

	nowNano := uint64(10 * secondNano)
	for range 10 {
		nowNano += c.rtoNano()
		n, _, err := c.flushStream(s, nowNano)
		assert.NoError(t, err)
		assert.Equal(t, 0, n, "a window probe carries no payload")
	}

	assert.Greater(t, w.writes, 0,
		"blocked on the receive window: the peer is never asked for an update")
	assert.LessOrEqual(t, w.writes, 10, "probe should be rate-limited to about one per RTO")
}

// The probe only works if the peer answers it. A control packet with no ACK of
// our own carries a stream header, and a stream header with no data is
// acknowledged like any other packet -- that ACK is what reopens the window.
func TestConn_RwndProbe_IsAcknowledgedByPeer(t *testing.T) {
	enc := encodeProto(&payloadHeader{maxPayload: 1452, streamId: 7}, nil)
	ph, userData, err := decodeProto(enc)
	assert.NoError(t, err)
	assert.NotNil(t, userData, "probe must carry a stream header")
	assert.Empty(t, userData)

	peer := createTestConn(false, false, true)
	peer.rcv = newReceiveBuffer(1000)
	_, err = peer.processIncomingPayload(ph, userData, 0, 1)
	assert.NoError(t, err)
	assert.True(t, peer.rcv.hasPendingAcks(), "peer must acknowledge the probe")

	// And that ACK carries the window, which is what the sender was missing.
	queued := peer.rcv.getSndAck()
	assert.NotNil(t, queued)
	assert.Equal(t, uint32(7), queued.streamId)

	// An ACK-only packet, by contrast, is not acknowledged back -- which is why
	// a blocked uploader cannot rely on one to learn the window.
	encAck := encodeProto(&payloadHeader{maxPayload: 1452, ack: &ack{streamId: 7}}, nil)
	phAck, dataAck, err := decodeProto(encAck)
	assert.NoError(t, err)
	assert.Nil(t, dataAck, "ack-only packet carries no stream header")
	assert.NotNil(t, phAck.ack)
}

// The window rides the fixed header, so any packet updates it -- a peer that
// drained its buffer does not need something to acknowledge in order to say so.
func TestConn_RcvWnd_TravelsOnEveryPacket(t *testing.T) {
	c := createTestConn(true, false, true)
	c.rcvWndSize = 1234

	// No ACK block at all, yet the window arrives.
	p, userData, err := decodeProto(mustEncode(&payloadHeader{maxPayload: 1452, rcvWnd: 1 << 20, streamId: 1}, nil))
	assert.NoError(t, err)
	assert.Nil(t, p.ack)
	_, err = c.processIncomingPayload(p, userData, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, decodeRcvWindow(encodeRcvWindow(1<<20)), c.rcvWndSize,
		"window must update from a packet carrying no ACK")
}

func mustEncode(p *payloadHeader, userData []byte) []byte {
	enc := encodeProto(p, userData)
	return enc
}

// A receiver whose buffer drained well past what it last advertised sends an
// unsolicited update rather than leaving a blocked peer to wait out its probe.
func TestConn_WindowReopened_PushesUpdate(t *testing.T) {
	c := createTestConn(true, false, true)
	w := &countingConn{}
	c.listener.localConn = w
	c.rcv = newReceiveBuffer(64 * 1024)
	c.mtu = conservativeMTU
	c.rcvWndSize = rcvBufferCapacity // our own sending is not blocked
	s := c.getOrCreateStream(1)

	// Buffer nearly full, and that is what the peer was told.
	c.rcv.insert(1, 0, 1, make([]byte, 63*1024))
	assert.Equal(t, uint64(1024), c.rcv.freeAdvertise())
	assert.False(t, c.rcv.windowReopened(c.mtu), "no change yet, nothing to announce")

	nowNano := uint64(10 * secondNano)
	_, _, err := c.flushStream(s, nowNano)
	assert.NoError(t, err)
	before := w.writes

	// The application reads: the buffer drains and the peer's view is stale.
	c.rcv.removeOldestInOrder(1)
	assert.True(t, c.rcv.windowReopened(c.mtu))

	_, _, err = c.flushStream(s, nowNano+secondNano)
	assert.NoError(t, err)
	assert.Greater(t, w.writes, before, "reopened window must be announced")
	assert.False(t, c.rcv.windowReopened(c.mtu), "and only announced once")
}

// The window is free space, so it means nothing except as of the moment it was
// built. A reordered older packet carries a smaller, stale value; applying it
// would block the sender until its next probe for no reason at all.
func TestConn_RcvWnd_StalePacketDoesNotShrinkWindow(t *testing.T) {
	c := createTestConn(true, false, true)
	hdr := func(wnd uint64) (*payloadHeader, []byte) {
		p, u, err := decodeProto(mustEncode(&payloadHeader{maxPayload: 1452, rcvWnd: wnd, streamId: 1}, nil))
		assert.NoError(t, err)
		return p, u
	}
	wnd := func(v uint64) uint64 { return decodeRcvWindow(encodeRcvWindow(v)) }

	// Newest packet: the peer has drained and has room again.
	p, u := hdr(1 << 20)
	_, err := c.processIncomingPayload(p, u, 100, 1)
	assert.NoError(t, err)
	assert.Equal(t, wnd(1<<20), c.rcvWndSize)

	// An older packet arrives late, built when the buffer was nearly full.
	p, u = hdr(4096)
	_, err = c.processIncomingPayload(p, u, 99, 2)
	assert.NoError(t, err)
	assert.Equal(t, wnd(1<<20), c.rcvWndSize, "stale window must be ignored")

	// A newer one is applied, even when it shrinks: that is real backpressure.
	p, u = hdr(4096)
	_, err = c.processIncomingPayload(p, u, 101, 3)
	assert.NoError(t, err)
	assert.Equal(t, wnd(4096), c.rcvWndSize)

	// The peer's sequence number restarts when its key rotates, so the
	// high-water mark must not lock out everything that follows.
	// A genuinely new key: not the current one, not the pending one, so
	// handlePeerKeyUpdate rotates rather than treating it as a retransmit.
	c.rcvKeys.next = bytes.Repeat([]byte{2}, 32)
	c.rcvKeys.prvKeyEpNext, c.rcvKeys.pubKeyEpNext = prvEpNew, prvEpNew.PublicKey()
	assert.NoError(t, c.handlePeerKeyUpdate(prvEpAlice.PublicKey().Bytes()))
	assert.Equal(t, uint64(0), c.rcvSnHigh)

	p, u = hdr(1 << 20)
	_, err = c.processIncomingPayload(p, u, 0, 4)
	assert.NoError(t, err)
	assert.Equal(t, wnd(1<<20), c.rcvWndSize, "window must work again after rotation")
}

// Empty packets are acknowledged on every arrival, not once per offset. That
// is what lets the same window probe be re-sent while the window stays shut:
// each one draws a fresh reply carrying the current window.
func TestConn_EmptyPacket_AckedOnEveryArrival(t *testing.T) {
	c := createTestConn(false, false, true)
	c.rcv = newReceiveBuffer(1000)
	p, u, err := decodeProto(mustEncode(&payloadHeader{maxPayload: 1452, streamId: 1}, nil))
	assert.NoError(t, err)

	for i := range 3 {
		_, err := c.processIncomingPayload(p, u, uint64(i+1), uint64(i+1))
		assert.NoError(t, err)
	}

	acked := 0
	for c.rcv.getSndAck() != nil {
		acked++
	}
	assert.Equal(t, 3, acked, "one acknowledgement per arrival")
}

// On the sending side the opposite holds: only the first acknowledgement of a
// packet counts. Later copies are duplicates and must not be counted twice --
// but they still carry a usable window, which is the point of putting it in
// the header rather than in the ACK block.
func TestConn_DuplicateAck_CountedOnce_StillCarriesWindow(t *testing.T) {
	c := createTestConn(true, false, true)
	c.snd.queueData(1, []byte("hello"))
	dataOut, offset, _ := c.snd.readyToSend(1, data, nil, 1200, true)
	assert.Len(t, dataOut, 5)
	c.snd.markSent(1, offset, 5, 60, 1, 0, 0, 0)
	c.dataInFlight = 5

	mk := func(wnd uint64) (*payloadHeader, []byte) {
		p, u, err := decodeProto(mustEncode(&payloadHeader{
			maxPayload: 1452, rcvWnd: wnd, streamId: 1,
			ack: &ack{streamId: 1, offset: offset, len: 5},
		}, nil))
		assert.NoError(t, err)
		return p, u
	}

	p, u := mk(1 << 20)
	_, err := c.processIncomingPayload(p, u, 10, 100)
	assert.NoError(t, err)
	assert.Equal(t, 0, c.dataInFlight)
	assert.Equal(t, uint64(5), c.deliveredBytes.Load())

	// Same ACK again, from a newer packet: not counted, window still applied.
	p, u = mk(4096)
	_, err = c.processIncomingPayload(p, u, 11, 101)
	assert.NoError(t, err)
	assert.Equal(t, 0, c.dataInFlight, "duplicate must not double-count")
	assert.Equal(t, uint64(5), c.deliveredBytes.Load())
	assert.Equal(t, decodeRcvWindow(encodeRcvWindow(4096)), c.rcvWndSize,
		"a duplicate ACK still carries a usable window")
}

// Probing must not go on at full rate forever. It backs off like a
// retransmit, but unlike one it never gives up: a peer refusing data is
// behaving correctly, so only silence may end the connection.
func TestConn_RwndProbe_BacksOffButNeverGivesUp(t *testing.T) {
	c := createTestConn(true, false, true)
	w := &countingConn{}
	c.listener.localConn = w
	c.mtu = conservativeMTU
	s := c.getOrCreateStream(1)
	c.snd.queueData(1, make([]byte, 64*1024))
	c.srtt, c.rttvar = 100*msNano, msNano
	c.rcvWndSize, c.dataInFlight = 1000, 5000

	rto := c.rtoNano()
	nowNano := uint64(10 * secondNano)

	// Probe, then ask how long until the next one is due.
	probe := func() uint64 {
		before := w.writes
		_, _, err := c.flushStream(s, nowNano)
		assert.NoError(t, err)
		assert.Equal(t, before+1, w.writes, "a probe goes out when due")

		_, wait, err := c.flushStream(s, nowNano)
		assert.NoError(t, err)
		assert.Equal(t, before+1, w.writes, "and not a second time before it is")
		nowNano += wait
		return wait
	}

	var intervals []uint64
	for range 8 {
		intervals = append(intervals, probe())
	}

	assert.Equal(t, rto*2, intervals[0])
	assert.Equal(t, rto*4, intervals[1])
	assert.Equal(t, rto*8, intervals[2])
	for i := 1; i < len(intervals); i++ {
		assert.GreaterOrEqual(t, intervals[i], intervals[i-1], "interval must not shrink")
		assert.LessOrEqual(t, intervals[i], maxRTO, "and stays capped")
	}
	last := len(intervals) - 1
	assert.Equal(t, intervals[last-1], intervals[last], "settles flat rather than growing")

	// The window opening resets it, so a later block probes at once again.
	c.rcvWndSize = rcvBufferCapacity
	_, _, err := c.flushStream(s, nowNano)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), c.rwndProbeNano)
	assert.Equal(t, uint(0), c.rwndProbeCount)
}

// A peer that has genuinely gone away stops the probing: nothing it sends
// updates lastReadTimeNano, so the read deadline tears the connection down.
// The probe must not keep it alive -- it reports zero bytes sent, so Flush
// still reaches the deadline check below.
func TestConn_RwndProbe_DeadPeerIsTornDown(t *testing.T) {
	w := &countingConn{}
	c := createTestConn(true, false, true)
	c.connId, c.mtu = 42, conservativeMTU
	c.listener = &Listener{
		connMap: newSharedLinkedMap[uint64, *conn](), prvKeyId: prvIdAlice,
		maxPayload: testMaxPayload, localConn: w,
	}
	c.listener.connMap.getOrPut(c.connId, c)

	s := c.getOrCreateStream(1)
	c.snd.queueData(s.streamID, make([]byte, 4096))
	c.srtt, c.rttvar = 100*msNano, msNano
	c.rcvWndSize, c.dataInFlight = 1000, 5000

	nowNano := uint64(10 * secondNano)
	c.lastReadTimeNano = nowNano // last heard from the peer here

	c.listener.Flush(nowNano)
	assert.Greater(t, w.writes, 0, "blocked, so it probes")
	_, stillThere := c.listener.connMap.get(c.connId)
	assert.True(t, stillThere, "peer only just went quiet")

	c.listener.Flush(nowNano + readDeadline + 1)
	_, stillThere = c.listener.connMap.get(c.connId)
	assert.False(t, stillThere, "read deadline must end a connection whose peer is gone")
}

// A KEY_UPDATE_ACK we owe the peer must not stop data going out. It rides
// along on the next packet, so blocking new data until it has been sent costs
// a packet for nothing -- which is what it did while it was a phase rather
// than a flag.
func TestConn_KeyUpdateAckDue_DoesNotBlockData(t *testing.T) {
	c := createTestConn(true, false, true)
	w := &countingConn{}
	c.listener.localConn = w
	c.mtu = testMaxPayload
	c.rcvWndSize = rcvBufferCapacity
	s := c.getOrCreateStream(1)

	// The peer sent a KEY_UPDATE, so we owe it an ack.
	assert.NoError(t, c.handlePeerKeyUpdate(prvEpNew.PublicKey().Bytes()))
	assert.True(t, c.kuAckPending(), "we owe a KEY_UPDATE_ACK")
	assert.Equal(t, phaseReady, c.phase, "owing an ack is not a handshake state")

	c.snd.queueData(s.streamID, []byte("payload that should still go out"))
	n, _, err := c.flushStream(s, uint64(secondNano))
	assert.NoError(t, err)
	assert.Greater(t, n, 0, "data must flow while a KEY_UPDATE_ACK is owed")
	assert.False(t, c.kuAckDue, "and the ack rode along on it")
}
