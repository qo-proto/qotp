package qotp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	testPrvSeed1   = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testPrvSeed2   = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	testPrvKey1, _ = ecdh.X25519().NewPrivateKey(testPrvSeed1[:])
	testPrvKey2, _ = ecdh.X25519().NewPrivateKey(testPrvSeed2[:])

	hexPubKey1 = fmt.Sprintf("0x%x", testPrvKey1.PublicKey().Bytes())
)

// =============================================================================
// TEST HELPER
// =============================================================================

func testDecode(l *Listener, encData []byte, rAddr netip.AddrPort) (*conn, []byte, cryptoMsgType, error) {
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

func getTestRemoteAddrPort() netip.AddrPort {
	addr, _ := netip.ParseAddr("127.0.0.1")
	return netip.AddrPortFrom(addr, 8080)
}

// =============================================================================
// LISTEN OPTION TESTS
// =============================================================================

func TestListen_DefaultOptions(t *testing.T) {
	listener, err := Listen()
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.prvKeyId)
	assert.NotNil(t, listener.connMap)
	assert.GreaterOrEqual(t, listener.maxPayload, conservativeMTU)
	defer listener.Close()
}

func TestListen_WithListenAddr_Valid(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:8080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	defer listener.Close()
}

func TestListen_WithListenAddr_InvalidPort(t *testing.T) {
	_, err := Listen(WithListenAddr("127.0.0.1:99999"), WithSeed(testPrvSeed1))
	assert.Error(t, err)
}

func TestListen_WithListenAddr_InvalidAddress(t *testing.T) {
	_, err := Listen(WithListenAddr("not-an-address"), WithSeed(testPrvSeed1))
	assert.Error(t, err)
}

func TestListen_WithSeed(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, testPrvKey1.PublicKey().Bytes(), listener.prvKeyId.PublicKey().Bytes())
	defer listener.Close()
}

func TestListen_WithSeedHex_Valid(t *testing.T) {
	hexSeed := fmt.Sprintf("%x", testPrvSeed1)
	listener, err := Listen(WithSeedHex(hexSeed))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, testPrvKey1.PublicKey().Bytes(), listener.prvKeyId.PublicKey().Bytes())
	defer listener.Close()
}

func TestListen_WithSeedHex_With0xPrefix(t *testing.T) {
	hexSeed := "0x" + fmt.Sprintf("%x", testPrvSeed1)
	listener, err := Listen(WithSeedHex(hexSeed))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	defer listener.Close()
}

func TestListen_WithSeedHex_InvalidHex(t *testing.T) {
	_, err := Listen(WithSeedHex("not-valid-hex!"))
	assert.Error(t, err)
}

func TestListen_WithSeedHex_WrongLength(t *testing.T) {
	_, err := Listen(WithSeedHex("abcd1234"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestListen_WithSeedString(t *testing.T) {
	listener, err := Listen(WithSeedString("my secret passphrase"))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.NotNil(t, listener.prvKeyId)
	defer listener.Close()
}

func TestListen_WithPrvKeyId(t *testing.T) {
	listener, err := Listen(WithPrvKeyId(testPrvKey1))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, testPrvKey1, listener.prvKeyId)
	defer listener.Close()
}

func TestListen_WithMaxPayload(t *testing.T) {
	listener, err := Listen(WithMaxPayload(1300))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, 1300, listener.maxPayload)
	defer listener.Close()
}

func TestListen_WithMaxPayload_BelowFloor(t *testing.T) {
	listener, err := Listen(WithMaxPayload(1000))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, conservativeMTU, listener.maxPayload)
	defer listener.Close()
}

func TestListen_WithKeyLogWriter(t *testing.T) {
	var buf bytes.Buffer
	listener, err := Listen(WithKeyLogWriter(&buf))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, &buf, listener.keyLogWriter)
	defer listener.Close()
}

func TestListen_WithNetworkConn(t *testing.T) {
	mockConn := NewConnPair("addr1", "addr2")
	listener, err := Listen(WithNetworkConn(mockConn.Conn1))
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, mockConn.Conn1, listener.localConn)
}

func TestListen_MultipleOptions(t *testing.T) {
	listener, err := Listen(
		WithSeed(testPrvSeed1),
		WithMaxPayload(1300),
	)
	assert.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, testPrvKey1.PublicKey().Bytes(), listener.prvKeyId.PublicKey().Bytes())
	assert.Equal(t, 1300, listener.maxPayload)
	defer listener.Close()
}

// =============================================================================
// LISTENER LIFECYCLE TESTS
// =============================================================================

func TestListener_Close(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)

	_, _ = listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)

	err = listener.Close()
	assert.NoError(t, err)
}

func TestListener_Close_Empty(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)

	err = listener.Close()
	assert.NoError(t, err)
}

func TestListener_HasActiveStreams_Empty(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	assert.False(t, listener.HasActiveStreams())
}

func TestListener_HasActiveStreams_WithConnection(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	conn, err := listener.DialString("127.0.0.1:9000")
	assert.NoError(t, err)

	// Create a stream
	conn.Stream(0)
	assert.True(t, listener.HasActiveStreams())
}

// =============================================================================
// DIAL FROM LISTENER TESTS
// =============================================================================

func TestListener_DialStringWithCryptoString_Valid(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	conn, err := listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestListener_DialStringWithCryptoString_InvalidPort(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	conn, err := listener.DialStringWithCryptoString("127.0.0.1:99999", hexPubKey1)
	assert.Nil(t, conn)
	assert.Error(t, err)
}

// =============================================================================
// REFRESH MAX PAYLOAD TESTS
// =============================================================================

func TestListener_RefreshMaxPayload_NonUDP(t *testing.T) {
	connPair := NewConnPair("a", "b")
	listener, err := Listen(WithNetworkConn(connPair.Conn1), WithSeed(testPrvSeed1))
	assert.NoError(t, err)

	// Non-UDP conn: interfaceMTU stays at 1500 (default), maxPayload = 1500 - 48 = 1452
	listener.RefreshMaxPayload()
	assert.Equal(t, 1452, listener.maxPayload)
}

func TestListener_RefreshMaxPayload_FloorAtConservativeMTU(t *testing.T) {
	connPair := NewConnPair("a", "b")
	listener, err := Listen(WithNetworkConn(connPair.Conn1), WithSeed(testPrvSeed1))
	assert.NoError(t, err)

	// Force interfaceMTU to something tiny
	listener.interfaceMTU = 100
	listener.RefreshMaxPayload()
	assert.Equal(t, conservativeMTU, listener.maxPayload)
}

// =============================================================================
// NEWCONN TESTS
// =============================================================================

func TestListener_newConn_DuplicateConnId(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	// First dial creates a connection
	conn1, err := listener.DialString("127.0.0.1:9000")
	assert.NoError(t, err)
	assert.NotNil(t, conn1)

	// Try to create connection with same connId - should fail
	_, err = listener.newConn(conn1.connId, getTestRemoteAddrPort(), testPrvKey1, nil, nil, true, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

// =============================================================================
// CLEANUP TESTS
// =============================================================================

func TestListener_cleanupConn(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	conn, err := listener.DialString("127.0.0.1:9000")
	assert.NoError(t, err)
	connId := conn.connId

	assert.True(t, listener.connMap.contains(connId))

	listener.cleanupConn(connId)

	assert.False(t, listener.connMap.contains(connId))
}

func TestListener_cleanupConn_UpdatesCurrentConnID(t *testing.T) {
	listener, err := Listen(WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	conn1, _ := listener.DialString("127.0.0.1:9000")
	conn2, _ := listener.DialString("127.0.0.1:9001")

	// Set current to first connection
	listener.currentConnID = &conn1.connId

	// Cleanup first connection - should advance currentConnID
	listener.cleanupConn(conn1.connId)

	assert.NotNil(t, listener.currentConnID)
	assert.Equal(t, conn2.connId, *listener.currentConnID)
}

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestListener_Decode_EmptyBuffer(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	_, _, _, err := testDecode(l, []byte{}, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

func TestListener_Decode_TooSmall(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	_, _, _, err := testDecode(l, []byte{0x00}, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too small")
}

func TestListener_Decode_InvalidVersion(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	buf := make([]byte, minPacketSize)
	buf[0] = 0x1F // Version 31 (invalid)

	_, _, _, err := testDecode(l, buf, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported version")
}

func TestListener_Decode_ConnNotFound_InitRcv(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	buf := make([]byte, minPacketSize)
	buf[0] = byte(initRcv) << 5

	_, _, _, err := testDecode(l, buf, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListener_Decode_ConnNotFound_InitCryptoRcv(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	buf := make([]byte, minPacketSize)
	buf[0] = byte(initCryptoRcv) << 5

	_, _, _, err := testDecode(l, buf, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListener_Decode_ConnNotFound_Data(t *testing.T) {
	l := &Listener{
		connMap:  newLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		maxPayload: testMaxPayload,
	}

	buf := make([]byte, minPacketSize)
	buf[0] = byte(data) << 5

	_, _, _, err := testDecode(l, buf, getTestRemoteAddrPort())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// =============================================================================
// DATA TRANSFER HELPER
// =============================================================================

func runDataTransferTest(t *testing.T, testDataSize int, maxIterations int,
	dataLossFunc func(int) bool, ackLossFunc func(int) bool,
	latencyNano uint64, testName string) {

	connA, listenerB, connPair := setupStreamTest(t)

	connPair.Conn1.latencyNano = latencyNano
	connPair.Conn2.latencyNano = latencyNano

	streamA := connA.Stream(0)

	testData := make([]byte, testDataSize)
	_, err := rand.Read(testData)
	assert.NoError(t, err)

	n, err := streamA.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, testDataSize, n)

	var streamB *Stream
	receivedData := []byte{}
	dropCounterSender := 0
	dropCounterReceiver := 0

	for i := 0; i < maxIterations; i++ {
		// Sender flushes
		_, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
		assert.NoError(t, err)
		minPacing := connA.listener.Flush(connPair.Conn1.localTime)
		connPair.Conn1.localTime += max(minPacing, 10*msNano)

		// Transfer data packets with loss
		if connPair.nrOutgoingPacketsSender() > 0 {
			nPackets := connPair.nrOutgoingPacketsSender()
			toDrop := make([]int, 0)
			toSend := make([]int, 0, nPackets)

			for j := 0; j < nPackets; j++ {
				dropCounterSender++
				if dataLossFunc(dropCounterSender) {
					toDrop = append(toDrop, j)
				} else {
					toSend = append(toSend, j)
				}
			}

			if len(toDrop) > 0 {
				err = connPair.dropSender(toDrop...)
				assert.NoError(t, err)
			}

			if len(toSend) > 0 {
				_, err = connPair.senderToRecipient(toSend...)
				assert.NoError(t, err)
			}
		}

		// Receiver processes incoming data
		s, err := listenerB.Listen(MinDeadLine, connPair.Conn2.localTime)
		assert.NoError(t, err)
		if s != nil {
			streamB = s
		}

		// Read available data
		if streamB != nil {
			data, err := streamB.Read()
			if err == nil && len(data) > 0 {
				receivedData = append(receivedData, data...)
			}
		}

		// Receiver flushes ACKs
		minPacing = listenerB.Flush(connPair.Conn2.localTime)
		connPair.Conn2.localTime += max(minPacing, 10*msNano)

		// Transfer ACKs with loss
		if connPair.nrOutgoingPacketsReceiver() > 0 {
			nPackets := connPair.nrOutgoingPacketsReceiver()
			toDrop := make([]int, 0)
			toSend := make([]int, 0, nPackets)

			for j := 0; j < nPackets; j++ {
				dropCounterReceiver++
				if ackLossFunc(dropCounterReceiver) {
					toDrop = append(toDrop, j)
				} else {
					toSend = append(toSend, j)
				}
			}

			if len(toDrop) > 0 {
				err = connPair.dropReceiver(toDrop...)
				assert.NoError(t, err)
			}

			if len(toSend) > 0 {
				_, err = connPair.recipientToSender(toSend...)
				assert.NoError(t, err)
			}
		}

		// Check completion
		if len(receivedData) >= testDataSize {
			t.Logf("%s: Transfer completed in %d iterations", testName, i+1)

			assert.Equal(t, testDataSize, len(receivedData), "should receive all data")
			assert.Equal(t, testData, receivedData, "received data should match sent data")
			return
		}
	}

	t.Errorf("%s: Failed to complete transfer in %d iterations (received %d/%d bytes)",
		testName, maxIterations, len(receivedData), testDataSize)
}

// =============================================================================
// DATA TRANSFER TESTS
// =============================================================================

func TestListener_DataTransfer_50PercentLoss(t *testing.T) {
	maxRetry = 10
	defer func() { maxRetry = 5 }()

	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%2 == 0 },
		func(counter int) bool { return counter%2 == 0 },
		50*msNano,
		"50% Loss")
}

func TestListener_DataTransfer_10PercentLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 500,
		func(counter int) bool { return counter%10 == 0 },
		func(counter int) bool { return counter%10 == 0 },
		50*msNano,
		"10% Loss")
}

func TestListener_DataTransfer_AsymmetricLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%5 == 0 },
		func(counter int) bool { return counter%2 == 0 },
		50*msNano,
		"Asymmetric Loss (20% data, 50% ack)")
}

func TestListener_DataTransfer_NoLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 100,
		func(counter int) bool { return false },
		func(counter int) bool { return false },
		10*msNano,
		"No Loss")
}

func TestListener_DataTransfer_Reordering(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	connPair.Conn1.latencyNano = 50 * msNano
	connPair.Conn2.latencyNano = 50 * msNano

	streamA := connA.Stream(0)

	testDataSize := 10 * 1024
	testData := make([]byte, testDataSize)
	_, err := rand.Read(testData)
	assert.NoError(t, err)

	n, err := streamA.Write(testData)
	assert.NoError(t, err)
	assert.Equal(t, testDataSize, n)

	var streamB *Stream
	receivedData := []byte{}
	maxIterations := 1000

	for i := 0; i < maxIterations; i++ {
		// Sender flushes
		_, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
		assert.NoError(t, err)
		minPacing := connA.listener.Flush(connPair.Conn1.localTime)
		connPair.Conn1.localTime += max(minPacing, 10*msNano)

		// Reorder and deliver packets if we have multiple
		if connPair.nrOutgoingPacketsSender() >= 3 {
			nPackets := connPair.nrOutgoingPacketsSender()
			indices := make([]int, nPackets)
			indices[0] = 2
			indices[1] = 1
			indices[2] = 0
			for j := 3; j < nPackets; j++ {
				indices[j] = j
			}
			_, err = connPair.senderToRecipient(indices...)
			assert.NoError(t, err)
		} else if connPair.nrOutgoingPacketsSender() > 0 {
			_, err = connPair.senderToRecipientAll()
			assert.NoError(t, err)
		}

		// Receiver processes
		s, err := listenerB.Listen(MinDeadLine, connPair.Conn2.localTime)
		assert.NoError(t, err)
		if s != nil {
			streamB = s
		}

		if streamB != nil {
			data, err := streamB.Read()
			if err == nil && len(data) > 0 {
				receivedData = append(receivedData, data...)
			}
		}

		// Receiver flushes ACKs
		minPacing = listenerB.Flush(connPair.Conn2.localTime)
		connPair.Conn2.localTime += max(minPacing, 10*msNano)

		if connPair.nrOutgoingPacketsReceiver() > 0 {
			_, err = connPair.recipientToSenderAll()
			assert.NoError(t, err)
		}

		// Check completion
		if len(receivedData) >= testDataSize {
			t.Logf("Reordering: Transfer completed in %d iterations", i+1)
			assert.Equal(t, testData, receivedData)
			return
		}
	}

	t.Errorf("Reordering: Failed to complete transfer (received %d/%d bytes)",
		len(receivedData), testDataSize)
}

func TestListener_DataTransfer_ExtremeConditions(t *testing.T) {
	maxRetry = 20
	ReadDeadLine = uint64(300 * secondNano)

	defer func() {
		maxRetry = 5
		ReadDeadLine = uint64(30 * secondNano)
	}()

	runDataTransferTest(t, 2*1024, 2000,
		func(counter int) bool { return (counter-1)%5 < 3 },
		func(counter int) bool { return (counter-1)%7 < 3 },
		100*msNano,
		"Extreme Conditions")
}

// =============================================================================
// BIDIRECTIONAL TEST
// =============================================================================

func TestListener_Bidirectional_MultipleStreams(t *testing.T) {
	listenerAlice, err := Listen(WithListenAddr("127.0.0.1:0"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listenerAlice.Close()

	listenerBob, err := Listen(WithListenAddr("127.0.0.1:0"), WithSeed(testPrvSeed2))
	assert.NoError(t, err)
	defer listenerBob.Close()

	connAlice, err := listenerAlice.DialStringWithCrypto(listenerBob.localConn.LocalAddrString(), testPrvKey2.PublicKey())
	assert.NoError(t, err)

	numStreams := 20
	dataSize := 20000

	type StreamState struct {
		stream *Stream
		data   []byte
		sent   int
	}

	aliceStreams := make([]*StreamState, numStreams)
	for i := 0; i < numStreams; i++ {
		data := make([]byte, dataSize)
		for j := range data {
			data[j] = byte(i)
		}
		aliceStreams[i] = &StreamState{
			stream: connAlice.Stream(uint32(i)),
			data:   data,
			sent:   0,
		}
	}

	aliceReceived := make(map[uint32][]byte)
	for i := 0; i < numStreams; i++ {
		aliceReceived[uint32(i)] = []byte{}
	}

	bobReceived := make(map[uint32]int)
	bobResponded := make(map[uint32]bool)

	ctxAlice, cancelAlice := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelAlice()

	ctxBob, cancelBob := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelBob()

	// Bob goroutine - server side
	bobDone := make(chan struct{})
	go func() {
		defer close(bobDone)
		listenerBob.Loop(ctxBob, func(ctx context.Context, s *Stream) error {
			if s != nil {
				slog.Debug("bob-callback", "streamID", s.streamID,
					"connID", s.ConnID(),
					"received", bobReceived[s.streamID],
					"responded", bobResponded[s.streamID])
				data, err := s.Read()
				slog.Debug("bob-received", "stream", s.streamID, "len", len(data), "total", bobReceived[s.streamID], "err", err)
				if err == nil && len(data) > 0 {
					bobReceived[s.streamID] += len(data)
				} else if err != nil && err != io.EOF {
					s.Close()
					return nil
				}

				if bobReceived[s.streamID] >= dataSize && !bobResponded[s.streamID] {
					bobResponded[s.streamID] = true
					slog.Debug("bob-writing", "stream", s.streamID, "connID", s.ConnID())

					responseData := make([]byte, dataSize)
					for j := range responseData {
						responseData[j] = byte(s.streamID + 100)
					}
					for len(responseData) > 0 {
						n, err := s.Write(responseData)
						if err != nil {
							return err
						}
						if n > 0 {
							responseData = responseData[n:]
						}
					}
					s.Close()
				}
			}

			slog.Debug("bob-state-all",
				"responded", bobResponded,
				"received-lens", len(bobReceived))

			allStreamsStarted := len(bobReceived) >= numStreams
			if allStreamsStarted && !listenerBob.HasActiveStreams() {
				slog.Debug("Bob exiting", "allStreamsStarted", allStreamsStarted)
				cancelBob()
			}

			slog.Debug("bob-state", "stream0-received", bobReceived[0], "stream0-responded", bobResponded[0])
			return nil
		})
	}()

	// Alice goroutine - client side
	aliceDone := make(chan struct{})
	go func() {
		defer close(aliceDone)
		listenerAlice.Loop(ctxAlice, func(ctx context.Context, s *Stream) error {
			// Write phase
			for _, ss := range aliceStreams {
				if ss.sent < len(ss.data) {
					remaining := ss.data[ss.sent:]
					n, err := ss.stream.Write(remaining)
					if err != nil {
						return err
					}
					if n > 0 {
						ss.sent += n
					}
				}
				if ss.sent >= len(ss.data) && !ss.stream.IsCloseRequested() {
					ss.stream.Close()
				}
			}

			// Read phase
			if s != nil {
				data, err := s.Read()
				if err == nil && len(data) > 0 {
					aliceReceived[s.streamID] = append(aliceReceived[s.streamID], data...)
				}
			}

			// Check completion
			allSent := true
			for _, ss := range aliceStreams {
				if ss.sent < len(ss.data) {
					allSent = false
					break
				}
			}

			allReceived := true
			for i := 0; i < numStreams; i++ {
				if len(aliceReceived[uint32(i)]) < dataSize {
					allReceived = false
					break
				}
			}

			allClosed := true
			for i := 0; i < numStreams; i++ {
				stream, exists := connAlice.streams.get(uint32(i))
				if exists && stream != nil && !stream.sndClosed {
					allClosed = false
					break
				}
			}

			slog.Debug("Alice check", "allSent", allSent, "allReceived", allReceived, "allClosed", allClosed, "pendingAcks", connAlice.rcv.hasPendingAcks(), "activeStreams", listenerAlice.HasActiveStreams())
			if allSent && allReceived && allClosed && !connAlice.rcv.hasPendingAcks() && !listenerAlice.HasActiveStreams() {
				slog.Debug("Alice exiting", "allSent", allSent, "allReceived", allReceived, "allClosed", allClosed, "pendingAcks", connAlice.rcv.hasPendingAcks())
				cancelAlice()
			}
			return nil
		})
	}()

	<-aliceDone
	<-bobDone

	// Verify Alice received all responses
	for i := 0; i < numStreams; i++ {
		assert.Equal(t, dataSize, len(aliceReceived[uint32(i)]),
			"Alice should receive full response on stream %d", i)
	}

	// Verify Bob received all data
	for i := 0; i < numStreams; i++ {
		assert.Equal(t, dataSize, bobReceived[uint32(i)],
			"Bob should receive all data on stream %d", i)
	}
}