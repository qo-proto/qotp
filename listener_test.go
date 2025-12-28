package qotp

import (
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
	hexPubKey2 = fmt.Sprintf("0x%x", testPrvKey2.PublicKey().Bytes())
)

// =============================================================================
// TEST HELPER - mirrors Listen() header parsing logic
// =============================================================================

func testDecode(l *Listener, encData []byte, rAddr netip.AddrPort) (*conn, []byte, cryptoMsgType, error) {
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

// =============================================================================
// LISTENER CREATION TESTS
// =============================================================================

func TestListenerNewListener(t *testing.T) {
	t.Run("valid address", func(t *testing.T) {
		listener, err := Listen(WithListenAddr("127.0.0.1:8080"), WithSeed(testPrvSeed1))
		assert.NoError(t, err)
		assert.NotNil(t, listener)
		defer listener.Close()
	})

	t.Run("invalid port", func(t *testing.T) {
		_, err := Listen(WithListenAddr("127.0.0.1:99999"), WithSeed(testPrvSeed1))
		assert.Error(t, err)
	})
}

func TestListenerNewStream(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listener.Close()

	t.Run("valid remote address", func(t *testing.T) {
		conn, err := listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)
		assert.NoError(t, err)
		assert.NotNil(t, conn)
	})

	t.Run("invalid port", func(t *testing.T) {
		conn, err := listener.DialStringWithCryptoString("127.0.0.1:99999", hexPubKey1)
		assert.Nil(t, conn)
		assert.Error(t, err)
	})
}

func TestListenerClose(t *testing.T) {
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)

	listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)
	err = listener.Close()
	assert.NoError(t, err)
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

func TestListenerStreamWithAdversarialNetwork50PercentLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%2 == 0 },
		func(counter int) bool { return counter%2 == 0 },
		50*msNano,
		"50% Loss")
}

func TestListenerStreamWith10PercentLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 500,
		func(counter int) bool { return counter%10 == 0 },
		func(counter int) bool { return counter%10 == 0 },
		50*msNano,
		"10% Loss")
}

func TestListenerStreamWithAsymmetricLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%5 == 0 },
		func(counter int) bool { return counter%2 == 0 },
		50*msNano,
		"Asymmetric Loss (20% data, 50% ack)")
}

func TestListenerStreamWithReordering(t *testing.T) {
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

func TestListenerStreamWithExtremeConditions(t *testing.T) {
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

func TestListenerBidirectional10Streams(t *testing.T) {
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
				stream, exists := connAlice.streams.Get(uint32(i))
				if exists && stream != nil && !stream.sndClosed {
					allClosed = false
					break
				}
			}

			slog.Debug("Alice check", "allSent", allSent, "allReceived", allReceived, "allClosed", allClosed, "pendingAcks", connAlice.rcv.HasPendingAcks(), "activeStreams", listenerAlice.HasActiveStreams())
			if allSent && allReceived && allClosed && !connAlice.rcv.HasPendingAcks() && !listenerAlice.HasActiveStreams() {
				slog.Debug("Alice exiting", "allSent", allSent, "allReceived", allReceived, "allClosed", allClosed, "pendingAcks", connAlice.rcv.HasPendingAcks())
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

// =============================================================================
// DECODE ERROR TESTS
// =============================================================================

func TestListenerDecodeErrors(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		mtu:      defaultMTU,
	}

	addr, _ := netip.ParseAddr("127.0.0.1")
	remoteAddr := netip.AddrPortFrom(addr, 8080)

	t.Run("empty buffer", func(t *testing.T) {
		_, _, _, err := testDecode(l, []byte{}, remoteAddr)
		assert.Error(t, err)
	})

	t.Run("too small", func(t *testing.T) {
		_, _, _, err := testDecode(l, []byte{0x00}, remoteAddr)
		assert.Error(t, err)
	})

	t.Run("invalid version", func(t *testing.T) {
		buf := make([]byte, MinPacketSize)
		buf[0] = 0x1F // Version 31 (invalid)
		_, _, _, err := testDecode(l, buf, remoteAddr)
		assert.Error(t, err)
	})
}

func TestListenerDecodeConnNotFound(t *testing.T) {
	l := &Listener{
		connMap:  NewLinkedMap[uint64, *conn](),
		prvKeyId: testPrvKey1,
		mtu:      defaultMTU,
	}

	addr, _ := netip.ParseAddr("127.0.0.1")
	remoteAddr := netip.AddrPortFrom(addr, 8080)

	tests := []struct {
		name    string
		msgType cryptoMsgType
	}{
		{"InitRcv", InitRcv},
		{"InitCryptoRcv", InitCryptoRcv},
		{"Data", Data},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, MinPacketSize)
			buf[0] = byte(tt.msgType) << 5
			_, _, _, err := testDecode(l, buf, remoteAddr)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})
	}
}
