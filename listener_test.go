package qotp

import (
	"crypto/ecdh"
	"crypto/rand"
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

func TestListenerNewListener(t *testing.T) {
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

func TestListenerNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	defer func() {
		err := listener.Close()
		assert.Nil(t, err)
	}()
	assert.Nil(t, err)
	conn, err := listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)
	assert.Nil(t, err)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, err = listener.DialStringWithCryptoString("127.0.0.1:99999", hexPubKey1)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestListenerClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, err := Listen(WithListenAddr("127.0.0.1:9080"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	// Test case 2: Close a listener with multi-streams
	listener.DialStringWithCryptoString("127.0.0.1:9081", hexPubKey1)
	err = listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

// Helper function to run data transfer test with specified parameters
func runDataTransferTest(t *testing.T, testDataSize int, maxIterations int,
	dataLossFunc func(int) bool, ackLossFunc func(int) bool,
	latencyNano uint64, testName string) {

	connA, listenerB, connPair := setupStreamTest(t)

	// Set up network conditions
	connPair.Conn1.latencyNano = latencyNano
	connPair.Conn2.latencyNano = latencyNano

	streamA := connA.Stream(0)

	// Generate test data
	testData := make([]byte, testDataSize)
	_, err := rand.Read(testData)
	assert.NoError(t, err)

	// Write data
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

			// Verify data integrity
			assert.Equal(t, testDataSize, len(receivedData), "should receive all data")
			assert.Equal(t, testData, receivedData, "received data should match sent data")
			return
		}
	}

	// If we get here, test failed
	t.Errorf("%s: Failed to complete transfer in %d iterations (received %d/%d bytes)",
		testName, maxIterations, len(receivedData), testDataSize)
}

func TestListenerStreamWithAdversarialNetwork50PercentLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%2 == 0 }, // 50% data loss
		func(counter int) bool { return counter%2 == 0 }, // 50% ack loss
		50*msNano,
		"50% Loss")
}

func TestListenerStreamWith10PercentLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 500,
		func(counter int) bool { return counter%10 == 0 }, // 10% data loss
		func(counter int) bool { return counter%10 == 0 }, // 10% ack loss
		50*msNano,
		"10% Loss")
}

func TestListenerStreamWithAsymmetricLoss(t *testing.T) {
	// 20% data loss, 50% ACK loss
	runDataTransferTest(t, 10*1024, 1000,
		func(counter int) bool { return counter%5 == 0 }, // 20% data loss
		func(counter int) bool { return counter%2 == 0 }, // 50% ack loss
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
		minPacing := connA.listener.Flush(connPair.Conn1.localTime)
		connPair.Conn1.localTime += max(minPacing, 10*msNano)

		// Reorder and deliver packets if we have multiple
		if connPair.nrOutgoingPacketsSender() >= 3 {
			// Reverse order of first 3 packets: [0,1,2] -> [2,1,0], then rest in order
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

			_, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
			assert.NoError(t, err)
		}

		if len(receivedData) >= testDataSize {
			t.Logf("Reordering: Transfer completed in %d iterations", i+1)
			assert.Equal(t, testDataSize, len(receivedData))
			assert.Equal(t, testData, receivedData)
			return
		}
	}

	t.Errorf("Reordering: Failed to complete transfer")
}

func TestListenerStreamWithHighLatency(t *testing.T) {
	runDataTransferTest(t, 5*1024, 1000,
		func(counter int) bool { return counter%5 == 0 }, // 20% data loss
		func(counter int) bool { return counter%5 == 0 }, // 20% ack loss
		200*msNano, // High latency
		"High Latency (200ms)")
}

func TestListenerStreamWithNoLoss(t *testing.T) {
	runDataTransferTest(t, 10*1024, 500,
		func(counter int) bool { return false }, // 0% data loss
		func(counter int) bool { return false }, // 0% ack loss
		50*msNano,
		"No Loss")
}

func TestListenerStreamMultipleStreams(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	connPair.Conn1.latencyNano = 50 * msNano
	connPair.Conn2.latencyNano = 50 * msNano

	// Create 3 streams
	numStreams := 3
	streams := make([]*Stream, numStreams)
	testData := make([][]byte, numStreams)
	testDataSize := 5 * 1024

	for i := 0; i < numStreams; i++ {
		streams[i] = connA.Stream(uint32(i))
		testData[i] = make([]byte, testDataSize)
		_, err := rand.Read(testData[i])
		assert.NoError(t, err)

		// Write to all streams
		n, err := streams[i].Write(testData[i])
		assert.NoError(t, err)
		assert.Equal(t, testDataSize, n)
	}

	receivedData := make([][]byte, numStreams)
	for i := range receivedData {
		receivedData[i] = []byte{}
	}

	maxIterations := 1000
	dropCounter := 0

	for iter := 0; iter < maxIterations; iter++ {
		// Sender flushes
		minPacing := connA.listener.Flush(connPair.Conn1.localTime)
		connPair.Conn1.localTime += max(minPacing, 10*msNano)

		// Transfer with 30% loss
		if connPair.nrOutgoingPacketsSender() > 0 {
			nPackets := connPair.nrOutgoingPacketsSender()
			toDrop := make([]int, 0)
			toSend := make([]int, 0, nPackets)

			for j := 0; j < nPackets; j++ {
				dropCounter++
				if dropCounter%10 < 3 {
					toDrop = append(toDrop, j)
				} else {
					toSend = append(toSend, j)
				}
			}

			if len(toDrop) > 0 {
				err := connPair.dropSender(toDrop...)
				assert.NoError(t, err)
			}

			if len(toSend) > 0 {
				_, err := connPair.senderToRecipient(toSend...)
				assert.NoError(t, err)
			}
		}

		// Receiver processes
		s, err := listenerB.Listen(MinDeadLine, connPair.Conn2.localTime)
		assert.NoError(t, err)

		if s != nil {
			data, err := s.Read()
			if err == nil && len(data) > 0 {
				receivedData[s.streamID] = append(receivedData[s.streamID], data...)
			}
		}

		// Receiver flushes
		minPacing = listenerB.Flush(connPair.Conn2.localTime)
		connPair.Conn2.localTime += max(minPacing, 10*msNano)

		// Transfer ACKs
		if connPair.nrOutgoingPacketsReceiver() > 0 {
			nPackets := connPair.nrOutgoingPacketsReceiver()
			toDrop := make([]int, 0)
			toSend := make([]int, 0, nPackets)

			for j := 0; j < nPackets; j++ {
				dropCounter++
				if dropCounter%10 < 3 {
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

			_, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
			assert.NoError(t, err)
		}

		// Check if all streams completed
		allComplete := true
		for i := 0; i < numStreams; i++ {
			if len(receivedData[i]) < testDataSize {
				allComplete = false
				break
			}
		}

		if allComplete {
			t.Logf("Multiple streams: Transfer completed in %d iterations", iter+1)

			// Verify all streams
			for i := 0; i < numStreams; i++ {
				assert.Equal(t, testDataSize, len(receivedData[i]),
					"stream %d should receive all data", i)
				assert.Equal(t, testData[i], receivedData[i],
					"stream %d data should match", i)
			}
			return
		}
	}

	t.Errorf("Multiple streams: Failed to complete transfer")
	for i := 0; i < numStreams; i++ {
		t.Logf("Stream %d: received %d/%d bytes", i, len(receivedData[i]), testDataSize)
	}
}

func TestListenerStreamWithExtremeConditions(t *testing.T) {
	// Test with very small MTU-sized chunks and high loss
	maxRetry = 20
	ReadDeadLine = uint64(300 * secondNano)

	defer func() {
		maxRetry = 5
		ReadDeadLine = uint64(30 * secondNano)
	}()

	runDataTransferTest(t, 2*1024, 2000, // Small data, many iterations
		func(counter int) bool {
			// Bursty loss: drop 3, deliver 2, repeat
			return (counter-1)%5 < 3
		},
		func(counter int) bool {
			// Different pattern for ACKs
			return (counter-1)%7 < 3
		},
		100*msNano,
		"Extreme Conditions")
}

func TestListenerBidirectional10Streams(t *testing.T) {
	// Setup alice and bob listeners
	listenerAlice, err := Listen(WithListenAddr("127.0.0.1:0"), WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	defer listenerAlice.Close()

	listenerBob, err := Listen(WithListenAddr("127.0.0.1:0"), WithSeed(testPrvSeed2))
	assert.NoError(t, err)
	defer listenerBob.Close()

	// Alice connects to Bob
	connAlice, err := listenerAlice.DialStringWithCrypto(listenerBob.localConn.LocalAddrString(), testPrvKey2.PublicKey())
	assert.NoError(t, err)

	numStreams := 10
	dataSize := 20000

	// Alice's send state
	type StreamState struct {
		stream *Stream
		data   []byte
		sent   int
	}

	aliceStreams := make([]*StreamState, numStreams)
	aliceTotalExpected := 0
	for i := 0; i < numStreams; i++ {
		data := make([]byte, dataSize)
		for j := range data {
			data[j] = byte(i) // Fill with stream ID
		}
		aliceTotalExpected += len(data)
		aliceStreams[i] = &StreamState{
			stream: connAlice.Stream(uint32(i)),
			data:   data,
			sent:   0,
		}
	}

	// Bob's receive state
	bobReceived := make(map[uint32]int)
	bobResponded := make(map[uint32]bool)
	
	// Alice's receive state
	aliceReceived := make(map[uint32][]byte)
	for i := 0; i < numStreams; i++ {
		aliceReceived[uint32(i)] = []byte{}
	}

	maxIterations := 2000
	aliceDone := false
	bobDone := false

	for iter := 0; iter < maxIterations; iter++ {
		// Alice loop iteration
		if !aliceDone {
			s, err := listenerAlice.Listen(MinDeadLine, uint64(iter*int(msNano)))
			assert.NoError(t, err)

			// Alice writes to all streams
			for _, ss := range aliceStreams {
				if ss.sent < len(ss.data) {
					remaining := ss.data[ss.sent:]
					n, err := ss.stream.Write(remaining)
					assert.NoError(t, err)
					if n > 0 {
						ss.sent += n
					}
				}
			}

			// Alice reads responses
			if s != nil {
				data, err := s.Read()
				if err == nil && len(data) > 0 {
					aliceReceived[s.streamID] = append(aliceReceived[s.streamID], data...)
				}
			}

			listenerAlice.Flush(uint64(iter * int(msNano)))

			// Check if Alice is done
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
			if allSent && allReceived {
				aliceDone = true
			}
		}

		// Bob loop iteration
		if !bobDone {
			s, err := listenerBob.Listen(MinDeadLine, uint64(iter*int(msNano)))
			assert.NoError(t, err)

			if s != nil {
				data, err := s.Read()
				if err == nil && len(data) > 0 {
					bobReceived[s.streamID] += len(data)

					// When Bob receives complete stream, spawn response goroutine
					if bobReceived[s.streamID] >= dataSize && !bobResponded[s.streamID] {
						bobResponded[s.streamID] = true
						// Write response synchronously for test simplicity
						responseData := make([]byte, dataSize)
						for j := range responseData {
							responseData[j] = byte(s.streamID + 100) // Different pattern
						}
						
						for len(responseData) > 0 {
							n, err := s.Write(responseData)
							if err != nil {
								t.Fatalf("Bob write failed on stream %d: %v", s.streamID, err)
							}
							if n > 0 {
								responseData = responseData[n:]
							}
						}
						s.Close()
					}
				}
			}

			listenerBob.Flush(uint64(iter * int(msNano)))

			// Check if Bob is done (all streams responded)
			if len(bobResponded) == numStreams {
				allDone := true
				for i := 0; i < numStreams; i++ {
					if !bobResponded[uint32(i)] {
						allDone = false
						break
					}
				}
				if allDone {
					bobDone = true
				}
			}
		}

		if aliceDone && bobDone {
			t.Logf("Bidirectional 10-stream test completed in %d iterations", iter+1)
			
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
			
			return
		}
	}

	t.Errorf("Bidirectional test failed to complete in %d iterations", maxIterations)
	t.Logf("Alice done: %v, Bob done: %v", aliceDone, bobDone)
	for i := 0; i < numStreams; i++ {
		t.Logf("Alice stream %d: sent %d/%d, received %d/%d",
			i, aliceStreams[i].sent, dataSize, len(aliceReceived[uint32(i)]), dataSize)
		t.Logf("Bob stream %d: received %d/%d, responded: %v",
			i, bobReceived[uint32(i)], dataSize, bobResponded[uint32(i)])
	}
}