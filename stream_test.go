package qotp

import (
	"fmt"
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// TEST HELPERS
// =============================================================================

func setupStreamTest(t *testing.T) (connA *conn, listenerB *Listener, connPair *ConnPair) {
	connPair = NewConnPair("alice", "bob")
	listenerA, err := Listen(WithNetworkConn(connPair.Conn1), WithPrvKeyId(testPrvKey1))
	assert.Nil(t, err)
	listenerB, err = Listen(WithNetworkConn(connPair.Conn2), WithPrvKeyId(testPrvKey2))
	assert.Nil(t, err)
	pubKeyIdRcv, err := decodeHexPubKey(fmt.Sprintf("0x%x", testPrvKey2.PublicKey().Bytes()))
	assert.Nil(t, err)
	connA, err = listenerA.DialWithCrypto(netip.AddrPort{}, pubKeyIdRcv)
	assert.Nil(t, err)
	assert.NotEmpty(t, connA)

	t.Cleanup(func() {
		connPair.Conn1.Close()
		connPair.Conn2.Close()
	})
	return connA, listenerB, connPair
}

// waitForStream polls until a stream is available or times out
func waitForStream(t *testing.T, listener *Listener, connPair *ConnPair, isRecipient bool) *Stream {
	var stream *Stream
	var err error
	var localTime uint64
	if isRecipient {
		localTime = connPair.Conn2.localTime
	} else {
		localTime = connPair.Conn1.localTime
	}
	for i := 0; i < 100 && stream == nil; i++ {
		stream, err = listener.Listen(MinDeadLine, localTime)
	}
	assert.NotNil(t, stream, "timeout waiting for stream")
	assert.Nil(t, err)
	return stream
}

// =============================================================================
// BASIC SEND/RECEIVE TESTS
// =============================================================================

func TestStream_BasicSendReceive(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	data := []byte("hello")
	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write(data)
	assert.Nil(t, err)

	minPacing := connA.listener.Flush(connPair.Conn1.localTime)
	assert.Equal(t, uint64(0), minPacing)

	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	// Receive
	streamB := waitForStream(t, listenerB, connPair, true)
	assert.True(t, streamB.IsOpen())

	received, err := streamB.Read()
	assert.Nil(t, err)
	assert.Equal(t, data, received)
}

func TestStream_ReadReturnsNilWhenNoData(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write([]byte("data"))
	assert.Nil(t, err)
	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0)

	streamB := waitForStream(t, listenerB, connPair, true)

	// First read gets data
	received, err := streamB.Read()
	assert.Nil(t, err)
	assert.Equal(t, []byte("data"), received)

	// Second read returns nil (no more data)
	received, err = streamB.Read()
	assert.Nil(t, err)
	assert.Nil(t, received)
}

func TestStream_WriteEmptyData(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	n, err := streamA.Write([]byte{})
	assert.Nil(t, err)
	assert.Equal(t, 0, n)

	n, err = streamA.Write(nil)
	assert.Nil(t, err)
	assert.Equal(t, 0, n)
}

// =============================================================================
// MULTIPLE STREAMS TESTS
// =============================================================================

func TestStream_MultipleStreams_SendReceive(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send on stream 0
	data1 := []byte("stream0-data")
	streamA1 := connA.getOrCreateStream(0)
	_, err := streamA1.Write(data1)
	assert.Nil(t, err)
	connA.listener.Flush(connPair.Conn1.localTime)

	// Send on stream 1
	data2 := []byte("stream1-data")
	streamA2 := connA.getOrCreateStream(1)
	_, err = streamA2.Write(data2)
	assert.Nil(t, err)

	// First packet sent
	connPair.senderToRecipientAll()

	// Receive stream 0
	streamB1 := waitForStream(t, listenerB, connPair, true)
	assert.True(t, streamB1.IsOpen())
	received1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, data1, received1)

	// Send ACK to allow more packets
	streamB1.Write(nil)
	listenerB.Flush(connPair.Conn2.localTime)
	connPair.recipientToSender(0)

	// Process ACK and send stream 1
	waitForStream(t, connA.listener, connPair, false)
	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0, 1)

	// Receive stream 1
	streamB2 := waitForStream(t, listenerB, connPair, true)
	assert.True(t, streamB2.IsOpen())
	received2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, data2, received2)
}

// =============================================================================
// RETRANSMISSION TESTS
// =============================================================================

func TestStream_Retransmission_FirstRetry(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	data := []byte("test")
	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write(data)
	assert.Nil(t, err)

	minPacing := connA.listener.Flush(0)
	assert.Equal(t, uint64(0), minPacing)

	// Drop the packet
	err = connPair.dropSender(0)
	assert.Nil(t, err)

	// First retransmission after RTO (200ms)
	minPacing = connA.listener.Flush((200 * msNano) + 1)
	assert.Equal(t, uint64(0), minPacing)

	// Deliver retransmitted packet
	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	streamB := waitForStream(t, listenerB, connPair, true)
	assert.True(t, streamB.IsOpen())
}

func TestStream_Retransmission_ExponentialBackoff(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	data := []byte("test")
	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write(data)
	assert.Nil(t, err)

	// Initial send
	connA.listener.Flush(0)
	connPair.dropSender(0)

	// 1st retry: 200ms
	connA.listener.Flush((200 * msNano) + 1)
	connPair.dropSender(0)

	// 2nd retry: 200 + 400 = 600ms
	connA.listener.Flush(((200 + 400) * msNano) + 2)
	connPair.dropSender(0)

	// 3rd retry: 200 + 400 + 800 = 1400ms
	connA.listener.Flush(((200 + 400 + 800) * msNano) + 3)
	connPair.dropSender(0)

	// 4th retry: 200 + 400 + 800 + 1600 = 3000ms
	minPacing := connA.listener.Flush(((200 + 400 + 800 + 1600) * msNano) + 4)
	assert.Equal(t, uint64(0), minPacing)

	// Finally deliver
	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	streamB := waitForStream(t, listenerB, connPair, true)
	assert.NotNil(t, streamB)
	assert.True(t, streamB.IsOpen())
}

func TestStream_Retransmission_MaxRetriesRemovesConnection(t *testing.T) {
	connA, _, connPair := setupStreamTest(t)

	data := []byte("test")
	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write(data)
	assert.Nil(t, err)

	// Initial send
	connA.listener.Flush(0)
	connPair.dropSender(0)

	// Exhaust all retries
	connA.listener.Flush((200 * msNano) + 1)
	connPair.dropSender(0)

	connA.listener.Flush(((200 + 400) * msNano) + 2)
	connPair.dropSender(0)

	connA.listener.Flush(((200 + 400 + 800) * msNano) + 3)
	connPair.dropSender(0)

	connA.listener.Flush(((200 + 400 + 800 + 1600) * msNano) + 4)
	connPair.dropSender(0)

	connA.listener.Flush(((200 + 400 + 800 + 1600 + 3200) * msNano) + 5)

	// After max retries, connection should be removed
	connA.listener.Flush((6210 * msNano) + 5)
	assert.Equal(t, 0, connA.listener.connMap.size(), "connection should be removed after max retries")
}

// =============================================================================
// CLOSE TESTS - SENDER INITIATED
// =============================================================================

func TestStream_Close_SenderInitiated_DataWithFIN(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	data := []byte("final")
	_, err := streamA.Write(data)
	assert.Nil(t, err)

	connA.closeAllStreams()
	assert.True(t, streamA.IsCloseRequested())

	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0)

	streamB := waitForStream(t, listenerB, connPair, true)

	// Read data
	received, err := streamB.Read()
	assert.Nil(t, err)
	assert.Equal(t, data, received)

	// Next read returns EOF (FIN received)
	_, err = streamB.Read()
	assert.Equal(t, io.EOF, err)
}

func TestStream_Close_SenderInitiated_HalfClose(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write([]byte("data"))
	assert.Nil(t, err)
	connA.closeAllStreams()

	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0)

	streamB := waitForStream(t, listenerB, connPair, true)
	streamB.Read()
	streamB.Read() // consume EOF

	// Half-close: receive side closed, send side open
	assert.True(t, streamB.RcvClosed())
	assert.False(t, streamB.IsCloseRequested())
}

func TestStream_Close_SenderInitiated_FullClose(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write([]byte("data"))
	assert.Nil(t, err)
	connA.closeAllStreams()
	assert.True(t, streamA.IsCloseRequested())

	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0)

	streamB := waitForStream(t, listenerB, connPair, true)
	streamB.Read()

	// Bob closes his send side
	streamB.Close()
	assert.True(t, streamB.IsCloseRequested())

	streamB.conn.listener.Flush(connPair.Conn2.localTime)
	connPair.recipientToSender(0)

	// Alice receives Bob's FIN
	streamA = nil
	for i := 0; i < 100 && streamA == nil; i++ {
		streamA, _ = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
	}
	assert.NotNil(t, streamA)

	// Alice is now fully closed
	assert.True(t, streamA.IsClosed())
}

// =============================================================================
// CLOSE TESTS - RECEIVER INITIATED
// =============================================================================

func TestStream_Close_ReceiverInitiated(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	data := []byte("data")
	_, err := streamA.Write(data)
	assert.Nil(t, err)
	assert.True(t, streamA.IsOpen())

	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipient(0)

	streamB := waitForStream(t, listenerB, connPair, true)

	// Bob initiates close
	streamB.conn.closeAllStreams()
	assert.True(t, streamB.IsCloseRequested())

	received, err := streamB.Read()
	assert.Nil(t, err)
	assert.Equal(t, data, received)

	streamB.conn.listener.Flush(connPair.Conn2.localTime)
	connPair.recipientToSender(0)

	// Alice receives FIN
	streamA = nil
	for i := 0; i < 100 && streamA == nil; i++ {
		streamA, _ = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
	}
	assert.NotNil(t, streamA)

	// Half-close: Alice's receive side closed, send side open
	assert.True(t, streamA.RcvClosed())
	assert.False(t, streamA.IsCloseRequested())
}

// =============================================================================
// WRITE AFTER CLOSE TESTS
// =============================================================================

func TestStream_Write_AfterClose_ReturnsEOF(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	streamA.Close()

	n, err := streamA.Write([]byte("data"))

	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 0, n)
}

// =============================================================================
// FLOW CONTROL TESTS
// =============================================================================

func TestStream_FlowControl_SenderBufferFull(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	// Try to write more than buffer capacity
	data := make([]byte, rcvBufferCapacity+1)
	n, err := streamA.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, rcvBufferCapacity, n) // Only capacity bytes accepted
}

func TestStream_FlowControl_ReceiverWindowReduced(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	data := make([]byte, rcvBufferCapacity)
	streamA.Write(data)

	connA.listener.Flush(connPair.Conn1.localTime)
	connPair.senderToRecipientAll()

	streamB := waitForStream(t, listenerB, connPair, true)
	assert.Equal(t, uint64(0x1000000), streamB.conn.rcvWndSize) // 16MB

	// B sends data back
	streamB.Write(make([]byte, rcvBufferCapacity))
	streamB.conn.listener.Flush(connPair.Conn2.localTime)
	connPair.recipientToSenderAll()

	// A receives - window reduced
	for i := 0; i < 100; i++ {
		s, _ := connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
		if s != nil {
			break
		}
	}

	assert.Less(t, streamA.conn.rcvWndSize, uint64(0x1000000))
}

// =============================================================================
// DUPLICATE PACKET TESTS
// =============================================================================

func TestStream_DuplicatePacket_DeliveredOnce(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	data := []byte("test data")
	_, err := streamA.Write(data)
	assert.NoError(t, err)

	connA.listener.Flush(connPair.Conn1.localTime)

	// Send same packet twice
	_, err = connPair.senderToRecipient(0, 0)
	assert.NoError(t, err)

	streamB := waitForStream(t, listenerB, connPair, true)

	// First read gets data
	received, err := streamB.Read()
	assert.NoError(t, err)
	assert.Equal(t, data, received)

	// Second read returns nil (duplicate not delivered twice)
	received, err = streamB.Read()
	assert.NoError(t, err)
	assert.Nil(t, received)
}

// =============================================================================
// STREAM LIFECYCLE TESTS
// =============================================================================

func TestStream_IsOpen_Initially(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	assert.True(t, streamA.IsOpen())
	assert.False(t, streamA.IsCloseRequested())
	assert.False(t, streamA.IsClosed())
}

func TestStream_IsCloseRequested_AfterClose(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	streamA.Close()

	assert.True(t, streamA.IsCloseRequested())
	assert.False(t, streamA.IsOpen())
}

func TestStream_RcvClosed_Initially(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	assert.False(t, streamA.RcvClosed())
}

func TestStream_SndClosed_Initially(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	assert.False(t, streamA.SndClosed())
}

// =============================================================================
// STREAM ID AND CONN ID TESTS
// =============================================================================

func TestStream_StreamID(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	stream0 := connA.getOrCreateStream(0)
	stream5 := connA.getOrCreateStream(5)

	assert.Equal(t, uint32(0), stream0.StreamID())
	assert.Equal(t, uint32(5), stream5.StreamID())
}

func TestStream_ConnID(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	stream := connA.getOrCreateStream(0)

	assert.Equal(t, connA.connId, stream.ConnID())
}

// =============================================================================
// PING TESTS
// =============================================================================

func TestStream_Ping(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	// Queue a ping
	streamA.Ping()

	connA.listener.Flush(connPair.Conn1.localTime)

	// Ping packet sent
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())

	_, err := connPair.senderToRecipient(0)
	assert.Nil(t, err)

	// Receiver processes ping
	streamB := waitForStream(t, listenerB, connPair, true)
	assert.NotNil(t, streamB)
}

// =============================================================================
// NOTIFY DATA AVAILABLE TESTS
// =============================================================================

func TestStream_NotifyDataAvailable(t *testing.T) {
	connA, _, _ := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)

	// Should not error
	err := streamA.NotifyDataAvailable()
	assert.Nil(t, err)
}
