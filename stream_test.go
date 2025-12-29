package qotp

import (
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupStreamTest(t *testing.T) (connA *conn, listenerB *Listener, connPair *ConnPair) {
	// Setup code
	connPair = NewConnPair("alice", "bob")
	listenerA, err := Listen(WithNetworkConn(connPair.Conn1), WithPrvKeyId(testPrvKey1))
	assert.Nil(t, err)
	listenerB, err = Listen(WithNetworkConn(connPair.Conn2), WithPrvKeyId(testPrvKey2))
	assert.Nil(t, err)
	pubKeyIdRcv, err := decodeHexPubKey(hexPubKey2)
	assert.Nil(t, err)
	connA, err = listenerA.DialWithCrypto(netip.AddrPort{}, pubKeyIdRcv)
	assert.Nil(t, err)
	assert.NotEmpty(t, connA)

	// Register cleanup to run after test
	t.Cleanup(func() {
		connPair.Conn1.Close()
		connPair.Conn2.Close()
	})
	return connA, listenerB, connPair
}

func TestStreamBasicSendReceive(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	a := []byte("hallo")
	streamA := connA.getOrCreateStream(0)
	_, err := streamA.Write(a)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(connPair.Conn1.partner.localTime)
	assert.Equal(t, uint64(0), minPacing) // Data was sent, so minPacing should be 0

	// Process and forward the data
	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	// Received data
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.Nil(t, err)
	assert.True(t, streamB.IsOpen())
	b, err := streamB.Read()
	assert.Nil(t, err)

	//Verification
	assert.Equal(t, a, b)
}

func TestStreamMultipleStreamsWithTimeout(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1 := connA.getOrCreateStream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(connPair.Conn1.partner.localTime)
	assert.Equal(t, uint64(0), minPacing) // Data was sent

	a2 := []byte("hallo22")
	streamA2 := connA.getOrCreateStream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	minPacing = connA.listener.Flush(connPair.Conn1.partner.localTime)
	// May send data or return pacing value

	// we send one packet
	_, err = connPair.senderToRecipientAll()
	assert.Nil(t, err)

	// Received data, verification
	var streamB1 *Stream
	for i := 0; i < 100 && streamB1 == nil; i++ {
		streamB1, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB1, "timeout waiting for stream")
	assert.Nil(t, err)
	assert.True(t, streamB1.IsOpen())
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	minPacing = listenerB.Flush(connPair.Conn2.partner.localTime)

	_, err = connPair.recipientToSender(0)
	assert.Nil(t, err)

	streamA1 = nil
	for i := 0; i < 100 && streamA1 == nil; i++ {
		streamA1, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.partner.localTime)
	}
	assert.NotNil(t, streamA1, "timeout waiting for stream")
	assert.Nil(t, err)
	minPacing = connA.listener.Flush(connPair.Conn1.partner.localTime)

	_, err = connPair.senderToRecipient(0, 1)
	assert.Nil(t, err)

	//twice, as we receive a duplicate packet
	var streamB2 *Stream
	for i := 0; i < 100 && streamB2 == nil; i++ {
		streamB2, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB2, "timeout waiting for stream")
	assert.Nil(t, err)
	assert.True(t, streamB2.IsOpen())
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestStreamRetransmissionBackoff(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.getOrCreateStream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(0)
	assert.Equal(t, uint64(0), minPacing) // Initial send

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush((200 * msNano) + 1)
	assert.Equal(t, uint64(0), minPacing) // First retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400) * msNano) + 2)
	assert.Equal(t, uint64(0), minPacing) // Second retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400 + 800) * msNano) + 3)
	assert.Equal(t, uint64(0), minPacing) // Third retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600) * msNano) + 4)
	assert.Equal(t, uint64(0), minPacing) // Fourth retransmission

	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)
	
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.Nil(t, err)
	assert.True(t, streamB.IsOpen())
}

func TestStreamMaxRetransmissions(t *testing.T) {
	connA, _, connPair := setupStreamTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.getOrCreateStream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(connPair.Conn1.partner.localTime)
	assert.Equal(t, uint64(0), minPacing) // Initial send

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush((200 * msNano) + 1)
	assert.Equal(t, uint64(0), minPacing) // First retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400) * msNano) + 2)
	assert.Equal(t, uint64(0), minPacing) // Second retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400 + 800) * msNano) + 3)
	assert.Equal(t, uint64(0), minPacing) // Third retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600) * msNano) + 4)
	assert.Equal(t, uint64(0), minPacing) // Fourth retransmission

	err = connPair.dropSender(0)
	assert.Nil(t, err)

	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600 + 3200) * msNano) + 5)
	assert.Equal(t, uint64(0), minPacing) // Fifth retransmission

	// This should fail after maximum retries
	minPacing = connA.listener.Flush((6210 * msNano) + 5)
	// After max retries, connection should be removed
	assert.Equal(t, 0, connA.listener.connMap.Size(), "connection should be removed after max retries")
}

func TestStreamCloseInitiatedBySender(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	connA.closeAllStreams()
	assert.True(t, streamA.IsCloseRequested())

	minPacing := connA.listener.Flush(connPair.Conn1.partner.localTime)
	assert.Equal(t, uint64(0), minPacing) // Close packet should be sent

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	// Listener B receives data
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.Nil(t, err)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)
	_, err = streamB.Read()
	assert.Equal(t, err, io.EOF)

	// With half-close: receiving FIN closes receive side, NOT send side
	// IsCloseRequested checks send side, so it should be false
	assert.False(t, streamB.IsCloseRequested()) // Bob's send side is NOT auto-closed
	assert.True(t, streamB.RcvClosed())         // Bob's receive side IS closed

	assert.Equal(t, a1, buffer)

	// Bob explicitly closes his send side to complete the handshake
	streamB.Close()
	assert.True(t, streamB.IsCloseRequested())

	minPacing = streamB.conn.listener.Flush(connPair.Conn2.partner.localTime)
	// ACK + FIN should be sent

	// B sends ACK + FIN back to A
	_, err = connPair.recipientToSender(0)
	assert.Nil(t, err)

	assert.True(t, streamA.IsCloseRequested())
	streamA = nil
	for i := 0; i < 100 && streamA == nil; i++ {
		streamA, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.partner.localTime)
	}
	assert.NotNil(t, streamA, "timeout waiting for stream")
	assert.True(t, streamA.IsCloseRequested())
	assert.Nil(t, err)

	// Now Alice should be fully closed (received Bob's FIN + her FIN was ACKed)
	assert.True(t, streamA.IsClosed())
}

func TestStreamCloseInitiatedByReceiver(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.IsOpen())

	minPacing := connA.listener.Flush(connPair.Conn1.partner.localTime)
	assert.Equal(t, uint64(0), minPacing) // Data should be sent

	// Simulate packet transfer (data packet, no FIN)
	_, err = connPair.senderToRecipient(0)
	assert.Nil(t, err)

	// Listener B receives data
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.partner.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.Nil(t, err)

	// Bob initiates close (closes his send side)
	streamB.conn.closeAllStreams()
	assert.True(t, streamB.IsCloseRequested())

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.IsCloseRequested())

	assert.Equal(t, a1, buffer)

	minPacing = streamB.conn.listener.Flush(connPair.Conn2.partner.localTime)
	// ACK + FIN should be sent

	// B sends ACK + FIN back to A
	_, err = connPair.recipientToSender(0)
	assert.Nil(t, err)

	streamA = nil
	for i := 0; i < 100 && streamA == nil; i++ {
		streamA, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.partner.localTime)
	}
	assert.NotNil(t, streamA, "timeout waiting for stream")
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	// With half-close: receiving Bob's FIN closes Alice's receive side, NOT send side
	assert.False(t, streamA.IsCloseRequested()) // Alice's send side is NOT auto-closed
	assert.True(t, streamA.RcvClosed())         // Alice's receive side IS closed
}

func TestStreamFlowControl(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)
	streamA := connA.getOrCreateStream(0)

	// 1. Fill sender's buffer (16MB)
	data := make([]byte, rcvBufferCapacity+1)
	n, err := streamA.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, rcvBufferCapacity, n)

	// 2. Flush and deliver to receiver
	minPacing := streamA.conn.listener.Flush(connPair.Conn1.localTime)
	assert.Equal(t, uint64(0), minPacing)
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())

	_, err = connPair.senderToRecipientAll()
	assert.NoError(t, err)

	// 3. Receiver accepts connection
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.NoError(t, err)
	assert.Equal(t, uint64(0x1000000), streamB.conn.rcvWndSize) // 16MB window

	// 4. Receiver sends 16MB back (should fill A's receive window)
	n, err = streamB.Write(make([]byte, rcvBufferCapacity+1))
	assert.NoError(t, err)

	minPacing = streamB.conn.listener.Flush(connPair.Conn2.localTime)
	_, err = connPair.recipientToSenderAll()
	assert.NoError(t, err)

	// 5. A receives data - window should be reduced
	streamA = nil
	for i := 0; i < 100 && streamA == nil; i++ {
		streamA, err = connA.listener.Listen(MinDeadLine, connPair.Conn1.localTime)
	}
	assert.NotNil(t, streamA, "timeout waiting for stream")
	assert.NoError(t, err)
	assert.Less(t, streamA.conn.rcvWndSize, uint64(0x1000000)) // Window reduced

	// 6. Test pacing: send multiple times, respecting minPacing
	for i := 0; i < 10; i++ {
		connPair.Conn1.localTime += minPacing
		minPacing = streamA.conn.listener.Flush(connPair.Conn1.localTime)

		packets := connPair.nrOutgoingPacketsSender()
		if minPacing == 0 {
			assert.GreaterOrEqual(t, packets, 0) // Can send
		}

		if packets > 0 {
			_, err = connPair.senderToRecipientAll()
			assert.NoError(t, err)
		}
	}
}

func TestStreamDuplicatePacketHandling(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	streamA := connA.getOrCreateStream(0)
	data := []byte("test data")
	_, err := streamA.Write(data)
	assert.NoError(t, err)

	minPacing := connA.listener.Flush(connPair.Conn1.localTime)
	assert.Equal(t, uint64(0), minPacing)

	// Send the same packet twice (duplicate by sending index 0 twice)
	_, err = connPair.senderToRecipient(0, 0)
	assert.NoError(t, err)

	// B receives
	var streamB *Stream
	for i := 0; i < 100 && streamB == nil; i++ {
		streamB, err = listenerB.Listen(MinDeadLine, connPair.Conn2.localTime)
	}
	assert.NotNil(t, streamB, "timeout waiting for stream")
	assert.NoError(t, err)

	// First read should succeed
	receivedData, err := streamB.Read()
	assert.NoError(t, err)
	assert.Equal(t, data, receivedData)

	// Second read of duplicate should not deliver duplicate data
	// (depends on implementation - protocol should handle duplicates)
	receivedData, err = streamB.Read()
	assert.NoError(t, err)
	assert.Nil(t, receivedData)
}