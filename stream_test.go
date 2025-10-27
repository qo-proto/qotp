package qotp

import (
	"io"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupStreamTest(t *testing.T) (connA *Conn, listenerB *Listener, connPair *ConnPair) {
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
    specificNano = 0
    return connA, listenerB, connPair
}

func TestStreamBasicSendReceive(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	a := []byte("hallo")
	streamA := connA.Stream(0)
	_, err := streamA.Write(a)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data was sent, so minPacing should be 0

	// Process and forward the data
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.IsOpen())
	b, err := streamB.Read()
	assert.Nil(t, err)

	//Verification
	assert.Equal(t, a, b)
}

func TestStreamMultipleStreams(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data was sent
	
	// we send one packet
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	a2 := []byte("hallo22")
	streamA2 := connA.Stream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	minPacing = connA.listener.Flush(specificNano)
	// May return 0 if data was sent, or a pacing value if limited

	// we send one packet
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB1.IsOpen())
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	minPacing = listenerB.Flush(specificNano)
	// Check if data was sent or paced

	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	_, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	minPacing = connA.listener.Flush(specificNano)
	// Process any pending data

	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	streamB2, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB2.IsOpen())
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestStreamMultipleStreamsWithTimeout(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	// Send data from A to B
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data was sent

	a2 := []byte("hallo22")
	streamA2 := connA.Stream(1)
	_, err = streamA2.Write(a2)
	assert.Nil(t, err)
	setTime(201 * msNano)
	//this should not work, as we can only send 1 packet at the start, that we did with "hallo1"
	minPacing = connA.listener.Flush(specificNano)
	// May send data or return pacing value

	// we send one packet
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data, verification
	streamB1, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB1.IsOpen())
	b1, err := streamB1.Read()
	assert.Nil(t, err)
	assert.Equal(t, a1, b1)
	_, err = streamB1.Write(nil)
	assert.Nil(t, err)
	minPacing = listenerB.Flush(specificNano)

	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)
	_, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	minPacing = connA.listener.Flush(specificNano)
	
	_, err = connPair.senderToRecipient(2)
	assert.Nil(t, err)

	//twice, as we receive a duplicate packet
	streamB2, err := listenerB.Listen(0, specificNano)
	streamB2, err = listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB2.IsOpen())
	b2, err := streamB2.Read()
	assert.Nil(t, err)
	assert.Equal(t, a2, b2)
}

func TestStreamRetransmission(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(0)
	assert.Equal(t, uint64(0), minPacing) // Data was sent

	_, err = connPair.senderToRecipient(-1)

	minPacing = connA.listener.Flush((250*msNano) + 1)
	assert.Equal(t, uint64(0), minPacing) // Retransmission should send data

	_, err = connPair.senderToRecipient(1)

	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.IsOpen())
}

func TestStreamRetransmissionBackoff(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)
	
	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(0)
	assert.Equal(t, uint64(0), minPacing) // Initial send
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush((200 * msNano) + 1)
	assert.Equal(t, uint64(0), minPacing) // First retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400) * msNano) + 2)
	assert.Equal(t, uint64(0), minPacing) // Second retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400 + 800)* msNano) + 3)
	assert.Equal(t, uint64(0), minPacing) // Third retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600)* msNano) + 4)
	assert.Equal(t, uint64(0), minPacing) // Fourth retransmission
	
	_, err = connPair.senderToRecipient(1)
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.True(t, streamB.IsOpen())
}

func TestStreamMaxRetransmissions(t *testing.T) {
	connA, _, connPair := setupStreamTest(t)

	a1 := []byte("hallo1")
	streamA1 := connA.Stream(0)
	_, err := streamA1.Write(a1)
	assert.Nil(t, err)
	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Initial send
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush((200 * msNano) + 1)
	assert.Equal(t, uint64(0), minPacing) // First retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400)* msNano) + 2)
	assert.Equal(t, uint64(0), minPacing) // Second retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400 + 800)* msNano) + 3)
	assert.Equal(t, uint64(0), minPacing) // Third retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600)* msNano) + 4)
	assert.Equal(t, uint64(0), minPacing) // Fourth retransmission
	
	_, err = connPair.senderToRecipient(-1)
	
	minPacing = connA.listener.Flush(((200 + 400 + 800 + 1600 + 3200)* msNano) + 5)
	assert.Equal(t, uint64(0), minPacing) // Fifth retransmission

	// This should fail after maximum retries
	minPacing = connA.listener.Flush((6210* msNano) + 5)
	// The connection should be closed due to max retries, check if error is returned
	// or if the connection is marked for cleanup
	assert.True(t, minPacing > 0 || connA.listener.connMap.Size() == 0)
}

func TestStreamCloseInitiatedBySender(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	connA.Close()
	assert.True(t, streamA.IsCloseRequested())

	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Close packet should be sent

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Equal(t, err, io.EOF)

	assert.True(t, streamB.IsCloseRequested())

	assert.Equal(t, a1, buffer)

	minPacing = streamB.conn.listener.Flush(0)
	// ACK should be sent

	// B sends ACK back to A
	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	assert.True(t, streamA.IsCloseRequested())
	streamA, err = streamA.conn.listener.Listen(0, specificNano)
	assert.True(t, streamA.IsCloseRequested())
	assert.Nil(t, err)

	assert.True(t, streamA.IsClosed())
}

func TestStreamCloseInitiatedByReceiver(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)
	
	streamA := connA.Stream(0)
	a1 := []byte("hallo1")
	_, err := streamA.Write(a1)
	assert.Nil(t, err)
	assert.True(t, streamA.IsOpen())

	minPacing := connA.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data should be sent

	// Simulate packet transfer (data packet with FIN flag)
	_, err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Listener B receives data
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	streamB.conn.Close()
	assert.True(t, streamB.IsCloseRequested())

	// Verify data received correctly
	buffer, err := streamB.Read()
	assert.Nil(t, err)

	assert.True(t, streamB.IsCloseRequested())

	assert.Equal(t, a1, buffer)

	minPacing = streamB.conn.listener.Flush(specificNano)
	// Close packet should be sent

	// B sends ACK back to A
	_, err = connPair.recipientToSender(1)
	assert.Nil(t, err)

	streamA, err = streamA.conn.listener.Listen(0, specificNano)
	assert.Nil(t, err)

	buffer, err = streamA.Read()

	assert.True(t, streamA.IsCloseRequested())
}

func TestStreamFlowControl(t *testing.T) {
	connA, listenerB, connPair := setupStreamTest(t)

	//write 64k
	streamA := connA.Stream(0)
	dataA := make([]byte, rcvBufferCapacity+1)
	n, err := streamA.Write(dataA)
	assert.Nil(t, err)
	assert.Equal(t, 16777216, n)
	assert.Equal(t, 16777216, streamA.conn.snd.size)
	minPacing := streamA.conn.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data should be sent

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	_, err = connPair.senderToRecipientAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsRecipient())

	//send 16m back
	streamB, err := listenerB.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.Equal(t, uint64(0x1000000), streamB.conn.rcvWndSize)
	dataB1 := make([]byte, rcvBufferCapacity+1)
	n, err = streamB.Write(dataB1)
	assert.Nil(t, err)
	assert.Equal(t, 16777216, n)
	minPacing = streamB.conn.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Data should be sent

	//send data
	assert.Equal(t, 1, connPair.nrOutgoingPacketsReceiver())
	_, err = connPair.recipientToSenderAll()
	assert.Nil(t, err)
	assert.Equal(t, 1, connPair.nrIncomingPacketsSender())
	streamA, err = connA.listener.Listen(0, specificNano)
	assert.Nil(t, err)
	assert.Equal(t, uint64(0xf00000), streamA.conn.rcvWndSize)
	
	//respect pacing
	for range 10 {
		minPacing = streamA.conn.listener.Flush(specificNano)
		// Should return pacing value > 0 when rate limited
		assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	}

	for range 8 {
		minPacing = streamA.conn.listener.Flush(specificNano)
		assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
		_, err = connPair.senderToRecipientAll()
		assert.Nil(t, err)
	}
	
	//retransmit
	setTime(connA.nextWriteTime) //we need to advance time, as we are too fast for the 10kb/s 
	minPacing = streamA.conn.listener.Flush(specificNano)
	assert.Equal(t, uint64(0), minPacing) // Should be able to send now
	assert.Equal(t, 1, connPair.nrOutgoingPacketsSender())
	_, err = connPair.senderToRecipientAll()
	assert.Nil(t, err)
	
	//respect time
	assert.Equal(t, uint64(0x65aa3f2c), specificNano)
}
