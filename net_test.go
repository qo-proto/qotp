package qotp

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// =============================================================================
// MOCK NETWORK IMPLEMENTATION FOR TESTING
// =============================================================================

// ConnPair represents a pair of connected NetworkConn implementations
type ConnPair struct {
	Conn1 *PairedConn
	Conn2 *PairedConn
}

// PairedConn implements the NetworkConn interface and connects to a partner
type PairedConn struct {
	localAddr string
	partner   *PairedConn

	// Write buffer
	writeQueue   []packetData
	writeQueueMu sync.Mutex

	// Read buffer
	readQueue   []packetData
	readQueueMu sync.Mutex

	latencyNano uint64 // One-way latency in nanoseconds
	bandwidth   uint64 // Bandwidth in bytes per second (0 = unlimited)
	localTime   uint64

	closed bool
}

// packetData represents a UDP packet
type packetData struct {
	data        []byte
	remoteAddr  string
	arrivalTime uint64
}

// NewConnPair creates a pair of connected NetworkConn implementations
func NewConnPair(addr1 string, addr2 string) *ConnPair {
	conn1 := newPairedConn(addr1)
	conn2 := newPairedConn(addr2)

	conn1.bandwidth = 10000 // 10KB/s
	conn2.bandwidth = 10000 // 10KB/s

	// Connect the two connections
	conn1.partner = conn2
	conn2.partner = conn1

	return &ConnPair{
		Conn1: conn1,
		Conn2: conn2,
	}
}

// NewMockNetworkPair creates a ConnPair with default addresses for use in tests
func NewMockNetworkPair() *ConnPair {
	return NewConnPair("alice", "bob")
}

func (c *ConnPair) senderToRecipient(sequence ...int) (n int, err error) {
	return c.Conn1.copyData(sequence...)
}

func (c *ConnPair) senderToRecipientAll() (n int, err error) {
	return c.Conn1.copyData()
}

func (c *ConnPair) recipientToSenderAll() (n int, err error) {
	return c.Conn2.copyData()
}

func (c *ConnPair) recipientToSender(sequence ...int) (n int, err error) {
	return c.Conn2.copyData(sequence...)
}

func (c *ConnPair) dropSender(indices ...int) error {
	return c.Conn1.dropData(indices...)
}

func (c *ConnPair) dropReceiver(indices ...int) error {
	return c.Conn2.dropData(indices...)
}

func (c *ConnPair) nrOutgoingPacketsSender() int {
	return len(c.Conn1.writeQueue)
}

func (c *ConnPair) nrOutgoingPacketsReceiver() int {
	return len(c.Conn2.writeQueue)
}

func (c *ConnPair) nrIncomingPacketsRecipient() int {
	return len(c.Conn2.readQueue)
}

func (c *ConnPair) nrIncomingPacketsSender() int {
	return len(c.Conn1.readQueue)
}

// newPairedConn creates a new PairedConn instance
func newPairedConn(localAddr string) *PairedConn {
	return &PairedConn{
		localAddr:  localAddr,
		writeQueue: make([]packetData, 0),
		readQueue:  make([]packetData, 0),
	}
}

// ReadFromUDPAddrPort reads data from the read queue
func (p *PairedConn) ReadFromUDPAddrPort(buf []byte, timeoutNano uint64, nowNano uint64) (int, netip.AddrPort, error) {
	if p.isClosed() {
		return 0, netip.AddrPort{}, errors.New("connection closed")
	}

	p.readQueueMu.Lock()
	defer p.readQueueMu.Unlock()

	if len(p.readQueue) == 0 {
		p.localTime += timeoutNano
		return 0, netip.AddrPort{}, nil
	}

	packet := p.readQueue[0]

	timeUntilPacket := packet.arrivalTime - p.localTime
	if packet.arrivalTime < p.localTime || timeUntilPacket <= timeoutNano {
		p.localTime = packet.arrivalTime
		p.readQueue = p.readQueue[1:]
		n := copy(buf, packet.data)
		return n, netip.AddrPort{}, nil
	} else {
		p.localTime += timeoutNano
		return 0, netip.AddrPort{}, nil
	}
}

// TimeoutReadNow cancels any pending read operation
func (p *PairedConn) TimeoutReadNow() error {
	return nil
}

// WriteToUDPAddrPort writes data to the partner connection
func (p *PairedConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, nowNano uint64) error {
	if p.isClosed() {
		return errors.New("connection closed")
	}

	// Make a copy of the data
	dataCopy := make([]byte, len(b))
	n := copy(dataCopy, b)

	if n != len(b) {
		return errors.New("could not send all data. This should not happen")
	}

	// Calculate transmission time based on bandwidth
	// bandwidth is in bytes per second, data is in bytes
	transmissionNano := uint64(0)
	if p.bandwidth > 0 {
		transmissionNano = (uint64(len(b)) * secondNano) / p.bandwidth
	}

	p.writeQueueMu.Lock()
	p.writeQueue = append(p.writeQueue, packetData{
		data:        dataCopy,
		remoteAddr:  remoteAddr.String(),
		arrivalTime: p.localTime + p.latencyNano + transmissionNano,
	})
	p.writeQueueMu.Unlock()

	p.localTime += transmissionNano

	return nil
}

func (p *PairedConn) copyData(indices ...int) (int, error) {
	if p.isClosed() || p.partner == nil || p.partner.isClosed() {
		return 0, errors.New("connection or partner unavailable")
	}

	p.writeQueueMu.Lock()
	defer p.writeQueueMu.Unlock()

	if len(p.writeQueue) == 0 {
		return 0, nil
	}

	// No arguments: copy all packets
	if len(indices) == 0 {
		totalBytes := 0
		for _, pkt := range p.writeQueue {
			totalBytes += len(pkt.data)
		}

		p.partner.readQueueMu.Lock()
		p.partner.readQueue = append(p.partner.readQueue, p.writeQueue...)
		p.partner.readQueueMu.Unlock()

		p.writeQueue = nil
		return totalBytes, nil
	}

	// With arguments: use absolute indices (all positive)
	totalBytes := 0
	maxIdx := -1

	for _, idx := range indices {
		if idx < 0 || idx >= len(p.writeQueue) {
			continue // Skip invalid indices
		}

		if idx > maxIdx {
			maxIdx = idx
		}

		pkt := p.writeQueue[idx]
		totalBytes += len(pkt.data)

		p.partner.readQueueMu.Lock()
		p.partner.readQueue = append(p.partner.readQueue, pkt)
		p.partner.readQueueMu.Unlock()
	}

	// Remove processed packets up to maxIdx
	if maxIdx >= 0 && maxIdx < len(p.writeQueue) {
		p.writeQueue = p.writeQueue[maxIdx+1:]
	} else if maxIdx >= len(p.writeQueue)-1 {
		p.writeQueue = nil
	}

	return totalBytes, nil
}

func (p *PairedConn) dropData(indices ...int) error {
	if p.isClosed() {
		return errors.New("connection closed")
	}

	p.writeQueueMu.Lock()
	defer p.writeQueueMu.Unlock()

	if len(p.writeQueue) == 0 {
		return nil
	}

	// No arguments: drop all packets
	if len(indices) == 0 {
		p.writeQueue = nil
		return nil
	}

	// With arguments: drop specific indices
	// Create a set of indices to drop
	toDrop := make(map[int]bool)
	for _, idx := range indices {
		if idx >= 0 && idx < len(p.writeQueue) {
			toDrop[idx] = true
		}
	}

	// Keep only packets that are not dropped
	newQueue := make([]packetData, 0, len(p.writeQueue)-len(toDrop))
	for i, pkt := range p.writeQueue {
		if !toDrop[i] {
			newQueue = append(newQueue, pkt)
		}
	}
	p.writeQueue = newQueue

	return nil
}

// Close closes the connection
func (p *PairedConn) Close() error {
	if p.closed {
		return errors.New("connection already closed")
	}

	p.closed = true
	return nil
}

// LocalAddrString returns the local address
func (p *PairedConn) LocalAddrString() string {
	// Format the address as local→remote
	if p.partner != nil {
		return p.localAddr + "→" + p.partner.localAddr
	}
	return p.localAddr + "→?"
}

// Helper method to check if connection is closed
func (p *PairedConn) isClosed() bool {
	return p.closed
}

// =============================================================================
// CONNPAIR TESTS
// =============================================================================

func TestNet_NewConnPair(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")

	assert.NotNil(t, connPair)
	assert.NotNil(t, connPair.Conn1)
	assert.NotNil(t, connPair.Conn2)
}

func TestNet_NewConnPair_ProperlyLinked(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")

	assert.Equal(t, "addr1", connPair.Conn1.localAddr)
	assert.Equal(t, "addr2", connPair.Conn2.localAddr)
	assert.Equal(t, connPair.Conn2, connPair.Conn1.partner)
	assert.Equal(t, connPair.Conn1, connPair.Conn2.partner)
}

func TestNet_NewMockNetworkPair(t *testing.T) {
	connPair := NewMockNetworkPair()

	assert.NotNil(t, connPair)
	assert.NotNil(t, connPair.Conn1)
	assert.NotNil(t, connPair.Conn2)
}

// =============================================================================
// BIDIRECTIONAL COMMUNICATION TESTS
// =============================================================================

func TestNet_BidirectionalCommunication(t *testing.T) {
	connPair := NewConnPair("endpoint1", "endpoint2")
	endpoint1 := connPair.Conn1
	endpoint2 := connPair.Conn2

	dataFromEndpoint1 := []byte("message from endpoint 1")
	dataFromEndpoint2 := []byte("response from endpoint 2")

	// Endpoint1 -> Endpoint2
	err := endpoint1.WriteToUDPAddrPort(dataFromEndpoint1, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(0)
	assert.NoError(t, err)

	buffer := make([]byte, 100)
	n, _, err := endpoint2.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n)

	// Endpoint2 -> Endpoint1
	err = endpoint2.WriteToUDPAddrPort(dataFromEndpoint2, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.recipientToSender(0)
	assert.NoError(t, err)

	n, _, err = endpoint1.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n)
}

// =============================================================================
// LOCAL TIME TESTS
// =============================================================================

func TestNet_LocalTime_WriteAdvances(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1

	initialTime := sender.localTime
	testData := []byte("test")

	err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Greater(t, sender.localTime, initialTime)
}

func TestNet_LocalTime_ReadAdvancesToArrival(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	testData := []byte("test")

	err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(0)
	assert.NoError(t, err)

	receiverInitialTime := receiver.localTime
	buffer := make([]byte, 100)
	_, _, err = receiver.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Greater(t, receiver.localTime, receiverInitialTime)
}

func TestNet_LocalTime_TimeoutAdvances(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	receiver := connPair.Conn2

	initialTime := receiver.localTime
	timeout := uint64(5 * secondNano)

	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, timeout, 0)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Equal(t, initialTime+timeout, receiver.localTime)
}

// =============================================================================
// CONNECTION CLOSE TESTS
// =============================================================================

func TestNet_Write_ToClosedConnection(t *testing.T) {
	connPair := NewConnPair("conn1", "conn2")
	conn1 := connPair.Conn1

	err := conn1.Close()
	assert.NoError(t, err)

	err = conn1.WriteToUDPAddrPort([]byte("test data"), netip.AddrPort{}, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestNet_Read_FromClosedConnection(t *testing.T) {
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	err := conn.Close()
	assert.NoError(t, err)

	buffer := make([]byte, 100)
	_, _, err = conn.ReadFromUDPAddrPort(buffer, 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection closed")
}

func TestNet_Close_Twice(t *testing.T) {
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	err := conn.Close()
	assert.NoError(t, err)

	err = conn.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already closed")
}

// =============================================================================
// MULTIPLE WRITE TESTS
// =============================================================================

func TestNet_MultipleWrites_InOrder(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}

	for _, msg := range messages {
		err := sender.WriteToUDPAddrPort(msg, netip.AddrPort{}, 0)
		assert.NoError(t, err)
	}

	_, err := connPair.senderToRecipient(0, 1, 2)
	assert.NoError(t, err)

	buffer := make([]byte, 100)
	for _, expectedMsg := range messages {
		n, _, err := receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
		assert.NoError(t, err)
		assert.Equal(t, len(expectedMsg), n)
		assert.Equal(t, expectedMsg, buffer[:n])
	}
}

// =============================================================================
// LOCAL ADDR STRING TESTS
// =============================================================================

func TestNet_LocalAddrString(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")

	assert.Equal(t, "addr1→addr2", connPair.Conn1.LocalAddrString())
	assert.Equal(t, "addr2→addr1", connPair.Conn2.LocalAddrString())
}

func TestNet_LocalAddrString_NoPartner(t *testing.T) {
	conn := newPairedConn("lonely")
	assert.Equal(t, "lonely→?", conn.LocalAddrString())
}

// =============================================================================
// DROP DATA TESTS
// =============================================================================

func TestNet_Drop_SpecificPacket(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	testData1 := []byte("packet 1")
	testData2 := []byte("packet 2")

	err := sender.WriteToUDPAddrPort(testData1, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	err = sender.WriteToUDPAddrPort(testData2, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	// Drop packet 1, deliver packet 0
	err = connPair.dropSender(1)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(0)
	assert.NoError(t, err)

	// Should only receive packet 1
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)
	assert.Equal(t, testData1, buffer[:n])

	// No more data
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestNet_Drop_MultiplePackets(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1

	packets := [][]byte{
		[]byte("packet 0"),
		[]byte("packet 1"),
		[]byte("packet 2"),
		[]byte("packet 3"),
	}

	for _, pkt := range packets {
		err := sender.WriteToUDPAddrPort(pkt, netip.AddrPort{}, 0)
		assert.NoError(t, err)
	}

	// Drop packets 0 and 2
	err := connPair.dropSender(0, 2)
	assert.NoError(t, err)

	// Deliver remaining (now at indices 0 and 1)
	_, err = connPair.senderToRecipient(0, 1)
	assert.NoError(t, err)

	buffer := make([]byte, 100)

	n, _, _ := connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[1], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[3], buffer[:n])

	// No more packets
	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, 0, n)
}

func TestNet_Drop_AllPackets(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1

	err := sender.WriteToUDPAddrPort([]byte("packet"), netip.AddrPort{}, 0)
	assert.NoError(t, err)

	// Drop all (no indices)
	err = connPair.dropSender()
	assert.NoError(t, err)

	assert.Equal(t, 0, connPair.nrOutgoingPacketsSender())
}

func TestNet_Drop_EmptyQueue(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	err := connPair.dropSender(0)
	assert.NoError(t, err)
}

func TestNet_Drop_ClosedConnection(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	connPair.Conn1.Close()

	err := connPair.dropSender(0)
	assert.Error(t, err)
}

// =============================================================================
// LATENCY AND ARRIVAL TIME TESTS
// =============================================================================

func TestNet_PacketArrivesAfterTimeout(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Send packet with high latency
	sender.latencyNano = 10 * secondNano
	err := sender.WriteToUDPAddrPort([]byte("late packet"), netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(0)
	assert.NoError(t, err)

	// Try to read with short timeout
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, 1*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)

	// Now read with sufficient timeout
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, 20*secondNano, 0)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)
}

// =============================================================================
// COPY DATA TESTS
// =============================================================================

func TestNet_CopyData_All(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	packets := [][]byte{
		[]byte("packet 0"),
		[]byte("packet 1"),
		[]byte("packet 2"),
		[]byte("packet 3"),
	}

	for _, pkt := range packets {
		connPair.Conn1.WriteToUDPAddrPort(pkt, netip.AddrPort{}, 0)
	}

	n, err := connPair.senderToRecipient()
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	buffer := make([]byte, 100)
	for i := 0; i < 4; i++ {
		n, _, err := connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
		assert.NoError(t, err)
		assert.Greater(t, n, 0)
	}
}

func TestNet_CopyData_Reorder(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	packets := [][]byte{
		[]byte("packet 0"),
		[]byte("packet 1"),
		[]byte("packet 2"),
		[]byte("packet 3"),
	}

	for _, pkt := range packets {
		connPair.Conn1.WriteToUDPAddrPort(pkt, netip.AddrPort{}, 0)
	}

	// Reorder: 0, 2, 1, 3
	n, err := connPair.senderToRecipient(0, 2, 1, 3)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	buffer := make([]byte, 100)

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[0], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[2], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[1], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[3], buffer[:n])
}

func TestNet_CopyData_Duplicate(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	packets := [][]byte{
		[]byte("packet 0"),
		[]byte("packet 1"),
		[]byte("packet 2"),
		[]byte("packet 3"),
	}

	for _, pkt := range packets {
		connPair.Conn1.WriteToUDPAddrPort(pkt, netip.AddrPort{}, 0)
	}

	// Duplicate packet 1: 0, 1, 1, 2
	n, err := connPair.senderToRecipient(0, 1, 1, 2)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	buffer := make([]byte, 100)

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[0], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[1], buffer[:n])

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[1], buffer[:n]) // Duplicate

	n, _, _ = connPair.Conn2.ReadFromUDPAddrPort(buffer, MinDeadLine, 0)
	assert.Equal(t, packets[2], buffer[:n])
}

func TestNet_CopyData_EmptyQueue(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	n, err := connPair.senderToRecipient()
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestNet_CopyData_InvalidIndices(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	connPair.Conn1.WriteToUDPAddrPort([]byte("packet"), netip.AddrPort{}, 0)

	// Invalid indices are skipped
	n, err := connPair.senderToRecipient(-1, 100)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestNet_CopyData_ClosedConnection(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	connPair.Conn1.WriteToUDPAddrPort([]byte("packet"), netip.AddrPort{}, 0)

	connPair.Conn1.Close()

	_, err := connPair.senderToRecipient()
	assert.Error(t, err)
}

func TestNet_CopyData_ClosedPartner(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	connPair.Conn1.WriteToUDPAddrPort([]byte("packet"), netip.AddrPort{}, 0)

	connPair.Conn2.Close()

	_, err := connPair.senderToRecipient()
	assert.Error(t, err)
}

// =============================================================================
// QUEUE COUNT TESTS
// =============================================================================

func TestNet_QueueCounts(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")

	assert.Equal(t, 0, connPair.nrOutgoingPacketsSender())
	assert.Equal(t, 0, connPair.nrOutgoingPacketsReceiver())
	assert.Equal(t, 0, connPair.nrIncomingPacketsSender())
	assert.Equal(t, 0, connPair.nrIncomingPacketsRecipient())

	connPair.Conn1.WriteToUDPAddrPort([]byte("packet 1"), netip.AddrPort{}, 0)
	connPair.Conn1.WriteToUDPAddrPort([]byte("packet 2"), netip.AddrPort{}, 0)

	assert.Equal(t, 2, connPair.nrOutgoingPacketsSender())

	connPair.senderToRecipient()

	assert.Equal(t, 0, connPair.nrOutgoingPacketsSender())
	assert.Equal(t, 2, connPair.nrIncomingPacketsRecipient())
}