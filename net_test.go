package qotp

import (
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	setupLogger(slog.LevelDebug)
	os.Exit(m.Run())
}

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
	bandwidth   uint64 // Bandwidth in bits per second (0 = unlimited)
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

func (c *ConnPair) senderToRecipientOrder(order ...int) (n int, err error) {
	err = c.reorderSender(order...)
	if err != nil {
		return 0, err
	}
	return c.senderToRecipientAll()
}

func (c *ConnPair) senderToRecipient(sequence ...int) (n int, err error) {
	return c.Conn1.copyData(sequence...)
}

func (c *ConnPair) senderToRecipientAll() (n int, err error) {
	return c.Conn1.copyData(len(c.Conn1.writeQueue))
}

func (c *ConnPair) recipientToSenderAll() (n int, err error) {
	return c.Conn2.copyData(len(c.Conn2.writeQueue))
}

func (c *ConnPair) recipientToSender(sequence ...int) (n int, err error) {
	return c.Conn2.copyData(sequence...)
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
		slog.Debug("    ReadUDP/no data/no queue", slog.Uint64("localTime", p.localTime))
		return 0, netip.AddrPort{}, nil
	}

	packet := p.readQueue[0]

	timeUntilPacket := packet.arrivalTime - p.localTime
	if packet.arrivalTime < p.localTime || timeUntilPacket <= timeoutNano {
		p.localTime = packet.arrivalTime
		p.readQueue = p.readQueue[1:]
		n := copy(buf, packet.data)
		slog.Debug("    ReadUDP", slog.Int("len(data)", len(buf)))
		return n, netip.AddrPort{}, nil
	} else {
		p.localTime += timeoutNano
		slog.Debug("    ReadUDP/no data/in queue", slog.Uint64("localTime", p.localTime))
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
	// bandwidth is in bits per second, data is in bytes
	transmissionNano := uint64(0)
	if p.bandwidth > 0 {
		transmissionNano = (uint64(len(b)) * secondNano) / p.bandwidth
	}

	slog.Debug("    WriteUDP",
		slog.Int("len(data)", len(b)),
		slog.Uint64("bandwidth:B/s", p.bandwidth),
		slog.Uint64("latency:ms", p.latencyNano/msNano),
		slog.Uint64("tx-time:ms", transmissionNano/msNano))

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

func (p *PairedConn) copyData(sequence ...int) (int, error) {
	if p.isClosed() || p.partner == nil || p.partner.isClosed() {
		return 0, errors.New("connection or partner unavailable")
	}

	p.writeQueueMu.Lock()
	defer p.writeQueueMu.Unlock()

	if len(p.writeQueue) == 0 {
		return 0, nil
	}

	pos, totalBytes := 0, 0

	for _, count := range sequence {
		if count == 0 {
			continue
		}

		if pos >= len(p.writeQueue) {
			break
		}

		available := len(p.writeQueue) - pos
		absCount := count
		if count < 0 {
			absCount = -count
			slog.Debug("Net/Drop", slog.Int("#pckts", absCount), slog.String("net", p.localAddr+"→"+p.partner.localAddr))
		}
		if absCount > available {
			absCount = available
		}

		if count > 0 {
			// Copy packets AND count bytes
			packets := p.writeQueue[pos : pos+absCount]
			for _, pkt := range packets {
				totalBytes += len(pkt.data)
				slog.Debug("Time/Warp/Auto",
					slog.Int("len(data)", len(pkt.data)))
			}

			p.partner.readQueueMu.Lock()
			p.partner.readQueue = append(p.partner.readQueue, packets...)
			p.partner.readQueueMu.Unlock()
		}
		// For negative counts, we just advance position (drop packets)
		// without counting bytes or copying

		pos += absCount
	}

	// Remove processed packets
	p.writeQueue = p.writeQueue[pos:]

	return totalBytes, nil
}

func (c *ConnPair) reorderSender(order ...int) error {
	c.Conn1.writeQueueMu.Lock()
	defer c.Conn1.writeQueueMu.Unlock()

	if len(order) > len(c.Conn1.writeQueue) {
		return errors.New("order indices exceed queue size")
	}

	reordered := make([]packetData, len(order))
	for i, idx := range order {
		if idx < 0 || idx >= len(c.Conn1.writeQueue) {
			return errors.New("invalid order index")
		}
		reordered[i] = c.Conn1.writeQueue[idx]
	}
	c.Conn1.writeQueue = reordered
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

// LocalAddr returns the local address
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

//************************************* TESTS

func TestNewConnPair(t *testing.T) {
	// Test creating a new connection pair
	connPair := NewConnPair("addr1", "addr2")

	// Assert connections were created
	assert.NotNil(t, connPair)
	assert.NotNil(t, connPair.Conn1)
	assert.NotNil(t, connPair.Conn2)

	// Assert connections are properly linked
	conn1 := connPair.Conn1
	conn2 := connPair.Conn2

	assert.Equal(t, "addr1", conn1.localAddr)
	assert.Equal(t, "addr2", conn2.localAddr)
	assert.Equal(t, conn2, conn1.partner)
	assert.Equal(t, conn1, conn2.partner)
}

func TestBidirectionalCommunication(t *testing.T) {
	connPair := NewConnPair("endpoint1", "endpoint2")
	endpoint1 := connPair.Conn1
	endpoint2 := connPair.Conn2

	dataFromEndpoint1 := []byte("message from endpoint 1")
	dataFromEndpoint2 := []byte("response from endpoint 2")

	err := endpoint1.WriteToUDPAddrPort(dataFromEndpoint1, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	buffer := make([]byte, 100)
	n2, _, err := endpoint2.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n2)

	err = endpoint2.WriteToUDPAddrPort(dataFromEndpoint2, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.recipientToSender(1)
	assert.NoError(t, err)

	n4, _, err := endpoint1.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n4)
}

// Add test for localTime behavior:
func TestLocalTimeAdvancement(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	initialTime := sender.localTime
	testData := []byte("test")

	// Write advances sender time by transmission time
	err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Greater(t, sender.localTime, initialTime)

	_, err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	// Read advances receiver time to packet arrival
	receiverInitialTime := receiver.localTime
	buffer := make([]byte, 100)
	_, _, err = receiver.ReadFromUDPAddrPort(buffer, 10*secondNano, 0)
	assert.NoError(t, err)
	assert.Greater(t, receiver.localTime, receiverInitialTime)
}

// Add timeout test:
func TestReadTimeout(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	receiver := connPair.Conn2

	initialTime := receiver.localTime
	timeout := uint64(5 * secondNano)

	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, timeout, 0)
	assert.NoError(t, err)
	assert.Equal(t, 0, n) // No data
	assert.Equal(t, initialTime+timeout, receiver.localTime)
}

func TestWriteToClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn1 := connPair.Conn1

	// Close one connection
	err := conn1.Close()
	assert.NoError(t, err)

	// Attempt to write to the closed connection
	err = conn1.WriteToUDPAddrPort([]byte("test data"), netip.AddrPort{}, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestReadFromClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	// Close the connection
	err := conn.Close()
	assert.NoError(t, err)

	// Attempt to read from the closed connection
	buffer := make([]byte, 100)
	_, _, err = conn.ReadFromUDPAddrPort(buffer, 0, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection closed")
}

func TestCloseTwice(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	// Close the connection once
	err := conn.Close()
	assert.NoError(t, err)

	// Close the connection again
	err = conn.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already closed")
}

func TestMultipleWrites(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("isSender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Test data
	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}

	// Send all messages
	for _, msg := range messages {
		err := sender.WriteToUDPAddrPort(msg, netip.AddrPort{}, 0)
		assert.NoError(t, err)
	}

	_, err := connPair.senderToRecipient(3)
	assert.NoError(t, err)

	// Read and verify all messages in order
	buffer := make([]byte, 100)
	for _, expectedMsg := range messages {
		n, _, err := receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
		assert.NoError(t, err)
		assert.Equal(t, len(expectedMsg), n)
		assert.Equal(t, expectedMsg, buffer[:n])
	}
}

func TestLocalAddrString(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("addr1", "addr2")
	conn1 := connPair.Conn1
	conn2 := connPair.Conn2

	// Check local addresses
	assert.Equal(t, "addr1→addr2", conn1.LocalAddrString())
	assert.Equal(t, "addr2→addr1", conn2.LocalAddrString())
}

func TestWriteAndReadUDPWithDrop(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("isSender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Test data - two packets
	testData1 := []byte("packet 1")
	testData2 := []byte("packet 2")

	// Write both packets from isSender to receiver
	err := sender.WriteToUDPAddrPort(testData1, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	err = sender.WriteToUDPAddrPort(testData2, netip.AddrPort{}, 0)
	assert.NoError(t, err)

	// Copy the first packet and drop the second one
	_, err = connPair.senderToRecipient(1, -1) // Copy packet 1, Drop packet 2
	assert.NoError(t, err)

	// Read on receiver side - should only receive packet 1
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)
	assert.Equal(t, testData1, buffer[:n])

	// Verify that packet 2 was not received (no more data in the queue)
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, MinDeadLine, receiver.localTime)
	assert.NoError(t, err) // Should return no error but zero bytes
	assert.Equal(t, 0, n)
}

func TestPacketArrivesAfterTimeout(t *testing.T) {
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Send packet with latency
	sender.latencyNano = 10 * secondNano
	err := sender.WriteToUDPAddrPort([]byte("late packet"), netip.AddrPort{}, 0)
	assert.NoError(t, err)

	_, err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	// Try to read with short timeout (packet won't arrive in time)
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, 1*secondNano, 0)
	assert.NoError(t, err)
	assert.Equal(t, 0, n) // Timeout, no data

	// Now read with sufficient timeout
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, 20*secondNano, 0)
	assert.NoError(t, err)
	assert.Greater(t, n, 0) // Should get the packet
}
