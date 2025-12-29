package qotp

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// =============================================================================
// NetworkConn - Abstraction over UDP socket
//
// Allows injecting mock connections for testing (see net_test.go PairedConn).
// Real implementation wraps net.UDPConn.
// =============================================================================

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (n int, remoteAddr netip.AddrPort, err error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowNano uint64) error
	TimeoutReadNow() error
	Close() error
	LocalAddrString() string
}

// =============================================================================
// UDPNetworkConn - Real UDP socket implementation
// =============================================================================

type UDPNetworkConn struct {
	conn *net.UDPConn
	mu   sync.Mutex
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	return &UDPNetworkConn{conn: conn}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeoutNano, nowNano uint64) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Unix(0, int64(nowNano+timeoutNano))
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, err
	}

	return c.conn.ReadFromUDPAddrPort(p)
}

// TimeoutReadNow cancels any pending Read by setting deadline to the past.
// Used to unblock the reader when data is ready to send.
func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Unix(0, 1))
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, _ uint64) error {
	n, err := c.conn.WriteToUDPAddrPort(b, remoteAddr)
	if err != nil {
		return err
	}
	if n != len(b) {
		return errors.New("short write")
	}
	return nil
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}