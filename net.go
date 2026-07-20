package qotp

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// =============================================================================
// NetworkConn - Abstraction over UDP socket
//
// Allows injecting mock connections for testing (see net_test.go PairedConn).
// Real implementation wraps net.UDPConn.
// =============================================================================

// Absolute time is always supplied by the caller (nowNano); implementations
// never generate absolute timestamps. Blocking calls instead report how long
// they blocked (elapsedNano, monotonic), so the caller can compute the
// completion time as nowNano+elapsedNano — a pre-block timestamp must not be
// used for events that happen after the block (RTT samples would come out
// too small by the blocked duration). Mock implementations return synthetic
// durations.
type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (n int, remoteAddr netip.AddrPort, elapsedNano uint64, err error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowNano uint64) (elapsedNano uint64, err error)
	TimeoutReadNow() error
	Close() error
	LocalAddrString() string
}

// =============================================================================
// UDPNetworkConn - Real UDP socket implementation
// =============================================================================

// No mutex: net.UDPConn is goroutine-safe, and reads are only issued by the
// single event-loop goroutine. TimeoutReadNow intentionally runs concurrently
// with a blocked read (that is its purpose).
type UDPNetworkConn struct {
	conn *net.UDPConn
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	return &UDPNetworkConn{conn: conn}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeoutNano, nowNano uint64) (int, netip.AddrPort, uint64, error) {
	deadline := time.Unix(0, int64(nowNano+timeoutNano))
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, 0, err
	}

	// time.Since is monotonic: a wall-clock jump during the blocked read
	// cannot corrupt the elapsed duration
	start := time.Now()
	n, addr, err := c.conn.ReadFromUDPAddrPort(p)
	return n, addr, uint64(time.Since(start)), err
}

// TimeoutReadNow cancels any pending Read by setting deadline to the past.
// Used to unblock the reader when data is ready to send.
func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Unix(0, 1))
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, _ uint64) (uint64, error) {
	start := time.Now()
	n, err := c.conn.WriteToUDPAddrPort(b, remoteAddr)
	elapsed := uint64(time.Since(start))
	if err != nil {
		return elapsed, err
	}
	if n != len(b) {
		return elapsed, errors.New("short write")
	}
	return elapsed, nil
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}

func getInterfaceMTU(conn *net.UDPConn) int {
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 1500
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return 1500
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(localAddr.IP) {
				return iface.MTU
			}
		}
	}
	return 1500
}

func logDFResult(errIPv4, errIPv6 error) {
	switch {
	case errIPv4 == nil && errIPv6 == nil:
		slog.Info("setting DF for IPv4 and IPv6")
	case errIPv4 == nil && errIPv6 != nil:
		slog.Info("setting DF for IPv4 only")
	case errIPv4 != nil && errIPv6 == nil:
		slog.Info("setting DF for IPv6 only")
	case errIPv4 != nil && errIPv6 != nil:
		slog.Error("setting DF failed for both IPv4 and IPv6")
	}
}
