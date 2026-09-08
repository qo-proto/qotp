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
// never generate absolute timestamps, only durations measured from the
// caller's stamp (elapsedNano), so the caller can compute the completion time
// as nowNano+elapsedNano. Mock implementations return synthetic durations.
//
// Elapsed must run from nowNano and not from wherever the implementation
// starts counting: whatever sits in between — arming the read deadline, and
// any scheduling delay — is real waiting, and dropping it dates the arrival
// too early, which makes every RTT sample computed from it short.
// localAddr carries the address the peer actually sent to. A socket bound to
// a wildcard address on a multi-homed host would otherwise reply from whatever
// source the kernel picks, which is often not the address the peer contacted —
// and a stateful firewall or NAT on the peer's side drops that reply. The zero
// Addr means "no preference": the kernel chooses, which is right for a dialed
// connection and for platforms without the support.
type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (n int, remoteAddr netip.AddrPort, localAddr netip.Addr, elapsedNano uint64, err error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, localAddr netip.Addr, nowNano uint64) (elapsedNano uint64, err error)
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
	// oob is the scratch buffer for the destination-address control message.
	// nil when the platform cannot report it, or when the socket is bound to
	// one address and the kernel's choice is therefore already correct.
	oob []byte
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	c := &UDPNetworkConn{conn: conn}
	// Only wildcard-bound sockets can reply from the wrong address.
	if a, ok := conn.LocalAddr().(*net.UDPAddr); ok && (a.IP == nil || a.IP.IsUnspecified()) {
		if err := enablePktInfo(conn); err == nil {
			c.oob = make([]byte, pktInfoOobSize)
		} else {
			slog.Info("cannot track the local address of inbound packets; "+
				"replies may use the wrong source on a multi-homed host", "err", err)
		}
	}
	return c
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeoutNano, nowNano uint64) (int, netip.AddrPort, netip.Addr, uint64, error) {
	deadline := time.Unix(0, int64(nowNano+timeoutNano))
	if err := c.conn.SetReadDeadline(deadline); err != nil {
		return 0, netip.AddrPort{}, netip.Addr{}, 0, err
	}

	// Measured from nowNano: arming the deadline above and any scheduling
	// before the read are part of the wait too.
	if c.oob == nil {
		n, addr, err := c.conn.ReadFromUDPAddrPort(p)
		return n, addr, netip.Addr{}, sinceNano(nowNano), err
	}
	n, oobn, _, addr, err := c.conn.ReadMsgUDPAddrPort(p, c.oob)
	return n, addr, parseLocalAddr(c.oob[:oobn]), sinceNano(nowNano), err
}

// sinceNano is the time since a wall-clock nanosecond stamp, clamped at zero
// so that a clock stepped backwards during the read cannot wrap the result.
func sinceNano(nowNano uint64) uint64 {
	if n := uint64(time.Now().UnixNano()); n > nowNano {
		return n - nowNano
	}
	return 0
}

// TimeoutReadNow cancels any pending Read by setting deadline to the past.
// Used to unblock the reader when data is ready to send.
func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Unix(0, 1))
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, localAddr netip.Addr, _ uint64) (uint64, error) {
	start := time.Now()
	var n int
	var err error
	if oob := srcControlMessage(localAddr); oob != nil {
		n, _, err = c.conn.WriteMsgUDPAddrPort(b, oob, remoteAddr)
	} else {
		n, err = c.conn.WriteToUDPAddrPort(b, remoteAddr)
	}
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
