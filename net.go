package qotp

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// NetworkConn abstracts the UDP socket so tests can inject a mock.
//
// Time is the caller's: nowNano is its stamp, and a read returns elapsedNano
// measured from that stamp, so the arrival time is nowNano+elapsedNano.
// Measuring from any later point would date arrivals early and shorten RTT
// samples.
//
// localAddr is the address the peer sent to. A wildcard-bound socket on a
// multi-homed host would otherwise reply from whatever source the kernel
// picks, which a stateful firewall on the peer's side drops. The zero Addr
// leaves the choice to the kernel.
type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (n int, remoteAddr netip.AddrPort, localAddr netip.Addr, elapsedNano uint64, err error)
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, localAddr netip.Addr, nowNano uint64) error
	TimeoutReadNow() error
	Close() error
	LocalAddrString() string
}

type UDPNetworkConn struct {
	conn *net.UDPConn
	// Scratch buffer for the destination-address control message; nil when
	// the platform cannot report it or the socket is bound to one address
	oob []byte
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	c := &UDPNetworkConn{conn: conn}
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

	if c.oob == nil {
		n, addr, err := c.conn.ReadFromUDPAddrPort(p)
		return n, addr, netip.Addr{}, sinceNano(nowNano), err
	}
	n, oobn, _, addr, err := c.conn.ReadMsgUDPAddrPort(p, c.oob)
	return n, addr, parseLocalAddr(c.oob[:oobn]), sinceNano(nowNano), err
}

// sinceNano clamps at zero so a clock stepped backwards cannot wrap it
func sinceNano(nowNano uint64) uint64 {
	if n := uint64(time.Now().UnixNano()); n > nowNano {
		return n - nowNano
	}
	return 0
}

// TimeoutReadNow unblocks a pending read
func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Unix(0, 1))
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, localAddr netip.Addr, _ uint64) error {
	var n int
	var err error
	if oob := srcControlMessage(localAddr); oob != nil {
		n, _, err = c.conn.WriteMsgUDPAddrPort(b, oob, remoteAddr)
	} else {
		n, err = c.conn.WriteToUDPAddrPort(b, remoteAddr)
	}
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
