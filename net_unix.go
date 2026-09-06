//go:build linux || darwin

package qotp

import (
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"
)

// =============================================================================
// Destination-address reporting (IP_PKTINFO)
//
// Linux and Darwin share the control-message layout; they differ only in the
// option that turns reporting on, which each OS file provides as
// ipv4RecvPktInfo.
// =============================================================================

// Room for one IPv6 pktinfo control message, which is the larger of the two.
var pktInfoOobSize = unix.CmsgSpace(unix.SizeofInet6Pktinfo)

// enablePktInfo asks the kernel to report, with every datagram, the address it
// was actually sent to. Without it a wildcard-bound socket cannot know which
// of the host's addresses a peer used.
func enablePktInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var errIPv4, errIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4RecvPktInfo, 1)
		errIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	}); err != nil {
		return err
	}
	// A v4-only or v6-only socket rejects the other family's option; one
	// working is enough.
	if errIPv4 != nil && errIPv6 != nil {
		return errIPv4
	}
	return nil
}

// parseLocalAddr pulls the datagram's destination address out of the control
// message. Returns the zero Addr if it is not there, which leaves the reply's
// source to the kernel.
func parseLocalAddr(oob []byte) netip.Addr {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO:
			if len(m.Data) < unix.SizeofInet4Pktinfo {
				continue
			}
			pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&m.Data[0]))
			// Addr is the destination in the IP header: the address the peer
			// aimed at, which is what the reply must come from.
			return netip.AddrFrom4(pi.Addr)
		case m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_PKTINFO:
			if len(m.Data) < unix.SizeofInet6Pktinfo {
				continue
			}
			pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&m.Data[0]))
			// A dual-stack socket reports an IPv4 destination in 16-byte
			// mapped form; unmap so it is one canonical value everywhere.
			return netip.AddrFrom16(pi.Addr).Unmap()
		}
	}
	return netip.Addr{}
}

// srcControlMessage builds the control message that pins a reply's source
// address. Returns nil for the zero Addr, leaving the choice to the kernel.
func srcControlMessage(src netip.Addr) []byte {
	src = src.Unmap()
	switch {
	case !src.IsValid():
		return nil

	case src.Is4():
		b := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.IPPROTO_IP
		h.Type = unix.IP_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
		// Spec_dst, not Addr: on send this field is what sets the source.
		pi := (*unix.Inet4Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
		pi.Spec_dst = src.As4()
		return b

	default:
		b := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
		h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level = unix.IPPROTO_IPV6
		h.Type = unix.IPV6_PKTINFO
		h.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
		pi := (*unix.Inet6Pktinfo)(unsafe.Pointer(&b[unix.CmsgLen(0)]))
		pi.Addr = src.As16()
		return b
	}
}
