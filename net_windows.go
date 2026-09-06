//go:build windows

package qotp

import (
	"net"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// IP_DONTFRAGMENT controls the Don't Fragment (DF) bit.
	// It's the same code point for both IPv4 and IPv6 on Windows.
	IP_DONTFRAGMENT = 14
)

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_windows.go
func setDontFragment(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, IP_DONTFRAGMENT, 1)
		errDFIPv6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, IP_DONTFRAGMENT, 1)
	}); err != nil {
		return err
	}

	logDFResult(errDFIPv4, errDFIPv6)
	return nil
}

// =============================================================================
// Destination-address reporting (IP_PKTINFO)
//
// Same idea as net_unix.go. WSA control messages have the POSIX layout but are
// aligned to the pointer size, and x/sys/windows offers no helpers for them,
// so the three CMSG macros are spelled out here.
// =============================================================================

const cmsgAlignTo = int(unsafe.Sizeof(uintptr(0)))

func cmsgAlign(n int) int { return (n + cmsgAlignTo - 1) &^ (cmsgAlignTo - 1) }

var cmsgHdrLen = cmsgAlign(int(unsafe.Sizeof(windows.WSACMSGHDR{})))

func cmsgLen(dataLen int) int   { return cmsgHdrLen + dataLen }
func cmsgSpace(dataLen int) int { return cmsgHdrLen + cmsgAlign(dataLen) }

const (
	sizeofInPktinfo  = int(unsafe.Sizeof(windows.IN_PKTINFO{}))
	sizeofIn6Pktinfo = int(unsafe.Sizeof(windows.IN6_PKTINFO{}))
)

// Room for one IPv6 pktinfo control message, which is the larger of the two.
var pktInfoOobSize = cmsgSpace(sizeofIn6Pktinfo)

// enablePktInfo asks the stack to report, with every datagram, the address it
// was actually sent to. On Windows the same option name enables reporting and
// tags the control message.
func enablePktInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var errIPv4, errIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errIPv4 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_PKTINFO, 1)
		errIPv6 = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO, 1)
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
// messages. Returns the zero Addr if it is not there, which leaves the reply's
// source to the stack.
func parseLocalAddr(oob []byte) netip.Addr {
	for len(oob) >= cmsgHdrLen {
		h := (*windows.WSACMSGHDR)(unsafe.Pointer(&oob[0]))
		n := int(h.Len)
		if n < cmsgHdrLen || n > len(oob) {
			break
		}
		data := oob[cmsgHdrLen:n]
		switch {
		case h.Level == windows.IPPROTO_IP && h.Type == windows.IP_PKTINFO && len(data) >= sizeofInPktinfo:
			pi := (*windows.IN_PKTINFO)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom4(pi.Addr)
		case h.Level == windows.IPPROTO_IPV6 && h.Type == windows.IPV6_PKTINFO && len(data) >= sizeofIn6Pktinfo:
			pi := (*windows.IN6_PKTINFO)(unsafe.Pointer(&data[0]))
			return netip.AddrFrom16(pi.Addr).Unmap()
		}
		next := cmsgAlign(n)
		if next > len(oob) {
			break
		}
		oob = oob[next:]
	}
	return netip.Addr{}
}

// srcControlMessage builds the control message that pins a reply's source
// address. Returns nil for the zero Addr, leaving the choice to the stack. An
// interface index of zero lets the routing table pick the interface.
func srcControlMessage(src netip.Addr) []byte {
	src = src.Unmap()
	switch {
	case !src.IsValid():
		return nil

	case src.Is4():
		b := make([]byte, cmsgSpace(sizeofInPktinfo))
		h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
		h.Len, h.Level, h.Type = uintptr(cmsgLen(sizeofInPktinfo)), windows.IPPROTO_IP, windows.IP_PKTINFO
		pi := (*windows.IN_PKTINFO)(unsafe.Pointer(&b[cmsgHdrLen]))
		pi.Addr = src.As4()
		return b

	default:
		b := make([]byte, cmsgSpace(sizeofIn6Pktinfo))
		h := (*windows.WSACMSGHDR)(unsafe.Pointer(&b[0]))
		h.Len, h.Level, h.Type = uintptr(cmsgLen(sizeofIn6Pktinfo)), windows.IPPROTO_IPV6, windows.IPV6_PKTINFO
		pi := (*windows.IN6_PKTINFO)(unsafe.Pointer(&b[cmsgHdrLen]))
		pi.Addr = src.As16()
		return b
	}
}
