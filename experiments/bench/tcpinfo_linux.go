//go:build linux

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// tcpBytesAcked reads tcpi_bytes_acked from the kernel: bytes the peer has
// acknowledged — true wire delivery, the TCP analogue of qotp's
// BytesDelivered. Returns false if the socket info is unavailable (e.g.,
// connection already closed).
func tcpBytesAcked(conn *net.TCPConn) (uint64, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var serr error
	if err := raw.Control(func(fd uintptr) {
		info, serr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || serr != nil || info == nil {
		return 0, false
	}
	return info.Bytes_acked, true
}
