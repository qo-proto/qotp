//go:build windows

package qotp

import (
	"net"

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
