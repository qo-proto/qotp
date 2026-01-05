//go:build darwin

package qotp

import (
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// based on https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_darwin.go
func setDontFragment(conn *net.UDPConn) error {
	if supportsDF, err := isAtLeastMacOS11(); !supportsDF || err != nil {
		return err
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	// Enabling IP_DONTFRAG will force the kernel to return "sendto: message too long"
	// and the datagram will not be fragmented
	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_DONTFRAG, 1)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
	}); err != nil {
		return err
	}

	logDFResult(errDFIPv4, errDFIPv6)
	return nil
}

func isAtLeastMacOS11() (bool, error) {
	uname := &unix.Utsname{}
	err := unix.Uname(uname)
	if err != nil {
		return false, err
	}

	release := string(uname.Release[:])
	if idx := strings.Index(release, "."); idx != -1 {
		version, err := strconv.Atoi(release[:idx])
		if err != nil {
			return false, err
		}
		// Darwin version 20 is macOS version 11
		// https://en.wikipedia.org/wiki/Darwin_(operating_system)#Darwin_20_onwards
		return version >= 20, nil
	}
	return false, nil
}
