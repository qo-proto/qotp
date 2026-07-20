//go:build !linux

package main

import "net"

// tcpBytesAcked is unavailable off Linux; callers fall back to the
// write-side counter (kernel-buffer skew).
func tcpBytesAcked(conn *net.TCPConn) (uint64, bool) {
	return 0, false
}
