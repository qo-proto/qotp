//go:build !linux

package qotp

import (
	"errors"
	"net"
	"net/netip"
)

// Platforms without destination-address reporting wired up. Everything falls
// back to letting the kernel choose the source address, which is correct for
// a dialed connection and for any socket bound to one address. A wildcard-bound
// server on a multi-homed host should bind explicitly there.
var pktInfoOobSize = 0

func enablePktInfo(*net.UDPConn) error { return errors.New("not supported on this platform") }

func parseLocalAddr([]byte) netip.Addr { return netip.Addr{} }

func srcControlMessage(netip.Addr) []byte { return nil }
