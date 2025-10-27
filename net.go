package qotp

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

type NetworkConn interface {
	ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (n int, remoteAddr netip.AddrPort, err error)
	TimeoutReadNow() error
	WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort, nowNano uint64) (err error)
	Close() error
	LocalAddrString() string
}

type UDPNetworkConn struct {
	conn *net.UDPConn
	mu   sync.Mutex
}

func NewUDPNetworkConn(conn *net.UDPConn) NetworkConn {
	return &UDPNetworkConn{
		conn: conn,
		mu:   sync.Mutex{},
	}
}

func (c *UDPNetworkConn) ReadFromUDPAddrPort(p []byte, timeoutNano uint64, nowNano uint64) (
	n int, sourceAddress netip.AddrPort, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	readDeadline := time.Unix(0, int64(nowNano + timeoutNano))
	err = c.conn.SetReadDeadline(readDeadline)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n, sourceAddress, err = c.conn.ReadFromUDPAddrPort(p)

	return n, sourceAddress, err
}

func (c *UDPNetworkConn) TimeoutReadNow() error {
	return c.conn.SetReadDeadline(time.Time{})
}

func (c *UDPNetworkConn) WriteToUDPAddrPort(b []byte, remoteAddr netip.AddrPort, _ uint64) error {
	n, err := c.conn.WriteToUDPAddrPort(b, remoteAddr)
	if n != len(b) {
		return errors.New("could not send all data. This should not happen")
	}
	return err
}

func (c *UDPNetworkConn) Close() error {
	return c.conn.Close()
}

func (c *UDPNetworkConn) LocalAddrString() string {
	return c.conn.LocalAddr().String()
}
