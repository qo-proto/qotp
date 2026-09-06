package qotp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// A wildcard-bound listener on a host with several addresses must reply from
// the address the peer used. Replying from the kernel's default source instead
// gets the packet dropped by any stateful firewall or NAT in front of the peer.
func TestMultiHomed_ReplyUsesContactedAddress(t *testing.T) {
	// Two loopback addresses stand in for a multi-homed host.
	const a1, a2 = "127.0.0.1", "127.0.0.2"

	srv, err := Listen(WithListenAddr("0.0.0.0:0")) // wildcard: the broken case
	assert.NoError(t, err)
	defer srv.Close()
	srvPort := srv.localConn.(*UDPNetworkConn).conn.LocalAddr().(*net.UDPAddr).Port

	// The responder's localAddr is owned by its event loop, so it is read
	// here, on that goroutine, and published over a channel.
	contacted := make(chan netip.Addr, 8)
	go srv.Loop(context.Background(), func(ctx context.Context, s *Stream) error {
		if s != nil {
			if d, _ := s.Read(); len(d) > 0 {
				s.Write([]byte("pong"))
				contacted <- s.conn.localAddr
			}
		}
		return nil
	})

	for _, dst := range []string{a1, a2} {
		t.Run("contacted via "+dst, func(t *testing.T) {
			// Bind the client to a fixed local address so we can see exactly
			// what the reply's source was.
			raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.3")})
			assert.NoError(t, err)
			defer raw.Close()

			cli, err := Listen(WithNetworkConn(NewUDPNetworkConn(raw)))
			assert.NoError(t, err)
			defer cli.Close()

			conn, err := cli.DialString(fmt.Sprintf("%s:%d", dst, srvPort))
			assert.NoError(t, err)
			st := conn.Stream(0)

			var got int
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sent := false
			cli.Loop(ctx, func(ctx context.Context, s *Stream) error {
				if !sent {
					if n, _ := st.Write([]byte("ping")); n > 0 {
						sent = true
					}
				}
				if d, _ := st.Read(); len(d) > 0 {
					got += len(d)
					return fmt.Errorf("done")
				}
				return nil
			})
			assert.Positive(t, got, "no reply reached the client")

			// The responder is the wildcard-bound side, so it is the one that
			// has to remember which of its addresses was contacted.
			select {
			case srvLocal := <-contacted:
				assert.Equal(t, netip.MustParseAddr(dst), srvLocal,
					"responder must reply from the address the peer contacted")
			case <-time.After(2 * time.Second):
				t.Fatal("responder never reported a local address")
			}
		})
	}
}
