package qotp

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The diagnostic is only worth shipping if it fires on the shape it is meant
// to catch -- a bulk transfer that stops delivering while it still has work --
// and stays quiet otherwise.
func TestDiag_FiresOnStallNotOnIdle(t *testing.T) {
	diagOn = true
	defer func() { diagOn = false }()

	newConn := func(delivered uint64, queue int) (*conn, *Stream, *bytes.Buffer) {
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		c := &conn{
			snd: newSendBuffer(sndBufferCapacity), rcv: newReceiveBuffer(rcvBufferCapacity),
			streams: newSharedLinkedMap[uint32, *Stream](), mtu: conservativeMTU,
			measurements: newMeasurements(), rcvWndSize: rcvBufferCapacity,
		}
		c.deliveredBytes.Store(delivered)
		if queue > 0 {
			c.snd.queueData(1, make([]byte, queue))
		}
		return c, &Stream{streamID: 1, conn: c, reliable: true}, &buf
	}
	// Two calls a stall interval apart with no delivery in between. Timestamps
	// start at 1: zero means "not yet initialised" to diagCheck.
	const t0, t1, t2 = uint64(1), diagStallNano + 2, 2*diagStallNano + 3
	run := func(c *conn, s *Stream) {
		c.diagCheck(s, false, t0)
		c.diagCheck(s, false, t1)
	}

	t.Run("bulk transfer that stops delivering", func(t *testing.T) {
		c, s, buf := newConn(diagMinDelivered+1, 4096)
		run(c, s)
		assert.Contains(t, buf.String(), "DIAG stall")
		assert.Contains(t, buf.String(), "queued=4096")
	})

	t.Run("recovery is reported", func(t *testing.T) {
		c, s, buf := newConn(diagMinDelivered+1, 4096)
		run(c, s)
		c.deliveredBytes.Add(64 * 1024)
		c.diagCheck(s, false, t2)
		assert.Contains(t, buf.String(), "DIAG recovered")
		assert.Contains(t, buf.String(), "deliveredKB=64")
	})

	t.Run("short exchange is idle, not stalled", func(t *testing.T) {
		c, s, buf := newConn(4096, 0) // never got going
		run(c, s)
		assert.NotContains(t, buf.String(), "DIAG")
	})

	t.Run("bulk transfer with nothing left to send", func(t *testing.T) {
		c, s, buf := newConn(diagMinDelivered+1, 0)
		run(c, s)
		assert.NotContains(t, buf.String(), "DIAG")
	})
}
