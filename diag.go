package qotp

import (
	"log/slog"
	"os"
)

// =============================================================================
// Stall diagnostics
//
// Off unless QOTP_DIAG is set. When a connection delivers no acknowledged
// bytes for diagStallNano while it still has data to send, this reports every
// gate that could be holding it: the pacer, the receive window, the
// retransmission backlog per generation, and whether packets and ACKs are
// moving at all. One line per stall interval, on the event-loop goroutine.
// =============================================================================

var diagOn = os.Getenv("QOTP_DIAG") != ""

const (
	diagStallNano    = 200 * msNano
	diagMinDelivered = 1 << 20 // ignore connections that never got going
)

type diagState struct {
	lastNano      uint64
	lastDelivered uint64
	sent          uint64 // packets written since the last report
	acks          uint64 // ACKs processed since the last report
	stalling      bool
}

// diagCheck reports a stall in progress, and its end. Called per flush.
func (c *conn) diagCheck(s *Stream, ackPending bool, nowNano uint64) {
	d := &c.diag
	if d.lastNano == 0 {
		d.lastNano, d.lastDelivered = nowNano, c.deliveredBytes.Load()
		return
	}
	if nowNano-d.lastNano < diagStallNano {
		return
	}

	delivered := c.deliveredBytes.Load()
	progress := delivered - d.lastDelivered
	elapsed := nowNano - d.lastNano
	queued, g0, g1, g2 := c.snd.diagCounts(s.streamID)

	// Only bulk transfers that were already flowing: a short control exchange
	// with one packet outstanding is idle, not stalled.
	bulk := delivered > diagMinDelivered
	busy := queued > 0 || g0+g1+g2 > 1
	if bulk && busy && progress == 0 {
		d.stalling = true
		pacingWait := int64(0)
		if c.nextWriteTime > nowNano {
			pacingWait = int64(c.nextWriteTime-nowNano) / int64(msNano)
		}
		slog.Warn("DIAG stall",
			"conn", c.connId, "stream", s.streamID, "forMs", elapsed/uint64(msNano),
			"sent", d.sent, "acksIn", d.acks,
			"pacingWaitMs", pacingWait,
			"rwndBlocked", c.dataInFlight+c.mtu > int(c.rcvWndSize),
			"dataInFlight", c.dataInFlight, "rcvWnd", c.rcvWndSize,
			"queued", queued, "gen0", g0, "gen1", g1, "gen2plus", g2,
			"ackPending", ackPending,
			"throttlePct", c.throttlePct, "state", int(c.state),
			"bwMaxMbps", c.bwMax*8/1_000_000,
			"srttUs", c.srtt/1000, "rtoMs", c.rtoNano()/uint64(msNano),
			"mtu", c.mtu)
	} else if d.stalling && progress > 0 {
		d.stalling = false
		slog.Warn("DIAG recovered",
			"conn", c.connId, "stream", s.streamID,
			"afterMs", elapsed/uint64(msNano),
			"deliveredKB", progress/1024, "sent", d.sent, "acksIn", d.acks)
	}

	d.lastNano, d.lastDelivered = nowNano, delivered
	d.sent, d.acks = 0, 0
}
