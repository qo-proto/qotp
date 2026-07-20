package qotp

import (
	"io"
	"sync/atomic"
)

// =============================================================================
// Stream - Bidirectional byte stream within a connection
//
// Each connection can have multiple independent streams (multiplexing).
// Streams have separate send and receive directions that close independently.
// Read returns in-order data; Write queues data for transmission.
// =============================================================================

type Stream struct {
	streamID            uint32
	conn                *conn
	reliable            bool   // Retransmit lost data (default true)
	reorderDeadlineNano uint64 // Max wait for reordered data before skipping a gap (unreliable streams)

	// Close flags are written by the event loop and by user-goroutine Read,
	// and read lock-free by both sides — hence atomic. All other stream
	// state is either loop-owned or guarded by the send/receive buffer locks.
	rcvClosed atomic.Bool // Receive direction closed (received FIN)
	sndClosed atomic.Bool // Send direction closed (sent FIN and ACKed)
}

// =============================================================================
// Read/Write
// =============================================================================

// Read returns available in-order data from the stream.
// Returns io.EOF after receiving FIN and delivering all data.
// Returns nil data (not error) if no data available yet.
func (s *Stream) Read() ([]byte, error) {
	if s.rcvClosed.Load() {
		return nil, io.EOF
	}

	data := s.conn.rcv.removeOldestInOrder(s.streamID)

	if s.conn.rcv.isReadyToClose(s.streamID) {
		s.rcvClosed.Store(true)
	}

	return data, nil
}

// Write queues data for transmission. May return less than len(userData)
// if send buffer is full. Returns io.EOF if stream is closing.
func (s *Stream) Write(userData []byte) (int, error) {
	if s.sndClosed.Load() || s.IsCloseRequested() {
		return 0, io.EOF
	}

	if len(userData) == 0 {
		return 0, nil
	}

	n, status := s.conn.snd.queueData(s.streamID, userData)
	if status == insertStatusOk {
		// Signal to unblock any pending read so Flush can run
		if err := s.conn.listener.localConn.TimeoutReadNow(); err != nil {
			return 0, err
		}
	}

	return n, nil
}

// =============================================================================
// Stream lifecycle
// =============================================================================

// Close initiates graceful close of the send direction.
// Receive direction remains open until peer's FIN arrives.
func (s *Stream) Close() {
	s.conn.snd.close(s.streamID)
}

// IsClosed returns true when both directions are fully closed.
func (s *Stream) IsClosed() bool {
	return s.rcvClosed.Load() && s.sndClosed.Load()
}

// IsCloseRequested returns true if Close() has been called (FIN queued).
func (s *Stream) IsCloseRequested() bool {
	return s.conn.snd.getOffsetClosedAt(s.streamID) != nil
}

// IsOpen returns true if stream is not closing and not closed.
func (s *Stream) IsOpen() bool {
	return !s.IsCloseRequested() && !s.IsClosed()
}

// RcvClosed returns true if receive direction is closed.
func (s *Stream) RcvClosed() bool {
	return s.rcvClosed.Load()
}

// SndClosed returns true if send direction is fully closed (FIN ACKed).
func (s *Stream) SndClosed() bool {
	return s.sndClosed.Load()
}

// =============================================================================
// Configuration
// =============================================================================

// SetReliable controls whether lost data packets are retransmitted.
// Default is true. Set to false for real-time streams where retransmitting
// stale data is worse than dropping it. Call before the first Write: the
// receiver marks a stream unreliable on the first best-effort data packet
// and the marking is sticky.
//
// On an unreliable stream the delivered byte stream may have lost ranges
// silently removed (after the reorder deadline), so the application must do
// its own message framing. Close (FIN) and key updates are always
// retransmitted, and ACKs are best-effort in both modes.
func (s *Stream) SetReliable(reliable bool) {
	s.reliable = reliable
}

// SetReorderDeadlineNano sets how long the receiver waits for out-of-order
// data to fill a gap on an unreliable stream before skipping it (default
// 100ms). Lower values reduce added latency after a loss; higher values
// tolerate more network reordering. RTTNano/RTTVarNano can guide tuning,
// e.g. srtt/2 or 4*rttvar.
func (s *Stream) SetReorderDeadlineNano(deadlineNano uint64) {
	s.reorderDeadlineNano = deadlineNano
}

// RTTNano returns the connection's smoothed RTT estimate in nanoseconds
// (0 until the first RTT sample).
//
// Call this from the Loop callback: the RTT estimate is written by the event
// loop without a lock (the send path is single-goroutine), so reading it from
// another goroutine is a data race. No lock is taken here because a lock on
// the reader alone would not make it safe.
func (s *Stream) RTTNano() uint64 {
	return s.conn.srtt
}

// RTTVarNano returns the connection's RTT variation (jitter) estimate in
// nanoseconds (RFC 6298 rttvar). Call from the Loop callback - see RTTNano.
func (s *Stream) RTTVarNano() uint64 {
	return s.conn.rttvar
}

// LatePackets returns the number of packets on this stream that arrived
// after their range had already been skipped as lost. Safe from any
// goroutine (the counter is guarded by the receive buffer's lock).
func (s *Stream) LatePackets() uint64 {
	packets, _ := s.conn.rcv.lateStats(s.streamID)
	return packets
}

// LateBytes returns the number of bytes on this stream that arrived after
// their range had already been skipped as lost.
func (s *Stream) LateBytes() uint64 {
	_, bytes := s.conn.rcv.lateStats(s.streamID)
	return bytes
}

// =============================================================================
// Misc
// =============================================================================

func (s *Stream) StreamID() uint32 {
	return s.streamID
}

func (s *Stream) ConnID() uint64 {
	return s.conn.connId
}

// Ping queues a ping packet for RTT measurement.
func (s *Stream) Ping() {
	s.conn.snd.queuePing(s.streamID)
}

// NotifyDataAvailable interrupts any blocking read to allow immediate processing.
func (s *Stream) NotifyDataAvailable() error {
	return s.conn.listener.localConn.TimeoutReadNow()
}