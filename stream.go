package qotp

import (
	"io"
	"sync/atomic"
)

const defaultGapTimeoutNano = uint64(100 * msNano) // see SetGapTimeoutNano

// Stream is a bidirectional byte stream within a connection. The two
// directions close independently.
type Stream struct {
	streamID       uint32
	conn           *conn
	reliable       bool
	gapTimeoutNano uint64

	// Written by the event loop and by Read on the user's goroutine
	rcvClosed atomic.Bool // FIN received and delivered
	sndClosed atomic.Bool // FIN sent and ACKed
}

// =============================================================================
// Read/Write
// =============================================================================

// Read returns available in-order data, nil if none yet, and io.EOF once
// the peer's FIN and everything before it have been delivered.
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

// Write queues data. It returns less than len(userData) when the send
// buffer is full, and io.EOF once the stream is closing.
func (s *Stream) Write(userData []byte) (int, error) {
	if s.sndClosed.Load() || s.IsCloseRequested() {
		return 0, io.EOF
	}

	n := s.conn.snd.queueData(s.streamID, userData)
	if n > 0 { // wake the loop so Flush can send it
		if err := s.conn.listener.localConn.TimeoutReadNow(); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// =============================================================================
// Stream lifecycle
// =============================================================================

// Close closes the send direction; receiving continues until the peer's FIN
func (s *Stream) Close() {
	s.conn.snd.close(s.streamID)
}

func (s *Stream) IsClosed() bool {
	return s.rcvClosed.Load() && s.sndClosed.Load()
}

// IsCloseRequested reports whether Close has been called
func (s *Stream) IsCloseRequested() bool {
	return s.conn.snd.isCloseRequested(s.streamID)
}

func (s *Stream) IsOpen() bool {
	return !s.IsCloseRequested() && !s.IsClosed()
}

func (s *Stream) RcvClosed() bool {
	return s.rcvClosed.Load()
}

func (s *Stream) SndClosed() bool {
	return s.sndClosed.Load()
}

// =============================================================================
// Configuration
// =============================================================================

// SetReliable controls whether lost data is retransmitted (default true).
// Call it before the first Write: the receiver's marking is sticky, so a
// stream can be made best-effort but not reliable again. On an unreliable
// stream lost ranges are removed from the byte stream after the gap timeout,
// so the application must do its own framing. FIN and key updates are
// always retransmitted.
func (s *Stream) SetReliable(reliable bool) {
	s.reliable = reliable
}

// SetGapTimeoutNano sets how long an unreliable stream waits for a missing
// packet before skipping it and delivering the data behind it (default
// 100ms). In-order data is never delayed. RTTNano and RTTVarNano can guide
// tuning, e.g. 4*rttvar.
func (s *Stream) SetGapTimeoutNano(timeoutNano uint64) {
	s.gapTimeoutNano = timeoutNano
}

func (s *Stream) GapTimeoutNano() uint64 {
	return s.gapTimeoutNano
}

// RTTNano is the smoothed RTT, 0 until the first sample. Call it from the
// Loop callback: the event loop writes it without a lock.
func (s *Stream) RTTNano() uint64 {
	return s.conn.srtt
}

// RTTVarNano is the RTT variation (RFC 6298). Call it from the Loop callback.
func (s *Stream) RTTVarNano() uint64 {
	return s.conn.rttvar
}

// LatePackets counts packets that arrived after their range was skipped as
// lost. Safe from any goroutine.
func (s *Stream) LatePackets() uint64 {
	packets, _ := s.conn.rcv.lateStats(s.streamID)
	return packets
}

func (s *Stream) LateBytes() uint64 {
	_, bytes := s.conn.rcv.lateStats(s.streamID)
	return bytes
}

// DroppedPackets counts packets dropped because the receive buffer was full,
// i.e. the application reads slower than the peer sends. On a reliable
// stream the peer retransmits them; on an unreliable one they are lost.
// Safe from any goroutine.
func (s *Stream) DroppedPackets() uint64 {
	packets, _ := s.conn.rcv.dropStats(s.streamID)
	return packets
}

func (s *Stream) DroppedBytes() uint64 {
	_, bytes := s.conn.rcv.dropStats(s.streamID)
	return bytes
}

// =============================================================================
// Misc
// =============================================================================

func (s *Stream) StreamID() uint32 {
	return s.streamID
}

// BytesAcked is the contiguous acknowledged offset of this stream. Safe
// from any goroutine.
func (s *Stream) BytesAcked() uint64 {
	return s.conn.snd.getOffsetAcked(s.streamID)
}

// BytesDelivered is the connection's acked payload in any order, so unlike
// BytesAcked it does not freeze at head-of-line holes: the better signal for
// rate sampling. Safe from any goroutine.
func (s *Stream) BytesDelivered() uint64 {
	return s.conn.deliveredBytes.Load()
}

// BytesReceived is the connection's payload accepted into the receive
// buffer, counted on arrival: the receive-side counterpart of
// BytesDelivered. Safe from any goroutine.
func (s *Stream) BytesReceived() uint64 {
	return s.conn.rcv.bytesReceived()
}

func (s *Stream) ConnID() uint64 {
	return s.conn.connId
}

// Ping queues a best-effort ping, e.g. for an RTT sample
func (s *Stream) Ping() {
	s.conn.snd.queuePing(s.streamID)
}

// NotifyDataAvailable wakes the event loop
func (s *Stream) NotifyDataAvailable() error {
	return s.conn.listener.localConn.TimeoutReadNow()
}
