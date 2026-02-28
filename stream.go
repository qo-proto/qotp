package qotp

import (
	"io"
	"sync"
)

// =============================================================================
// Stream - Bidirectional byte stream within a connection
//
// Each connection can have multiple independent streams (multiplexing).
// Streams have separate send and receive directions that close independently.
// Read returns in-order data; Write queues data for transmission.
// =============================================================================

type Stream struct {
	streamID  uint32
	conn      *conn
	reliable  bool // Retransmit lost data (default true)
	rcvClosed bool // Receive direction closed (received FIN)
	sndClosed bool // Send direction closed (sent FIN and ACKed)
	mu        sync.Mutex
}

// =============================================================================
// Read/Write
// =============================================================================

// Read returns available in-order data from the stream.
// Returns io.EOF after receiving FIN and delivering all data.
// Returns nil data (not error) if no data available yet.
func (s *Stream) Read() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rcvClosed {
		return nil, io.EOF
	}

	data := s.conn.rcv.removeOldestInOrder(s.streamID)

	if s.conn.rcv.isReadyToClose(s.streamID) {
		s.rcvClosed = true
	}

	return data, nil
}

// Write queues data for transmission. May return less than len(userData)
// if send buffer is full. Returns io.EOF if stream is closing.
func (s *Stream) Write(userData []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sndClosed || s.IsCloseRequested() {
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
	return s.rcvClosed && s.sndClosed
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rcvClosed
}

// SndClosed returns true if send direction is fully closed (FIN ACKed).
func (s *Stream) SndClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sndClosed
}

// =============================================================================
// Configuration
// =============================================================================

// SetReliable controls whether lost data packets are retransmitted.
// Default is true. Set to false for real-time streams where
// retransmitting stale data is worse than dropping it.
// Control packets (close, key updates) are always retransmitted.
func (s *Stream) SetReliable(reliable bool) {
	s.reliable = reliable
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