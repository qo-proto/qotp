package qotp

import (
	"io"
	"sync"
)

type Stream struct {
	streamID     uint32
	conn         *Conn
	rcvClosed    bool // When receive direction closed
	sndClosed    bool // When send direction closed
	mu           sync.Mutex
}

func (s *Stream) StreamID() uint32 {
	return s.streamID
}

func (s *Stream) NotifyDataAvailable() error {
	return s.conn.listener.localConn.TimeoutReadNow()
}

func (s *Stream) Ping() {
	s.conn.snd.QueuePing(s.streamID)
}

func (s *Stream) Close() {
	s.conn.snd.Close(s.streamID)
}

func (s *Stream) IsClosed() bool {
	return s.rcvClosed && s.sndClosed
}

func (s *Stream) IsCloseRequested() bool {
	return s.conn.snd.GetOffsetClosedAt(s.streamID) != nil
}

func (s *Stream) IsOpen() bool {
	return !s.IsCloseRequested() && !s.IsClosed()
}

func (s *Stream) Read() (data []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rcvClosed {
		return nil, io.EOF
	}

	data = s.conn.rcv.RemoveOldestInOrder(s.streamID)

	// check if our receive buffer is marked as closed
	if !s.rcvClosed && s.conn.rcv.IsReadyToClose(s.streamID) {
		// it is marked to close
		s.rcvClosed = true
	}

	return data, nil
}

func (s *Stream) Write(userData []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sndClosed || s.IsCloseRequested() {
		return 0, io.EOF
	}

	if len(userData) == 0 {
		return 0, nil
	}

	n, status := s.conn.snd.QueueData(s.streamID, userData)
	if status == InsertStatusOk {
		// data is read, so signal to cancel read, since we could do a flush
		err = s.conn.listener.localConn.TimeoutReadNow()
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}
