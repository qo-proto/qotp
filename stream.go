package qotp

import (
	"io"
	"log/slog"
	"sync"
)

type Stream struct {
	streamID     uint32
	conn         *Conn
	closedAtNano uint64 // 0 means not closed
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
	return s.closedAtNano != 0
}

func (s *Stream) IsCloseRequested() bool {
	return s.conn.snd.GetOffsetClosedAt(s.streamID) != nil
}

func (s *Stream) IsOpen() bool {
	return !s.IsCloseRequested() && !s.IsClosed()
}

func (s *Stream) Read() (userData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.closedAtNano != 0 {
		slog.Debug("Read/closed", gId(), s.debug())
		return nil, io.EOF
	}

	offset, data, receiveTimeNano := s.conn.rcv.RemoveOldestInOrder(s.streamID)

	// check if our receive buffer is marked as closed
	closeOffset := s.conn.rcv.GetOffsetClosedAt(s.streamID)
	if closeOffset != nil {
		// it is marked to close
		if offset >= *closeOffset {
			// we got all data, mark as closed //TODO check wrap around
			s.closedAtNano = receiveTimeNano
		}
	}

	slog.Debug("Read", gId(), s.debug(), slog.String("b…", string(data[:min(16, len(data))])))
	return data, nil
}

func (s *Stream) Write(userData []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closedAtNano != 0 || s.conn.snd.GetOffsetClosedAt(s.streamID) != nil {
		return 0, io.ErrUnexpectedEOF
	}

	if len(userData) == 0 {
		return 0, nil
	}

	slog.Debug("Write", gId(), s.debug(), slog.String("b…", string(userData[:min(16, len(userData))])))
	n, status := s.conn.snd.QueueData(s.streamID, userData)
	if status != InsertStatusOk {
		slog.Debug("Status Nok", gId(), s.debug(), slog.Any("status", status))
	} else {
		// data is read, so signal to cancel read, since we could do a flush
		err = s.conn.listener.localConn.TimeoutReadNow()
		if err != nil {
			return 0, err
		}
	}

	return n, nil
}

func (s *Stream) debug() slog.Attr {
	if s.conn == nil {
		return slog.String("net", "s.conn is nil")
	} else if s.conn.listener == nil {
		return slog.String("net", "s.conn.listener is nil")
	} else if s.conn.listener.localConn == nil {
		return slog.String("net", "s.conn.listener.localConn is nil")
	}

	return slog.String("net", s.conn.listener.localConn.LocalAddrString())
}
