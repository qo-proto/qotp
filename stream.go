package qotp

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
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
	_, file, line, _ := runtime.Caller(1)
	slog.Debug("Close called", gId(),
		"caller", fmt.Sprintf("%s:%d", file, line),
		"rcvClosed", s.rcvClosed,
		"sndClosed", s.sndClosed,
		"streamID", s.streamID)

	slog.Debug("Close called", s.debug())
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

func (s *Stream) Read() (userData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rcvClosed {
		slog.Debug("Read/closed", gId(), s.debug())
		return nil, io.EOF
	}

	data := s.conn.rcv.RemoveOldestInOrder(s.streamID)

	// check if our receive buffer is marked as closed
	if !s.rcvClosed && s.conn.rcv.IsReadyToClose(s.streamID) {
		// it is marked to close
		s.rcvClosed = true
		slog.Debug("Read/set closed", gId(), s.debug())

	}

	slog.Debug("Read", gId(), s.debug(), slog.Any("b…", userData[:min(16, len(userData))]))
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

	slog.Debug("Write", gId(), s.debug(), slog.Any("b…", userData[:min(16, len(userData))]))
	n, status := s.conn.snd.QueueData(s.streamID, userData)
	if status != InsertStatusOk {
		slog.Debug("Status Nok", gId(), s.debug(), slog.Any("status", status))
	} else {
		// data is read, so signal to cancel read, since we could do a flush
		err = s.conn.listener.localConn.TimeoutReadNow()
		if err != nil {
			return 0, err
		}
		slog.Debug("TimeoutReadNow called", gId(), s.debug())
	}

	return n, nil
}

func (s *Stream) debug() slog.Attr {
	var attr slog.Attr
	if s.conn == nil {
		attr = slog.String("conn", "s.conn is nil")
	} else if s.conn.listener == nil {
		attr = slog.String("conn", "s.conn.listener is nil")
	} else if s.conn.listener.localConn == nil {
		attr = slog.String("conn", "s.conn.listener.localConn is nil")
	} else {
		attr = slog.String("conn", s.conn.listener.localConn.LocalAddrString())
	}

	return slog.Group("net", attr, slog.Uint64("streamId", uint64(s.streamID)), s.conn.debug())
}
