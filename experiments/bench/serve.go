// Benchmark server: serves the same upload/download request on QOTP, TCP and
// QUIC so the three can be compared, including head-to-head on one link.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/qo-proto/qotp"
	"github.com/qo-proto/qotp/experiments/internal/bench"
	quic "github.com/quic-go/quic-go"
)

// Bytes the server has received per protocol, so the upload direction can be
// checked against the client's sender-side numbers.
// A client in duration mode just stops and closes; there is no FIN. Without an
// idle drop its session lives forever, and because the requested size is
// effectively unbounded the pump keeps writing into a dead connection on every
// loop iteration -- which starves the handshakes of later runs.
const sessionIdle = 15 * time.Second

// How far a download may run ahead of what the peer has acknowledged. Bounds
// the send buffer per session instead of queueing the whole requested size.
const downloadWindow = 2 << 20

var serverStartTime = time.Now()

// currentReport snapshots what this side measured.
func currentReport() bench.ServerReport {
	r := bench.ServerReport{
		NumCPU:        bench.NumCPU(),
		ReceivedBytes: map[string]uint64{},
		SessionSecs:   time.Since(serverStartTime).Seconds(),
	}
	for _, p := range bench.Protocols {
		r.ReceivedBytes[p] = received[p].Load()
	}
	c := bench.ReadCPU()
	r.CPUBusy, r.CPUTotal, r.CPUKnown = c.Busy, c.Total, c.OK
	return r
}

var received = map[string]*atomic.Uint64{
	"qotp": {}, "tcp": {}, "quic": {},
}

// serve runs the responder side until interrupted.
func serve(addrStr string, base int) {
	addr, b := &addrStr, &base
	serverStartTime = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpLn := serveTCP(fmt.Sprintf("%s:%d", *addr, bench.Port(*b, "tcp")))
	quicLn, udpConn := serveQUIC(ctx, fmt.Sprintf("%s:%d", *addr, bench.Port(*b, "quic")))
	qotpLn := serveQOTP(ctx, fmt.Sprintf("%s:%d", *addr, bench.Port(*b, "qotp")))

	fmt.Printf("READY qotp=:%d tcp=:%d quic=:%d\n",
		bench.Port(*b, "qotp"), bench.Port(*b, "tcp"), bench.Port(*b, "quic"))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()

	fmt.Println("\nreceived (upload direction, server side):")
	for _, p := range bench.Protocols {
		fmt.Printf("  %-5s %8.1f MB\n", p, float64(received[p].Load())/1e6)
	}

	tcpLn.Close()
	quicLn.Close()
	udpConn.Close()
	qotpLn.Close()
}

// =============================================================================
// TCP
// =============================================================================

func serveTCP(addr string) net.Listener {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		die("tcp listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if err := serveStream(c, "tcp"); err != nil && !isClosed(err) {
					log.Printf("tcp: %v", err)
				}
			}()
		}
	}()
	return ln
}

// =============================================================================
// QUIC
// =============================================================================

func serveQUIC(ctx context.Context, addr string) (*quic.Listener, *net.UDPConn) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		die("quic resolve: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		die("quic listen: %v", err)
	}
	ln, err := quic.Listen(udpConn, bench.ServerTLS(), &quic.Config{MaxIdleTimeout: idleTimeout})
	if err != nil {
		die("quic: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					go func() {
						defer s.Close()
						if err := serveStream(s, "quic"); err != nil && !isClosed(err) {
							log.Printf("quic: %v", err)
						}
					}()
				}
			}()
		}
	}()
	return ln, udpConn
}

// serveStream handles one request on any io.ReadWriter (TCP conn, QUIC stream).
func serveStream(rw io.ReadWriter, proto string) error {
	hdr := make([]byte, bench.HeaderSize)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return err
	}
	dir, size, err := bench.DecodeHeader(hdr)
	if err != nil {
		return err
	}

	if dir == bench.Report {
		body, err := encodeReport(currentReport())
		if err != nil {
			return err
		}
		_, err = rw.Write(body)
		return err
	}

	if dir == bench.Download {
		filler := bench.Filler()
		for sent := uint64(0); sent < size; {
			n := uint64(len(filler))
			if r := size - sent; r < n {
				n = r
			}
			w, err := rw.Write(filler[:n])
			if err != nil {
				return err
			}
			sent += uint64(w)
		}
		return nil
	}

	n, err := io.CopyN(io.Discard, rw, int64(size))
	received[proto].Add(uint64(n))
	if err != nil {
		return err
	}
	_, err = rw.Write([]byte{bench.AckByte})
	return err
}

// =============================================================================
// QOTP
//
// Event-loop rather than goroutine-per-connection, so request state lives in a
// map driven by the loop callback.
// =============================================================================

type qotpSession struct {
	hdr     []byte
	dir     bench.Dir
	size    uint64
	haveHdr bool
	got     uint64
	sent    uint64
	acked   bool
	filler  []byte
	reply   []byte // the responder's report, when dir is Report

	lastMark     uint64 // bytes moved as of lastProgress
	lastProgress time.Time
}

func serveQOTP(ctx context.Context, addr string) *qotp.Listener {
	ln, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		die("qotp listen: %v", err)
	}
	go func() {
		sessions := map[*qotp.Stream]*qotpSession{}
		err := ln.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
			if s != nil {
				sess := sessions[s]
				if sess == nil {
					sess = &qotpSession{filler: bench.Filler()}
					sessions[s] = sess
				}
				data, err := s.Read()
				if err == nil && len(data) > 0 {
					sess.feed(data)
				}
			}
			for st, sess := range sessions {
				if sess.pump(st) {
					delete(sessions, st)
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("qotp loop: %v", err)
		}
	}()
	return ln
}

// stalled reports whether the peer has stopped moving bytes for long enough
// that the session should be dropped.
func (s *qotpSession) stalled(st *qotp.Stream) bool {
	// Any forward movement counts, including a partly received header.
	moved := uint64(len(s.hdr)) + s.got
	if s.haveHdr && s.dir != bench.Upload {
		moved = st.BytesDelivered()
	}
	if moved != s.lastMark || s.lastProgress.IsZero() {
		s.lastMark, s.lastProgress = moved, time.Now()
		return false
	}
	return time.Since(s.lastProgress) > sessionIdle
}

func (s *qotpSession) feed(data []byte) {
	if !s.haveHdr {
		need := bench.HeaderSize - len(s.hdr)
		if need > len(data) {
			need = len(data)
		}
		s.hdr = append(s.hdr, data[:need]...)
		data = data[need:]
		if len(s.hdr) < bench.HeaderSize {
			return
		}
		dir, size, err := bench.DecodeHeader(s.hdr)
		if err != nil {
			return
		}
		s.dir, s.size, s.haveHdr = dir, size, true
	}
	if s.dir == bench.Report {
		return
	}
	if s.dir == bench.Upload && len(data) > 0 {
		s.got += uint64(len(data))
		received["qotp"].Add(uint64(len(data)))
	}
}

// pump makes progress on a session; reports whether it is finished or has been
// abandoned by its peer.
func (s *qotpSession) pump(st *qotp.Stream) bool {
	// The stall check comes first: a session whose peer vanished before the
	// header was complete would otherwise never be examined again.
	if s.stalled(st) {
		return true
	}
	if !s.haveHdr {
		return false
	}
	switch s.dir {
	case bench.Report:
		if s.reply == nil {
			body, err := encodeReport(currentReport())
			if err != nil {
				return true
			}
			s.reply = body
		}
		n, _ := st.Write(s.reply[s.sent:])
		s.sent += uint64(n)
		return s.sent >= uint64(len(s.reply))

	case bench.Download:
		// Stay within a window of what the peer has acknowledged, so a session
		// cannot queue the whole requested size into the send buffer.
		if s.sent < s.size && s.sent-st.BytesDelivered() < downloadWindow {
			n := uint64(len(s.filler))
			if r := s.size - s.sent; r < n {
				n = r
			}
			w, _ := st.Write(s.filler[:n])
			s.sent += uint64(w)
		}
		return s.sent >= s.size
	default:
		if s.got >= s.size && !s.acked {
			if n, _ := st.Write([]byte{bench.AckByte}); n == 1 {
				s.acked = true
			}
		}
		return s.acked
	}
}

func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
