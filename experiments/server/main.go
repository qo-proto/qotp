// Benchmark server: serves the same upload/download request on QOTP, TCP and
// QUIC so the three can be compared, including head-to-head on one link.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
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

// Long enough that a protocol still waiting its turn during a solo phase does
// not time out while the others transfer.
const idleTimeout = 5 * time.Minute

// Bytes the server has received per protocol, so the upload direction can be
// checked against the client's sender-side numbers.
var received = map[string]*atomic.Uint64{
	"qotp": {}, "tcp": {}, "quic": {},
}

func main() {
	addr := flag.String("addr", "0.0.0.0", "bind IP address")
	base := flag.Int("port", bench.DefaultPortBase, "base port: qotp=port, tcp=port+1, quic=port+2")
	verbose := flag.Bool("v", false, "enable qotp debug logging (skews timing)")
	flag.Parse()

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tcpLn := serveTCP(fmt.Sprintf("%s:%d", *addr, bench.Port(*base, "tcp")))
	quicLn, udpConn := serveQUIC(ctx, fmt.Sprintf("%s:%d", *addr, bench.Port(*base, "quic")))
	qotpLn := serveQOTP(ctx, fmt.Sprintf("%s:%d", *addr, bench.Port(*base, "qotp")))

	fmt.Printf("READY qotp=:%d tcp=:%d quic=:%d\n",
		bench.Port(*base, "qotp"), bench.Port(*base, "tcp"), bench.Port(*base, "quic"))

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
		log.Fatalf("tcp listen: %v", err)
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
		log.Fatalf("quic resolve: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("quic listen: %v", err)
	}
	ln, err := quic.Listen(udpConn, bench.ServerTLS(), &quic.Config{MaxIdleTimeout: idleTimeout})
	if err != nil {
		log.Fatalf("quic: %v", err)
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
}

func serveQOTP(ctx context.Context, addr string) *qotp.Listener {
	ln, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatalf("qotp listen: %v", err)
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
	if s.dir == bench.Upload && len(data) > 0 {
		s.got += uint64(len(data))
		received["qotp"].Add(uint64(len(data)))
	}
}

// pump makes progress on a session; reports whether it is finished.
func (s *qotpSession) pump(st *qotp.Stream) bool {
	if !s.haveHdr {
		return false
	}
	switch s.dir {
	case bench.Download:
		if s.sent < s.size {
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
