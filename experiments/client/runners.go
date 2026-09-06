package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/qo-proto/qotp"
	"github.com/qo-proto/qotp/experiments/internal/bench"
	quic "github.com/quic-go/quic-go"
)

// =============================================================================
// TCP
// =============================================================================

func runTCP(addr string, dir bench.Dir, size uint64, prog *atomic.Uint64) (time.Duration, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	tc, _ := c.(*net.TCPConn)

	start := time.Now()
	if _, err := c.Write(bench.EncodeHeader(dir, size)); err != nil {
		return 0, err
	}

	if dir == bench.Download {
		if err := drain(c, size, prog); err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}

	filler := bench.Filler()
	for sent := uint64(0); sent < size; {
		n := uint64(len(filler))
		if r := size - sent; r < n {
			n = r
		}
		w, err := c.Write(filler[:n])
		if err != nil {
			return 0, err
		}
		sent += uint64(w)
		// Write-side bytes overstate delivery by the kernel send buffer; ask
		// the kernel what the peer actually acked.
		if tc != nil {
			if acked, ok := tcpBytesAcked(tc); ok {
				prog.Store(acked)
				continue
			}
		}
		prog.Store(sent)
	}
	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return 0, err
	}
	prog.Store(size)
	return time.Since(start), nil
}

// =============================================================================
// QUIC
// =============================================================================

func runQUIC(addr string, dir bench.Dir, size uint64, prog *atomic.Uint64) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), idleTimeout)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, bench.ClientTLS(), &quic.Config{MaxIdleTimeout: idleTimeout})
	if err != nil {
		return 0, err
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return 0, err
	}
	defer s.Close()

	start := time.Now()
	if _, err := s.Write(bench.EncodeHeader(dir, size)); err != nil {
		return 0, err
	}

	if dir == bench.Download {
		if err := drain(s, size, prog); err != nil {
			return 0, err
		}
		return time.Since(start), nil
	}

	filler := bench.Filler()
	for sent := uint64(0); sent < size; {
		n := uint64(len(filler))
		if r := size - sent; r < n {
			n = r
		}
		w, err := s.Write(filler[:n])
		if err != nil {
			return 0, err
		}
		sent += uint64(w)
		prog.Store(sent)
	}
	var ack [1]byte
	if _, err := io.ReadFull(s, ack[:]); err != nil {
		return 0, err
	}
	prog.Store(size)
	return time.Since(start), nil
}

// =============================================================================
// QOTP
//
// Event-loop driven: the transfer is a state machine advanced by the Loop
// callback, which returns errDone to break out once the run finishes.
// =============================================================================

var errDone = errors.New("done")

func runQOTP(addr string, dir bench.Dir, size uint64, prog *atomic.Uint64) (time.Duration, error) {
	ln, err := qotp.Listen(qotp.WithListenAddr("0.0.0.0:0"))
	if err != nil {
		return 0, err
	}
	defer ln.Close()

	conn, err := ln.DialString(addr)
	if err != nil {
		return 0, err
	}
	stream := conn.Stream(0)
	if stream == nil {
		return 0, fmt.Errorf("qotp: stream 0 unavailable")
	}

	hdr := bench.EncodeHeader(dir, size)
	filler := bench.Filler()
	toSend := uint64(len(hdr))
	if dir == bench.Upload {
		toSend += size
	}

	var sent, recvd uint64
	start := time.Now()
	var dur time.Duration

	ctx, cancel := context.WithTimeout(context.Background(), idleTimeout)
	defer cancel()

	loopErr := ln.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
		if sent < toSend {
			var chunk []byte
			switch {
			case sent < uint64(len(hdr)):
				chunk = hdr[sent:]
			default:
				n := uint64(len(filler))
				if r := toSend - sent; r < n {
					n = r
				}
				chunk = filler[:n]
			}
			n, err := stream.Write(chunk)
			if err != nil {
				return err
			}
			sent += uint64(n)
		}

		if data, err := stream.Read(); err == nil && len(data) > 0 {
			recvd += uint64(len(data))
		}

		if dir == bench.Upload {
			// BytesDelivered is connection-wide acked payload, which includes
			// the 9-byte header; the send buffer holds 16MB, so write-side
			// bytes would be badly wrong here.
			if d := stream.BytesDelivered(); d > uint64(len(hdr)) {
				prog.Store(d - uint64(len(hdr)))
			}
			if recvd >= 1 { // the server's ack
				dur = time.Since(start)
				prog.Store(size)
				return errDone
			}
		} else {
			prog.Store(recvd)
			if recvd >= size {
				dur = time.Since(start)
				return errDone
			}
		}
		return nil
	})
	if loopErr != nil && !errors.Is(loopErr, errDone) {
		return 0, loopErr
	}
	if dur == 0 {
		return 0, fmt.Errorf("qotp: transfer did not complete")
	}
	return dur, nil
}

// drain reads exactly size bytes, publishing progress as it goes.
func drain(r io.Reader, size uint64, prog *atomic.Uint64) error {
	buf := make([]byte, bench.Chunk)
	var got uint64
	for got < size {
		n := uint64(len(buf))
		if rem := size - got; rem < n {
			n = rem
		}
		k, err := r.Read(buf[:n])
		if k > 0 {
			got += uint64(k)
			prog.Store(got)
		}
		if got >= size {
			return nil // a final short read may also report EOF
		}
		if err != nil {
			return err
		}
	}
	return nil
}
