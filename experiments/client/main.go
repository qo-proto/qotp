package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qo-proto/qotp"
	"github.com/quic-go/quic-go/http3"
)

type result struct {
	protocol string
	size     int
	duration time.Duration
}

const sampleInterval = 100 * time.Millisecond

func main() {
	addr := flag.String("addr", "127.0.0.1", "server IP address")
	sizeMB := flag.Int("size", 32, "data size in MB")
	scenario := flag.String("scenario", "loopback", "scenario label for CSV")
	verbose := flag.Bool("v", false, "enable qotp debug logging (skews timing; for congestion-control analysis only)")
	proto := flag.String("proto", "", "comma-separated protocols to run CONCURRENTLY (tcp,qotp,quic); empty = all three sequentially")
	ratelog := flag.String("ratelog", "", "write per-protocol rate samples (protocol,t_s,mbps,cum_mb) to this file (concurrent mode)")
	flag.Parse()

	// Benchmark mode: suppress qotp's per-ACK debug logging, which would
	// otherwise penalize only qotp. Enable with -v for CC analysis.
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	data := make([]byte, *sizeMB*1024*1024)
	if _, err := rand.Read(data); err != nil {
		log.Fatal(err)
	}

	var results []result
	if *proto == "" {
		// Sequential: isolated capacity measurement. Concurrent runs would
		// contend for the CPU and the link and corrupt each protocol's
		// measurement.
		results = []result{
			runTCPClient(fmt.Sprintf("%s:9001", *addr), data),
			runQOTPClient(fmt.Sprintf("%s:9000", *addr), data),
			runHTTP3Client(fmt.Sprintf("%s:9002", *addr), data),
		}
	} else {
		// Concurrent: coexistence/fairness measurement — all listed
		// protocols share the bottleneck, started from a common barrier.
		results = runConcurrent(parseProtos(*proto), *addr, data, *ratelog)
	}

	w := csv.NewWriter(os.Stdout)
	defer w.Flush()

	for _, r := range results {
		w.Write([]string{
			r.protocol,
			fmt.Sprintf("%d", r.size/1024/1024),
			fmt.Sprintf("%.3f", float64(r.duration.Microseconds())/1000.0),
			*scenario,
		})
	}
}

func parseProtos(list string) []string {
	var protos []string
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "quic" || p == "http3" {
			p = "http3"
		}
		switch p {
		case "tcp", "qotp", "http3":
			protos = append(protos, p)
		default:
			log.Fatalf("unknown protocol %q (want tcp, qotp, quic)", p)
		}
	}
	return protos
}

// =============================================================================
// Concurrent mode
//
// Each runner sets up before the barrier (no wire traffic), then connects
// and transfers after it, so all protocols start cold at the same instant.
// A sampler polls each runner's cumulative progress every sampleInterval.
//
// Progress sources per protocol (skew noted; skews are constant offsets, so
// starvation patterns remain visible):
//   - qotp:  bytes ACKed by the peer (exact wire progress)
//   - tcp:   bytes written to the socket (skewed by the kernel send buffer)
//   - http3: bytes consumed from the request body by quic-go (skewed by its
//     internal flow-control buffering)
// =============================================================================

type runner struct {
	name     string
	progress func() uint64
	run      func() error // connect + transfer + wait for delivery
}

type rateSample struct {
	tMs int64
	cum uint64
}

func runConcurrent(protos []string, addr string, data []byte, ratelogPath string) []result {
	runners := make([]*runner, 0, len(protos))
	for _, p := range protos {
		switch p {
		case "tcp":
			runners = append(runners, newTCPRunner(fmt.Sprintf("%s:9001", addr), data))
		case "qotp":
			runners = append(runners, newQOTPRunner(fmt.Sprintf("%s:9000", addr), data))
		case "http3":
			runners = append(runners, newHTTP3Runner(fmt.Sprintf("%s:9002", addr), data))
		}
	}

	start := make(chan struct{})
	done := make(chan struct{})
	durations := make([]time.Duration, len(runners))

	var wg sync.WaitGroup
	for i, r := range runners {
		wg.Add(1)
		go func(i int, r *runner) {
			defer wg.Done()
			<-start
			begin := time.Now()
			if err := r.run(); err != nil {
				log.Fatalf("%s: %v", r.name, err)
			}
			durations[i] = time.Since(begin)
		}(i, r)
	}

	// Sampler: cumulative progress per runner on a fixed tick
	samples := make([][]rateSample, len(runners))
	var samplerWg sync.WaitGroup
	samplerWg.Add(1)
	go func() {
		defer samplerWg.Done()
		ticker := time.NewTicker(sampleInterval)
		defer ticker.Stop()
		begin := <-startedAt(start)
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				tMs := now.Sub(begin).Milliseconds()
				for i, r := range runners {
					samples[i] = append(samples[i], rateSample{tMs: tMs, cum: r.progress()})
				}
			}
		}
	}()

	close(start)
	wg.Wait()
	close(done)
	samplerWg.Wait()

	if ratelogPath != "" {
		writeRatelog(ratelogPath, runners, samples)
	}

	results := make([]result, len(runners))
	for i, r := range runners {
		results[i] = result{r.name, len(data), durations[i]}
	}
	return results
}

// startedAt converts the barrier close into a timestamped channel read.
func startedAt(start <-chan struct{}) <-chan time.Time {
	ch := make(chan time.Time, 1)
	go func() {
		<-start
		ch <- time.Now()
	}()
	return ch
}

func writeRatelog(path string, runners []*runner, samples [][]rateSample) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	fmt.Fprintln(f, "protocol,t_s,mbps,cum_mb")
	for i, r := range runners {
		var prev rateSample
		for _, s := range samples[i] {
			dtMs := s.tMs - prev.tMs
			if dtMs <= 0 {
				continue
			}
			mbps := float64(s.cum-prev.cum) * 8 / float64(dtMs) / 1000
			fmt.Fprintf(f, "%s,%.1f,%.2f,%.2f\n",
				r.name, float64(s.tMs)/1000, mbps, float64(s.cum)/1024/1024)
			prev = s
		}
	}
}

// =============================================================================
// Concurrent runners
// =============================================================================

func newTCPRunner(addr string, data []byte) *runner {
	var sent atomic.Uint64
	return &runner{
		name:     "tcp",
		progress: sent.Load,
		run: func() error {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer conn.Close()

			// Chunked writes so the progress counter tracks backpressure
			for off := 0; off < len(data); off += 64 * 1024 {
				end := min(off+64*1024, len(data))
				n, err := conn.Write(data[off:end])
				if err != nil {
					return err
				}
				sent.Add(uint64(n))
			}
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
				return err
			}
			// Wait for the server to receive everything and close its side
			_, err = io.Copy(io.Discard, conn)
			return err
		},
	}
}

func newQOTPRunner(addr string, data []byte) *runner {
	listener, err := qotp.Listen(qotp.WithListenAddr("0.0.0.0:0"))
	if err != nil {
		log.Fatal(err)
	}
	conn, err := listener.DialString(addr)
	if err != nil {
		log.Fatal(err)
	}
	stream := conn.Stream(0)

	return &runner{
		name:     "qotp",
		progress: stream.BytesAcked,
		run: func() error {
			defer listener.Close()
			written := 0
			size := len(data)
			return ignoreDone(listener.Loop(context.Background(), func(ctx context.Context, s *qotp.Stream) error {
				if written < size {
					n, _ := stream.Write(data[written:])
					written += n
				}
				if written >= size && !stream.IsCloseRequested() {
					stream.Close()
				}
				if stream.SndClosed() {
					return errDone
				}
				return nil
			}))
		},
	}
}

var errDone = fmt.Errorf("done")

func ignoreDone(err error) error {
	if err == errDone {
		return nil
	}
	return err
}

func newHTTP3Runner(addr string, data []byte) *runner {
	var consumed atomic.Uint64
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	return &runner{
		name:     "http3",
		progress: consumed.Load,
		run: func() error {
			defer tr.Close()

			pr, pw := io.Pipe()
			go func() {
				pw.Write(data)
				pw.Close()
			}()

			url := fmt.Sprintf("https://%s/bench", addr)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url,
				&countingReader{r: pr, n: &consumed})
			if err != nil {
				return err
			}
			req.ContentLength = int64(len(data))

			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
	}
}

type countingReader struct {
	r io.Reader
	n *atomic.Uint64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(uint64(n))
	return n, err
}

// =============================================================================
// Sequential mode (isolated capacity measurement)
// =============================================================================

func runTCPClient(addr string, data []byte) result {
	// Time connection setup too, matching QOTP (handshake in Loop) and
	// HTTP/3 (handshake in client.Do).
	start := time.Now()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	if _, err = conn.Write(data); err != nil {
		log.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
	// Wait for the server to receive everything and close its side. Without
	// this, CloseWrite returns locally and TCP would be timed on "handed to
	// kernel", not "delivered" — unlike QOTP (FIN ack) and HTTP/3 (response).
	io.Copy(io.Discard, conn)
	dur := time.Since(start)

	return result{"tcp", len(data), dur}
}

func runQOTPClient(addr string, data []byte) result {
	listener, err := qotp.Listen(qotp.WithListenAddr("0.0.0.0:0"))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	conn, err := listener.DialString(addr)
	if err != nil {
		log.Fatal(err)
	}

	stream := conn.Stream(0)
	written := 0
	size := len(data)

	start := time.Now()
	listener.Loop(context.Background(), func(ctx context.Context, s *qotp.Stream) error {
		if written < size {
			n, _ := stream.Write(data[written:])
			written += n
		}
		if written >= size && !stream.IsCloseRequested() {
			stream.Close()
		}
		if stream.SndClosed() {
			return fmt.Errorf("done")
		}
		return nil
	})
	dur := time.Since(start)

	return result{"qotp", size, dur}
}

func runHTTP3Client(addr string, data []byte) result {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr}

	pr, pw := io.Pipe()
	go func() {
		pw.Write(data)
		pw.Close()
	}()

	url := fmt.Sprintf("https://%s/bench", addr)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, pr)
	if err != nil {
		log.Fatal(err)
	}
	req.ContentLength = int64(len(data))

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()
	dur := time.Since(start)

	return result{"http3", len(data), dur}
}
