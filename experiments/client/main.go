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
	"time"

	"github.com/qo-proto/qotp"
	"github.com/quic-go/quic-go/http3"
)

type result struct {
	protocol string
	size     int
	duration time.Duration
}

func main() {
	addr := flag.String("addr", "127.0.0.1", "server IP address")
	sizeMB := flag.Int("size", 32, "data size in MB")
	scenario := flag.String("scenario", "loopback", "scenario label for CSV")
	verbose := flag.Bool("v", false, "enable qotp debug logging (skews timing; for congestion-control analysis only)")
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

	// Run sequentially: concurrent runs would contend for the CPU and the
	// loopback/link and corrupt each protocol's measurement.
	results := []result{
		runTCPClient(fmt.Sprintf("%s:9001", *addr), data),
		runQOTPClient(fmt.Sprintf("%s:9000", *addr), data),
		runHTTP3Client(fmt.Sprintf("%s:9002", *addr), data),
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
