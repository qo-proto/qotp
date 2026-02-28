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
	"sync"
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
	out := flag.String("out", "", "csv output file (default: stdout)")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	data := make([]byte, *sizeMB*1024*1024)
	rand.Read(data)

	results := make([]result, 3)
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		results[0] = runTCPClient(fmt.Sprintf("%s:9001", *addr), data)
	}()
	go func() {
		defer wg.Done()
		results[1] = runQOTPClient(fmt.Sprintf("%s:9000", *addr), data)
	}()
	go func() {
		defer wg.Done()
		results[2] = runHTTP3Client(fmt.Sprintf("%s:9002", *addr), data)
	}()

	wg.Wait()

	w := csv.NewWriter(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = csv.NewWriter(f)
	}
	defer w.Flush()

	w.Write([]string{"protocol", "size_mb", "total_ms"})
	for _, r := range results {
		w.Write([]string{
			r.protocol,
			fmt.Sprintf("%d", r.size/1024/1024),
			fmt.Sprintf("%.3f", float64(r.duration.Microseconds())/1000.0),
		})
	}
}

func runTCPClient(addr string, data []byte) result {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Write(data)
	if err != nil {
		log.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()
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
