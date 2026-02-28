package main

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/qo-proto/qotp"
)

func main() {
	mode := flag.String("mode", "", "server or client")
	addr := flag.String("addr", "127.0.0.1:9000", "listen/connect address")
	size := flag.Int("size", 32*1024*1024, "data size in bytes")
	out := flag.String("out", "", "csv output file (default: stdout)")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*addr)
	case "client":
		runClient(*addr, *size, *out)
	default:
		fmt.Println("Usage: bench_qotp -mode=server|client [-addr=host:port] [-size=bytes] [-out=file.csv]")
		os.Exit(1)
	}
}

func runServer(addr string) {
	listener, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("QOTP server listening on %s\n", addr)

	received := 0
	ctx := context.Background()
	listener.Loop(ctx, func(ctx context.Context, stream *qotp.Stream) error {
		if stream == nil {
			return nil
		}
		data, _ := stream.Read()
		received += len(data)
		return nil
	})
}

func runClient(addr string, size int, outFile string) {
	listener, err := qotp.Listen(qotp.WithListenAddr("127.0.0.1:0"))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	conn, err := listener.DialString(addr)
	if err != nil {
		log.Fatal(err)
	}

	data := make([]byte, size)
	rand.Read(data)

	stream := conn.Stream(0)

	start := time.Now()
	written := 0

	ctx := context.Background()
	listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
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

	end := time.Now()
	totalTime := end.Sub(start)

	w := csv.NewWriter(os.Stdout)
	if outFile != "" {
		f, err := os.Create(outFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = csv.NewWriter(f)
	}
	defer w.Flush()

	w.Write([]string{"protocol", "size_bytes", "send_ms", "total_ms"})
	w.Write([]string{
		"qotp",
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
	})
}
