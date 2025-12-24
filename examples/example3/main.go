package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/qo-proto/qotp"
)

const (
	numStreams = 10
	dataSize   = 20000
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./example [server|client] [addr]")
		os.Exit(1)
	}

	addr := "127.0.0.1:8888"
	if len(os.Args) > 2 {
		addr = os.Args[2]
	}

	switch os.Args[1] {
	case "server":
		runServer(addr)
	case "client":
		runClient(addr)
	default:
		log.Fatal("First argument must be 'server' or 'client'")
	}
}

func runServer(addr string) {
	listener, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s (Ctrl+C to stop)\n", addr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	type streamKey struct {
		connID   uint64
		streamID uint32
	}

	received := make(map[streamKey]int)
	responded := make(map[streamKey]bool)

	listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
		if s == nil {
			return nil
		}
		data, err := s.Read()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if len(data) == 0 {
			return nil
		}

		key := streamKey{connID: s.ConnID(), streamID: s.StreamID()}

		received[key] += len(data)
		fmt.Printf("Server recv: conn=%d stream=%d total=%d/%d\n",
			key.connID, key.streamID, received[key], dataSize)

		if received[key] >= dataSize && !responded[key] {
			responded[key] = true
			go func(s *qotp.Stream) {
				time.Sleep(100 * time.Millisecond)
				response := makeData(byte(s.StreamID()+100), dataSize)
				writeAll(s, response)
				s.Close()
				fmt.Printf("Server sent response: conn=%d stream=%d\n", s.ConnID(), s.StreamID())
			}(s)
		}
		return nil
	})
}

func runClient(serverAddr string) {
	listener, err := qotp.Listen()
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	conn, err := listener.DialString(serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Connected to %s\n", serverAddr)

	type streamState struct {
		stream   *qotp.Stream
		data     []byte
		sent     int
		received int
	}

	streams := make([]*streamState, numStreams)
	for i := 0; i < numStreams; i++ {
		streams[i] = &streamState{
			stream: conn.Stream(uint32(i)),
			data:   makeData(byte(i), dataSize),
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
		// Write: try to send on all streams
		for _, ss := range streams {
			if ss.sent >= len(ss.data) {
				continue
			}
			n, err := ss.stream.Write(ss.data[ss.sent:])
			if err != nil {
				return err
			}
			if n > 0 {
				ss.sent += n
				fmt.Printf("Client sent: stream=%d total=%d/%d\n",
					ss.stream.StreamID(), ss.sent, dataSize)
			}
		}

		// Read: process incoming responses
		if s != nil {
			data, _ := s.Read()
			if len(data) > 0 {
				for _, ss := range streams {
					if ss.stream.StreamID() == s.StreamID() {
						ss.received += len(data)
						fmt.Printf("Client recv: stream=%d total=%d/%d\n",
							s.StreamID(), ss.received, dataSize)

						// Close after receiving full response
						if ss.received >= dataSize {
							fmt.Println("Close")
							ss.stream.Close()
						}
						break
					}
				}
			}
		}

		if !conn.HasActiveStreams() {
			cancel()
		} else {
			for _, ss := range streams {
				fmt.Printf("Stream %d (%p): sndClosed=%v rcvClosed=%v, %p\n",
					ss.stream.StreamID(), ss.stream, ss.stream.SndClosed(), ss.stream.RcvClosed(), ss.stream)
			}
		}
		return nil
	})

	fmt.Println("Done")
}

func makeData(fill byte, size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = fill
	}
	return data
}

func writeAll(s *qotp.Stream, data []byte) {
	for len(data) > 0 {
		n, err := s.Write(data)
		slog.Debug("writeAll", slog.Int("n", n), slog.Any("err", err), slog.Int("remaining", len(data)))
		if err != nil {
			return
		}
		if n > 0 {
			data = data[n:]
		}
	}
}
