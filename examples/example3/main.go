package main

import (
	"context"
	"fmt"
	"io"
	"log"
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

	received := make(map[uint32]int)
	responded := make(map[uint32]bool)

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

		received[s.StreamID()] += len(data)
		fmt.Printf("Server recv: stream=%d total=%d/%d\n",
			s.StreamID(), received[s.StreamID()], dataSize)

		if received[s.StreamID()] >= dataSize && !responded[s.StreamID()] {
			responded[s.StreamID()] = true
			go func(s *qotp.Stream) {
				time.Sleep(100 * time.Millisecond)
				response := makeData(byte(s.StreamID()+100), dataSize)
				writeAll(s, response)
				s.Close()
				fmt.Printf("Server sent response: stream=%d\n", s.StreamID())
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
		stream *qotp.Stream
		data   []byte
		sent   int
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

	received := make(map[uint32]int)

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

				// Close stream when done sending
				if ss.sent >= len(ss.data) {
					ss.stream.Close()
				}
			}
		}

		// Read: process incoming responses
		if s != nil {
			data, _ := s.Read()
			if len(data) > 0 {
				received[s.StreamID()] += len(data)
				fmt.Printf("Client recv: stream=%d total=%d/%d\n",
					s.StreamID(), received[s.StreamID()], dataSize)
			}
		}

		if !conn.HasActiveStreams() {
			cancel()
		} else {
			// Debug: why still active?
			for i := 0; i < numStreams; i++ {
				stream := conn.Stream(uint32(i))
				closeAt := conn.Rcv().GetOffsetClosedAt(uint32(i))
				fmt.Printf("Stream %d: sndClosed=%v rcvClosed=%v closeAt=%v\n",
					i, stream.SndClosed(), stream.RcvClosed(), closeAt)
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
		if err != nil {
			return
		}
		if n > 0 {
			data = data[n:]
		}
	}
}
