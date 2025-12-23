package main

import (
	"fmt"
	"io"
	"log"
	"os"
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

	fmt.Printf("Server listening on %s\n", addr)

	received := make(map[uint32]int)
	responded := make(map[uint32]bool)

	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s == nil {
			return true, nil
		}

		data, err := s.Read()
		if err != nil {
			if err == io.EOF {
				return true, nil
			}
			return false, err
		}

		if len(data) == 0 {
			return true, nil
		}

		received[s.StreamID()] += len(data)
		fmt.Printf("Server recv: stream=%d total=%d/%d\n",
			s.StreamID(), received[s.StreamID()], dataSize)

		// Once we receive all data for a stream, send response
		if received[s.StreamID()] >= dataSize && !responded[s.StreamID()] {
			responded[s.StreamID()] = true

			go func(s *qotp.Stream) {
				time.Sleep(100 * time.Millisecond) // Simulate processing delay

				response := makeData(byte(s.StreamID()+100), dataSize)
				writeAll(s, response)
				s.Close()
				fmt.Printf("Server sent response: stream=%d\n", s.StreamID())
			}(s)
		}

		return true, nil
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

	// Prepare streams
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

	received := make(map[uint32]int)

	listener.Loop(func(s *qotp.Stream) (bool, error) {
		// Write: try to send on all streams
		for _, ss := range streams {
			if ss.sent >= len(ss.data) {
				continue
			}
			n, err := ss.stream.Write(ss.data[ss.sent:])
			if err != nil {
				return false, err
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
				received[s.StreamID()] += len(data)
				fmt.Printf("Client recv: stream=%d total=%d/%d\n",
					s.StreamID(), received[s.StreamID()], dataSize)
			}
		}

		return conn.HasActiveStreams(), nil
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