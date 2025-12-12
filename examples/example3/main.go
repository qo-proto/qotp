package main

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/qo-proto/qotp"
)

func repeatText(text string, targetBytes int) []byte {
	if len(text) == 0 {
		return []byte{}
	}

	result := make([]byte, 0, targetBytes)
	for len(result) < targetBytes {
		result = append(result, []byte(text)...)
	}

	return result[:targetBytes]
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  ./example1 server [addr]     # default: 127.0.0.1:8888")
		fmt.Println("  ./example1 client [addr]     # default: 127.0.0.1:8888")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		addr := "127.0.0.1:8888"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		runServer(addr)
	case "client":
		addr := "127.0.0.1:8888"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		runClient(addr)
	default:
		fmt.Println("First argument must be 'server' or 'client'")
		os.Exit(1)
	}
}

func runServer(addr string) {
	// Create server listener (will auto-generate keys)
	listener, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("Server listening on %s\n", addr)
	fmt.Println("Waiting for clients...")

	var m = make(map[uint32]int)
	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s == nil { //nothing to read
			return true, nil //continue
		}

		data, err := s.Read()
		if err != nil {
			if err == io.EOF {
				return true, nil // Stream closed, this is normal
			}
			fmt.Printf("error %v", err)
			return false, nil
		}

		if len(data) > 0 {
			m[s.StreamID()] += len(data)
			fmt.Printf("Server received: streamID=%v total=%v chunk=%v\n",
				s.StreamID(), m[s.StreamID()], len(data))
			fmt.Printf("Server received: [%v] %v\n", m[s.StreamID()], len(data))

			// Send reply
			if m[s.StreamID()] == 20000 {
				slog.Info("Starting response goroutine",
					slog.Uint64("streamID", uint64(s.StreamID())))
				go func(s *qotp.Stream) {
					time.Sleep(time.Millisecond * 200)
					data := repeatText("Hello from server! "+strconv.Itoa(int(s.StreamID())), 20000)
					slog.Info("About to write response",
						slog.Uint64("streamID", uint64(s.StreamID())),
						slog.Int("bytes", len(data)))
					for len(data) > 0 {
						n, err := s.Write(data)
						if err != nil {
							slog.Error("Write failed",
								slog.Uint64("streamID", uint64(s.StreamID())),
								slog.Any("error", err))
							return
						}
						if n == 0 {
							slog.Warn("Write returned 0, waiting",
								slog.Uint64("streamID", uint64(s.StreamID())),
								slog.Int("remaining", len(data)))
							time.Sleep(time.Millisecond * 10)
							continue
						}
						data = data[n:]
					}
					slog.Info("Finished writing, closing stream",
						slog.Uint64("streamID", uint64(s.StreamID())))
					s.Close()
				}(s)
			}
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
	fmt.Printf("Connected to server at %s\n", serverAddr)

	// Prepare all stream data upfront
	type StreamState struct {
		stream *qotp.Stream
		data   []byte
		sent   int
	}

	streams := make([]*StreamState, 10)
	totalExpected := 0
	for i := 0; i < 10; i++ {
		data := repeatText("Hello from client! "+strconv.Itoa(i), 20000)
		totalExpected += len(data)
		streams[i] = &StreamState{
			stream: conn.Stream(uint32(i)),
			data:   data,
			sent:   0,
		}
	}

	var bytesReceived atomic.Int64

	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s != nil {
			fmt.Printf("Received on stream %v\n", s.StreamID())
		}
		// WRITE PHASE: Try to write on all streams
		for _, ss := range streams {
			if ss.sent < len(ss.data) {
				remaining := ss.data[ss.sent:]
				n, err := ss.stream.Write(remaining)
				if err != nil {
					log.Fatal(err)
				}
				if n > 0 {
					ss.sent += n
					fmt.Printf("Sent: streamID=%v chunk=%v total=%v/%v\n",
						ss.stream.StreamID(), n, ss.sent, len(ss.data))
				}
			}
		}

		// READ PHASE: Process incoming data
		if s != nil {
			data, _ := s.Read()
			if len(data) > 0 {
				totalReceived := bytesReceived.Add(int64(len(data)))
				fmt.Printf("Received: streamID=%v chunk=%v total=%v/%v\n",
					s.StreamID(), len(data), totalReceived, totalExpected)

				if totalReceived >= int64(totalExpected) {
					slog.Info("Closing stream early",
						slog.Uint64("streamID", uint64(s.StreamID())),
						slog.Int64("totalReceived", totalReceived),
						slog.Int("totalExpected", totalExpected),
						slog.Int("thisChunk", len(data)))
					//s.Close()
				}
			}
		}

		activeStreams := conn.HasActiveStreams()
		if !activeStreams {
			fmt.Printf("HasActiveStreams() = %v, bytesReceived=%v/%v\n",
				activeStreams, bytesReceived.Load(), totalExpected)
		}
		return activeStreams, nil
	})
}
