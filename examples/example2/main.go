package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"

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
	listener, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("Server listening on %s\n", addr)
	fmt.Println("Waiting for clients... (Ctrl+C to stop)")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	type streamKey struct {
		connID   uint64
		streamID uint32
	}

	received := make(map[streamKey]int)
	responded := make(map[streamKey]bool)

	listener.Loop(ctx, func(ctx context.Context, stream *qotp.Stream) error {
		if stream == nil {
			return nil
		}
		data, err := stream.Read()
		if err != nil {
			return nil
		}
		if len(data) > 0 {
			key := streamKey{connID: stream.ConnID(), streamID: stream.StreamID()}

			received[key] += len(data)
			fmt.Printf("Server received: conn=%d stream=%d [%v] %s\n",
				key.connID, key.streamID, received[key], data)

			if received[key] >= 20000 && !responded[key] {
				responded[key] = true
				stream.Write(repeatText("Hello from server! ", 20000))
				stream.Close()
			}
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
	fmt.Printf("Connected to server at %s\n", serverAddr)

	stream := conn.Stream(0)
	_, err = stream.Write(repeatText("Hello from client! ", 20000))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Sent: Hello from client!")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n := 0

	listener.Loop(ctx, func(ctx context.Context, s *qotp.Stream) error {
		if s == nil {
			return nil
		}

		data, _ := s.Read()
		if len(data) > 0 {
			n += len(data)
			fmt.Printf("Received: [%v] %s\n", n, data)

			if n == 20000 {
				cancel()
			}
		}
		return nil
	})
}