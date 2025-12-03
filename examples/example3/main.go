package main

import (
	"fmt"
	"log"
	"os"
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

	n := 0

	// Handle incoming streams
	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s == nil { //nothing to read
			return true, nil //continue
		}

		go func(s *qotp.Stream) {
			data, err := s.Read()
			if err != nil {
				fmt.Printf("error %v", err)
				return
			}

			if len(data) > 0 {
				n += len(data)
				fmt.Printf("Server received: [%v] %s\n", n, data)

				// Send reply
				if n == 20000 {
					time.Sleep(time.Millisecond * 200)
					s.Write(repeatText("Hello from server! ", 20000))
					s.Close()
				}
			}
		}(s)
		return true, nil
	})
}

func runClient(serverAddr string) {
	// Create client listener (will auto-generate keys)
	listener, err := qotp.Listen()
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Connect to server without crypto (in-band key exchange)
	conn, err := listener.DialString(serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Connected to server at %s\n", serverAddr)

	for i := 0; i < 10; i++ {
		// Send message
		stream := conn.Stream(uint32(i))
		_, err = stream.Write(repeatText("Hello from client! ", 20000))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Sent: Hello from client!")
	}

	//n := 0
	var n atomic.Int64
	// Read reply
	var count atomic.Int32
	listener.Loop(func(s *qotp.Stream) (bool, error) {

		if s == nil { //nothing to read
			return true, nil //continue
		}

		go func(stream *qotp.Stream) {
			data, _ := s.Read()
			if len(data) > 0 {
				n.Add(int64(len(data)))
				fmt.Printf("Received: [%v] %s\n", n, data)
				if n.Load() == int64(20001) {
					count.Add(1)
				}
			}
		}(s)

		if count.Load() > 0 {
			return false, nil
		}
		return true, nil //continue
	})

}
