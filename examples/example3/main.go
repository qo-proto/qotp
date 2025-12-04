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

	var m = make(map[uint32]int)
	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s == nil { //nothing to read
			return true, nil //continue
		}

		data, err := s.Read()
		if err != nil {
			fmt.Printf("error %v", err)
			return false, nil
		}

		if len(data) > 0 {
			m[s.StreamID()]=+len(data)
			fmt.Printf("Server received: [%v] %s\n", m[s.StreamID()], data)

			// Send reply
			if m[s.StreamID()] == 20000 {
				go func(s *qotp.Stream) {
					time.Sleep(time.Millisecond * 200) //hard work
					data := repeatText("Hello from server! ", 20000)
					for len(data) > 0 {
						n, err := s.Write(data)
						if err != nil {
							log.Fatal(err)
						}
						data = data[0:n]
					}
					s.Close()
				}(s)
			}
		}

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

	total := 0
	for i := 0; i < 10; i++ {
		// Send message
		stream := conn.Stream(uint32(i))
		go func(stream *qotp.Stream) {
			data := repeatText("Hello from client! ", 20000)
			total += len(data)
			for len(data) > 0 {
				n, err := stream.Write(data)
				if err != nil {
					log.Fatal(err)
				}
				data = data[0:n]
				fmt.Println("Sent: Hello from client!")
			}
		}(stream)
	}

	var bytesReceived atomic.Int64
	listener.Loop(func(s *qotp.Stream) (bool, error) {

		if s == nil { //nothing to read
			return true, nil //continue
		}

		data, _ := s.Read()
		if len(data) > 0 {
			totalReceived := bytesReceived.Add(int64(len(data)))
			fmt.Printf("Received: [%v] %s\n", totalReceived, data)
			if totalReceived >= int64(total) {
				return false, nil
			}
		}

		return true, nil //continue
	})

}
