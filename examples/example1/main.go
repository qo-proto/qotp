package main
import (
	"os"
	"fmt"
	"log"
	"bufio"
	"strings"
	"github.com/tbocek/qotp"
)
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
	fmt.Println("Waiting for clients...")
	
	listener.Loop(func(stream *qotp.Stream) (bool, error) {
		if stream == nil {	
			return true, nil
		}
		data, err := stream.Read()
		if err != nil {
			fmt.Printf("Server exit loop, %v\n", err)
			return false, nil
		}
		
		if len(data) > 0 {
			msg := string(data)
			fmt.Printf("Server received: %s\n", msg)
			
			upper := strings.ToUpper(msg)
			stream.Write([]byte(upper))
			stream.Close()
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
	
	// Read user input
	fmt.Print("Enter message: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	
	stream := conn.Stream(0)
	_, err = stream.Write([]byte(input))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sent: %s\n", input)
	
	// Read reply
	listener.Loop(func(s *qotp.Stream) (bool, error) {
		if s == nil {
			return true, nil
		}
		data, _ := s.Read()
		if len(data) > 0 {
			fmt.Printf("Received, exit: %s\n", data)
			return false, nil
		}
		return true, nil
	})
}