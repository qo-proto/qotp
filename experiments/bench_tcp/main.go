package main

import (
	"crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	mode := flag.String("mode", "", "server or client")
	addr := flag.String("addr", "127.0.0.1:9001", "listen/connect address")
	size := flag.Int("size", 32*1024*1024, "data size in bytes")
	out := flag.String("out", "", "csv output file (default: stdout)")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*addr)
	case "client":
		runClient(*addr, *size, *out)
	default:
		fmt.Println("Usage: bench_tcp -mode=server|client [-addr=host:port] [-size=bytes] [-out=file.csv]")
		os.Exit(1)
	}
}

func runServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Printf("TCP server listening on %s\n", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go func() {
			defer conn.Close()
			io.Copy(io.Discard, conn)
		}()
	}
}

func runClient(addr string, size int, outFile string) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	data := make([]byte, size)
	rand.Read(data)

	start := time.Now()

	_, err = conn.Write(data)
	if err != nil {
		log.Fatal(err)
	}
	conn.(*net.TCPConn).CloseWrite()

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
		"tcp",
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
	})
}
