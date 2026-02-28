package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	mode := flag.String("mode", "", "server or client")
	addr := flag.String("addr", "127.0.0.1:9002", "listen/connect address")
	size := flag.Int("size", 32*1024*1024, "data size in bytes")
	out := flag.String("out", "", "csv output file (default: stdout)")
	flag.Parse()

	switch *mode {
	case "server":
		runServer(*addr)
	case "client":
		runClient(*addr, *size, *out)
	default:
		fmt.Println("Usage: bench_http3 -mode=server|client [-addr=host:port] [-size=bytes] [-out=file.csv]")
		os.Exit(1)
	}
}

func generateTLSConfig() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"Bench"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}

func runServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})

	server := &http3.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: generateTLSConfig(),
	}

	fmt.Printf("HTTP/3 server listening on %s\n", addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func runClient(addr string, size int, outFile string) {
	data := make([]byte, size)
	rand.Read(data)

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr}

	start := time.Now()

	pr, pw := io.Pipe()
	go func() {
		pw.Write(data)
		pw.Close()
	}()

	url := fmt.Sprintf("https://%s/bench", addr)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, pr)
	if err != nil {
		log.Fatal(err)
	}
	req.ContentLength = int64(size)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	resp.Body.Close()

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
		"http3",
		fmt.Sprintf("%d", size),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
		fmt.Sprintf("%.3f", float64(totalTime.Microseconds())/1000.0),
	})
}
