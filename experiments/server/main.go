package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qo-proto/qotp"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	addr := flag.String("addr", "0.0.0.0", "bind IP address")
	flag.Parse()

	// TCP
	tcpAddr := fmt.Sprintf("%s:9001", *addr)
	tcpLn, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(io.Discard, conn)
			}()
		}
	}()

	// QOTP
	qotpAddr := fmt.Sprintf("%s:9000", *addr)
	qotpLn, err := qotp.Listen(qotp.WithListenAddr(qotpAddr))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		qotpLn.Loop(context.Background(), func(ctx context.Context, stream *qotp.Stream) error {
			if stream == nil {
				return nil
			}
			stream.Read()
			return nil
		})
	}()

	// HTTP/3
	h3Addr := fmt.Sprintf("%s:9002", *addr)
	mux := http.NewServeMux()
	mux.HandleFunc("/bench", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	})
	udpAddr, err := net.ResolveUDPAddr("udp", h3Addr)
	if err != nil {
		log.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	h3Srv := &http3.Server{
		Addr:      h3Addr,
		Handler:   mux,
		TLSConfig: generateTLSConfig(),
	}
	go h3Srv.Serve(udpConn)

	fmt.Println("READY")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	tcpLn.Close()
	qotpLn.Close()
	h3Srv.Close()
	udpConn.Close()
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
