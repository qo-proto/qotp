// Package bench holds the wire convention and helpers shared by the benchmark
// client and server.
//
// Each protocol carries the same tiny request framing so the three are doing
// identical work:
//
//	client -> server: [dir byte]['U'|'D'][size uint64 LE]   (9 bytes)
//	dir 'U' (upload):   client then sends size bytes; server replies one AckByte
//	dir 'D' (download): server then sends size bytes; client reads until size
//
// The client times every run, so upload timing includes the final ack (one RTT).
package bench

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

type Dir byte

const (
	Upload   Dir = 'U' // client -> server
	Download Dir = 'D' // server -> client
	Report   Dir = 'R' // client asks the responder for its own measurements
)

func (d Dir) String() string {
	switch d {
	case Upload:
		return "upload"
	case Report:
		return "report"
	default:
		return "download"
	}
}

const (
	HeaderSize = 9
	AckByte    = 'K'

	// Default base; each protocol takes an offset from it (see Port).
	DefaultPortBase = 9000

	ALPN = "qotp-bench"
)

// Port returns the port a protocol listens on for a given base.
func Port(base int, proto string) int {
	switch proto {
	case "qotp":
		return base
	case "tcp":
		return base + 1
	default:
		return base + 2
	}
}

// Protocols is the fixed set; every run exercises all three.
var Protocols = []string{"qotp", "tcp", "quic"}

func EncodeHeader(d Dir, size uint64) []byte {
	b := make([]byte, HeaderSize)
	b[0] = byte(d)
	binary.LittleEndian.PutUint64(b[1:], size)
	return b
}

func DecodeHeader(b []byte) (Dir, uint64, error) {
	d := Dir(b[0])
	if d != Upload && d != Download && d != Report {
		return 0, 0, fmt.Errorf("bad direction %q", b[0])
	}
	return d, binary.LittleEndian.Uint64(b[1:]), nil
}

// ServerReport is what the responder measured, sent back over qotp when the
// client asks. The receive-side byte counts are exact where the client can
// only approximate, and the responder's CPU load answers the question a
// one-sided benchmark cannot: was the far end the bottleneck?
type ServerReport struct {
	NumCPU int `json:"num_cpu"`
	// Raw cumulative CPU counters rather than an average: the client asks for
	// a report after every phase and differences successive ones, so it gets
	// the responder's load *during that phase*. A session-wide average hides
	// a core pinned for ten seconds.
	CPUBusy       float64           `json:"cpu_busy"`
	CPUTotal      float64           `json:"cpu_total"`
	CPUKnown      bool              `json:"cpu_known"`
	ReceivedBytes map[string]uint64 `json:"received_bytes"`
	SessionSecs   float64           `json:"session_seconds"`
}

// Chunk is the unit both sides move data in. Large enough to keep syscall
// overhead off the measurement, small enough to sample progress finely.
const Chunk = 256 * 1024

// Filler returns a reusable buffer written repeatedly to make up the transfer.
// Content is irrelevant to throughput, so one buffer is cycled rather than
// allocating the whole transfer.
func Filler() []byte {
	b := make([]byte, Chunk)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// JainIndex is Jain's fairness index over the achieved rates: 1.0 means every
// flow got an equal share, 1/n means one flow took everything.
func JainIndex(rates []float64) float64 {
	var sum, sumSq float64
	for _, r := range rates {
		sum += r
		sumSq += r * r
	}
	if sumSq == 0 {
		return 1
	}
	return (sum * sum) / (float64(len(rates)) * sumSq)
}

func ServerTLS() *tls.Config {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"qotp-bench"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{ALPN},
	}
}

func ClientTLS() *tls.Config {
	// Self-signed throwaway cert: this measures transport throughput, not PKI.
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{ALPN}}
}

// SelectProtocols resolves a comma-separated filter to a protocol list; empty
// means all of them, in the canonical order.
func SelectProtocols(filter string) ([]string, error) {
	if filter == "" {
		return Protocols, nil
	}
	want := map[string]bool{}
	for _, f := range strings.Split(filter, ",") {
		f = strings.TrimSpace(f)
		if !slices.Contains(Protocols, f) {
			return nil, fmt.Errorf("unknown protocol %q, want one of %s", f, strings.Join(Protocols, ", "))
		}
		want[f] = true
	}
	var out []string
	for _, p := range Protocols {
		if want[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// SelectDirs resolves a direction filter; empty means both.
func SelectDirs(filter string) ([]Dir, error) {
	switch strings.TrimSpace(filter) {
	case "":
		return []Dir{Upload, Download}, nil
	case "upload", "up":
		return []Dir{Upload}, nil
	case "download", "down":
		return []Dir{Download}, nil
	}
	return nil, fmt.Errorf("unknown direction %q, want upload or download", filter)
}
