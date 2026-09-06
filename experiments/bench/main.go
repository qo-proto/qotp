// qotp-bench measures QOTP against TCP and QUIC over the same path, in both
// directions, alone and competing. One binary plays both roles.
//
//	qotp-bench -listen                 on the far machine
//	qotp-bench -addr HOST              here
//
// The responder's own measurements travel back over qotp at the end, so the
// whole result is printed by, and only by, the side you ran the client on.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/qo-proto/qotp/experiments/internal/bench"
)

type config struct {
	addr     string
	port     int
	sizeMB   int
	runs     int
	duration time.Duration
	noSolo   bool
	jsonPath string
}

// die reports a fatal error and exits. Not log.Fatalf: slog.SetDefault routes
// the log package through slog at Info level, which the Warn level used here
// then discards — the process would exit silently.
func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	listen := flag.Bool("listen", false, "run as the responder and wait (no other flags needed)")
	addr := flag.String("addr", "", "responder address; with -listen, the bind address")
	port := flag.Int("port", bench.DefaultPortBase, "base port: qotp=port, tcp=port+1, quic=port+2")
	sizeMB := flag.Int("size", 32, "MB per protocol per direction; ignored with -duration")
	runs := flag.Int("runs", 3, "repeat N times and report median [min-max]")
	duration := flag.Duration("duration", 0, "measure for this long per transfer instead of a fixed size")
	noSolo := flag.Bool("no-solo", false, "skip the solo baseline phase")
	jsonPath := flag.String("json", "", "write the full result as JSON for plotting")
	verbose := flag.Bool("v", false, "enable qotp debug logging (skews timing)")
	flag.Usage = usage
	flag.Parse()

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *listen {
		bind := *addr
		if bind == "" {
			bind = "0.0.0.0"
		}
		serve(bind, *port)
		return
	}
	if *addr == "" {
		usage()
		die("either -listen or -addr is required")
	}
	runClient(config{
		addr: *addr, port: *port, sizeMB: *sizeMB, runs: *runs,
		duration: *duration, noSolo: *noSolo, jsonPath: *jsonPath,
	})
}

func usage() {
	fmt.Fprint(os.Stderr, `qotp-bench — QOTP vs TCP vs QUIC over one path

  on the far machine:   qotp-bench -listen
  here:                 qotp-bench -addr HOST [-duration 10s] [-runs 5] [-json r.json]

The responder needs three ports open from this machine, and two protocols:
  UDP port      qotp
  TCP port+1    tcp
  UDP port+2    quic

Flags:
`)
	flag.PrintDefaults()
}
