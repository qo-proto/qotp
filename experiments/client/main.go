// Benchmark client: measures QOTP, TCP and QUIC over the same link.
//
// Every invocation runs all three protocols, in both directions, twice:
//
//	solo     — one protocol at a time, the link to itself: capacity baseline
//	parallel — all three at once, competing: fairness
//
// Fairness is reported over the contended window (start until the first flow
// finishes), because once a flow completes the survivors get its bandwidth and
// a whole-run average would flatter whoever finished last.
package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qo-proto/qotp/experiments/internal/bench"
)

const (
	sampleInterval = 100 * time.Millisecond
	idleTimeout    = 5 * time.Minute
)

type runFn func(addr string, dir bench.Dir, size uint64, prog *atomic.Uint64) (time.Duration, error)

var runners = map[string]runFn{
	"qotp": runQOTP,
	"tcp":  runTCP,
	"quic": runQUIC,
}

var portBase = bench.DefaultPortBase

type outcome struct {
	proto   string
	dir     bench.Dir
	mode    string // "solo" | "parallel"
	dur     time.Duration
	bytes   uint64
	contBps float64 // bytes/s during the contended window (parallel only)
	err     error
}

func (o outcome) mbps() float64 {
	if o.dur == 0 {
		return 0
	}
	return float64(o.bytes) * 8 / o.dur.Seconds() / 1e6
}

type sample struct {
	proto string
	t     time.Duration
	bytes uint64
}

func main() {
	addr := flag.String("addr", "127.0.0.1", "server IP address")
	base := flag.Int("port", bench.DefaultPortBase, "base port: qotp=port, tcp=port+1, quic=port+2")
	sizeMB := flag.Int("size", 32, "MB per protocol per direction")
	csvPath := flag.String("csv", "", "write per-protocol rate samples here")
	skipSolo := flag.Bool("no-solo", false, "skip the solo baseline phase")
	verbose := flag.Bool("v", false, "enable qotp debug logging (skews timing)")
	flag.Parse()

	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	portBase = *base
	size := uint64(*sizeMB) * 1024 * 1024
	var all []outcome
	var samples []sample

	if !*skipSolo {
		for _, dir := range []bench.Dir{bench.Upload, bench.Download} {
			for _, p := range bench.Protocols {
				fmt.Fprintf(os.Stderr, "solo %-8s %s ...\n", dir, p)
				all = append(all, runSolo(p, *addr, dir, size))
			}
		}
	}
	for _, dir := range []bench.Dir{bench.Upload, bench.Download} {
		fmt.Fprintf(os.Stderr, "parallel %-8s qotp+tcp+quic ...\n", dir)
		outs, ss := runParallel(*addr, dir, size)
		all = append(all, outs...)
		samples = append(samples, ss...)
	}

	report(all, *sizeMB)
	if *csvPath != "" {
		if err := writeCSV(*csvPath, samples); err != nil {
			log.Printf("csv: %v", err)
		} else {
			fmt.Printf("\nrate samples: %s\n", *csvPath)
		}
	}
}

func target(addr string, proto string) string {
	return fmt.Sprintf("%s:%d", addr, bench.Port(portBase, proto))
}

func runSolo(proto, addr string, dir bench.Dir, size uint64) outcome {
	var prog atomic.Uint64
	dur, err := runners[proto](target(addr, proto), dir, size, &prog)
	return outcome{proto: proto, dir: dir, mode: "solo", dur: dur, bytes: size, err: err}
}

// runParallel starts all three at the same instant and samples their progress,
// so the shares are measured while they are actually competing.
func runParallel(addr string, dir bench.Dir, size uint64) ([]outcome, []sample) {
	progs := map[string]*atomic.Uint64{}
	for _, p := range bench.Protocols {
		progs[p] = &atomic.Uint64{}
	}

	var wg sync.WaitGroup
	outs := make([]outcome, len(bench.Protocols))
	start := make(chan struct{})
	done := make(chan struct{}, len(bench.Protocols))
	stopSampler := make(chan struct{})
	var samples []sample
	var mu sync.Mutex

	for i, p := range bench.Protocols {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			<-start
			dur, err := runners[p](target(addr, p), dir, size, progs[p])
			outs[i] = outcome{proto: p, dir: dir, mode: "parallel", dur: dur, bytes: size, err: err}
			done <- struct{}{}
		}(i, p)
	}

	t0 := time.Now()
	snap := func() {
		el := time.Since(t0)
		mu.Lock()
		for _, p := range bench.Protocols {
			samples = append(samples, sample{p, el, progs[p].Load()})
		}
		mu.Unlock()
	}
	close(start)
	go func() {
		tick := time.NewTicker(sampleInterval)
		defer tick.Stop()
		for {
			select {
			case <-stopSampler:
				return
			case <-tick.C:
				snap()
			}
		}
	}()
	// A flow finishing ends the contended window, so snapshot on each
	// completion: on a fast link every transfer can finish inside one tick.
	go func() {
		for range done {
			snap()
		}
	}()
	wg.Wait()
	close(stopSampler)
	close(done)

	// Contended window: until the first flow finished.
	first := time.Duration(1<<62 - 1)
	for _, o := range outs {
		if o.err == nil && o.dur < first {
			first = o.dur
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range outs {
		outs[i].contBps = rateAt(samples, outs[i].proto, first)
		if outs[i].contBps == 0 && outs[i].err == nil && outs[i].dur > 0 {
			outs[i].contBps = float64(outs[i].bytes) / outs[i].dur.Seconds()
		}
	}
	return outs, samples
}

// rateAt returns the average byte rate of proto from t=0 up to the last sample
// at or before cutoff.
func rateAt(samples []sample, proto string, cutoff time.Duration) float64 {
	var bytes uint64
	var at time.Duration
	for _, s := range samples {
		if s.proto == proto && s.t <= cutoff && s.t > at {
			at, bytes = s.t, s.bytes
		}
	}
	if at == 0 {
		return 0
	}
	return float64(bytes) / at.Seconds()
}

// =============================================================================
// Reporting
// =============================================================================

func report(all []outcome, sizeMB int) {
	solo := map[string]map[bench.Dir]float64{}
	for _, o := range all {
		if o.mode == "solo" && o.err == nil {
			if solo[o.proto] == nil {
				solo[o.proto] = map[bench.Dir]float64{}
			}
			solo[o.proto][o.dir] = o.mbps()
		}
	}

	fmt.Printf("\n%d MB per protocol per direction\n", sizeMB)
	for _, mode := range []string{"solo", "parallel"} {
		for _, dir := range []bench.Dir{bench.Upload, bench.Download} {
			rows := filter(all, mode, dir)
			if len(rows) == 0 {
				continue
			}
			fmt.Printf("\n== %s / %s ==\n", mode, dir)
			if mode == "solo" {
				fmt.Printf("  %-5s %10s %10s\n", "proto", "time", "Mbps")
				for _, o := range rows {
					if o.err != nil {
						fmt.Printf("  %-5s %10s  FAILED: %v\n", o.proto, "-", o.err)
						continue
					}
					fmt.Printf("  %-5s %10s %10.1f\n", o.proto, o.dur.Round(time.Millisecond), o.mbps())
				}
				continue
			}

			var rates []float64
			var total float64
			for _, o := range rows {
				r := o.contBps * 8 / 1e6
				rates = append(rates, r)
				total += r
			}
			fmt.Printf("  %-5s %12s %8s %10s %s\n", "proto", "Mbps(cont)", "share", "vs solo", "total time")
			for i, o := range rows {
				if o.err != nil {
					fmt.Printf("  %-5s %12s  FAILED: %v\n", o.proto, "-", o.err)
					continue
				}
				share := 0.0
				if total > 0 {
					share = 100 * rates[i] / total
				}
				vsSolo := "-"
				if s, ok := solo[o.proto][dir]; ok && s > 0 {
					vsSolo = fmt.Sprintf("%.0f%%", 100*rates[i]/s)
				}
				fmt.Printf("  %-5s %12.1f %7.1f%% %10s %s\n",
					o.proto, rates[i], share, vsSolo, o.dur.Round(time.Millisecond))
			}
			fmt.Printf("  Jain fairness index: %.3f  (1.000 = equal shares, %.3f = one flow takes all)\n",
				bench.JainIndex(rates), 1/float64(len(rates)))
		}
	}
	fmt.Println("\nMbps(cont) is measured over the contended window only: from the start")
	fmt.Println("until the first flow finished. Upload progress is sampled from each")
	fmt.Println("protocol's delivery counter (qotp BytesDelivered, TCP tcpi_bytes_acked);")
	fmt.Println("QUIC has no acked-bytes counter, so its upload samples lag by up to one")
	fmt.Println("flow-control window. Download progress is counted on receipt for all three.")
}

func filter(all []outcome, mode string, dir bench.Dir) []outcome {
	var out []outcome
	for _, o := range all {
		if o.mode == mode && o.dir == dir {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].proto < out[j].proto })
	return out
}

func writeCSV(path string, samples []sample) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	if err := w.Write([]string{"protocol", "t_s", "cum_bytes"}); err != nil {
		return err
	}
	for _, s := range samples {
		if err := w.Write([]string{
			s.proto,
			strconv.FormatFloat(s.t.Seconds(), 'f', 3, 64),
			strconv.FormatUint(s.bytes, 10),
		}); err != nil {
			return err
		}
	}
	return nil
}
