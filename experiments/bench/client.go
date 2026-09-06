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
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/qo-proto/qotp/experiments/internal/bench"
)

const (
	sampleInterval = 100 * time.Millisecond
	// Long enough that a protocol waiting its turn during a solo phase does
	// not time out while the others transfer.
	idleTimeout = 5 * time.Minute
	dialTimeout = 10 * time.Second
)

// runTimeout bounds one transfer, so an unreachable or dead server fails in
// seconds instead of hanging on the idle timeout.
func runTimeout() time.Duration {
	if runDuration > 0 {
		return runDuration + 30*time.Second
	}
	return 5 * time.Minute
}

type runFn func(addr string, dir bench.Dir, size uint64, until time.Time, prog *atomic.Uint64) (time.Duration, error)

var runners = map[string]runFn{
	"qotp": runQOTP,
	"tcp":  runTCP,
	"quic": runQUIC,
}

var (
	portBase    = bench.DefaultPortBase
	runDuration time.Duration
)

// deadline returns the stop time for duration mode, or the zero time for
// size-based runs.
func deadline() time.Time {
	if runDuration == 0 {
		return time.Time{}
	}
	return time.Now().Add(runDuration)
}

// warmup is skipped before measuring, so the rate reflects steady state rather
// than the ramp — which is a different question and answered differently.
func warmupOf(d time.Duration) time.Duration { return d / 5 }

type outcome struct {
	run       int
	proto     string
	dir       bench.Dir
	mode      string // "solo" | "parallel"
	dur       time.Duration
	bytes     uint64
	contBps   float64 // bytes/s over the measured window
	cores     float64 // cores busy on this side during the measurement
	coresOK   bool
	srvCores  float64 // cores busy on the responder during the same phase
	srvNumCPU int
	srvOK     bool
	err       error
}

func (o outcome) mbps() float64 { return o.contBps * 8 / 1e6 }

// stats returns the median and range. A single fairness number from one run is
// noise; the spread is what says whether it can be compared at all.
func stats(v []float64) (med, lo, hi float64) {
	if len(v) == 0 {
		return 0, 0, 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	return c[len(c)/2], c[0], c[len(c)-1]
}

type sample struct {
	proto string
	phase string // e.g. "parallel-upload": without it a plot mixes phases
	run   int
	t     time.Duration
	bytes uint64
}

func runClient(cfg config) {
	portBase = cfg.port
	size := uint64(cfg.sizeMB) * 1024 * 1024
	runDuration = cfg.duration
	if runDuration > 0 {
		// The request size only has to outlast the clock.
		size = 1 << 50
	}
	addr := &cfg.addr

	// Resolve once, here. qotp.DialString takes a literal address by design --
	// name resolution is the application's job -- and resolving once is right
	// anyway: a name with several A records could otherwise send the three
	// protocols to different hosts and quietly invalidate the comparison.
	host, err := resolveHost(cfg.addr)
	if err != nil {
		die("%v", err)
	}
	if host != cfg.addr {
		fmt.Fprintf(os.Stderr, "%s resolves to %s\n", cfg.addr, host)
	}
	cfg.addr = host

	protos, err := bench.SelectProtocols(cfg.only)
	if err != nil {
		die("%v", err)
	}
	activeProtocols = protos
	dirs, err := bench.SelectDirs(cfg.dirs)
	if err != nil {
		die("%v", err)
	}

	fmt.Fprintf(os.Stderr, "checking %s ...\n", cfg.addr)
	preflight(cfg.addr)
	mark := markServer(cfg.addr) // responder CPU baseline

	var all []outcome
	var samples []sample
	for r := 1; r <= cfg.runs; r++ {
		if !cfg.noSolo {
			for _, dir := range dirs {
				for _, p := range protos {
					fmt.Fprintf(os.Stderr, "run %d/%d  solo %-8s %s ...\n", r, cfg.runs, dir, p)
					o, ss := runSolo(p, *addr, dir, size, r)
					mark = attachServerCPU(cfg.addr, mark, o)
					all = append(all, o...)
					samples = append(samples, ss...)
				}
			}
		}
		if len(protos) < 2 {
			continue // a single protocol has nothing to compete with
		}
		for _, dir := range dirs {
			fmt.Fprintf(os.Stderr, "run %d/%d  parallel %-8s qotp+tcp+quic ...\n", r, cfg.runs, dir)
			outs, ss := runParallel(*addr, dir, size, r)
			mark = attachServerCPU(cfg.addr, mark, outs)
			all = append(all, outs...)
			samples = append(samples, ss...)
		}
	}

	// The responder counted every byte it actually received. Ask for the final
	// totals over qotp rather than leaving the operator to read two consoles.
	srv, err := fetchServerReport(target(cfg.addr, "qotp"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: could not collect the responder's report: %v\n", err)
	}

	report(all, cfg.sizeMB, cfg.runs, srv)

	if cfg.jsonPath != "" {
		if err := writeJSON(cfg, all, samples, srv); err != nil {
			die("json: %v", err)
		}
		fmt.Printf("\njson: %s\n", cfg.jsonPath)
	}
}

// /proc/stat advances in 10 ms ticks, so a phase shorter than this yields a
// CPU figure that is mostly quantisation. Better no column than a wrong one.
const minCPUWindow = 500 * time.Millisecond

// activeProtocols is the set this run measures; -only narrows it.
var activeProtocols = bench.Protocols

// srvMark is a responder CPU reading and when it was taken; two of them
// difference to the responder's load during the phase between.
type srvMark struct {
	rep *bench.ServerReport
	at  time.Time
}

func markServer(addr string) srvMark {
	r, err := fetchServerReport(target(addr, "qotp"))
	if err != nil {
		return srvMark{}
	}
	return srvMark{rep: r, at: time.Now()}
}

func target(addr string, proto string) string {
	return fmt.Sprintf("%s:%d", addr, bench.Port(portBase, proto))
}

func runSolo(proto, addr string, dir bench.Dir, size uint64, run int) ([]outcome, []sample) {
	return runGroup([]string{proto}, addr, dir, size, "solo", run)
}

// runParallel starts all three at the same instant, so the shares are measured
// while they are actually competing.
func runParallel(addr string, dir bench.Dir, size uint64, run int) ([]outcome, []sample) {
	return runGroup(activeProtocols, addr, dir, size, "parallel", run)
}

// runGroup runs protos concurrently and measures them all over one window, so
// a solo baseline and a contended run are directly comparable.
func runGroup(protos []string, addr string, dir bench.Dir, size uint64, mode string, run int) ([]outcome, []sample) {
	progs := map[string]*atomic.Uint64{}
	for _, p := range protos {
		progs[p] = &atomic.Uint64{}
	}

	var wg sync.WaitGroup
	outs := make([]outcome, len(protos))
	start := make(chan struct{})
	done := make(chan struct{}, len(protos))
	stopAt := deadline()
	cpu0, groupStart := bench.ReadCPU(), time.Now()
	stopSampler := make(chan struct{})
	var samples []sample
	var mu sync.Mutex

	for i, p := range protos {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			<-start
			dur, err := runners[p](target(addr, p), dir, size, stopAt, progs[p])
			outs[i] = outcome{run: run, proto: p, dir: dir, mode: mode, dur: dur, err: err}
			done <- struct{}{}
		}(i, p)
	}

	t0 := time.Now()
	snap := func() {
		el := time.Since(t0)
		mu.Lock()
		phase := mode + "-" + dir.String()
		for _, p := range protos {
			samples = append(samples, sample{p, phase, run, el, progs[p].Load()})
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

	cores, coresOK := bench.CoresBusy(cpu0, bench.ReadCPU())
	if time.Since(groupStart) < minCPUWindow {
		coresOK = false
	}

	// Measurement window. In duration mode every flow runs the whole time, so
	// the window is [warmup, end] and all three are measured over the same
	// steady-state interval. In size mode it has to close when the first flow
	// finishes, because after that the survivors inherit its bandwidth.
	from, to := time.Duration(0), time.Duration(1<<62-1)
	for _, o := range outs {
		if o.err == nil && o.dur < to {
			to = o.dur
		}
	}
	if runDuration > 0 {
		from = warmupOf(runDuration)
	}

	mu.Lock()
	defer mu.Unlock()
	for i := range outs {
		outs[i].cores, outs[i].coresOK = cores, coresOK
		outs[i].bytes = progs[outs[i].proto].Load()
		outs[i].contBps = rateBetween(samples, outs[i].proto, from, to)
		if outs[i].contBps == 0 && outs[i].err == nil && outs[i].dur > 0 {
			outs[i].contBps = float64(outs[i].bytes) / outs[i].dur.Seconds()
		}
	}
	return outs, samples
}

// rateBetween is the average byte rate of proto across [from, to], taken from
// the cumulative samples that bracket the window.
func rateBetween(samples []sample, proto string, from, to time.Duration) float64 {
	var loT, hiT time.Duration
	var loB, hiB uint64
	for _, s := range samples {
		if s.proto != proto {
			continue
		}
		if s.t <= from && s.t >= loT {
			loT, loB = s.t, s.bytes
		}
		if s.t <= to && s.t > hiT {
			hiT, hiB = s.t, s.bytes
		}
	}
	if hiT <= loT || hiB < loB {
		return 0
	}
	return float64(hiB-loB) / (hiT - loT).Seconds()
}

// =============================================================================
// Reporting
// =============================================================================

func report(all []outcome, sizeMB, runs int, srv *bench.ServerReport) {
	soloMed := map[string]map[bench.Dir]float64{}
	for _, p := range activeProtocols {
		soloMed[p] = map[bench.Dir]float64{}
		for _, d := range []bench.Dir{bench.Upload, bench.Download} {
			if m, _, _ := stats(rates(all, "solo", d, p)); m > 0 {
				soloMed[p][d] = m
			}
		}
	}

	if runDuration > 0 {
		fmt.Printf("\n%v per transfer, %d run(s), %d cores\n", runDuration, runs, bench.NumCPU())
	} else {
		fmt.Printf("\n%d MB per protocol per direction, %d run(s), %d cores\n", sizeMB, runs, bench.NumCPU())
	}

	for _, mode := range []string{"solo", "parallel"} {
		for _, dir := range []bench.Dir{bench.Upload, bench.Download} {
			rows := filter(all, mode, dir)
			if len(rows) == 0 {
				continue
			}
			fmt.Printf("\n== %s / %s ==\n", mode, dir)
			flows := 1
			if mode == "parallel" {
				flows = len(activeProtocols)
			}
			fmt.Printf("  %-5s %10s %-16s %8s %8s %s\n", "proto", "Mbps", "[min-max]", "share", "vs solo", "cpu (here / responder)")

			var meds []float64
			for _, p := range activeProtocols {
				m, _, _ := stats(rates(all, mode, dir, p))
				meds = append(meds, m)
			}
			var total float64
			for _, m := range meds {
				total += m
			}

			for i, p := range activeProtocols {
				if e := firstErr(rows, p); e != nil {
					fmt.Printf("  %-5s  FAILED: %v\n", p, e)
					continue
				}
				_, lo, hi := stats(rates(all, mode, dir, p))
				share, vsSolo := "-", "-"
				if mode == "parallel" && total > 0 {
					share = fmt.Sprintf("%.1f%%", 100*meds[i]/total)
					if sm := soloMed[p][dir]; sm > 0 {
						vsSolo = fmt.Sprintf("%.0f%%", 100*meds[i]/sm)
					}
				}
				fmt.Printf("  %-5s %10.1f %-16s %8s %8s %s\n", p, meds[i],
					fmt.Sprintf("[%.1f-%.1f]", lo, hi), share, vsSolo, cpuCol(rows, p))
			}

			if mode == "parallel" {
				jm, jlo, jhi := stats(jains(all, dir))
				fmt.Printf("  Jain fairness index: %.3f [%.3f-%.3f]   (1.000 = equal shares, %.3f = one flow takes all)\n",
					jm, jlo, jhi, 1/float64(len(activeProtocols)))
				if jhi-jlo > 0.15 {
					fmt.Printf("  !! spread %.3f across runs: too unstable to compare protocols — raise -runs and check the bottleneck queue\n", jhi-jlo)
				}
			}
			warnCPU(rows, flows)
		}
	}

	if srv != nil {
		fmt.Printf("\n== responder ==\n")
		for _, p := range activeProtocols {
			fmt.Printf("  %-5s received %8.1f MB\n", p, float64(srv.ReceivedBytes[p])/1e6)
		}
		fmt.Printf("  session %.0fs, %d cores\n", srv.SessionSecs, srv.NumCPU)
	}

	fmt.Println("\nMbps is measured over the steady-state window: after a warm-up, and")
	if runDuration > 0 {
		fmt.Println("across the same interval for all three, since every flow runs the full")
		fmt.Println("duration. Upload progress is sampled from each protocol's delivery")
	} else {
		fmt.Println("ending when the first flow finishes, since the survivors then inherit its")
		fmt.Println("bandwidth. Upload progress is sampled from each protocol's delivery")
	}
	fmt.Println("counter (qotp BytesDelivered, TCP tcpi_bytes_acked); QUIC has no")
	fmt.Println("acked-bytes counter, so its upload samples lag by up to one flow-control")
	fmt.Println("window. Download progress is counted on receipt for all three.")
	fmt.Println("\nThe cpu column is cores busy on each side during that phase alone. A")
	fmt.Println("flagged phase is a CPU measurement, not a protocol comparison: qotp and")
	fmt.Println("quic do per-packet work in userspace where tcp does it in the kernel, so")
	fmt.Println("at a rate that pins a core the table ranks stacks by cost per packet.")
	fmt.Println("Re-run at a rate that leaves headroom to compare the protocols instead.")
}

// attachServerCPU asks the responder for a fresh report and records how busy
// it was since the previous one — that is, during the phase just finished.
// Returns the new mark. A failure is not fatal: the column is simply omitted.
func attachServerCPU(addr string, prev srvMark, outs []outcome) srvMark {
	now := markServer(addr)
	if now.rep == nil || prev.rep == nil || !now.rep.CPUKnown || !prev.rep.CPUKnown {
		return now
	}
	dt := now.rep.CPUTotal - prev.rep.CPUTotal
	if dt <= 0 || now.at.Sub(prev.at) < minCPUWindow {
		return now
	}
	cores := (now.rep.CPUBusy - prev.rep.CPUBusy) / dt * float64(now.rep.NumCPU)
	for i := range outs {
		outs[i].srvCores, outs[i].srvNumCPU, outs[i].srvOK = cores, now.rep.NumCPU, true
	}
	return now
}

func rates(all []outcome, mode string, dir bench.Dir, proto string) []float64 {
	var v []float64
	for _, o := range all {
		if o.mode == mode && o.dir == dir && o.proto == proto && o.err == nil {
			v = append(v, o.mbps())
		}
	}
	return v
}

// jains computes the fairness index per run, then reports the set — a single
// index hides how much it moved between runs, which is the thing that decides
// whether the number means anything.
func jains(all []outcome, dir bench.Dir) []float64 {
	byRun := map[int][]float64{}
	seen := map[string]int{}
	for _, o := range all {
		if o.mode != "parallel" || o.dir != dir || o.err != nil {
			continue
		}
		r := seen[o.proto]
		seen[o.proto]++
		byRun[r] = append(byRun[r], o.mbps())
	}
	var out []float64
	for _, v := range byRun {
		if len(v) == len(activeProtocols) {
			out = append(out, bench.JainIndex(v))
		}
	}
	return out
}

func firstErr(rows []outcome, proto string) error {
	for _, o := range rows {
		if o.proto == proto && o.err != nil {
			return o.err
		}
	}
	return nil
}

func cpuCol(rows []outcome, proto string) string {
	local, srv := "-", "-"
	for _, o := range rows {
		if o.proto != proto {
			continue
		}
		if o.coresOK && local == "-" {
			local = fmt.Sprintf("%.1f/%d", o.cores, bench.NumCPU())
		}
		if o.srvOK && srv == "-" {
			srv = fmt.Sprintf("%.1f/%d", o.srvCores, o.srvNumCPU)
		}
	}
	if local == "-" && srv == "-" {
		return ""
	}
	return local + " / " + srv
}

// peak returns the busiest observation on one side, so a core pinned during a
// single phase is not averaged away by the quiet ones around it.
func peak(rows []outcome, pick func(outcome) (float64, bool)) (float64, bool) {
	worst, ok := 0.0, false
	for _, o := range rows {
		if v, valid := pick(o); valid && v > worst {
			worst, ok = v, true
		}
	}
	return worst, ok
}

// Either side pinning a core per flow means the benchmark measured per-packet
// CPU cost rather than the path. Both userspace stacks here run a connection on
// one goroutine, so this caps throughput long before the machine looks busy.
func warnCPU(rows []outcome, flows int) {
	local, localOK := peak(rows, func(o outcome) (float64, bool) { return o.cores, o.coresOK })
	srv, srvOK := peak(rows, func(o outcome) (float64, bool) { return o.srvCores, o.srvOK })

	var who []string
	if localOK && bench.CPUBound(local, flows) {
		who = append(who, fmt.Sprintf("this side %.1f", local))
	}
	if srvOK && bench.CPUBound(srv, flows) {
		who = append(who, fmt.Sprintf("responder %.1f", srv))
	}
	if len(who) > 0 {
		fmt.Printf("  !! CPU-bound (%s cores for %d flow(s)): measures per-packet CPU, not the link\n",
			strings.Join(who, ", "), flows)
	}
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
