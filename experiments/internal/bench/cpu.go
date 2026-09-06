package bench

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

// CPU sampling. A throughput number is only about the network if the machine
// had CPU to spare; if the box was saturated, the benchmark measured the CPU,
// not the link. Sampling is system-wide because client, server and any qdisc
// all compete on the same host in a loopback or netns setup.
type CPU struct {
	Busy, Total float64
	OK          bool
}

// ReadCPU samples /proc/stat. Returns ok=false off Linux, and callers then
// simply omit the CPU column rather than reporting something invented.
func ReadCPU() CPU {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPU{}
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 8 || f[0] != "cpu" {
		return CPU{}
	}
	var total, idle float64
	for i, v := range f[1:] {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return CPU{}
		}
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return CPU{Busy: total - idle, Total: total, OK: true}
}

// CoresBusy reports the average number of cores busy between two samples.
func CoresBusy(start, end CPU) (float64, bool) {
	if !start.OK || !end.OK {
		return 0, false
	}
	dt := end.Total - start.Total
	if dt <= 0 {
		return 0, false
	}
	return (end.Busy - start.Busy) / dt * float64(runtime.NumCPU()), true
}

// NumCPU is the core count the fractions above are measured against.
func NumCPU() int { return runtime.NumCPU() }

// CPUBound reports whether the measurement says more about the CPU than about
// the network. The test that matters is a core per flow, not the machine
// total: both userspace stacks here process a connection on one goroutine, so
// a pinned core caps throughput while the box still looks 85% idle.
func CPUBound(cores float64, flows int) bool {
	if flows < 1 {
		flows = 1
	}
	return cores/float64(flows) >= 0.9 || cores > 0.9*float64(runtime.NumCPU())
}
