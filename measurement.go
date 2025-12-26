package qotp

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
)

var (
	defaultRTO = uint64(200 * msNano)
	minRTO     = uint64(100 * msNano)
	maxRTO     = uint64(2000 * msNano)

	rttExpiry       = uint64(10 * secondNano)
	probeMultiplier = uint64(8)

	startupGain = uint64(277)
	normalGain  = uint64(100)
	drainGain   = uint64(75)
	probeGain   = uint64(125)

	bwDecThreshold = uint64(3)

	dupAckBwReduction = uint64(98)
	dupAckGain        = uint64(90)

	lossBwReduction = uint64(95)

	fallbackInterval = uint64(10 * msNano)
	rttDivisor       = uint64(10)

	rttInflationHigh     = uint64(150)
	rttInflationModerate = uint64(125)

	MinDeadLine  = uint64(100 * msNano)
	ReadDeadLine = uint64(30 * secondNano) // 30 seconds

	//backoff
	maxRetry      = 5
	rtoBackoffPct = uint64(200)
)

// Combined measurement state - both RTT and BBR in one struct
type Measurements struct {
	// RTT fields
	srtt   uint64 // Smoothed RTT
	rttvar uint64 // RTT variation

	// BBR fields
	isStartup         bool   // true = startup, false = normal
	rttMinNano        uint64 // Keep lowest RTT samples
	rttMinTimeNano    uint64 // When we observed the lowest RTT sample
	bwMax             uint64 // Bytes per second
	bwDec             uint64
	lastProbeTimeNano uint64 // When we last probed for more bandwidth
	pacingGainPct     uint64 // Current pacing gain (100 = 1.0x, 277 = 2.77x)
	lastReadTimeNano  uint64 // Time of last activity

	//Perf numbers
	packetLossNr int
	packetDupNr  int

	cwnd uint64
}

// NewMeasurements creates a new instance with default values
func NewMeasurements() Measurements {
	return Measurements{
		isStartup:      true,
		pacingGainPct:  startupGain,
		rttMinNano:     math.MaxUint64,
		rttMinTimeNano: math.MaxUint64,
		cwnd:           10 * 1400,
	}
}

func (c *Conn) updateMeasurements(rttMeasurementNano uint64, rawLen int, nowNano uint64) {
	// Validation
	if rttMeasurementNano == 0 {
		slog.Warn("cannot update measurements, rtt is 0")
		return
	}
	if rttMeasurementNano > ReadDeadLine {
		slog.Warn("suspiciously high RTT measurement", "rtt_seconds", rttMeasurementNano/secondNano)
		return
	}
	if nowNano == 0 {
		slog.Warn("invalid timestamp")
		return
	}

	// Update RTT (smoothed RTT and variation)
	if c.srtt == 0 {
		// First measurement
		c.srtt = rttMeasurementNano
		c.rttvar = rttMeasurementNano / 2
	} else {
		// Calculate absolute difference for RTT variation
		var delta uint64
		if rttMeasurementNano > c.srtt {
			delta = rttMeasurementNano - c.srtt
		} else {
			delta = c.srtt - rttMeasurementNano
		}

		// Integer-based updates using exact fractions
		c.rttvar = (c.rttvar*3)/4 + (delta*1)/4
		c.srtt = (c.srtt*7)/8 + (rttMeasurementNano*1)/8
	}

	// Update BBR minimum RTT tracking
	if (nowNano > c.rttMinTimeNano && nowNano-c.rttMinTimeNano >= rttExpiry) ||
		rttMeasurementNano < c.rttMinNano {
		c.rttMinNano = rttMeasurementNano
		c.rttMinTimeNano = nowNano
	}

	// Update BBR bandwidth estimation
	bwCurrent := uint64(0)
	if c.rttMinNano > 0 {
		bwCurrent = (uint64(rawLen) * 1_000_000_000) / c.rttMinNano
	}

	if bwCurrent > c.bwMax {
		c.bwMax = bwCurrent
		c.bwDec = 0
	} else {
		c.bwDec++
	}

	// Initialize probe time on first measurement
	if c.lastProbeTimeNano == 0 {
		c.lastProbeTimeNano = nowNano
	}

	// BBR state-specific behavior
	if c.isStartup {
		if c.bwDec >= bwDecThreshold {
			c.isStartup = false
			c.pacingGainPct = normalGain
		}

		c.cwnd += uint64(rawLen) * c.pacingGainPct / 100
	} else {
		// Normal state logic
		rttRatioPct := (c.srtt * 100) / c.rttMinNano

		if rttRatioPct > rttInflationHigh {
			c.pacingGainPct = drainGain
		} else if rttRatioPct > rttInflationModerate {
			c.pacingGainPct = dupAckGain
		} else if nowNano-c.lastProbeTimeNano > c.rttMinNano*probeMultiplier {
			c.pacingGainPct = probeGain
			c.lastProbeTimeNano = nowNano
		} else {
			c.pacingGainPct = normalGain
		}

		bdp := (c.bwMax * c.rttMinNano) / 1_000_000_000
		c.cwnd = max(bdp*2, 10*1400)
	}
}

func (c *Conn) rtoNano() uint64 {
	rto := c.srtt + 4*c.rttvar

	switch {
	case rto == 0:
		return defaultRTO
	case rto < minRTO:
		return minRTO
	case rto > maxRTO:
		return maxRTO
	default:
		return rto
	}
}

func (c *Conn) onDuplicateAck() {
	c.bwMax = c.bwMax * dupAckBwReduction / 100
	c.pacingGainPct = dupAckGain
	c.packetDupNr++

	if c.isStartup {
		c.isStartup = false
	}
	
	// Reduce cwnd immediately
    c.cwnd = c.cwnd * dupAckBwReduction / 100
    c.cwnd = max(c.cwnd, 10*1400)
}

func (c *Conn) onPacketLoss() {
	c.bwMax = c.bwMax * lossBwReduction / 100
	c.pacingGainPct = normalGain
	c.isStartup = false
	c.packetLossNr++
	
	// Reduce cwnd immediately
    c.cwnd = c.cwnd * lossBwReduction / 100
    c.cwnd = max(c.cwnd, 10*1400)
}

func (c *Conn) calcPacing(packetSize uint64) uint64 {
	if c.bwMax == 0 {
		if c.srtt > 0 {
			return c.srtt / rttDivisor
		}
		return fallbackInterval
	}

	adjustedBandwidth := (c.bwMax * c.pacingGainPct) / 100
	if adjustedBandwidth == 0 {
		return fallbackInterval
	}

	return (packetSize * 1_000_000_000) / adjustedBandwidth
}

func backoff(rtoNano uint64, rtoNr int) (uint64, error) {
	if rtoNr <= 0 {
		return 0, errors.New("backoff requires a positive rto number")
	}
	if rtoNr > maxRetry {
		return 0, fmt.Errorf("max retry attempts: %v exceeded limit %v", rtoNr, maxRetry)
	}

	for i := 1; i < rtoNr; i++ {
		rtoNano = (rtoNano * rtoBackoffPct) / 100
	}

	return rtoNano, nil
}
