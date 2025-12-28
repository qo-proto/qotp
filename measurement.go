package qotp

import (
	"fmt"
	"log/slog"
	"math"
)

const (
	defaultMTU     = 1400
	minCwndPackets = 10
	
	secondNano        = 1_000_000_000
	msNano            = 1_000_000
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
	maxRetry      = uint(5)
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
		cwnd:           minCwndPackets * defaultMTU,
	}
}

func (m *Measurements) updateMeasurements(rttMeasurementNano uint64, packetSize uint16, nowNano uint64) {
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
	if m.srtt == 0 {
		// First measurement
		m.srtt = rttMeasurementNano
		m.rttvar = rttMeasurementNano / 2
	} else {
		// Calculate absolute difference for RTT variation
		var delta uint64
		if rttMeasurementNano > m.srtt {
			delta = rttMeasurementNano - m.srtt
		} else {
			delta = m.srtt - rttMeasurementNano
		}

		// Integer-based updates using exact fractions
		m.rttvar = (m.rttvar*3)/4 + (delta*1)/4
		m.srtt = (m.srtt*7)/8 + (rttMeasurementNano*1)/8
	}

	// Update BBR minimum RTT tracking
	if (nowNano > m.rttMinTimeNano && nowNano-m.rttMinTimeNano >= rttExpiry) ||
		rttMeasurementNano < m.rttMinNano {
		m.rttMinNano = rttMeasurementNano
		m.rttMinTimeNano = nowNano
	}

	// Update BBR bandwidth estimation
	bwCurrent := uint64(0)
	if m.rttMinNano > 0 {
		bwCurrent = (uint64(packetSize) * 1_000_000_000) / m.rttMinNano
	}

	if bwCurrent > m.bwMax {
		m.bwMax = bwCurrent
		m.bwDec = 0
	} else {
		m.bwDec++
	}

	// Initialize probe time on first measurement
	if m.lastProbeTimeNano == 0 {
		m.lastProbeTimeNano = nowNano
	}

	// BBR state-specific behavior
	if m.isStartup {
		if m.bwDec >= bwDecThreshold {
			m.isStartup = false
			m.pacingGainPct = normalGain
		}

		m.cwnd += uint64(packetSize) * m.pacingGainPct / 100
	} else {
		// Normal state logic
		rttRatioPct := (m.srtt * 100) / m.rttMinNano

		if rttRatioPct > rttInflationHigh {
			m.pacingGainPct = drainGain
		} else if rttRatioPct > rttInflationModerate {
			m.pacingGainPct = dupAckGain
		} else if nowNano-m.lastProbeTimeNano > m.rttMinNano*probeMultiplier {
			m.pacingGainPct = probeGain
			m.lastProbeTimeNano = nowNano
		} else {
			m.pacingGainPct = normalGain
		}

		bdp := (m.bwMax * m.rttMinNano) / 1_000_000_000
		m.cwnd = max(bdp*2, minCwndPackets*defaultMTU)
	}
}

func (c *Measurements) rtoNano() uint64 {
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

func (m *Measurements) onDuplicateAck() {
	m.bwMax = m.bwMax * dupAckBwReduction / 100
	m.pacingGainPct = dupAckGain
	m.packetDupNr++

	if m.isStartup {
		m.isStartup = false
	}

	// Reduce cwnd immediately
	m.cwnd = m.cwnd * dupAckBwReduction / 100
	m.cwnd = max(m.cwnd, minCwndPackets*defaultMTU)
}

func (m *Measurements) onPacketLoss() {
	m.bwMax = m.bwMax * lossBwReduction / 100
	m.pacingGainPct = normalGain
	m.isStartup = false
	m.packetLossNr++

	// Reduce cwnd immediately
	m.cwnd = m.cwnd * lossBwReduction / 100
	m.cwnd = max(m.cwnd, minCwndPackets*defaultMTU)
}

func (m *Measurements) calcPacing(packetSize uint64) uint64 {
	if m.bwMax == 0 {
		if m.srtt > 0 {
			return m.srtt / rttDivisor
		}
		return fallbackInterval
	}

	adjustedBandwidth := (m.bwMax * m.pacingGainPct) / 100
	if adjustedBandwidth == 0 {
		return fallbackInterval
	}

	return (packetSize * 1_000_000_000) / adjustedBandwidth
}

func backoff(rtoNano uint64, rtoNr uint) (uint64, error) {
	if rtoNr >= maxRetry {
		return 0, fmt.Errorf("max retry attempts: %v exceeded limit %v", rtoNr, maxRetry)
	}
	for i := uint(0); i < rtoNr; i++ {
		rtoNano = (rtoNano * rtoBackoffPct) / 100
	}
	return rtoNano, nil
}
