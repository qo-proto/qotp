package qotp

import (
	"fmt"
	"log/slog"
	"math"
)

// =============================================================================
// Constants
// =============================================================================

const (
	defaultMTU     = 1400
	minCwndPackets = 10

	secondNano = 1_000_000_000
	msNano     = 1_000_000
)

// =============================================================================
// Tunable parameters (var to allow test overrides)
// =============================================================================

var (
	// RTO bounds
	defaultRTO = uint64(200 * msNano)
	minRTO     = uint64(100 * msNano)
	maxRTO     = uint64(2000 * msNano)

	// Retransmission backoff
	maxRetry      = uint(5)
	rtoBackoffPct = uint64(200) // 2x per retry

	// BBR timing
	rttExpiry       = uint64(10 * secondNano) // Min RTT sample expiry
	probeMultiplier = uint64(8)               // Probe every 8x RTT_min

	// BBR pacing gains (percentage, 100 = 1.0x)
	startupGain = uint64(277) // 2.77x aggressive growth
	normalGain  = uint64(100) // 1.0x steady state
	drainGain   = uint64(75)  // 0.75x reduce queue
	probeGain   = uint64(125) // 1.25x probe bandwidth

	// BBR state transitions
	bwDecThreshold = uint64(3) // Exit startup after 3 non-increasing samples

	// Congestion response
	dupAckBwReduction = uint64(98) // 2% reduction on dup ACK
	dupAckGain        = uint64(90)
	lossBwReduction   = uint64(95) // 5% reduction on loss

	// RTT inflation thresholds (percentage of min RTT)
	rttInflationHigh     = uint64(150) // > 1.5x triggers drain
	rttInflationModerate = uint64(125) // > 1.25x triggers mild backoff

	// Pacing fallbacks
	fallbackInterval = uint64(10 * msNano)
	rttDivisor       = uint64(10)

	// Timeouts
	MinDeadLine  = uint64(100 * msNano)
	ReadDeadLine = uint64(30 * secondNano)
)

// =============================================================================
// Measurements - RTT estimation and BBR congestion control
// =============================================================================

type measurements struct {
	// RTT estimation (RFC 6298)
	srtt   uint64 // Smoothed RTT
	rttvar uint64 // RTT variation

	// BBR state
	isStartup         bool
	rttMinNano        uint64 // Minimum RTT sample (expires after rttExpiry)
	rttMinTimeNano    uint64 // When min RTT was observed
	bwMax             uint64 // Maximum bandwidth estimate (bytes/sec)
	bwDec             uint64 // Consecutive samples without bandwidth increase
	lastProbeTimeNano uint64 // When we last probed for more bandwidth
	pacingGainPct     uint64 // Current pacing multiplier
	cwnd              uint64 // Congestion window (bytes)

	// Stats
	packetLossNr int
	packetDupNr  int
}

func newMeasurements() measurements {
	return measurements{
		isStartup:      true,
		pacingGainPct:  startupGain,
		rttMinNano:     math.MaxUint64,
		rttMinTimeNano: math.MaxUint64,
		cwnd:           minCwndPackets * defaultMTU,
	}
}

// =============================================================================
// RTT and bandwidth updates
// =============================================================================

func (m *measurements) updateMeasurements(rttNano uint64, packetSize uint16, nowNano uint64) {
	if rttNano == 0 || nowNano == 0 {
		slog.Warn("invalid measurement", "rtt", rttNano, "now", nowNano)
		return
	}
	if rttNano > ReadDeadLine {
		slog.Warn("suspiciously high RTT", "rtt_seconds", rttNano/secondNano)
		return
	}

	m.updateRTT(rttNano)
	m.updateMinRTT(rttNano, nowNano)
	m.updateBandwidth(packetSize)
	m.updateBBRState(packetSize, nowNano)
}

// updateRTT implements RFC 6298 smoothed RTT calculation
func (m *measurements) updateRTT(rttNano uint64) {
	if m.srtt == 0 {
		m.srtt = rttNano
		m.rttvar = rttNano / 2
		return
	}

	// delta = |SRTT - R|
	var delta uint64
	if rttNano > m.srtt {
		delta = rttNano - m.srtt
	} else {
		delta = m.srtt - rttNano
	}

	// RTTVAR = 3/4 * RTTVAR + 1/4 * delta
	// SRTT = 7/8 * SRTT + 1/8 * R
	m.rttvar = (m.rttvar*3 + delta) / 4
	m.srtt = (m.srtt*7 + rttNano) / 8
}

func (m *measurements) updateMinRTT(rttNano, nowNano uint64) {
	expired := nowNano > m.rttMinTimeNano && nowNano-m.rttMinTimeNano >= rttExpiry
	if expired || rttNano < m.rttMinNano {
		m.rttMinNano = rttNano
		m.rttMinTimeNano = nowNano
	}
}

func (m *measurements) updateBandwidth(packetSize uint16) {
	if m.rttMinNano == 0 {
		return
	}

	bwCurrent := (uint64(packetSize) * secondNano) / m.rttMinNano
	if bwCurrent > m.bwMax {
		m.bwMax = bwCurrent
		m.bwDec = 0
	} else {
		m.bwDec++
	}
}

func (m *measurements) updateBBRState(packetSize uint16, nowNano uint64) {
	if m.lastProbeTimeNano == 0 {
		m.lastProbeTimeNano = nowNano
	}

	if m.isStartup {
		m.updateStartup(packetSize)
	} else {
		m.updateNormal(nowNano)
	}
}

func (m *measurements) updateStartup(packetSize uint16) {
	if m.bwDec >= bwDecThreshold {
		m.isStartup = false
		m.pacingGainPct = normalGain
	}
	m.cwnd += uint64(packetSize) * m.pacingGainPct / 100
}

func (m *measurements) updateNormal(nowNano uint64) {
	rttRatioPct := (m.srtt * 100) / m.rttMinNano

	switch {
	case rttRatioPct > rttInflationHigh:
		m.pacingGainPct = drainGain
	case rttRatioPct > rttInflationModerate:
		m.pacingGainPct = dupAckGain
	case nowNano-m.lastProbeTimeNano > m.rttMinNano*probeMultiplier:
		m.pacingGainPct = probeGain
		m.lastProbeTimeNano = nowNano
	default:
		m.pacingGainPct = normalGain
	}

	bdp := (m.bwMax * m.rttMinNano) / secondNano
	m.cwnd = max(bdp*2, minCwndPackets*defaultMTU)
}

// =============================================================================
// RTO calculation
// =============================================================================

func (m *measurements) rtoNano() uint64 {
	rto := m.srtt + 4*m.rttvar

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

func backoff(rtoNano uint64, attempt uint) (uint64, error) {
	if attempt >= maxRetry {
		return 0, fmt.Errorf("max retry attempts: %v exceeded limit %v", attempt, maxRetry)
	}
	for i := uint(0); i < attempt; i++ {
		rtoNano = (rtoNano * rtoBackoffPct) / 100
	}
	return rtoNano, nil
}

// =============================================================================
// Congestion events
// =============================================================================

func (m *measurements) reduceCwnd(reduction, gain uint64) {
	m.bwMax = m.bwMax * reduction / 100
	m.pacingGainPct = gain
	m.isStartup = false
	m.cwnd = max(m.cwnd*reduction/100, minCwndPackets*defaultMTU)
}

func (m *measurements) onDuplicateAck() {
	m.reduceCwnd(dupAckBwReduction, dupAckGain)
	m.packetDupNr++
}

func (m *measurements) onPacketLoss() {
	m.reduceCwnd(lossBwReduction, normalGain)
	m.packetLossNr++
}

// =============================================================================
// Pacing
// =============================================================================

func (m *measurements) calcPacing(packetSize uint64) uint64 {
	if m.bwMax == 0 {
		if m.srtt > 0 {
			return m.srtt / rttDivisor
		}
		return fallbackInterval
	}

	adjustedBw := (m.bwMax * m.pacingGainPct) / 100
	if adjustedBw == 0 {
		return fallbackInterval
	}

	return (packetSize * secondNano) / adjustedBw
}