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
	secondNano = 1_000_000_000
	msNano     = 1_000_000

	// MTU negotiation constants
	ipOverhead      = 48   // always use IPv6 worst-case (IPv4=28, IPv6=48)
	conservativeMTU = 1232 // IPv6 min link MTU (1280) - 48 headers; hard floor

	mtuFallbackThreshold = 5  // consecutive losses before fallback to conservativeMTU
	windowSize           = 10 // rolling window for min/max filters
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
	probeMultiplier = uint64(8) // Probe every 8x RTT_min
	probeRounds     = uint64((windowSize + 1) / 2) // Keep probe gain long enough to fill bw window

	// BBR pacing gains (percentage, 100 = 1.0x)
	startupGain = uint64(277) // 2.77x aggressive growth
	normalGain  = uint64(100) // 1.0x steady state
	probeGain   = uint64(200) // 2.0x probe bandwidth

	// BBR state transitions
	bwDecThreshold    = uint64(3)   // Exit startup after 3 non-increasing rounds
	startupGrowthPct  = uint64(125) // Require 25% bandwidth growth per round

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
	rttSamples        [windowSize]uint64 // Rolling window of RTT samples
	rttSampleIdx      int                // Next write index into rttSamples
	rttMinNano        uint64             // Min of rttSamples (cached)
	bwSamples         [windowSize]uint64 // Rolling window of bandwidth samples
	bwSampleIdx       int                // Next write index into bwSamples
	bwMax             uint64             // Max of bwSamples (cached)
	bwDec             uint64             // Consecutive samples without bandwidth increase
	lastProbeTimeNano    uint64 // When we last probed for more bandwidth
	probeRoundsRemaining uint64 // Rounds left in current probe cycle
	pacingGainPct        uint64 // Current pacing multiplier

	// Delivery rate tracking
	totalDelivered uint64 // cumulative bytes ACK'd

	// Round tracking (BBR packet-timed rounds)
	roundDeliveredTarget uint64 // totalDelivered threshold to end current round
	roundBwBest          uint64 // best bw sample seen during the current round
	prevRoundBwBest      uint64 // best bw sample from the previous round

	// MTU
	negotiatedMTU int // original negotiated value (for restoring after fallback)

	// Stats
	packetLossNr int
	packetDupNr  int
}

func newMeasurements(mtu int) measurements {
	m := measurements{
		isStartup:     true,
		pacingGainPct: startupGain,
		rttMinNano:    math.MaxUint64,
		negotiatedMTU: mtu,
	}
	for i := range m.rttSamples {
		m.rttSamples[i] = math.MaxUint64
	}
	return m
}

// updateMTU adjusts MTU-dependent fields without resetting congestion state.
func (m *measurements) updateMTU(mtu int) {
	m.negotiatedMTU = mtu
}

// =============================================================================
// RTT and bandwidth updates
// =============================================================================

func (m *measurements) updateMeasurements(rttNano uint64, ackLen uint16, deliveredAtSend uint64, nowNano uint64) {
	if rttNano == 0 || nowNano == 0 {
		slog.Warn("invalid measurement", "rtt", rttNano, "now", nowNano)
		return
	}
	if rttNano > ReadDeadLine {
		slog.Warn("suspiciously high RTT", "rtt_seconds", rttNano/secondNano)
		return
	}

	m.totalDelivered += uint64(ackLen)
	m.updateRTT(rttNano)
	m.updateMinRTT(rttNano)
	m.updateBandwidth(deliveredAtSend, rttNano)
	m.updateBBRState(nowNano)
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

func (m *measurements) updateMinRTT(rttNano uint64) {
	m.rttSamples[m.rttSampleIdx] = rttNano
	m.rttSampleIdx = (m.rttSampleIdx + 1) % windowSize

	rttMin := uint64(math.MaxUint64)
	for _, s := range m.rttSamples {
		if s < rttMin {
			rttMin = s
		}
	}
	m.rttMinNano = rttMin
}

func (m *measurements) updateBandwidth(deliveredAtSend uint64, rttNano uint64) {
	if rttNano == 0 || m.totalDelivered <= deliveredAtSend {
		return
	}

	delivered := m.totalDelivered - deliveredAtSend
	bwCurrent := (delivered * secondNano) / rttNano

	slog.Debug("bwSample",
		"bwCurrent_MBs", bwCurrent/1_000_000,
		"delivered", delivered,
		"rtt_us", rttNano/1000,
		"deliveredAtSend", deliveredAtSend,
		"totalDelivered", m.totalDelivered,
	)

	// Write into rolling window
	m.bwSamples[m.bwSampleIdx] = bwCurrent
	m.bwSampleIdx = (m.bwSampleIdx + 1) % windowSize

	// Recompute max from window
	var bwMax uint64
	for _, s := range m.bwSamples {
		if s > bwMax {
			bwMax = s
		}
	}
	m.bwMax = bwMax

	// Track best bandwidth in current round
	if bwCurrent > m.roundBwBest {
		m.roundBwBest = bwCurrent
	}

	// Round completion: all packets in-flight at round start have been ACK'd
	if deliveredAtSend >= m.roundDeliveredTarget {
		m.onRoundEnd()
		m.roundDeliveredTarget = m.totalDelivered
		m.prevRoundBwBest = m.roundBwBest
		m.roundBwBest = 0

		if m.probeRoundsRemaining > 0 {
			m.probeRoundsRemaining--
			if m.probeRoundsRemaining == 0 {
				m.pacingGainPct = normalGain
			}
		}
	}
}

// onRoundEnd checks bandwidth growth over the completed round.
func (m *measurements) onRoundEnd() {
	if m.prevRoundBwBest == 0 {
		return
	}
	// Did bandwidth grow by at least 25% this round?
	threshold := (m.prevRoundBwBest * startupGrowthPct) / 100
	if m.roundBwBest >= threshold {
		m.bwDec = 0
	} else {
		m.bwDec++
	}
}

func (m *measurements) updateBBRState(nowNano uint64) {
	if m.lastProbeTimeNano == 0 {
		m.lastProbeTimeNano = nowNano
	}

	if m.isStartup {
		m.updateStartup()
	} else {
		m.updateNormal(nowNano)
	}
}

func (m *measurements) updateStartup() {
	slog.Debug("updateStartup",
		"bwMax_MBs", m.bwMax/1_000_000,
		"roundBwBest_MBs", m.roundBwBest/1_000_000,
		"prevRoundBwBest_MBs", m.prevRoundBwBest/1_000_000,
		"bwDec", m.bwDec,
		"roundTarget", m.roundDeliveredTarget,
		"delivered", m.totalDelivered,
		"gain_pct", m.pacingGainPct,
	)
	if m.bwDec >= bwDecThreshold {
		m.isStartup = false
		m.pacingGainPct = normalGain
	}
}

func (m *measurements) updateNormal(nowNano uint64) {
	if m.probeRoundsRemaining == 0 && nowNano-m.lastProbeTimeNano > m.rttMinNano*probeMultiplier {
		m.pacingGainPct = probeGain
		m.probeRoundsRemaining = probeRounds
		m.lastProbeTimeNano = nowNano
	}

	slog.Debug("updateNormal",
		"bwMax_MBs", m.bwMax/1_000_000,
		"gain_pct", m.pacingGainPct,
		"srtt_us", m.srtt/1000,
		"rttMin_us", m.rttMinNano/1000,
		"delivered_MB", m.totalDelivered/1_000_000,
	)
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
		if rtoNano > maxRTO {
			rtoNano = maxRTO
		}
	}
	return rtoNano, nil
}

// =============================================================================
// Congestion events
// =============================================================================

func (m *measurements) onDuplicateAck() {
	m.packetDupNr++
}

func (m *measurements) onPacketLoss() {
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