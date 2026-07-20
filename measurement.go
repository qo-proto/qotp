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
	mtuFlapWarnThreshold = 3  // fallback→restore cycles before warning about a black hole
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

	// Fast retransmit: declare an original (gen-0) packet lost once this
	// many later-sent packets have been ACKed. 3 is QUIC's kPacketThreshold
	// (RFC 9002), inherited from TCP's three-dup-ACK rule — it tolerates
	// mild reordering while detecting loss in ~1 RTT instead of an RTO.
	fastRetxThreshold = uint8(3)

	// BBR timing
	probeMultiplier  = uint64(8) // Probe every 8x RTT_min
	probeCycleRounds = uint64(2) // One probe round (probeGain) + one drain round (drainGain)

	// BBR pacing gains (percentage, 100 = 1.0x)
	startupGain = uint64(277) // 2.77x aggressive growth
	normalGain  = uint64(100) // 1.0x steady state
	probeGain   = uint64(125) // 1.25x probe for spare bandwidth
	drainGain   = uint64(75)  // 0.75x drain the queue the probe built

	// BBR state transitions
	bwDecThreshold    = uint64(3)   // Exit startup after 3 non-increasing rounds
	startupGrowthPct  = uint64(125) // Require 25% bandwidth growth per round

	// Queue feedback: srtt above rttMin x queueThresholdPct/100 means a
	// standing queue is building at the bottleneck — drain instead of probe
	queueThresholdPct = uint64(125)

	// Fairness throttle: a persistent pacing multiplier with TCP-like
	// dynamics (multiplicative decrease, gradual recovery), so loss-based
	// flows sharing the bottleneck can claim their share. Engages only
	// when a round's loss rate exceeds the threshold — random loss below
	// it stays ignored (lossy-link performance is preserved). bwMax is
	// never touched: policy lives here, the sensor stays truthful.
	lossRateThresholdPct = uint64(2)  // congestion = >2% loss per window
	throttleBetaPct      = uint64(70) // multiplicative decrease per event
	throttleFloorPct     = uint64(30) // keep the flow alive
	throttleRecoverPct   = uint64(10) // points regained per clean window
	// Loss is judged over a multi-round window, not per round: single-round
	// ratios are far too noisy (a round is one flight; detections for
	// independent losses cluster into the round where their gap evidence
	// completes, and Karn shrinks the denominator during recovery), which
	// made random loss trigger spurious decreases. A window also gives
	// episode semantics for free: at most one MD per window. Minimum-lost
	// count protects small windows (low-rate phases) from small-sample
	// flukes.
	throttleWindowRounds = uint64(8)
	throttleMinLost      = uint64(8)

	// Pacing fallbacks
	fallbackInterval = uint64(10 * msNano)
	rttDivisor       = uint64(10)

	// Pacing burst allowance: how many unspent send opportunities may be
	// carried across late wakeups (token-bucket depth, in packets). Lets a
	// late wakeup catch up in a short burst instead of losing the slots.
	maxBurstPackets = uint64(10)

	// Timeouts
	MinDeadLine  = uint64(100 * msNano)
	ReadDeadLine = uint64(30 * secondNano)

	// Min-RTT filter: samples older than this can no longer be the minimum
	rttMinTTLNano = uint64(10 * secondNano)

	// Unreliable streams: how long a receive gap may wait for reordered data
	// before being skipped. Per-stream override via Stream.SetReorderDeadlineNano.
	defaultReorderDeadlineNano = uint64(100 * msNano)
)

// rttMinEntry is a min-RTT candidate: a sample that may become the window
// minimum once older (smaller) samples expire.
type rttMinEntry struct {
	rttNano  uint64
	timeNano uint64
}

// =============================================================================
// Measurements - RTT estimation and BBR congestion control
// =============================================================================

type measurements struct {
	// RTT estimation (RFC 6298)
	srtt   uint64 // Smoothed RTT
	rttvar uint64 // RTT variation

	// BBR state
	isStartup         bool
	rttMinWin         [windowSize]rttMinEntry // Min-RTT candidates, ascending: [0] = oldest & smallest
	rttMinCount       int                     // Number of valid entries in rttMinWin
	rttMinNano        uint64                  // rttMinWin[0].rttNano (cached)
	bwRounds          [windowSize]uint64 // Best bw sample of each of the last completed rounds
	bwRoundIdx        int                // Next write index into bwRounds
	bwMax             uint64             // Max of bwRounds and the in-progress round (cached)
	bwDec             uint64             // Consecutive samples without bandwidth increase
	lastProbeTimeNano    uint64 // When we last probed for more bandwidth
	probeRoundsRemaining uint64 // Rounds left in current probe cycle
	pacingGainPct        uint64 // Current pacing multiplier

	// Fairness throttle state (see lossRateThresholdPct)
	throttlePct           uint64 // persistent pacing multiplier, 100 = none
	throttleWindowRound   uint64 // rounds completed in the current window
	roundLostPackets      uint64 // fast-retx loss declarations this window
	roundDeliveredPackets uint64 // measured ACKs this window

	// Delivery rate tracking (BBR delivery-rate estimation): each send
	// snapshots these into the packet so its ACK can compute an honest
	// sample interval — see updateBandwidth
	totalDelivered    uint64 // cumulative bytes ACK'd
	deliveredTimeNano uint64 // when the last delivery (measured ACK) happened
	firstSentTimeNano uint64 // send time of the packet delivered last

	// Round tracking (BBR packet-timed rounds)
	roundDeliveredTarget uint64 // totalDelivered threshold to end current round
	roundBwBest          uint64 // best bw sample seen during the current round
	prevRoundBwBest      uint64 // best bw sample from the previous round

}

func newMeasurements() measurements {
	return measurements{
		isStartup:     true,
		pacingGainPct: startupGain,
		throttlePct:   100,
		rttMinNano:    math.MaxUint64,
	}
}

// =============================================================================
// RTT and bandwidth updates
// =============================================================================

func (m *measurements) updateMeasurements(rttNano uint64, ackLen uint16, pkt *sendPacket, nowNano uint64) {
	if rttNano == 0 || nowNano == 0 {
		slog.Warn("invalid measurement", "rtt", rttNano, "now", nowNano)
		return
	}
	if rttNano > ReadDeadLine {
		slog.Warn("suspiciously high RTT", "rtt_seconds", rttNano/secondNano)
		return
	}

	m.totalDelivered += uint64(ackLen)
	m.roundDeliveredPackets++
	// Delivery-rate bookkeeping: future sends snapshot these to anchor
	// their sample intervals
	m.deliveredTimeNano = nowNano
	m.firstSentTimeNano = pkt.sentTimeNano
	m.updateRTT(rttNano)
	m.updateMinRTT(rttNano, nowNano)
	m.updateBandwidth(pkt, nowNano)
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

// updateMinRTT maintains a time-windowed minimum via a monotonic staircase:
// entries ascend in both age and value, so [0] is always the current minimum
// and later entries are the successors once it expires.
func (m *measurements) updateMinRTT(rttNano uint64, nowNano uint64) {
	// Expire candidates older than the TTL (front = oldest)
	expired := 0
	for expired < m.rttMinCount && nowNano-m.rttMinWin[expired].timeNano > rttMinTTLNano {
		expired++
	}
	if expired > 0 {
		copy(m.rttMinWin[:], m.rttMinWin[expired:m.rttMinCount])
		m.rttMinCount -= expired
	}

	// Evict candidates dominated by the new sample (older and >= it)
	for m.rttMinCount > 0 && m.rttMinWin[m.rttMinCount-1].rttNano >= rttNano {
		m.rttMinCount--
	}

	// Admit as newest candidate; if full, the new sample is the largest of all
	// candidates and the least likely to be needed, so drop it
	if m.rttMinCount < len(m.rttMinWin) {
		m.rttMinWin[m.rttMinCount] = rttMinEntry{rttNano: rttNano, timeNano: nowNano}
		m.rttMinCount++
	}

	m.rttMinNano = m.rttMinWin[0].rttNano
}

func (m *measurements) updateBandwidth(pkt *sendPacket, nowNano uint64) {
	deliveredAtSend := pkt.deliveredAtSend
	if m.totalDelivered <= deliveredAtSend {
		return
	}
	delivered := m.totalDelivered - deliveredAtSend

	// Honest sample interval (BBR delivery-rate estimation): the counted
	// bytes were ACK'd over ackElapsed but sent over sendElapsed. A rush of
	// backlogged ACKs (the sender loop reads one ACK per iteration, so they
	// can pile up in the socket buffer) compresses ackElapsed, but the
	// backlogged ACKs belong to older packets, which stretches sendElapsed
	// by the same amount — taking the larger of the two cancels the
	// inflation, so samples can no longer exceed the true rate and the max
	// filter latches onto capacity instead of measurement noise.
	ackElapsed := nowNano - pkt.deliveredTimeAtSend
	sendElapsed := pkt.sentTimeNano - pkt.firstSentTimeAtSend
	elapsed := max(ackElapsed, sendElapsed)
	if elapsed == 0 {
		return
	}
	bwCurrent := (delivered * secondNano) / elapsed

	slog.Debug("bwSample",
		"bwCurrent_MBs", bwCurrent/1_000_000,
		"delivered", delivered,
		"ackElapsed_us", ackElapsed/1000,
		"sendElapsed_us", sendElapsed/1000,
		"deliveredAtSend", deliveredAtSend,
		"totalDelivered", m.totalDelivered,
	)

	// Track best bandwidth in current round; bwMax reacts to increases immediately
	if bwCurrent > m.roundBwBest {
		m.roundBwBest = bwCurrent
	}
	if bwCurrent > m.bwMax {
		m.bwMax = bwCurrent
	}

	// Round completion: all packets in-flight at round start have been ACK'd
	if deliveredAtSend >= m.roundDeliveredTarget {
		m.onRoundEnd()
		m.updateThrottle()

		// Retire the round into the max window; recompute so that maxima
		// older than windowSize rounds can age out. Skipped while the
		// fairness throttle is active: throttled rounds measure the
		// throttled rate, and retiring them would decay bwMax to the
		// policy level — the sensor must keep the last honest capacity
		// reading until pacing is back at 100%.
		if m.throttlePct >= 100 {
			m.bwRounds[m.bwRoundIdx] = m.roundBwBest
			m.bwRoundIdx = (m.bwRoundIdx + 1) % windowSize
			var bwMax uint64
			for _, s := range m.bwRounds {
				if s > bwMax {
					bwMax = s
				}
			}
			m.bwMax = bwMax
		}

		m.roundDeliveredTarget = m.totalDelivered
		m.prevRoundBwBest = m.roundBwBest
		m.roundBwBest = 0

		// Probe gain cycle: probe (1.25x) -> drain (0.75x) -> normal (1.0x)
		if m.probeRoundsRemaining > 0 {
			m.probeRoundsRemaining--
			switch m.probeRoundsRemaining {
			case 1:
				m.pacingGainPct = drainGain
			case 0:
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

// updateThrottle runs at each round end and evaluates once per
// throttleWindowRounds: the fairness response with TCP-like dynamics. A
// window whose loss rate exceeds lossRateThresholdPct (with at least
// throttleMinLost losses as evidence) is a congestion event: multiplicative
// decrease, at most once per window. A clean window ratchets the throttle
// back toward 100%. Sustained loss during startup also ends startup: a full
// pipe announces itself through loss (BBRv2-style exit; this replaces the
// former static in-flight cap as overshoot protection).
func (m *measurements) updateThrottle() {
	m.throttleWindowRound++
	if m.throttleWindowRound < throttleWindowRounds {
		return
	}
	m.throttleWindowRound = 0

	lost, delivered := m.roundLostPackets, m.roundDeliveredPackets
	m.roundLostPackets, m.roundDeliveredPackets = 0, 0

	total := lost + delivered
	if total == 0 {
		return
	}

	if lost >= throttleMinLost && lost*100 > total*lossRateThresholdPct {
		m.throttlePct = (m.throttlePct * throttleBetaPct) / 100
		if m.throttlePct < throttleFloorPct {
			m.throttlePct = throttleFloorPct
		}
		if m.isStartup {
			m.isStartup = false
			m.pacingGainPct = normalGain
		}
	} else if m.throttlePct < 100 {
		m.throttlePct += throttleRecoverPct
		if m.throttlePct > 100 {
			m.throttlePct = 100
		}
	}
}

// onLossEvent applies a one-round drain (0.75x) after fast-retransmit loss
// detection. Loss is the only congestion signal on shallow-buffer paths,
// where the queue is too small to move srtt past the delay threshold in
// updateNormal. BBRv2/v3 semantics: react once per congestion event with a
// bounded reduction, and never touch bwMax — the max filter keeps the true
// rate for windowSize rounds, so pacing snaps back when the drain round
// ends (probeRoundsRemaining=1 -> round end restores normalGain).
func (m *measurements) onLossEvent(nowNano uint64) {
	// Startup overshoot is bounded by the BDP cap; bwDec handles its exit
	if m.isStartup {
		return
	}
	// Already draining (this event's round, or a probe's drain phase):
	// all losses within one round count as a single congestion event
	if m.pacingGainPct == drainGain {
		return
	}
	m.pacingGainPct = drainGain
	m.probeRoundsRemaining = 1
	m.lastProbeTimeNano = nowNano // postpone the next bandwidth probe
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
	// Queue feedback: a standing queue means we pace faster than the link
	// drains (estimator over-report, probe residue). Drain at 0.75x until
	// the delay falls back toward rttMin; also postpone probing, which
	// would only refill the queue. Safety net independent of the estimator.
	isQueueBuilding := m.rttMinNano != math.MaxUint64 &&
		m.srtt > (m.rttMinNano*queueThresholdPct)/100
	if isQueueBuilding {
		m.pacingGainPct = drainGain
		m.probeRoundsRemaining = 0
		m.lastProbeTimeNano = nowNano
	} else if m.probeRoundsRemaining == 0 {
		// Not draining, not probing: restore steady state (also the exit
		// path from a queue-drain episode)
		m.pacingGainPct = normalGain
		if nowNano-m.lastProbeTimeNano > m.rttMinNano*probeMultiplier {
			m.pacingGainPct = probeGain
			m.probeRoundsRemaining = probeCycleRounds
			m.lastProbeTimeNano = nowNano
		}
	}

	slog.Debug("updateNormal",
		"bwMax_MBs", m.bwMax/1_000_000,
		"gain_pct", m.pacingGainPct,
		"throttle_pct", m.throttlePct,
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
// Pacing
// =============================================================================

func (m *measurements) calcPacing(packetSize uint64) uint64 {
	if m.bwMax == 0 {
		if m.srtt > 0 {
			return m.srtt / rttDivisor
		}
		return fallbackInterval
	}

	// bwMax (sensor) x pacingGainPct (BBR cycle, transient) x throttlePct
	// (fairness policy, persistent)
	adjustedBw := (m.bwMax * m.pacingGainPct * m.throttlePct) / 10_000
	if adjustedBw == 0 {
		return fallbackInterval
	}

	return (packetSize * secondNano) / adjustedBw
}