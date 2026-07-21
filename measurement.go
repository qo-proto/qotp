package qotp

import (
	"fmt"
	"log/slog"
	"math"
	"slices"
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
	windowSize           = 10 // rolling window for min-RTT and max-bandwidth filters
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

	// BBR pacing gains (percentage, 100 = 1.0x)
	startupGain = uint64(277) // 2.77x aggressive growth
	normalGain  = uint64(100) // 1.0x steady state
	probeGain   = uint64(125) // 1.25x probe for spare bandwidth
	drainGain   = uint64(75)  // 0.75x drain the queue the probe built

	// BBR probing and startup exit
	probeIntervalRtts = uint64(8)   // probe for more bandwidth every 8x rttMin
	probeCycleRounds  = uint64(2)   // one probe round + one drain round
	startupGrowthPct  = uint64(125) // startup expects >=25% bandwidth growth per round
	startupExitRounds = uint64(3)   // exit startup after this many rounds without growth

	// Queue feedback: srtt above rttMin x queueThresholdPct/100 means a
	// standing queue is building at the bottleneck — drain instead of probe
	queueThresholdPct = uint64(125)

	// Fairness throttle: a persistent pacing multiplier with TCP-like
	// dynamics (multiplicative decrease, gradual recovery), so loss-based
	// flows sharing a bottleneck can claim their share. bwMax is never
	// touched: policy lives here, the sensor stays truthful.
	//
	// Loss is judged over a multi-round window, not per round: single-round
	// ratios are far too noisy (a round is one flight; detections for
	// independent losses cluster into the round where their gap evidence
	// completes, and Karn shrinks the denominator during recovery). The
	// window also gives episode semantics for free: at most one decrease
	// per window. Random loss below the threshold stays ignored, which
	// preserves lossy-link performance.
	lossRateThresholdPct = uint64(2)  // congestion = >2% loss per window
	throttleWindowRounds = uint64(8)  // rounds per evaluation window
	throttleMinLost      = uint64(8)  // min losses to act (small-sample guard)
	throttleBetaPct      = uint64(70) // multiplicative decrease per event
	throttleFloorPct     = uint64(30) // keep the flow alive
	// Recovery is deliberately modest so regaining bandwidth after
	// congestion stays comparable to TCP's additive increase — faster
	// values let qotp out-regain loss-based flows after every shared-loss
	// episode and skew fairness.
	throttleRecoverPct = uint64(5) // points regained per clean window

	// Cold-start pacing, used until the first bandwidth sample exists:
	// one packet per srtt/coldStartRttDivisor, or per coldStartInterval
	// before the first RTT sample
	coldStartInterval   = uint64(10 * msNano)
	coldStartRttDivisor = uint64(10)

	// Pacing burst allowance: how many unspent send opportunities may be
	// carried across late wakeups (token-bucket depth, in packets). Lets a
	// late wakeup catch up in a short burst instead of losing the slots.
	maxBurstPackets = uint64(10)

	// Timeouts
	minDeadline  = uint64(100 * msNano)
	readDeadline = uint64(30 * secondNano)

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

// ccState is the congestion-control pacing state. Transitions go through
// setState only, which also derives the pacing gain — one auditable place.
type ccState uint8

const (
	ccStartup  ccState = iota // exponential growth (2.77x) until bandwidth flattens
	ccSteady                  // pace at measured bandwidth (1.0x)
	ccProbing                 // probe for spare bandwidth (1.25x, one round)
	ccDraining                // drain the bottleneck queue (0.75x): probe-cycle
	                          // drain phase or queue/delay feedback
)

func gainFor(s ccState) uint64 {
	switch s {
	case ccStartup:
		return startupGain
	case ccProbing:
		return probeGain
	case ccDraining:
		return drainGain
	default:
		return normalGain
	}
}

// =============================================================================
// Measurements - RTT estimation and BBR congestion control
// =============================================================================

type measurements struct {
	// RTT estimation (RFC 6298)
	srtt   uint64 // Smoothed RTT
	rttvar uint64 // RTT variation

	// Min-RTT filter (time-windowed)
	rttMinWin   [windowSize]rttMinEntry // candidates, ascending: [0] = oldest & smallest
	rttMinCount int                     // number of valid entries in rttMinWin
	rttMinNano  uint64                  // rttMinWin[0].rttNano (cached)

	// Bandwidth filter (round-windowed max)
	bwRounds   [windowSize]uint64 // best bw sample of each of the last completed rounds
	bwRoundIdx int                // next write index into bwRounds
	bwMax      uint64             // max of bwRounds and the in-progress round (cached)

	// BBR state machine (transitions via setState only)
	state                ccState
	noGrowthRounds       uint64 // consecutive rounds without startup-level bw growth
	pacingGainPct        uint64 // gain for state, kept in sync by setState (tests may override)
	probeRoundsRemaining uint64 // rounds left in the current probe cycle
	lastProbeTimeNano    uint64 // when we last probed for more bandwidth

	// Fairness throttle (see lossRateThresholdPct)
	throttlePct        uint64 // persistent pacing multiplier, 100 = none
	windowRoundsDone   uint64 // rounds completed in the current evaluation window
	windowLostPackets  uint64 // fast-retx loss declarations in the current window
	windowAckedPackets uint64 // measured ACKs in the current window

	// Delivery-rate tracking (BBR delivery-rate estimation): each send
	// snapshots these into the packet so its ACK can compute an honest
	// sample interval — see deliveryRateSample
	totalDelivered    uint64 // cumulative bytes ACK'd
	deliveredTimeNano uint64 // when the last delivery (measured ACK) happened
	firstSentTimeNano uint64 // send time of the packet delivered last

	// Round tracking (BBR packet-timed rounds)
	roundDeliveredTarget uint64 // totalDelivered threshold to end the current round
	roundBwBest          uint64 // best bw sample seen during the current round
	prevRoundBwBest      uint64 // best bw sample from the previous round
}

func newMeasurements() measurements {
	// The one place besides setState that pairs state and gain: struct
	// literals cannot call methods
	return measurements{
		state:         ccStartup,
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
	if rttNano > readDeadline {
		slog.Warn("suspiciously high RTT", "rtt_seconds", rttNano/secondNano)
		return
	}

	m.totalDelivered += uint64(ackLen)
	m.windowAckedPackets++
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

// updateBandwidth feeds one ACK's delivery-rate sample into the filters and
// closes the current round once all packets in flight at its start are ACK'd.
func (m *measurements) updateBandwidth(pkt *sendPacket, nowNano uint64) {
	bwSample, valid := m.deliveryRateSample(pkt, nowNano)
	if !valid {
		return
	}

	// Track the best sample of the round; bwMax reacts to increases
	// immediately (decreases only age in via round retirement)
	if bwSample > m.roundBwBest {
		m.roundBwBest = bwSample
	}
	if bwSample > m.bwMax {
		m.bwMax = bwSample
	}

	// Round completion: all packets in flight at round start have been ACK'd
	if pkt.deliveredAtSend >= m.roundDeliveredTarget {
		m.finishRound()
	}
}

// deliveryRateSample computes an honest bandwidth sample for one ACKed
// packet (BBR delivery-rate estimation): the counted bytes were ACK'd over
// ackElapsed but sent over sendElapsed. A rush of backlogged ACKs (the
// sender loop reads one ACK per iteration, so they can pile up in the
// socket buffer) compresses ackElapsed, but the backlogged ACKs belong to
// older packets, which stretches sendElapsed by the same amount — taking
// the larger of the two cancels the inflation, so samples cannot exceed
// the true rate and the max filter latches onto capacity, not noise.
func (m *measurements) deliveryRateSample(pkt *sendPacket, nowNano uint64) (uint64, bool) {
	if m.totalDelivered <= pkt.deliveredAtSend {
		return 0, false
	}
	delivered := m.totalDelivered - pkt.deliveredAtSend

	ackElapsed := nowNano - pkt.deliveredTimeAtSend
	sendElapsed := pkt.sentTimeNano - pkt.firstSentTimeAtSend
	elapsed := max(ackElapsed, sendElapsed)
	if elapsed == 0 {
		return 0, false
	}
	bwSample := (delivered * secondNano) / elapsed

	slog.Debug("bwSample",
		"bwCurrent_MBs", bwSample/1_000_000,
		"delivered", delivered,
		"ackElapsed_us", ackElapsed/1000,
		"sendElapsed_us", sendElapsed/1000,
		"deliveredAtSend", pkt.deliveredAtSend,
		"totalDelivered", m.totalDelivered,
	)
	return bwSample, true
}

// finishRound closes a BBR round: growth tracking, fairness-throttle
// evaluation, retiring the round into the max filter, and advancing the
// probe gain cycle.
func (m *measurements) finishRound() {
	m.trackGrowth()
	m.updateThrottle()

	// Retire the round into the max window; recompute so that maxima older
	// than windowSize rounds can age out. Skipped while pacing is
	// policy-reduced (fairness throttle active, or draining from queue
	// feedback): reduced rounds measure the reduced rate, and retiring
	// them would decay bwMax to the policy level, which then lowers pacing
	// further — a self-clamp spiral (hit live on short-RTT paths where the
	// drain runs long). The sensor keeps the last honest capacity reading
	// until pacing is back at 100%.
	if m.throttlePct >= 100 && m.state != ccDraining {
		m.bwRounds[m.bwRoundIdx] = m.roundBwBest
		m.bwRoundIdx = (m.bwRoundIdx + 1) % windowSize
		m.bwMax = slices.Max(m.bwRounds[:])
	}

	m.roundDeliveredTarget = m.totalDelivered
	m.prevRoundBwBest = m.roundBwBest
	m.roundBwBest = 0

	// Probe gain cycle: probe (1.25x) -> drain (0.75x) -> steady (1.0x)
	if m.probeRoundsRemaining > 0 {
		m.probeRoundsRemaining--
		switch m.probeRoundsRemaining {
		case 1:
			m.setState(ccDraining)
		case 0:
			m.setState(ccSteady)
		}
	}
}

// trackGrowth counts consecutive rounds without startup-level bandwidth
// growth; updateStartup exits startup once the count reaches
// startupExitRounds.
func (m *measurements) trackGrowth() {
	if m.prevRoundBwBest == 0 {
		return
	}
	// Did bandwidth grow by at least 25% this round?
	threshold := (m.prevRoundBwBest * startupGrowthPct) / 100
	if m.roundBwBest >= threshold {
		m.noGrowthRounds = 0
	} else {
		m.noGrowthRounds++
	}
}

// updateThrottle runs at each round end and evaluates once per
// throttleWindowRounds: the fairness response with TCP-like dynamics. A
// window whose loss rate exceeds lossRateThresholdPct (with at least
// throttleMinLost losses as evidence) is a congestion event: multiplicative
// decrease, at most once per window. A clean window ratchets the throttle
// back toward 100%. Sustained loss during startup also ends startup: a full
// pipe announces itself through loss (BBRv2-style exit).
func (m *measurements) updateThrottle() {
	m.windowRoundsDone++
	if m.windowRoundsDone < throttleWindowRounds {
		return
	}
	m.windowRoundsDone = 0

	lost, acked := m.windowLostPackets, m.windowAckedPackets
	m.windowLostPackets, m.windowAckedPackets = 0, 0

	total := lost + acked
	if total == 0 {
		return
	}

	isCongested := lost >= throttleMinLost && lost*100 > total*lossRateThresholdPct
	switch {
	case isCongested:
		m.throttlePct = max((m.throttlePct*throttleBetaPct)/100, throttleFloorPct)
		if m.inStartup() {
			m.exitStartup()
		}
	case m.throttlePct < 100:
		m.throttlePct = min(m.throttlePct+throttleRecoverPct, 100)
	}
}

// =============================================================================
// BBR state machine
// =============================================================================

// setState is the only writer of the pacing state; it derives the matching
// gain, so state and gain cannot drift apart.
func (m *measurements) setState(s ccState) {
	m.state = s
	m.pacingGainPct = gainFor(s)
}

func (m *measurements) inStartup() bool {
	return m.state == ccStartup
}

func (m *measurements) exitStartup() {
	m.setState(ccSteady)
}

func (m *measurements) updateBBRState(nowNano uint64) {
	if m.lastProbeTimeNano == 0 {
		m.lastProbeTimeNano = nowNano
	}

	if m.inStartup() {
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
		"noGrowthRounds", m.noGrowthRounds,
		"roundTarget", m.roundDeliveredTarget,
		"delivered", m.totalDelivered,
		"gain_pct", m.pacingGainPct,
	)
	if m.noGrowthRounds >= startupExitRounds {
		m.exitStartup()
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
		m.setState(ccDraining)
		m.probeRoundsRemaining = 0
		m.lastProbeTimeNano = nowNano
	} else if m.probeRoundsRemaining == 0 {
		// Not draining, not probing: restore steady state (also the exit
		// path from a queue-drain episode)
		m.setState(ccSteady)
		if nowNano-m.lastProbeTimeNano > m.rttMinNano*probeIntervalRtts {
			m.setState(ccProbing)
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
	// Cold start: no bandwidth sample yet
	if m.bwMax == 0 {
		if m.srtt > 0 {
			return m.srtt / coldStartRttDivisor
		}
		return coldStartInterval
	}

	// bwMax (sensor) x pacingGainPct (BBR cycle, transient) x throttlePct
	// (fairness policy, persistent)
	pacedBw := (m.bwMax * m.pacingGainPct * m.throttlePct) / 10_000
	if pacedBw == 0 {
		return coldStartInterval
	}

	return (packetSize * secondNano) / pacedBw
}
