package qotp

import (
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

	ipOverhead      = 48   // IPv6 worst case (IPv4 is 28)
	conservativeMTU = 1232 // IPv6 minimum link MTU (1280) minus ipOverhead; hard floor

	// A packet this close to giving up is retransmitted at conservativeMTU:
	// if that gets through where the working size did not, the path cannot
	// carry the working size. Ordinary loss never moves the MTU.
	mtuProbeLastAttempts = 2
	filterLen            = 10 // rolling window of the min-RTT and max-bandwidth filters
)

// Tunables are vars so tests can override them.
var (
	defaultRTO = uint64(200 * msNano)
	minRTO     = uint64(100 * msNano)
	maxRTO     = uint64(2000 * msNano)
	maxRetry   = uint(5)

	// Declare an original packet lost once this many later packets are
	// ACKed: QUIC's kPacketThreshold (RFC 9002), TCP's three dup-ACKs.
	fastRetxThreshold = uint8(3)

	// Pacing gains in percent
	startupGain = uint64(289) // 2/ln2, BBR's startup gain, rounded up like Linux
	normalGain  = uint64(100)
	probeGain   = uint64(125) // one round above the link rate to find spare bandwidth
	drainGain   = uint64(75)  // one round below it to drain what the probe built

	// Decision cadence, in rounds (about one RTT each): probe every
	// cycleRounds x rttMin, evaluate loss every cycleRounds rounds. One
	// value so each loss window spans about one probe cycle.
	cycleRounds = uint64(8)

	// Startup ends after this many rounds in a row without a probe's worth
	// (probeGain) of bandwidth growth
	startupExitRounds = uint64(3)

	// Allowed standing queue, as delay above rttMin: the larger of one probe
	// round's overshoot (a fraction of BDP is the same fraction of rttMin)
	// and the target an AQM like fq_codel or CAKE holds on purpose. On an
	// 11ms path the AQM target alone is 44% of rttMin; without the floor the
	// flow drained 27% of the time for nothing.
	queueSizeRttPct  = probeGain - 100
	queueSizeMinNano = uint64(5 * msNano)

	// Fairness throttle: a persistent pacing multiplier so loss-based flows
	// sharing a bottleneck can claim their share. Same normal/probe/drain
	// principle as pacing, with its own gains and per window instead of per
	// round. Loss is judged per window because per-round ratios are noise:
	// detections cluster into the round where their gap evidence completes,
	// and Karn shrinks the denominator during recovery.
	throttleNormalGain   = uint64(100)
	throttleProbeGain    = uint64(125) // per clean window
	throttleDrainGain    = uint64(75)  // per congested window; CUBIC uses 0.7, Reno 0.5
	throttleDrainMin     = uint64(30)  // keeps the flow alive and measuring
	lossRateThresholdPct = uint64(2)
	// A window does not close until the threshold amounts to one loss per
	// round, so a slow path extends the window instead of never acting
	throttleMinPackets = cycleRounds * 100 / lossRateThresholdPct

	// Until the first bandwidth sample: initialWindowPackets per RTT, TCP's
	// initial window (RFC 6928), assuming defaultRTO before the first sample
	initialWindowPackets  = uint64(10)
	initialWindowInterval = defaultRTO / initialWindowPackets

	// Token-bucket depth in packets: unspent send slots a late wakeup may
	// catch up in one burst. At least initialWindowPackets, or the bucket
	// would throttle the initial window.
	maxBurstLen = uint64(10)

	minDeadline  = uint64(100 * msNano)
	readDeadline = uint64(30 * secondNano)

	rttMinTTLNano = uint64(10 * secondNano)
)

// rttMinEntry is a min-RTT candidate that becomes the minimum once older,
// smaller samples expire.
type rttMinEntry struct {
	rttNano  uint64
	timeNano uint64
}

type ccState uint8

const (
	ccStartup  ccState = iota // exponential growth until bandwidth flattens
	ccSteady                  // pace at measured bandwidth
	ccProbing                 // one round above it, looking for spare bandwidth
	ccDraining                // one round below it: probe cycle or queue feedback
)

// =============================================================================
// Measurements - RTT estimation and BBR congestion control
// =============================================================================

// ackState is where the ACK bookkeeping stood at some moment
type ackState struct {
	bytes    uint64 // total wire bytes the peer has ACKed
	timeNano uint64 // when the latest ACK arrived
	sentNano uint64 // when the packet that ACK acknowledged had been sent
}

type measurements struct {
	// RTT estimation (RFC 6298)
	srtt   uint64
	rttvar uint64

	// Min-RTT filter: candidates ascending in age and value, [0] is the minimum
	rttMinWin   [filterLen]rttMinEntry
	rttMinCount int
	rttMinNano  uint64 // rttMinWin[0].rttNano, cached

	// Max-bandwidth filter over the best sample of each recent round
	bwRounds   [filterLen]uint64
	bwRoundIdx int
	bwMax      uint64 // max of bwRounds and the round in progress, cached

	state                ccState
	noGrowthRounds       uint64 // consecutive rounds without a probe's worth of growth
	probeRoundsRemaining uint64
	lastProbeTimeNano    uint64

	// Fairness throttle, 100 = none. lossEpochNano starts the current loss
	// episode: a packet sent at or before it was already in flight when we
	// last responded, so its loss is not new evidence (see acknowledgeRange).
	throttlePct        uint64
	lossEpochNano      uint64
	windowRoundsDone   uint64
	windowLostPackets  uint64
	windowAckedPackets uint64

	// Each send copies this into the packet, so its ACK can compute a
	// bandwidth sample over the interval since (BBR delivery-rate estimation)
	acked ackState

	// Packet-timed rounds
	roundAckedTarget uint64 // acked.bytes at which the current round ends
	roundBwBest      uint64
	prevRoundBwBest  uint64
}

func newMeasurements() measurements {
	return measurements{
		state:       ccStartup,
		throttlePct: throttleNormalGain,
		rttMinNano:  math.MaxUint64,
	}
}

// =============================================================================
// RTT and bandwidth updates
// =============================================================================

// updateMeasurements folds one acknowledged packet into the estimates. It
// counts wire bytes, the unit calcPacing spends; payload bytes are tracked
// separately for flow control and the application.
func (m *measurements) updateMeasurements(rttNano uint64, pkt *sendPacket, nowNano uint64) {
	if rttNano == 0 || nowNano == 0 {
		slog.Warn("invalid measurement", "rtt", rttNano, "now", nowNano)
		return
	}
	if rttNano > readDeadline {
		slog.Warn("suspiciously high RTT", "rtt_seconds", rttNano/secondNano)
		return
	}

	m.acked = ackState{bytes: m.acked.bytes + uint64(pkt.wireLen), timeNano: nowNano, sentNano: pkt.sentTimeNano}
	m.windowAckedPackets++

	m.updateRTT(rttNano)
	m.updateMinRTT(rttNano, nowNano)
	m.updateBandwidth(pkt, nowNano)
	m.updateState(nowNano)
}

// updateRTT is RFC 6298
func (m *measurements) updateRTT(rttNano uint64) {
	if m.srtt == 0 {
		m.srtt = rttNano
		m.rttvar = rttNano / 2
		return
	}
	delta := max(rttNano, m.srtt) - min(rttNano, m.srtt)
	m.rttvar = (m.rttvar*3 + delta) / 4
	m.srtt = (m.srtt*7 + rttNano) / 8
}

// updateMinRTT keeps a time-windowed minimum as a monotonic staircase: a new
// sample evicts every older candidate at or above it, so the candidates stay
// ascending in both age and value and [0] is always the current minimum.
func (m *measurements) updateMinRTT(rttNano uint64, nowNano uint64) {
	expired := 0
	for expired < m.rttMinCount && nowNano-m.rttMinWin[expired].timeNano > rttMinTTLNano {
		expired++
	}
	if expired > 0 {
		copy(m.rttMinWin[:], m.rttMinWin[expired:m.rttMinCount])
		m.rttMinCount -= expired
	}

	for m.rttMinCount > 0 && m.rttMinWin[m.rttMinCount-1].rttNano >= rttNano {
		m.rttMinCount--
	}

	// When full the new sample is the largest candidate and the least needed
	if m.rttMinCount < len(m.rttMinWin) {
		m.rttMinWin[m.rttMinCount] = rttMinEntry{rttNano: rttNano, timeNano: nowNano}
		m.rttMinCount++
	}

	m.rttMinNano = m.rttMinWin[0].rttNano
}

func (m *measurements) updateBandwidth(pkt *sendPacket, nowNano uint64) {
	bwSample, valid := m.deliveryRateSample(pkt, nowNano)
	if !valid {
		return
	}

	// bwMax rises at once; it falls only as rounds retire from the window
	m.roundBwBest = max(m.roundBwBest, bwSample)
	m.bwMax = max(m.bwMax, bwSample)

	// A round ends once everything in flight at its start is ACKed
	if pkt.ackedAtSend.bytes >= m.roundAckedTarget {
		m.finishRound(nowNano)
	}
}

// deliveryRateSample is BBR's delivery-rate estimate: bytes delivered since
// the packet was sent, over the longer of the ACK-side and send-side
// intervals. A rush of backlogged ACKs compresses the ACK interval, but those
// ACKs belong to older packets and stretch the send interval by the same
// amount, so taking the larger keeps samples at or below the true rate.
func (m *measurements) deliveryRateSample(pkt *sendPacket, nowNano uint64) (uint64, bool) {
	// A packet with no payload went out because there was nothing else to
	// send; its rate measures our idleness, not the link
	if len(pkt.data) == 0 {
		return 0, false
	}
	if m.acked.bytes <= pkt.ackedAtSend.bytes {
		return 0, false
	}
	bytes := m.acked.bytes - pkt.ackedAtSend.bytes

	ackElapsed := nowNano - pkt.ackedAtSend.timeNano
	sendElapsed := pkt.sentTimeNano - pkt.ackedAtSend.sentNano
	elapsed := max(ackElapsed, sendElapsed)
	if elapsed == 0 {
		return 0, false
	}
	return (bytes * secondNano) / elapsed, true
}

func (m *measurements) finishRound(nowNano uint64) {
	m.trackGrowth()
	m.updateThrottle(nowNano)

	// Rounds paced below the link rate (throttled, or draining on queue
	// feedback) measure the reduced rate. Retiring them would decay bwMax to
	// the policy level and lower pacing further, a self-clamp spiral seen
	// live on short-RTT paths. Keep the last honest reading instead.
	if m.throttlePct >= throttleNormalGain && m.state != ccDraining {
		m.bwRounds[m.bwRoundIdx] = m.roundBwBest
		m.bwRoundIdx = (m.bwRoundIdx + 1) % filterLen
		m.bwMax = slices.Max(m.bwRounds[:])
	}

	m.roundAckedTarget = m.acked.bytes
	m.prevRoundBwBest = m.roundBwBest
	m.roundBwBest = 0

	// Probe cycle: probe -> drain -> steady, one round each
	if m.probeRoundsRemaining > 0 {
		m.probeRoundsRemaining--
		switch m.probeRoundsRemaining {
		case 1:
			m.state = ccDraining
		case 0:
			m.state = ccSteady
		}
	}
}

func (m *measurements) trackGrowth() {
	if m.prevRoundBwBest == 0 {
		return
	}
	if m.roundBwBest >= (m.prevRoundBwBest*probeGain)/100 {
		m.noGrowthRounds = 0
	} else {
		m.noGrowthRounds++
	}
}

// updateThrottle evaluates each window of cycleRounds rounds and at least
// throttleMinPackets packets: a congested window drains, a clean one probes.
//
// Loss during startup ends startup but does not throttle: startup finds the
// ceiling by growing until the path objects, so that loss is our own probe.
// Measured on 100mbit/20ms netem, startup loss was 6-34% of the first
// window, so throttling on it clamped an idle path for one to two seconds.
func (m *measurements) updateThrottle(nowNano uint64) {
	m.windowRoundsDone++
	total := m.windowLostPackets + m.windowAckedPackets
	if m.windowRoundsDone < cycleRounds || total < throttleMinPackets {
		return
	}
	m.windowRoundsDone = 0

	lost := m.windowLostPackets
	m.windowLostPackets, m.windowAckedPackets = 0, 0

	isCongested := lost*100 > total*lossRateThresholdPct
	switch {
	case isCongested && m.state == ccStartup:
		m.exitStartup(nowNano)
	case isCongested:
		m.throttlePct = max((m.throttlePct*throttleDrainGain)/100, throttleDrainMin)
		m.lossEpochNano = nowNano
	case m.throttlePct < throttleNormalGain:
		m.throttlePct = min((m.throttlePct*throttleProbeGain)/100, throttleNormalGain)
	}
}

// =============================================================================
// BBR state machine
// =============================================================================

// exitStartup also discards the window in progress, which holds startup's
// overshoot, and opens a new loss episode, because gap evidence for packets
// dropped during startup keeps arriving after it.
func (m *measurements) exitStartup(nowNano uint64) {
	m.state = ccSteady
	m.windowRoundsDone = 0
	m.windowLostPackets, m.windowAckedPackets = 0, 0
	m.lossEpochNano = nowNano
}

func (m *measurements) updateState(nowNano uint64) {
	if m.lastProbeTimeNano == 0 {
		m.lastProbeTimeNano = nowNano
	}
	if m.state == ccStartup {
		if m.noGrowthRounds >= startupExitRounds {
			m.exitStartup(nowNano)
		}
		return
	}

	// Queue feedback, independent of the bandwidth estimator: smoothed delay
	// above the allowed queue means we pace faster than the link drains.
	// Drain until it falls back, and postpone probing meanwhile.
	if m.srtt > m.queueLimit() {
		m.state = ccDraining
		m.probeRoundsRemaining = 0
		m.lastProbeTimeNano = nowNano
	} else if m.probeRoundsRemaining == 0 {
		m.state = ccSteady
		if nowNano-m.lastProbeTimeNano > m.rttMinNano*cycleRounds {
			m.state = ccProbing
			m.probeRoundsRemaining = 2 // one probe round, one drain round
			m.lastProbeTimeNano = nowNano
		}
	}
}

func (m *measurements) queueLimit() uint64 {
	if m.rttMinNano == math.MaxUint64 {
		return math.MaxUint64 // no sample yet
	}
	return m.rttMinNano + max((m.rttMinNano*queueSizeRttPct)/100, queueSizeMinNano)
}

// =============================================================================
// RTO and pacing
// =============================================================================

func (m *measurements) rtoNano() uint64 {
	rto := m.srtt + 4*m.rttvar
	if rto == 0 {
		return defaultRTO
	}
	return min(max(rto, minRTO), maxRTO)
}

// backoff doubles the RTO per attempt. The attempt is clamped to the last
// one: the caller decides when to give up, and its final try is owed a full
// window.
func backoff(rtoNano uint64, attempt uint) uint64 {
	for range min(attempt, maxRetry-1) {
		rtoNano = min(rtoNano*2, maxRTO)
	}
	return rtoNano
}

func (m *measurements) calcPacing(packetSize uint64) uint64 {
	// Both fallbacks are the cost of one full-size packet, scaled by the
	// actual size so an ACK does not cost as much send budget as a data packet
	if m.bwMax == 0 {
		interval := initialWindowInterval
		if m.srtt > 0 {
			interval = m.srtt / initialWindowPackets
		}
		return (packetSize * interval) / conservativeMTU
	}

	var pacedBw uint64
	switch m.state {
	case ccStartup:
		pacedBw = (m.bwMax * startupGain * m.throttlePct) / 10_000
	case ccProbing:
		pacedBw = (m.bwMax * probeGain * m.throttlePct) / 10_000
	case ccDraining:
		pacedBw = (m.bwMax * drainGain * m.throttlePct) / 10_000
	default:
		pacedBw = (m.bwMax * normalGain * m.throttlePct) / 10_000
	}

	if pacedBw == 0 {
		return initialWindowInterval
	}
	return (packetSize * secondNano) / pacedBw
}
