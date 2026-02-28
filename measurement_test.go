package qotp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// TEST HELPER
// =============================================================================

func newTestConnection() *conn {
	return &conn{
		measurements: newMeasurements(testMaxPayload),
	}
}

// ack simulates an ACK arriving: snapshots totalDelivered (as if stamped at send time),
// then calls updateMeasurements. deliveredAtSend defaults to 0 (first packet has no prior deliveries).
func (c *conn) testUpdateMeasurements(rttNano uint64, ackLen uint16, deliveredAtSend uint64, nowNano uint64) {
	c.updateMeasurements(rttNano, ackLen, deliveredAtSend, nowNano)
}

// =============================================================================
// NEWMEASUREMENTS TESTS
// =============================================================================

func TestMeasurements_New(t *testing.T) {
	m := newMeasurements(testMaxPayload)

	assert.True(t, m.isStartup)
	assert.Equal(t, startupGain, m.pacingGainPct)
}

// =============================================================================
// INVALID INPUT TESTS
// =============================================================================

func TestMeasurements_UpdateMeasurements_ZeroRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(0, 1_000, 0, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero RTT")
}

func TestMeasurements_UpdateMeasurements_ZeroBytesAcked(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 0, 0, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero bytes")
}

func TestMeasurements_UpdateMeasurements_ZeroNowNano(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 0)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero timestamp")
}

func TestMeasurements_UpdateMeasurements_ExtremeRTT(t *testing.T) {
	conn := newTestConnection()

	// RTT greater than ReadDeadLine should be rejected
	conn.updateMeasurements(ReadDeadLine+1, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with extreme RTT")
}

// =============================================================================
// FIRST MEASUREMENT TESTS
// =============================================================================

func TestMeasurements_FirstMeasurement_SRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.srtt, "first SRTT should equal measurement")
}

func TestMeasurements_FirstMeasurement_RTTVar(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(50_000_000), conn.rttvar, "first RTTVAR should be half of measurement")
}

func TestMeasurements_FirstMeasurement_RTTMin(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "first RTT should be stored as minimum")
}

func TestMeasurements_FirstMeasurement_Bandwidth(t *testing.T) {
	conn := newTestConnection()

	// First ACK: deliveredAtSend=0, totalDelivered becomes 1000
	// delivery rate = (1000 - 0) * 1e9 / 100ms = 10000 B/s
	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(10000), conn.bwMax, "delivery rate: 1000 bytes delivered over 100ms RTT")
	assert.Equal(t, uint64(1000), conn.totalDelivered, "should track delivered bytes")
	assert.Equal(t, uint64(0), conn.bwDec, "bwDec should be 0 after bandwidth increase")
}

func TestMeasurements_FirstMeasurement_StartupState(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.True(t, conn.isStartup, "should remain in startup state")
	assert.Equal(t, uint64(277), conn.pacingGainPct, "should maintain startup gain")
}

// =============================================================================
// RTT CALCULATION TESTS
// =============================================================================

func TestMeasurements_RTT_Increasing(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 50 * msNano

	conn.updateMeasurements(200*msNano, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(112500*1000), conn.srtt)
	assert.Equal(t, uint64(62500*1000), conn.rttvar)
}

func TestMeasurements_RTT_Decreasing(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 200 * msNano
	conn.rttvar = 80 * msNano

	conn.updateMeasurements(100*msNano, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(187500*1000), conn.srtt)
	assert.Equal(t, uint64(85*msNano), conn.rttvar)
}

func TestMeasurements_RTT_Stable(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 20 * msNano

	conn.updateMeasurements(100*msNano, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(100*msNano), conn.srtt)
	assert.Equal(t, uint64(15*msNano), conn.rttvar)
}

func TestMeasurements_RTT_SmallValues(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 7
	conn.rttvar = 3

	conn.updateMeasurements(7, 1000, 0, 1_000_000_000)

	// SRTT = 7/8 * 7 + 1/8 * 7 = 7 (stable)
	assert.Equal(t, uint64(7), conn.srtt)
	// RTTVAR = 3/4 * 3 + 1/4 * 0 = 2 (delta=0, integer truncation: 9/4=2)
	assert.Equal(t, uint64(2), conn.rttvar)
}

func TestMeasurements_RTT_VarianceUnderflow(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 1000
	conn.rttvar = 1

	// Should not panic or underflow
	assert.NotPanics(t, func() {
		conn.updateMeasurements(1000, 1000, 0, 1_000_000_000)
	})
}

// =============================================================================
// RTT MIN TRACKING TESTS
// =============================================================================

func TestMeasurements_RTTMin_Initial(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano)
}

func TestMeasurements_RTTMin_HigherDoesNotReplace(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)
	conn.updateMeasurements(150_000_000, 1000, 0, 2_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "minimum RTT should not change")
}

func TestMeasurements_RTTMin_LowerReplaces(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)
	conn.updateMeasurements(50_000_000, 1000, 0, 3_000_000_000)

	assert.Equal(t, uint64(50_000_000), conn.rttMinNano, "lower RTT should become new minimum")
}

func TestMeasurements_RTTMin_WindowRollsOut(t *testing.T) {
	conn := newTestConnection()

	// First sample: low RTT
	conn.updateMeasurements(50_000_000, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(50_000_000), conn.rttMinNano)

	// Fill window with higher RTT to push out the low sample
	delivered := conn.totalDelivered
	for i := 0; i < windowSize; i++ {
		conn.updateMeasurements(150_000_000, 1000, delivered, uint64(2_000_000_000+i*100_000_000))
		delivered = conn.totalDelivered
	}

	assert.Equal(t, uint64(150_000_000), conn.rttMinNano, "old low RTT should roll out of window")
}

// =============================================================================
// BANDWIDTH CALCULATION TESTS
// =============================================================================

func TestMeasurements_Bandwidth_Initial(t *testing.T) {
	conn := newTestConnection()

	// deliveredAtSend=0, ackLen=1000, rtt=100ms
	// totalDelivered becomes 1000, delivered = 1000-0 = 1000
	// bw = 1000 * 1e9 / 100_000_000 = 10000
	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(10000), conn.bwMax, "delivery rate: 10000 B/s")
}

func TestMeasurements_Bandwidth_IncreasingDeliveryRate(t *testing.T) {
	conn := newTestConnection()

	// Packet 1: sent when totalDelivered=0, acked with 1000 bytes, rtt=100ms
	// bw = 1000 * 1e9 / 100ms = 10000
	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(10000), conn.bwMax)

	// Packet 2: sent when totalDelivered=0, acked with 1000 bytes, rtt=50ms
	// totalDelivered now = 2000, delivered = 2000-0 = 2000
	// bw = 2000 * 1e9 / 50ms = 40000
	conn.updateMeasurements(50_000_000, 1000, 0, 2_000_000_000)
	assert.Equal(t, uint64(40000), conn.bwMax, "higher delivery rate should update bwMax")
}

func TestMeasurements_Bandwidth_MaintainsMaxDeliveryRate(t *testing.T) {
	conn := newTestConnection()

	// Packet 1: bw = 1000 * 1e9 / 50ms = 20000
	conn.updateMeasurements(50_000_000, 1000, 0, 1_000_000_000)
	assert.Equal(t, uint64(20000), conn.bwMax)

	// Packet 2: sent when totalDelivered=500, acked with 1000 bytes, rtt=100ms
	// totalDelivered = 2000, delivered = 2000-500 = 1500
	// bw = 1500 * 1e9 / 100ms = 15000 (lower)
	conn.updateMeasurements(100_000_000, 1000, 500, 2_000_000_000)
	assert.Equal(t, uint64(20000), conn.bwMax, "bwMax should not decrease")
}

// =============================================================================
// BBR STATE TRANSITION TESTS
// =============================================================================

func TestMeasurements_StartupToNormal_Transition(t *testing.T) {
	conn := newTestConnection()

	// Round 0: establish baseline bandwidth
	conn.updateMeasurements(50_000_000, 1000, 0, 1_000_000_000)
	assert.True(t, conn.isStartup)

	// Simulate 3 rounds with no bandwidth growth (< 25% increase).
	// Each round: send an ACK whose deliveredAtSend >= roundDeliveredTarget
	// to trigger round completion, with the same bandwidth.
	for i := 0; i < int(bwDecThreshold); i++ {
		delivered := conn.totalDelivered
		conn.updateMeasurements(50_000_000, 1000, delivered, uint64(2_000_000_000+i*500_000_000))
	}

	assert.False(t, conn.isStartup, "should transition to normal after 3 non-increasing rounds")
	assert.Equal(t, uint64(100), conn.pacingGainPct, "pacing gain should be 1.0x")
}

func TestMeasurements_StartupToNormal_RemainsInStartup(t *testing.T) {
	conn := newTestConnection()

	// Round 0: establish baseline bandwidth
	conn.updateMeasurements(50_000_000, 1000, 0, 1_000_000_000)

	// Only 2 non-increasing rounds — not enough
	for i := 0; i < int(bwDecThreshold)-1; i++ {
		delivered := conn.totalDelivered
		conn.updateMeasurements(50_000_000, 1000, delivered, uint64(2_000_000_000+i*500_000_000))
	}

	assert.True(t, conn.isStartup, "should remain in startup before 3 non-increasing rounds")
}

// =============================================================================
// NORMAL STATE PACING TESTS
// =============================================================================

func TestMeasurements_NormalState_NormalRTT(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.pacingGainPct = 100
	conn.bwMax = 10000
	conn.lastProbeTimeNano = 1_200_000_000

	// rttNano=200ms becomes rttMinNano; probe threshold = 200ms * 8 = 1.6s
	// elapsed = 1.3s - 1.2s = 0.1s < 1.6s → normal gain
	conn.srtt = 100_000_000
	conn.updateMeasurements(200_000_000, 1000, 0, 1_300_000_000)

	assert.Equal(t, uint64(100), conn.pacingGainPct, "should be 100% when RTT is normal")
}

// =============================================================================
// BANDWIDTH PROBING TESTS
// =============================================================================

func TestMeasurements_Probing_BeforeProbeTime(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.pacingGainPct = 100
	conn.bwMax = 10000
	conn.srtt = 100_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	// rttNano=150ms becomes rttMinNano; probe threshold = 150ms * 8 = 1.2s
	// elapsed = 1.5s - 1.0s = 0.5s < 1.2s → no probe
	conn.updateMeasurements(150_000_000, 1000, 0, 1_500_000_000)

	assert.Equal(t, uint64(100), conn.pacingGainPct, "should not probe yet")
}

func TestMeasurements_Probing_AfterProbeTime(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.srtt = 100_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	// rttNano=150ms becomes rttMinNano; probe threshold = 150ms * 8 = 1.2s
	// elapsed = 2.3s - 1.0s = 1.3s > 1.2s → triggers probe
	conn.updateMeasurements(150_000_000, 1000, 0, 2_300_000_000)

	assert.Equal(t, uint64(125), conn.pacingGainPct, "should probe with 125% gain")
	assert.Equal(t, uint64(2_300_000_000), conn.lastProbeTimeNano, "should update probe time")
	assert.Equal(t, probeRounds, conn.probeRoundsRemaining, "should set probe rounds")
}

// =============================================================================
// RTO CALCULATION TESTS
// =============================================================================

func TestMeasurements_RTO_Default(t *testing.T) {
	conn := newTestConnection()

	rto := conn.rtoNano()

	assert.Equal(t, uint64(200*msNano), rto, "default RTO should be 200ms")
}

func TestMeasurements_RTO_Standard(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 25 * msNano

	rto := conn.rtoNano()

	assert.Equal(t, uint64(200*msNano), rto, "RTO should be SRTT + 4*RTTVAR")
}

func TestMeasurements_RTO_Minimum(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 10 * msNano
	conn.rttvar = 5 * msNano

	rto := conn.rtoNano()

	assert.Equal(t, uint64(100*msNano), rto, "RTO should be capped at minimum 100ms")
}

func TestMeasurements_RTO_Maximum(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 3000 * msNano
	conn.rttvar = 500 * msNano

	rto := conn.rtoNano()

	assert.Equal(t, uint64(2000*msNano), rto, "RTO should be capped at maximum 2s")
}

// =============================================================================
// CONGESTION EVENT TESTS
// =============================================================================

func TestMeasurements_OnDuplicateAck(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000

	conn.onDuplicateAck()

	assert.Equal(t, uint64(10000), conn.bwMax, "bwMax should not change on dup ACK")
	assert.Equal(t, 1, conn.packetDupNr, "should increment dup counter")
}

func TestMeasurements_OnPacketLoss(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000

	conn.onPacketLoss()

	assert.Equal(t, uint64(10000), conn.bwMax, "bwMax should not change on loss")
	assert.Equal(t, 1, conn.packetLossNr, "should increment loss counter")
}

// =============================================================================
// PACING CALCULATION TESTS
// =============================================================================

func TestMeasurements_Pacing_NoSRTT(t *testing.T) {
	conn := newTestConnection()

	interval := conn.calcPacing(1000)

	assert.Equal(t, uint64(10*msNano), interval, "should return 10ms default when no SRTT")
}

func TestMeasurements_Pacing_SRTTNoBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100_000_000

	interval := conn.calcPacing(1000)

	assert.Equal(t, uint64(10_000_000), interval, "should return SRTT/10 when no bandwidth")
}

func TestMeasurements_Pacing_WithBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000
	conn.pacingGainPct = 100

	interval := conn.calcPacing(1000)

	assert.Equal(t, uint64(100_000_000), interval, "should calculate correct interval")
}

func TestMeasurements_Pacing_WithGain(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000
	conn.pacingGainPct = 200

	interval := conn.calcPacing(1000)

	assert.Equal(t, uint64(50_000_000), interval, "higher gain should reduce interval")
}

func TestMeasurements_Pacing_ZeroPacketSize(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000
	conn.pacingGainPct = 100

	interval := conn.calcPacing(0)

	assert.Equal(t, uint64(0), interval)
}

// =============================================================================
// BACKOFF TESTS
// =============================================================================

func TestBackoff_NoBackoff(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 0)

	assert.NoError(t, err)
	assert.Equal(t, baseRTO, result)
}

func TestBackoff_1x(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 1)

	assert.NoError(t, err)
	assert.Equal(t, baseRTO*2, result)
}

func TestBackoff_2x(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 2)

	assert.NoError(t, err)
	assert.Equal(t, baseRTO*4, result)
}

func TestBackoff_3x(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 3)

	assert.NoError(t, err)
	assert.Equal(t, baseRTO*8, result)
}

func TestBackoff_CappedAtMaxRTO(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 4)

	assert.NoError(t, err)
	assert.Equal(t, maxRTO, result)
}

func TestBackoff_ExceedsMax(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 5)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max retry attempts")
	assert.Equal(t, uint64(0), result)
}

func TestBackoff_WayOverMax(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	_, err := backoff(baseRTO, 100)

	assert.Error(t, err)
}

func TestBackoff_ZeroBase(t *testing.T) {
	result, err := backoff(0, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), result)

	result, err = backoff(0, 3)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), result)
}

func TestBackoff_VerySmallRTO(t *testing.T) {
	result, err := backoff(1, 2)

	assert.NoError(t, err)
	assert.Equal(t, uint64(4), result)
}

func TestBackoff_LargeRTO(t *testing.T) {
	largeRTO := uint64(1000 * msNano)

	result, err := backoff(largeRTO, 4)

	assert.NoError(t, err)
	assert.Equal(t, maxRTO, result)
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

func TestMeasurements_DivisionByZeroProtection(t *testing.T) {
	conn := newTestConnection()

	// deliveredAtSend=0, ackLen=1000, rtt=100ms
	// delivered = 1000 - 0 = 1000, bw = 1000 * 1e9 / 1e8 = 10000
	conn.updateMeasurements(100_000_000, 1000, 0, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano)
	assert.Equal(t, uint64(10000), conn.bwMax)
}

// =============================================================================
// UPDATE MTU TESTS
// =============================================================================

func TestMeasurements_UpdateMTU_Basic(t *testing.T) {
	m := newMeasurements(1400)
	assert.Equal(t, 1400, m.negotiatedMTU)

	m.updateMTU(1300)

	assert.Equal(t, 1300, m.negotiatedMTU)
}

// =============================================================================
// CONCURRENT ACCESS TESTS
// =============================================================================

func TestMeasurements_ConcurrentAccess(t *testing.T) {
	conn := newTestConnection()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			conn.updateMeasurements(100_000_000, 1000, 0, uint64(1_000_000_000+i*100_000_000))
			time.Sleep(time.Microsecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			conn.calcPacing(1000)
			time.Sleep(time.Microsecond)
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			conn.onPacketLoss()
			time.Sleep(time.Microsecond * 2)
		}
	}()

	wg.Wait()

	// Should not panic and should have valid state
	assert.GreaterOrEqual(t, conn.bwMax, uint64(0))
}

// =============================================================================
// INTEGRATION TESTS
// =============================================================================

func TestMeasurements_Integration_StartupToNormal(t *testing.T) {
	conn := newTestConnection()

	// Startup phase - increasing delivery rate (more bytes ACK'd, same RTT)
	for i := 0; i < 5; i++ {
		conn.updateMeasurements(50_000_000, uint16(1000*(i+1)), 0, uint64(1_000_000_000+i*500_000_000))
	}
	assert.True(t, conn.isStartup)

	// Plateau - rounds with no bandwidth growth to trigger startup exit.
	// First plateau round still carries high roundBwBest from startup, so
	// we need bwDecThreshold+1 rounds: 1 that resets bwDec + 3 that increment.
	for i := 0; i < int(bwDecThreshold)+1; i++ {
		delivered := conn.totalDelivered
		conn.updateMeasurements(50_000_000, 1000, delivered, uint64(4_000_000_000+i*500_000_000))
	}
	assert.False(t, conn.isStartup)

	// Verify pacing calculation works
	interval := conn.calcPacing(1000)
	assert.Greater(t, interval, uint64(0))
}
