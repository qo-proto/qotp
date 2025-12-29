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
		Measurements: NewMeasurements(),
	}
}

// =============================================================================
// NEWMEASUREMENTS TESTS
// =============================================================================

func TestMeasurements_New(t *testing.T) {
	m := NewMeasurements()

	assert.True(t, m.isStartup)
	assert.Equal(t, startupGain, m.pacingGainPct)
	assert.Equal(t, uint64(minCwndPackets*defaultMTU), m.cwnd)
}

// =============================================================================
// INVALID INPUT TESTS
// =============================================================================

func TestMeasurements_UpdateMeasurements_ZeroRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(0, 1_000, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero RTT")
}

func TestMeasurements_UpdateMeasurements_ZeroBytesAcked(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 0, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero bytes")
}

func TestMeasurements_UpdateMeasurements_ZeroNowNano(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 0)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with zero timestamp")
}

func TestMeasurements_UpdateMeasurements_ExtremeRTT(t *testing.T) {
	conn := newTestConnection()

	// RTT greater than ReadDeadLine should be rejected
	conn.updateMeasurements(ReadDeadLine+1, 1000, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "bandwidth should not update with extreme RTT")
}

// =============================================================================
// FIRST MEASUREMENT TESTS
// =============================================================================

func TestMeasurements_FirstMeasurement_SRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.srtt, "first SRTT should equal measurement")
}

func TestMeasurements_FirstMeasurement_RTTVar(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(50_000_000), conn.rttvar, "first RTTVAR should be half of measurement")
}

func TestMeasurements_FirstMeasurement_RTTMin(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "first RTT should be stored as minimum")
	assert.Equal(t, uint64(1_000_000_000), conn.rttMinTimeNano, "timestamp should be stored")
}

func TestMeasurements_FirstMeasurement_Bandwidth(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(10000), conn.bwMax, "bandwidth should be calculated correctly")
	assert.Equal(t, uint64(0), conn.bwDec, "bwDec should be 0 after bandwidth increase")
}

func TestMeasurements_FirstMeasurement_StartupState(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

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

	conn.updateMeasurements(200*msNano, 1000, 1_000_000_000)

	assert.Equal(t, uint64(112500*1000), conn.srtt)
	assert.Equal(t, uint64(62500*1000), conn.rttvar)
}

func TestMeasurements_RTT_Decreasing(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 200 * msNano
	conn.rttvar = 80 * msNano

	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)

	assert.Equal(t, uint64(187500*1000), conn.srtt)
	assert.Equal(t, uint64(85*msNano), conn.rttvar)
}

func TestMeasurements_RTT_Stable(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 20 * msNano

	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)

	assert.Equal(t, uint64(100*msNano), conn.srtt)
	assert.Equal(t, uint64(15*msNano), conn.rttvar)
}

func TestMeasurements_RTT_SmallValues(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 7
	conn.rttvar = 3

	conn.updateMeasurements(7, 1000, 1_000_000_000)

	assert.Greater(t, conn.srtt, uint64(0))
	assert.Greater(t, conn.rttvar, uint64(0))
}

func TestMeasurements_RTT_VarianceUnderflow(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 1000
	conn.rttvar = 1

	// Should not panic or underflow
	assert.NotPanics(t, func() {
		conn.updateMeasurements(1000, 1000, 1_000_000_000)
	})
}

// =============================================================================
// RTT MIN TRACKING TESTS
// =============================================================================

func TestMeasurements_RTTMin_Initial(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano)
}

func TestMeasurements_RTTMin_HigherDoesNotReplace(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(150_000_000, 1000, 2_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "minimum RTT should not change")
}

func TestMeasurements_RTTMin_LowerReplaces(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(50_000_000, 1000, 3_000_000_000)

	assert.Equal(t, uint64(50_000_000), conn.rttMinNano, "lower RTT should become new minimum")
	assert.Equal(t, uint64(3_000_000_000), conn.rttMinTimeNano, "timestamp should be updated")
}

func TestMeasurements_RTTMin_ExpiryWithin10Seconds(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(150_000_000, 1000, 9_000_000_000)

	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "min RTT should persist within 10 seconds")
}

func TestMeasurements_RTTMin_ExpiryAfter10Seconds(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(120_000_000, 1000, 11_000_000_001)

	assert.Equal(t, uint64(120_000_000), conn.rttMinNano, "RTT min should update after 10 seconds")
	assert.Equal(t, uint64(11_000_000_001), conn.rttMinTimeNano, "timestamp should be updated")
}

// =============================================================================
// BANDWIDTH CALCULATION TESTS
// =============================================================================

func TestMeasurements_Bandwidth_Initial(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

	assert.Equal(t, uint64(10000), conn.bwMax, "initial bandwidth with 100ms RTT")
}

func TestMeasurements_Bandwidth_UpdatesWithLowerRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(50_000_000, 1000, 2_000_000_000)

	assert.Equal(t, uint64(20000), conn.bwMax, "bandwidth should use new minimum RTT")
}

func TestMeasurements_Bandwidth_MaintainsWithHigherRTT(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(50_000_000, 1000, 2_000_000_000)
	conn.updateMeasurements(75_000_000, 1000, 3_000_000_000)

	assert.Equal(t, uint64(20000), conn.bwMax, "bandwidth should still use 50ms minimum")
}

// =============================================================================
// BBR STATE TRANSITION TESTS
// =============================================================================

func TestMeasurements_StartupToNormal_Transition(t *testing.T) {
	conn := newTestConnection()

	// Establish baseline bandwidth
	conn.updateMeasurements(50_000_000, 2000, 1_000_000_000)
	assert.True(t, conn.isStartup)

	// Three consecutive measurements without bandwidth increase
	for i := 1; i <= 3; i++ {
		conn.updateMeasurements(50_000_000, 1000, uint64(1_000_000_000+i*1_000_000_000))
	}

	assert.False(t, conn.isStartup, "should transition to normal after 3 bwDec")
	assert.Equal(t, uint64(100), conn.pacingGainPct, "pacing gain should be 1.0x")
}

func TestMeasurements_StartupToNormal_RemainsInStartup(t *testing.T) {
	conn := newTestConnection()

	conn.updateMeasurements(50_000_000, 2000, 1_000_000_000)

	// Two consecutive without increase - should still be in startup
	conn.updateMeasurements(50_000_000, 1000, 2_000_000_000)
	conn.updateMeasurements(50_000_000, 1000, 3_000_000_000)

	assert.True(t, conn.isStartup, "should remain in startup after 2 bwDec")
}

// =============================================================================
// NORMAL STATE PACING TESTS
// =============================================================================

func TestMeasurements_NormalState_HighRTTInflation(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000
	conn.rttMinTimeNano = 1_000_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	conn.srtt = 160_000_000
	conn.updateMeasurements(200_000_000, 1000, 1_100_000_000)

	assert.Equal(t, uint64(75), conn.pacingGainPct, "should reduce to 75% when RTT > 1.5x min")
}

func TestMeasurements_NormalState_ModerateRTTInflation(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000
	conn.rttMinTimeNano = 1_000_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	conn.srtt = 130_000_000
	conn.updateMeasurements(200_000_000, 1000, 1_200_000_000)

	assert.Equal(t, uint64(90), conn.pacingGainPct, "should reduce to 90% when RTT > 1.25x min")
}

func TestMeasurements_NormalState_NormalRTT(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000
	conn.rttMinTimeNano = 1_000_000_000
	conn.lastProbeTimeNano = 1_200_000_000

	conn.srtt = 100_000_000
	conn.updateMeasurements(200_000_000, 1000, 1_300_000_000)

	assert.Equal(t, uint64(100), conn.pacingGainPct, "should be 100% when RTT is normal")
}

// =============================================================================
// BANDWIDTH PROBING TESTS
// =============================================================================

func TestMeasurements_Probing_BeforeProbeTime(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000
	conn.rttMinTimeNano = 1_000_000_000
	conn.srtt = 100_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	conn.updateMeasurements(150_000_000, 1000, 1_500_000_000) // 5 RTTs

	assert.Equal(t, uint64(100), conn.pacingGainPct, "should not probe yet")
}

func TestMeasurements_Probing_AfterProbeTime(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000
	conn.rttMinTimeNano = 1_000_000_000
	conn.srtt = 100_000_000
	conn.lastProbeTimeNano = 1_000_000_000

	conn.updateMeasurements(150_000_000, 1000, 1_900_000_000) // 9 RTTs

	assert.Equal(t, uint64(125), conn.pacingGainPct, "should probe with 125% gain")
	assert.Equal(t, uint64(1_900_000_000), conn.lastProbeTimeNano, "should update probe time")
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

	assert.False(t, conn.isStartup, "should exit startup on dup ACK")
	assert.Equal(t, uint64(9800), conn.bwMax, "bandwidth should reduce by 2%")
	assert.Equal(t, uint64(90), conn.pacingGainPct, "should set gain to 90%")
}

func TestMeasurements_OnPacketLoss(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000

	conn.onPacketLoss()

	assert.False(t, conn.isStartup, "should switch to normal state")
	assert.Equal(t, uint64(9500), conn.bwMax, "bandwidth should reduce by 5%")
	assert.Equal(t, uint64(100), conn.pacingGainPct, "should reset gain to 100%")
}

func TestMeasurements_OnPacketLoss_ZeroBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 0

	conn.onPacketLoss()

	assert.Equal(t, uint64(0), conn.bwMax)
}

func TestMeasurements_MultipleEvents(t *testing.T) {
	conn := newTestConnection()

	conn.onPacketLoss()
	conn.onDuplicateAck()

	assert.False(t, conn.isStartup)
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
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)

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

func TestBackoff_MaxAllowed(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	result, err := backoff(baseRTO, 4)

	assert.NoError(t, err)
	assert.Equal(t, baseRTO*16, result)
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
	assert.Equal(t, largeRTO*16, result)
}

// =============================================================================
// EDGE CASE TESTS
// =============================================================================

func TestMeasurements_DivisionByZeroProtection(t *testing.T) {
	conn := newTestConnection()
	conn.rttMinNano = 0

	assert.NotPanics(t, func() {
		conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	})
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
			conn.updateMeasurements(100_000_000, 1000, uint64(1_000_000_000+i*100_000_000))
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

	// Startup phase - increasing bandwidth
	for i := 0; i < 5; i++ {
		conn.updateMeasurements(50_000_000, uint16(1000*(i+1)), uint64(1_000_000_000*(i+1)))
	}
	assert.True(t, conn.isStartup)

	// Plateau - trigger transition
	for i := 0; i < 3; i++ {
		conn.updateMeasurements(50_000_000, 1000, uint64(6_000_000_000+i*1_000_000_000))
	}
	assert.False(t, conn.isStartup)

	// Verify pacing calculation works
	interval := conn.calcPacing(1000)
	assert.Greater(t, interval, uint64(0))
}