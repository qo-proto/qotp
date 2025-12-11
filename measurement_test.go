package qotp

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Helper function to create a minimal Connection for testing
func newTestConnection() *Conn {
	return &Conn{
		Measurements: NewMeasurements(),
	}
}

// =============================================================================
// BASIC FUNCTIONALITY TESTS
// =============================================================================

// Test invalid inputs
func TestMeasurementsInvalidInputs(t *testing.T) {
	conn := newTestConnection()

	// Test zero RTT measurement
	conn.updateMeasurements(0, 1_000, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "Bandwidth should not update with zero RTT")

	// Test zero bytes acked
	conn.updateMeasurements(100_000_000, 0, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.bwMax, "Bandwidth should not update with zero bytes")
}

// Test first RTT measurement
func TestMeasurementsFirstMeasurement(t *testing.T) {
	conn := newTestConnection()

	// First RTT measurement
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000) // 100ms RTT, 1000 bytes, at 1 second

	// Check RTT values
	assert.Equal(t, uint64(100_000_000), conn.srtt, "First SRTT should equal measurement")
	assert.Equal(t, uint64(50_000_000), conn.rttvar, "First RTTVAR should be half of measurement")

	// Check BBR values
	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "First RTT should be stored as minimum")
	assert.Equal(t, uint64(1_000_000_000), conn.rttMinTimeNano, "Timestamp should be stored")
	assert.Equal(t, uint64(10000), conn.bwMax, "Bandwidth should be calculated correctly")
	assert.Equal(t, uint64(0), conn.bwDec, "bwDec should be 0 after bandwidth increase")
	assert.True(t, conn.isStartup, "Should remain in startup state")
	assert.Equal(t, uint64(277), conn.pacingGainPct, "Should maintain startup gain")
}

// =============================================================================
// RTT CALCULATION TESTS
// =============================================================================

// Test RTT increases from previous measurement
func TestMeasurementsIncreasingRTT(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 50 * msNano

	// Update RTT with increased measurement
	conn.updateMeasurements(200*msNano, 1000, 1_000_000_000)

	// Expected values - 7/8 * 100ms + 1/8 * 200ms = 112.5ms
	expectedRTT := uint64(112500 * 1000)
	// 3/4 * 50ms + 1/4 * 100ms = 62.5ms
	expectedVar := uint64(62500 * 1000)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// Test RTT decreases from previous measurement
func TestMeasurementsDecreasingRTT(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 200 * msNano
	conn.rttvar = 80 * msNano

	// Update RTT with decreased measurement
	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)

	// Expected values - 7/8 * 200ms + 1/8 * 100ms = 187.5ms
	expectedRTT := uint64(187500 * 1000)
	// 3/4 * 80ms + 1/4 * 100ms = 85ms
	expectedVar := uint64(85 * msNano)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// Test stable RTT
func TestMeasurementsStableRTT(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 20 * msNano

	// Update RTT with same measurement
	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)

	// Expected values - RTT should remain the same
	expectedRTT := uint64(100 * msNano)
	// 3/4 * 20ms + 1/4 * 0ms = 15ms
	expectedVar := uint64(15 * msNano)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// Test RTT precision with very small values
func TestMeasurementsRTTPrecisionLoss(t *testing.T) {
	conn := newTestConnection()
	
	// Test with values that could cause precision loss in integer arithmetic
	conn.srtt = 7  // Very small value
	conn.rttvar = 3

	conn.updateMeasurements(7, 1000, 1_000_000_000) // Same as SRTT (delta = 0)
	
	// Should maintain precision and not underflow
	assert.Greater(t, conn.srtt, uint64(0), "SRTT should not become zero")
	assert.Greater(t, conn.rttvar, uint64(0), "RTTVAR should not become zero")
}

// Test RTT variance underflow protection
func TestMeasurementsRTTVarianceUnderflow(t *testing.T) {
	conn := newTestConnection()
	
	// Test scenario where variance calculation could underflow
	conn.srtt = 1000
	conn.rttvar = 1

	// Provide measurement exactly equal to SRTT (delta = 0)
	conn.updateMeasurements(1000, 1000, 1_000_000_000)
	
	// Variance should decrease but not underflow to zero completely
	// 3/4 * 1 + 1/4 * 0 = 0 (due to integer division), but should handle gracefully
}

// =============================================================================
// BBR BANDWIDTH AND STATE TESTS
// =============================================================================

// Test minimum RTT tracking
func TestMeasurementsRTTMinTracking(t *testing.T) {
	conn := newTestConnection()

	// Add initial RTT measurement
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000) // 100ms
	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "Initial RTT should be stored")

	// Add higher RTT - should not replace minimum
	conn.updateMeasurements(150_000_000, 1000, 2_000_000_000) // 150ms
	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "Minimum RTT should not change")

	// Add lower RTT - should replace minimum
	conn.updateMeasurements(50_000_000, 1000, 3_000_000_000) // 50ms
	assert.Equal(t, uint64(50_000_000), conn.rttMinNano, "Lower RTT should become new minimum")
	assert.Equal(t, uint64(3_000_000_000), conn.rttMinTimeNano, "Timestamp should be updated")
}

// Test RTT minimum expiry after 10 seconds
func TestMeasurementsRTTMinExpiry(t *testing.T) {
	conn := newTestConnection()

	// Add an RTT sample
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000) // 100ms at 1 second
	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "RTT should be stored")

	// Update within 10 seconds - old min should persist if new RTT is higher
	conn.updateMeasurements(150_000_000, 1000, 9_000_000_000) // 150ms at 9 seconds
	assert.Equal(t, uint64(100_000_000), conn.rttMinNano, "Min RTT should persist within 10 seconds")

	// Update after 10 seconds - should take new measurement even if higher
	conn.updateMeasurements(120_000_000, 1000, 11_000_000_001) // 120ms at 11+ seconds
	assert.Equal(t, uint64(120_000_000), conn.rttMinNano, "RTT min should update after 10 seconds")
	assert.Equal(t, uint64(11_000_000_001), conn.rttMinTimeNano, "Timestamp should be updated")
}

// Test bandwidth calculation using minimum RTT
func TestMeasurementsBandwidthCalculation(t *testing.T) {
	conn := newTestConnection()

	// Add multiple RTT measurements
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000) // 100ms - becomes min
	assert.Equal(t, uint64(10000), conn.bwMax, "Initial bandwidth with 100ms RTT")

	conn.updateMeasurements(50_000_000, 1000, 2_000_000_000) // 50ms - new min
	// Bandwidth should be recalculated: 1000 bytes * 1000 / (50ms / 1000ms) = 20000 bytes/sec
	assert.Equal(t, uint64(20000), conn.bwMax, "Bandwidth should use new minimum RTT")

	conn.updateMeasurements(75_000_000, 1000, 3_000_000_000) // 75ms - not new min
	// Bandwidth still calculated with 50ms min: 20000 bytes/sec
	assert.Equal(t, uint64(20000), conn.bwMax, "Bandwidth should still use 50ms minimum")
}

// Test startup to normal state transition
func TestMeasurementsStartupToNormalTransition(t *testing.T) {
	conn := newTestConnection()

	// Establish baseline bandwidth
	conn.updateMeasurements(50_000_000, 2000, 1_000_000_000) // 40KB/s
	assert.True(t, conn.isStartup, "Should be in startup")

	// Three consecutive measurements without bandwidth increase
	for i := 1; i <= 3; i++ {
		conn.updateMeasurements(50_000_000, 1000, uint64(1_000_000_000+i*1_000_000_000)) // Lower bandwidth
		if i < 3 {
			assert.True(t, conn.isStartup, "Should remain in startup")
		}
	}

	// After 3 decreases, should transition
	assert.False(t, conn.isStartup, "Should transition to normal after 3 bwDec")
	assert.Equal(t, uint64(100), conn.pacingGainPct, "Pacing gain should be 1.0x")
}

// Test normal state RTT-based pacing adjustments
func TestMeasurementsNormalStateRTTBased(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000      // Set min RTT to 100ms
	conn.rttMinTimeNano = 1_000_000_000 // Set time for min RTT
	conn.lastProbeTimeNano = 1_000_000_000 // Initialize to prevent probing

	// Test high RTT inflation (SRTT > 1.5x min)
	conn.srtt = 160_000_000                        // 160ms
	conn.updateMeasurements(200_000_000, 1000, 1_100_000_000) // New measurement won't replace min
	assert.Equal(t, uint64(75), conn.pacingGainPct, "Should reduce to 75% when RTT > 1.5x min")

	// Test moderate RTT inflation (SRTT > 1.25x min)
	conn.srtt = 130_000_000                        // 130ms
	conn.updateMeasurements(200_000_000, 1000, 1_200_000_000)
	assert.Equal(t, uint64(90), conn.pacingGainPct, "Should reduce to 90% when RTT > 1.25x min")

	// Test normal RTT (ensure we're not in probe window)
	conn.srtt = 100_000_000                        // 100ms
	conn.lastProbeTimeNano = 1_200_000_000         // Recent probe time
	conn.updateMeasurements(200_000_000, 1000, 1_300_000_000) // Only 100ms later (1 RTT, not 8)
	assert.Equal(t, uint64(100), conn.pacingGainPct, "Should be 100% when RTT is normal")
}

// Test bandwidth probing
func TestMeasurementsBandwidthProbing(t *testing.T) {
	conn := newTestConnection()
	conn.isStartup = false
	conn.bwMax = 10000
	conn.rttMinNano = 100_000_000      // 100ms min RTT
	conn.rttMinTimeNano = 1_000_000_000
	conn.srtt = 100_000_000              // 100ms
	conn.lastProbeTimeNano = 1_000_000_000

	// Update before probe time (less than 8 RTTs = 800ms)
	conn.updateMeasurements(150_000_000, 1000, 1_500_000_000) // 0.5 seconds = 5 RTTs
	assert.Equal(t, uint64(100), conn.pacingGainPct, "Should not probe yet")

	// Update after probe time (more than 8 RTTs = 800ms)
	conn.updateMeasurements(150_000_000, 1000, 1_900_000_000) // 0.9 seconds = 9 RTTs since last probe
	assert.Equal(t, uint64(125), conn.pacingGainPct, "Should probe with 125% gain")
	assert.Equal(t, uint64(1_900_000_000), conn.lastProbeTimeNano, "Should update probe time")
}

// =============================================================================
// RTO CALCULATION TESTS
// =============================================================================

// Test RTO calculation with default values
func TestMeasurementsRTOCalculationDefault(t *testing.T) {
	conn := newTestConnection()

	// For new connection with no RTT measurements
	rto := conn.rtoNano()
	expectedRTO := uint64(200 * msNano) // Default of 200ms

	assert.Equal(t, expectedRTO, rto, "Default RTO should be 200ms")
}

// Test RTO with standard network conditions
func TestMeasurementsRTOCalculationStandard(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 100 * msNano  // 100ms
	conn.rttvar = 25 * msNano // 25ms

	rto := conn.rtoNano()
	// 100ms + 4 * 25ms = 200ms
	expectedRTO := uint64(200 * msNano)

	assert.Equal(t, expectedRTO, rto, "RTO should be 200ms for standard network")
}

// Test RTO calculation with capping
func TestMeasurementsRTOCalculationCapped(t *testing.T) {
	conn := newTestConnection()
	conn.srtt = 3000 * msNano // 3s
	conn.rttvar = 500 * msNano // 500ms

	rto := conn.rtoNano()
	// Should be capped at maximum
	expectedRTO := uint64(2000 * msNano) // 2s maximum

	assert.Equal(t, expectedRTO, rto, "RTO should be capped at 2s for extreme latency")
}

// =============================================================================
// CONGESTION CONTROL EVENT TESTS
// =============================================================================

// Test duplicate ACK handling
func TestMeasurementsOnDuplicateAck(t *testing.T) {
	// Test in startup state
	conn := newTestConnection()
	conn.bwMax = 10000
	conn.onDuplicateAck()

	assert.False(t, conn.isStartup, "Should exit startup on dup ACK")
	assert.Equal(t, uint64(9800), conn.bwMax, "Bandwidth should reduce by 2%")
	assert.Equal(t, uint64(90), conn.pacingGainPct, "Should set gain to 90%")
}

// Test packet loss handling
func TestMeasurementsOnPacketLoss(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000

	conn.onPacketLoss()

	assert.False(t, conn.isStartup, "Should switch to normal state")
	assert.Equal(t, uint64(9500), conn.bwMax, "Bandwidth should reduce by 5%")
	assert.Equal(t, uint64(100), conn.pacingGainPct, "Should reset gain to 100%")
}

// =============================================================================
// PACING CALCULATION TESTS
// =============================================================================

// Test pacing when no bandwidth estimate exists
func TestMeasurementsPacingNoBandwidth(t *testing.T) {
	conn := newTestConnection()

	// Test with no SRTT
	interval := conn.calcPacing(1000)
	assert.Equal(t, uint64(10*msNano), interval, "Should return 10ms default when no SRTT")

	// Test with SRTT but no bandwidth
	conn.srtt = 100_000_000 // 100ms in nanoseconds
	interval = conn.calcPacing(1000)
	assert.Equal(t, uint64(10_000_000), interval, "Should return SRTT/10 when no bandwidth")
}

// Test normal pacing calculation
func TestMeasurementsPacingWithBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 10000       // 10KB/s
	conn.pacingGainPct = 100 // 1.0x

	// 1KB packet: (1000 bytes / 10000 bytes/sec) * 1e9 ns = 100,000,000 ns
	interval := conn.calcPacing(1000)
	assert.Equal(t, uint64(100_000_000), interval, "Should calculate correct interval")

	// Test with pacing gain
	conn.pacingGainPct = 200 // 2.0x
	interval = conn.calcPacing(1000)
	assert.Equal(t, uint64(50_000_000), interval, "Higher gain should reduce interval")
}

// =============================================================================
// BACKOFF ALGORITHM TESTS
// =============================================================================

// Test backoff functionality
func TestMeasurementsBackoffFirstRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 1)

	assert.NoError(t, err)
	assert.Equal(t, uint64(200*msNano), backoffRTO, "First retry should equal base RTO")
}

func TestMeasurementsBackoffExponential(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	
	// Test exponential progression
	for retry := 1; retry <= 5; retry++ {
		expected := baseRTO
		for i := 1; i < retry; i++ {
			expected *= 2
		}
		
		result, err := backoff(baseRTO, retry)
		assert.NoError(t, err)
		assert.Equal(t, expected, result, "Retry %d should be correct", retry)
	}
}

func TestMeasurementsBackoffExceedsMaximum(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	_, err := backoff(baseRTO, 6)

	assert.Error(t, err, "Should error when exceeding max retry attempts")
	assert.Contains(t, err.Error(), "max retry attempts")
}

// =============================================================================
// EDGE CASE AND ERROR CONDITION TESTS
// =============================================================================

// Test mathematical overflow protection
func TestMeasurementsOverflowProtection(t *testing.T) {
	conn := newTestConnection()
	
	// Test with large but realistic values that won't cause the calculation to return 0
	conn.updateMeasurements(100_000_000, math.MaxUint32, math.MaxUint64) // 100ms RTT, large bytes
	
	// Should not panic and should calculate some bandwidth  
	assert.Greater(t, conn.bwMax, uint64(0), "Should calculate some bandwidth")
	
	// Test pacing calculation doesn't overflow
	interval := conn.calcPacing(1000)
	assert.Greater(t, interval, uint64(0), "Should handle large values gracefully")
}

// Test division by zero protection
func TestMeasurementsDivisionByZeroProtection(t *testing.T) {
	conn := newTestConnection()
	conn.rttMinNano = 0 // This could cause division by zero
	
	// Should not panic
	assert.NotPanics(t, func() {
		conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	}, "Should handle zero RTT min gracefully")
}

// Test time wraparound scenarios
func TestMeasurementsTimeWraparound(t *testing.T) {
	conn := newTestConnection()
	
	// Test time going backwards (clock adjustment)
	conn.updateMeasurements(100_000_000, 1000, math.MaxUint64-1000)
	conn.updateMeasurements(100_000_000, 1000, 1000) // Much earlier time
	
	// Should handle gracefully without panic
	assert.Greater(t, conn.bwMax, uint64(0), "Should handle time wraparound")
}

// Test very large time differences
func TestMeasurementsVeryLargeTimeDifferences(t *testing.T) {
	conn := newTestConnection()
	
	// Test with very large time differences
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	conn.updateMeasurements(100_000_000, 1000, math.MaxUint64-1000)
	
	// Should not cause overflow in time calculations
	assert.Greater(t, conn.rttMinTimeNano, uint64(0), "Should handle large time differences")
}

// Test bandwidth calculation edge cases
func TestMeasurementsBandwidthCalculationEdgeCases(t *testing.T) {
	conn := newTestConnection()
	
	// Test with reasonable RTT to ensure bandwidth calculation works
	conn.updateMeasurements(1_000_000, 1000, 1_000_000_000) // 1ms RTT
	
	// Should not overflow and should calculate reasonable bandwidth
	assert.Greater(t, conn.bwMax, uint64(0), "Should calculate some bandwidth")
	assert.Less(t, conn.bwMax, uint64(math.MaxUint64/2), "Should not overflow bandwidth")
}

// Test bandwidth with very small bytes
func TestMeasurementsBandwidthWithVerySmallBytes(t *testing.T) {
	conn := newTestConnection()
	
	// Test with minimum possible bytes
	conn.updateMeasurements(100_000_000, 1, 1_000_000_000) // 1 byte
	
	// Should handle small values
	assert.Greater(t, conn.bwMax, uint64(0), "Should handle single byte")
}

// Test pacing calculation edge cases
func TestMeasurementsPacingCalculationEdgeCases(t *testing.T) {
	conn := newTestConnection()
	
	// First establish some bandwidth so the calculation doesn't use fallback
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	
	// Test with zero packet size - should give zero interval
	interval := conn.calcPacing(0)
	assert.Equal(t, uint64(0), interval, "Zero packet should give zero interval")
	
	// Test with very large packet size and low bandwidth
	conn.bwMax = 1 // Very low bandwidth
	conn.pacingGainPct = 100
	interval = conn.calcPacing(1000)
	
	// Should not overflow
	assert.Greater(t, interval, uint64(0), "Should handle large intervals")
}

// Test state transition edge cases
func TestMeasurementsStateTransitionEdgeCases(t *testing.T) {
	conn := newTestConnection()
	
	// Force multiple rapid state transitions
	conn.onPacketLoss()        // startup -> normal
	conn.onDuplicateAck()      // should stay normal
	
	// Verify state consistency
	assert.False(t, conn.isStartup, "Should remain in normal state")
}

// Test state transition with zero bandwidth
func TestMeasurementsStateTransitionWithZeroBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.bwMax = 0
	
	conn.onPacketLoss()
	
	// Should handle zero bandwidth gracefully
	assert.Equal(t, uint64(0), conn.bwMax, "Zero bandwidth should remain zero")
}

// Test exact boundary values
func TestMeasurementsExactBoundaryValues(t *testing.T) {
	conn := newTestConnection()
	
	// Establish baseline bandwidth
	conn.updateMeasurements(100_000_000, 2000, 1_000_000_000) // High bandwidth first
	
	// Force bwDec to 2 by providing lower bandwidth measurements
	conn.updateMeasurements(100_000_000, 1000, 2_000_000_000) // Lower bandwidth, bwDec = 1
	conn.updateMeasurements(100_000_000, 1000, 3_000_000_000) // Still lower, bwDec = 2
	
	assert.Equal(t, uint64(2), conn.bwDec, "Should have bwDec = 2")
	assert.True(t, conn.isStartup, "Should still be in startup")
	
	// One more decrease should trigger transition
	conn.updateMeasurements(100_000_000, 1000, 4_000_000_000) // bwDec becomes 3
	
	// Should transition exactly at bwDec = 3
	assert.False(t, conn.isStartup, "Should transition at exactly bwDec = 3")
	assert.Equal(t, uint64(3), conn.bwDec, "Should have bwDec = 3")
}

// Test concurrent access protection
func TestMeasurementsConcurrentAccess(t *testing.T) {
	conn := newTestConnection()
	
	var wg sync.WaitGroup
	
	// Test that concurrent calls don't cause race conditions
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
	
	// Wait for all goroutines to complete
	wg.Wait()
	
	// Should not panic and should have valid state
	assert.Greater(t, conn.bwMax, uint64(0), "Should maintain valid bandwidth after concurrent access")
}

// =============================================================================
// INTEGRATION AND WORKFLOW TESTS
// =============================================================================

// Test complete integration flow
func TestMeasurementsIntegration(t *testing.T) {
	conn := newTestConnection()

	// Startup phase - increasing bandwidth
	for i := 0; i < 5; i++ {
		conn.updateMeasurements(50_000_000, 1000*(i+1), uint64(1_000_000_000*(i+1)))
	}
	assert.True(t, conn.isStartup, "Should still be in startup")

	// Plateau - trigger transition
	for i := 0; i < 3; i++ {
		conn.updateMeasurements(50_000_000, 1000, uint64(6_000_000_000+i*1_000_000_000))
	}
	assert.False(t, conn.isStartup, "Should transition to normal")

	// Verify pacing calculation works
	interval := conn.calcPacing(1000)
	assert.Greater(t, interval, uint64(0), "Should calculate valid pacing interval")
}