package qotp

import (
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

func TestMeasurementsRTTCalculation(t *testing.T) {
	// Increasing RTT: 100ms -> 200ms
	conn := newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 50 * msNano
	conn.updateMeasurements(200*msNano, 1000, 1_000_000_000)
	assert.Equal(t, uint64(112500*1000), conn.srtt)
	assert.Equal(t, uint64(62500*1000), conn.rttvar)

	// Decreasing RTT: 200ms -> 100ms
	conn = newTestConnection()
	conn.srtt = 200 * msNano
	conn.rttvar = 80 * msNano
	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)
	assert.Equal(t, uint64(187500*1000), conn.srtt)
	assert.Equal(t, uint64(85*msNano), conn.rttvar)

	// Stable RTT: 100ms -> 100ms
	conn = newTestConnection()
	conn.srtt = 100 * msNano
	conn.rttvar = 20 * msNano
	conn.updateMeasurements(100*msNano, 1000, 1_000_000_000)
	assert.Equal(t, uint64(100*msNano), conn.srtt)
	assert.Equal(t, uint64(15*msNano), conn.rttvar)
}

func TestMeasurementsRTTEdgeCases(t *testing.T) {
	// Precision loss with small values
	conn := newTestConnection()
	conn.srtt = 7
	conn.rttvar = 3
	conn.updateMeasurements(7, 1000, 1_000_000_000)
	assert.Greater(t, conn.srtt, uint64(0))
	assert.Greater(t, conn.rttvar, uint64(0))

	// Variance underflow protection
	conn = newTestConnection()
	conn.srtt = 1000
	conn.rttvar = 1
	conn.updateMeasurements(1000, 1000, 1_000_000_000)
	// Should not panic or underflow
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

func TestMeasurementsBackoff(t *testing.T) {
	baseRTO := uint64(200 * msNano)

	// Exponential backoff
	for retry := 1; retry <= 5; retry++ {
		expected := baseRTO
		for i := 1; i < retry; i++ {
			expected *= 2
		}
		result, err := backoff(baseRTO, retry)
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
	}

	// Exceeds maximum
	_, err := backoff(baseRTO, 6)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "max retry attempts")

	// Invalid input
	_, err = backoff(baseRTO, 0)
	assert.Error(t, err)

	_, err = backoff(baseRTO, -1)
	assert.Error(t, err)
}

// =============================================================================
// EDGE CASE AND ERROR CONDITION TESTS
// =============================================================================

func TestMeasurementsEdgeCases(t *testing.T) {
	// Division by zero protection
	conn := newTestConnection()
	conn.rttMinNano = 0
	assert.NotPanics(t, func() {
		conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	})

	// Zero packet size gives zero interval
	conn = newTestConnection()
	conn.updateMeasurements(100_000_000, 1000, 1_000_000_000)
	assert.Equal(t, uint64(0), conn.calcPacing(0))

	// State transitions with zero bandwidth
	conn = newTestConnection()
	conn.bwMax = 0
	conn.onPacketLoss()
	assert.Equal(t, uint64(0), conn.bwMax)

	// Multiple rapid state transitions
	conn = newTestConnection()
	conn.onPacketLoss()
	conn.onDuplicateAck()
	assert.False(t, conn.isStartup)
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