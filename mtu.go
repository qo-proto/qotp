package qotp

// =============================================================================
// MTU Probing (RFC 8899 DPLPMTUD-style)
//
// Start at 1400 (safe). In normal phase:
// 1. Probe 1500
// 2. If success, probe interface max
// 3. If max fails, binary search between 1500 and max
// On retransmit failure: reset to 1400 and re-probe
// =============================================================================

const (
    ipv4Overhead = 28
    ipv6Overhead = 48

    baseMTU     = 1400
    ethernetMTU = 1500

    probeTimeoutNano = 5 * secondNano
    maxProbeAttempts = 3
)

type probePhase int

const (
    probePhaseEthernet probePhase = iota
    probePhaseMax
    probePhaseBinary
    probePhaseDone
)

type mtuProber struct {
    overhead    int
    maxPayload  int
    basePayload int

    confirmed     int
    phase         probePhase
    probeSize     int
    probeAttempts int

    searchLow  int
    searchHigh int

    lastProbeTime uint64
}

func newMTUProber(isIPv6 bool, interfaceMTU int) *mtuProber {
    overhead := ipv4Overhead
    if isIPv6 {
        overhead = ipv6Overhead
    }

    maxPayload := interfaceMTU - overhead
    basePayload := baseMTU - overhead

    phase := probePhaseEthernet
    if maxPayload <= basePayload {
        phase = probePhaseDone
    }

    return &mtuProber{
        overhead:    overhead,
        maxPayload:  maxPayload,
        basePayload: basePayload,
        confirmed:   basePayload,
        phase:       phase,
    }
}

func (p *mtuProber) shouldProbe(nowNano uint64) bool {
    if p.phase == probePhaseDone || p.probeSize != 0 {
        return false
    }
    return nowNano-p.lastProbeTime >= probeTimeoutNano
}

func (p *mtuProber) startProbe(nowNano uint64) int {
    if p.phase == probePhaseDone {
        return 0
    }

    p.lastProbeTime = nowNano
    p.probeAttempts = 0

    switch p.phase {
    case probePhaseEthernet:
        p.probeSize = ethernetMTU - p.overhead
        if p.probeSize >= p.maxPayload {
            p.probeSize = p.maxPayload
            p.phase = probePhaseMax
        }

    case probePhaseMax:
        p.probeSize = p.maxPayload

    case probePhaseBinary:
        if p.searchHigh-p.searchLow < 32 {
            p.phase = probePhaseDone
            return 0
        }
        p.probeSize = (p.searchLow + p.searchHigh) / 2
    }

    return p.probeSize
}

func (p *mtuProber) onProbeAcked() {
    if p.probeSize == 0 {
        return
    }

    p.confirmed = p.probeSize

    switch p.phase {
    case probePhaseEthernet:
        if p.maxPayload > p.confirmed {
            p.phase = probePhaseMax
        } else {
            p.phase = probePhaseDone
        }

    case probePhaseMax:
        p.phase = probePhaseDone

    case probePhaseBinary:
        p.searchLow = p.probeSize
        if p.searchHigh-p.searchLow < 32 {
            p.phase = probePhaseDone
        }
    }

    p.probeSize = 0
}

func (p *mtuProber) onProbeLost() bool {
    if p.probeSize == 0 {
        return false
    }

    p.probeAttempts++
    if p.probeAttempts < maxProbeAttempts {
        return true
    }

    failedSize := p.probeSize
    p.probeSize = 0

    switch p.phase {
    case probePhaseEthernet:
        p.phase = probePhaseDone

    case probePhaseMax:
        if failedSize-p.confirmed > 32 {
            p.phase = probePhaseBinary
            p.searchLow = p.confirmed
            p.searchHigh = failedSize - 1
        } else {
            p.phase = probePhaseDone
        }

    case probePhaseBinary:
        p.searchHigh = failedSize - 1
        if p.searchHigh-p.searchLow < 32 {
            p.phase = probePhaseDone
        }
    }

    return false
}

func (p *mtuProber) onRetransmitFailed() {
    if p.confirmed > p.basePayload {
        p.confirmed = p.basePayload
        p.phase = probePhaseEthernet
        p.probeSize = 0
    }
}

func (p *mtuProber) currentMTU() int {
    return p.confirmed
}

func (p *mtuProber) isProbing() bool {
    return p.probeSize != 0
}

func (p *mtuProber) getProbeSize() int {
    return p.probeSize
}