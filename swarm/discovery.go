package swarm

// Discovery handles relay probing, P2P latency measurement, and
// transport mode selection.
//
// Transport modes:
//   - Pinned:  always relay (e.g. strict corporate policy)
//   - Peer:    always P2P hole-punching
//   - Dynamic: choose the best option; re-evaluate every ProbeInterval
//
// Dynamic mode compares P2P latency vs best relay latency. If P2P
// exceeds the relay by more than the configured Threshold, traffic
// moves to the relay. The TransportMonitor re-probes continuously.

import (
	"sort"
	"sync"
	"time"
)

// Prober measures round-trip latency to a destination.
// Implementations wrap the actual network probe (relay ping/pong or
// P2P echo). Using an interface allows unit-testing transport selection
// without real network IO.
type Prober interface {
	ProbePeer(target EndpointAddr) (time.Duration, error)
	ProbeRelay(relay EndpointAddr) (time.Duration, error)
}

// SelectTransport is a pure function that decides transport based on
// measurements and config. No side effects, fully testable.
func SelectTransport(cfg TransportConfig, p2pLatency time.Duration, relays []RelayInfo) TransportDecision {
	switch cfg.Mode {
	case ModePinned:
		best := bestRelay(relays)
		return TransportDecision{
			UseRelay:     true,
			RelayAddr:    relayAddr(best),
			RelayLatency: relayLat(best),
		}

	case ModePeer:
		return TransportDecision{
			UseRelay:   false,
			P2PLatency: p2pLatency,
		}

	case ModeDynamic:
		best := bestRelay(relays)
		bestLat := relayLat(best)

		// If P2P is unavailable (0 means not measured / failed), use relay.
		if p2pLatency == 0 && best != nil {
			return TransportDecision{
				UseRelay:     true,
				RelayAddr:    relayAddr(best),
				RelayLatency: bestLat,
			}
		}

		// If no relay available, use P2P.
		if best == nil {
			return TransportDecision{
				UseRelay:   false,
				P2PLatency: p2pLatency,
			}
		}

		// Both available: compare. Switch to relay only if P2P exceeds
		// the relay + threshold (hysteresis to avoid flapping).
		if p2pLatency > bestLat+cfg.Threshold {
			return TransportDecision{
				UseRelay:     true,
				RelayAddr:    relayAddr(best),
				P2PLatency:   p2pLatency,
				RelayLatency: bestLat,
			}
		}
		return TransportDecision{
			UseRelay:     false,
			P2PLatency:   p2pLatency,
			RelayLatency: bestLat,
		}
	}

	// Fallback: P2P
	return TransportDecision{UseRelay: false, P2PLatency: p2pLatency}
}

// RankRelays sorts relays by latency (lowest first) and returns the sorted
// slice. Relays with zero latency (not yet probed) are placed last.
func RankRelays(relays []RelayInfo) []RelayInfo {
	sorted := make([]RelayInfo, len(relays))
	copy(sorted, relays)
	sort.Slice(sorted, func(i, j int) bool {
		li, lj := sorted[i].Latency, sorted[j].Latency
		if li == 0 {
			return false // unprobed goes last
		}
		if lj == 0 {
			return true
		}
		return li < lj
	})
	return sorted
}

// ProbeRelays probes all relays and updates their latency values.
// Returns the list sorted by latency.
func ProbeRelays(prober Prober, relays []RelayInfo) []RelayInfo {
	result := make([]RelayInfo, len(relays))
	for i, r := range relays {
		lat, err := prober.ProbeRelay(r.Addr)
		if err != nil {
			result[i] = RelayInfo{Addr: r.Addr, Latency: 0}
		} else {
			result[i] = RelayInfo{Addr: r.Addr, Latency: lat}
		}
	}
	return RankRelays(result)
}

func bestRelay(relays []RelayInfo) *RelayInfo {
	ranked := RankRelays(relays)
	for _, r := range ranked {
		if r.Latency > 0 {
			return &r
		}
	}
	if len(ranked) > 0 {
		return &ranked[0]
	}
	return nil
}

func relayAddr(r *RelayInfo) *EndpointAddr {
	if r == nil {
		return nil
	}
	a := r.Addr
	return &a
}

func relayLat(r *RelayInfo) time.Duration {
	if r == nil {
		return 0
	}
	return r.Latency
}

// --- TransportMonitor ---

// TransportMonitor runs continuous probing in Dynamic mode.
// It re-evaluates the transport decision every ProbeInterval and
// calls OnChange when the decision changes.
type TransportMonitor struct {
	cfg     TransportConfig
	prober  Prober
	peer    EndpointAddr
	relays  []RelayInfo

	mu       sync.Mutex
	current  TransportDecision
	onChange func(TransportDecision) // called when decision changes

	stopCh  chan struct{}
	stopped chan struct{}
}

// NewTransportMonitor creates a monitor. Call Start() to begin probing.
func NewTransportMonitor(cfg TransportConfig, prober Prober, peer EndpointAddr, relays []RelayInfo, onChange func(TransportDecision)) *TransportMonitor {
	return &TransportMonitor{
		cfg:      cfg,
		prober:   prober,
		peer:     peer,
		relays:   relays,
		onChange: onChange,
		stopCh:   make(chan struct{}),
		stopped:  make(chan struct{}),
	}
}

// Start begins continuous monitoring in a background goroutine.
// Does an initial probe immediately, then repeats every ProbeInterval.
func (m *TransportMonitor) Start() {
	go m.loop()
}

// Stop halts the monitor and waits for the goroutine to exit.
func (m *TransportMonitor) Stop() {
	close(m.stopCh)
	<-m.stopped
}

// Current returns the most recent transport decision.
func (m *TransportMonitor) Current() TransportDecision {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *TransportMonitor) loop() {
	defer close(m.stopped)

	// Initial probe
	m.evaluate()

	interval := m.cfg.ProbeInterval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.evaluate()
		case <-m.stopCh:
			return
		}
	}
}

func (m *TransportMonitor) evaluate() {
	// Probe relays
	probed := ProbeRelays(m.prober, m.relays)

	// Probe P2P
	p2pLat, _ := m.prober.ProbePeer(m.peer)

	decision := SelectTransport(m.cfg, p2pLat, probed)

	m.mu.Lock()
	prev := m.current
	m.current = decision
	m.relays = probed // update with fresh latencies
	m.mu.Unlock()

	if m.onChange != nil && prev.UseRelay != decision.UseRelay {
		m.onChange(decision)
	}
}
