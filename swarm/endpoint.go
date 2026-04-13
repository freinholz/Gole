package swarm

// Endpoint represents a swarm participant (client, agent, or relay).
//
// Zero-touch enrollment lifecycle:
//  1. NewEndpoint() generates Ed25519 keypair
//  2. AutoEnroll(ctx, reg, role, cfg, pollInterval):
//     a. Enroll → broker returns RequestID + challenge
//     b. Sign challenge → ConfirmEnrollment
//        - If pre-approved / relay: immediately Registered
//        - Otherwise: Pending, endpoint polls
//     c. PollEnrollment every `pollInterval` until Registered or Denied
//  3. Activate → Active
//
// An endpoint cannot claim another's identity: the PASETO token binds
// endpoint_id + domain + group + public_key, all signed by the broker.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

type Endpoint struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	addr       *EndpointAddr
	token      string
	state      uint8

	// Enrollment state
	requestID   string
	fingerprint string

	// Received from registrar after activation
	registrarKey ed25519.PublicKey
	relays       []RelayInfo

	// Transport
	transportCfg TransportConfig
	decision     *TransportDecision
	monitor      *TransportMonitor
}

// NewEndpoint creates a new endpoint with a fresh Ed25519 keypair.
func NewEndpoint() (*Endpoint, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate endpoint keypair: %w", err)
	}
	return &Endpoint{
		publicKey:    pub,
		privateKey:   priv,
		state:        StateUnregistered,
		transportCfg: DefaultTransportConfig(),
	}, nil
}

// SetTransportConfig sets the transport mode.
func (e *Endpoint) SetTransportConfig(cfg TransportConfig) {
	e.transportCfg = cfg
}

// Enroll sends the phase-1 enrollment request.
// Internal: most callers should use AutoEnroll.
func (e *Endpoint) Enroll(reg *Registrar, fingerprint string, roleFlags uint8) (*EnrollResponse, error) {
	if e.state != StateUnregistered {
		return nil, fmt.Errorf("cannot enroll: state is %s", StateName(e.state))
	}
	e.state = StateRequesting
	e.fingerprint = fingerprint

	resp, err := reg.Enroll(EnrollRequest{
		PublicKey:   e.publicKey,
		Fingerprint: fingerprint,
		RoleFlags:   roleFlags,
	})
	if err != nil {
		e.state = StateUnregistered
		return nil, fmt.Errorf("enroll: %w", err)
	}
	e.requestID = resp.RequestID
	e.state = StateChallengeIssued
	return resp, nil
}

// ConfirmEnrollment signs the challenge and submits phase-2.
func (e *Endpoint) ConfirmEnrollment(reg *Registrar, challenge [32]byte) (*EnrollStatus, error) {
	if e.state != StateChallengeIssued {
		return nil, fmt.Errorf("cannot confirm: state is %s", StateName(e.state))
	}
	sig := ed25519.Sign(e.privateKey, challenge[:])
	e.state = StateChallengeResponse

	status, err := reg.ConfirmEnrollment(EnrollConfirm{
		RequestID: e.requestID,
		Signature: sig,
	})
	if err != nil {
		e.state = StateUnregistered
		return nil, fmt.Errorf("confirm: %w", err)
	}
	e.applyStatus(status)
	return status, nil
}

// Poll sends a phase-3 poll. Endpoint signs (RequestID || "|poll").
func (e *Endpoint) Poll(reg *Registrar) (*EnrollStatus, error) {
	if e.requestID == "" {
		return nil, errors.New("no active enrollment")
	}
	msg := []byte(e.requestID + "|poll")
	sig := ed25519.Sign(e.privateKey, msg)

	status, err := reg.PollEnrollment(e.requestID, sig)
	if err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	e.applyStatus(status)
	return status, nil
}

// AutoEnroll performs the full zero-touch enrollment flow:
// Enroll → Confirm → Poll (with backoff) until approved/denied/cancelled.
// Polls every `pollInterval` (default 5s if zero) with capped exponential
// backoff up to 60s on unchanged Pending status.
func (e *Endpoint) AutoEnroll(ctx context.Context, reg *Registrar, role uint8, cfg *EndpointConfig, pollInterval time.Duration) error {
	// Derive fingerprint (relay uses empty)
	var fp string
	if role != RoleRelay {
		var err error
		fp, err = DeriveFingerprint(cfg.LocalID, RoleName(role))
		if err != nil {
			return fmt.Errorf("derive fingerprint: %w", err)
		}
	}

	// Phase 1
	resp, err := e.Enroll(reg, fp, role)
	if err != nil {
		return err
	}

	// Phase 2
	status, err := e.ConfirmEnrollment(reg, resp.Challenge)
	if err != nil {
		return err
	}
	if status.State == StateRegistered {
		return nil
	}
	if status.State == StateDenied {
		return errors.New("enrollment denied by admin")
	}

	// Phase 3: poll until approved/denied
	interval := pollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	maxInterval := 60 * time.Second

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}

		status, err := e.Poll(reg)
		if err != nil {
			return err
		}
		switch status.State {
		case StateRegistered:
			return nil
		case StateDenied:
			return errors.New("enrollment denied by admin")
		case StatePending:
			// Exponential backoff up to maxInterval
			interval = interval * 2
			if interval > maxInterval {
				interval = maxInterval
			}
			timer.Reset(interval)
		default:
			timer.Reset(interval)
		}
	}
}

// Activate transitions Registered -> Active and fetches relay list.
func (e *Endpoint) Activate(reg *Registrar) error {
	if e.state != StateRegistered {
		return fmt.Errorf("cannot activate: state is %s", StateName(e.state))
	}
	if e.addr == nil {
		return errors.New("cannot activate: not registered")
	}
	if err := reg.ActivateEndpoint(*e.addr, e.token); err != nil {
		return err
	}
	e.state = StateActive

	info, err := reg.FullRegistrationInfo(*e.addr)
	if err != nil {
		return fmt.Errorf("fetch registration info: %w", err)
	}
	e.registrarKey = info.RegistrarKey
	e.relays = info.Relays
	return nil
}

// applyStatus updates endpoint state from an EnrollStatus.
func (e *Endpoint) applyStatus(s *EnrollStatus) {
	switch s.State {
	case StateRegistered:
		if s.Result != nil {
			addr := s.Result.Address
			e.addr = &addr
			e.token = s.Result.Token
		}
		e.state = StateRegistered
	case StatePending:
		e.state = StatePending
	case StateDenied:
		e.state = StateDenied
	}
}

// Discover probes relays and P2P, selects transport mode.
// If reg is non-nil, looks up target reachability to prioritize its relay.
func (e *Endpoint) Discover(prober Prober, peer EndpointAddr, reg *Registrar) (*TransportDecision, error) {
	if e.state != StateActive {
		return nil, fmt.Errorf("cannot discover: state is %s", StateName(e.state))
	}

	relays := e.relays
	if reg != nil {
		reach, _ := reg.LookupReachability(peer)
		if reach != nil && reach.Relay != nil {
			relays = PrioritizeRelay(relays, reach.Relay.RelayAddr)
		}
	}

	probed := ProbeRelays(prober, relays)
	e.relays = probed

	p2pLat, _ := prober.ProbePeer(peer)

	decision := SelectTransport(e.transportCfg, p2pLat, probed)
	e.decision = &decision

	if e.transportCfg.Mode == ModeDynamic {
		e.StopMonitor()
		e.monitor = NewTransportMonitor(
			e.transportCfg, prober, peer, probed,
			func(d TransportDecision) { e.decision = &d },
		)
		e.monitor.Start()
	}
	return &decision, nil
}

// StopMonitor stops the continuous transport monitor if running.
func (e *Endpoint) StopMonitor() {
	if e.monitor != nil {
		e.monitor.Stop()
		e.monitor = nil
	}
}

// TransportDecisionResult returns the current transport decision.
func (e *Endpoint) TransportDecisionResult() *TransportDecision {
	return e.decision
}

// SetRelayRoute tells the broker which relay this endpoint is connected to.
func (e *Endpoint) SetRelayRoute(reg *Registrar, relayAddr EndpointAddr) error {
	if e.state != StateActive {
		return fmt.Errorf("cannot set relay route: state is %s", StateName(e.state))
	}
	if e.addr == nil {
		return errors.New("cannot set relay route: not registered")
	}
	return reg.SetRelayRoute(*e.addr, e.token, relayAddr)
}

// LookupTarget queries the broker for a target endpoint's reachability.
func (e *Endpoint) LookupTarget(reg *Registrar, target EndpointAddr) (*ReachabilityInfo, error) {
	return reg.LookupReachability(target)
}

// PrepareMessage creates a signed, addressed SwarmMessage.
func (e *Endpoint) PrepareMessage(to EndpointAddr, payload []byte) (*SwarmMessage, error) {
	if e.state != StateActive {
		return nil, fmt.Errorf("cannot send: state is %s", StateName(e.state))
	}
	if e.addr == nil {
		return nil, errors.New("cannot send: not registered")
	}
	sig := ed25519.Sign(e.privateKey, payload)
	return &SwarmMessage{
		From:      *e.addr,
		To:        to,
		Token:     e.token,
		Payload:   payload,
		Signature: sig,
	}, nil
}

// Accessors
func (e *Endpoint) Addr() *EndpointAddr            { return e.addr }
func (e *Endpoint) Token() string                  { return e.token }
func (e *Endpoint) State() uint8                   { return e.state }
func (e *Endpoint) PublicKey() ed25519.PublicKey   { return e.publicKey }
func (e *Endpoint) Relays() []RelayInfo            { return e.relays }
func (e *Endpoint) RegistrarKey() ed25519.PublicKey { return e.registrarKey }
func (e *Endpoint) RequestID() string              { return e.requestID }
func (e *Endpoint) Fingerprint() string            { return e.fingerprint }
