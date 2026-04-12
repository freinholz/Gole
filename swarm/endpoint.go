package swarm

// Endpoint represents a swarm participant (client, agent, or relay).
//
// Lifecycle:
//  1. NewEndpoint() — generates Ed25519 keypair
//  2. Register(registrar, ...) — challenge-response, gets ID + token
//  3. Activate(registrar) — transitions to Active
//  4. Discover(prober) — probes relays + P2P, selects transport
//  5. PrepareMessage() / communicate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

type Endpoint struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	addr       *EndpointAddr
	token      string
	state      uint8

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

// SetTransportConfig sets the transport mode before or after registration.
func (e *Endpoint) SetTransportConfig(cfg TransportConfig) {
	e.transportCfg = cfg
}

// Register performs the full challenge-response with the registrar.
//
// State: Unregistered -> Requesting -> ChallengeIssued -> ChallengeResponse -> Registered
func (e *Endpoint) Register(reg *Registrar, domain DomainID, group GroupID, roleFlags uint8) error {
	if e.state != StateUnregistered {
		return fmt.Errorf("cannot register: state is %s", StateName(e.state))
	}
	e.state = StateRequesting

	challenge, err := reg.RegisterRequest(RegistrationRequest{
		PublicKey: e.publicKey,
		Domain:    domain,
		Group:     group,
		RoleFlags: roleFlags,
	})
	if err != nil {
		e.state = StateUnregistered
		return fmt.Errorf("registration request: %w", err)
	}
	e.state = StateChallengeIssued

	sig := ed25519.Sign(e.privateKey, challenge.Nonce[:])
	e.state = StateChallengeResponse

	result, err := reg.RegisterResponse(e.publicKey, ChallengeResponse{Signature: sig})
	if err != nil {
		e.state = StateUnregistered
		return fmt.Errorf("registration response: %w", err)
	}

	e.addr = &EndpointAddr{
		Domain:    domain,
		Group:     group,
		Endpoint:  result.ID,
		RoleFlags: roleFlags,
	}
	e.token = result.Token
	e.state = StateRegistered
	return nil
}

// Activate transitions Registered -> Active and fetches relay info from
// the registrar.
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

	// Fetch full registration info (trust root + relays).
	info, err := reg.FullRegistrationInfo(*e.addr)
	if err != nil {
		return fmt.Errorf("fetch registration info: %w", err)
	}
	e.registrarKey = info.RegistrarKey
	e.relays = info.Relays

	return nil
}

// Discover probes relays and P2P, selects transport mode.
// For Dynamic mode, this also starts the continuous monitor.
func (e *Endpoint) Discover(prober Prober, peer EndpointAddr) (*TransportDecision, error) {
	if e.state != StateActive {
		return nil, fmt.Errorf("cannot discover: state is %s", StateName(e.state))
	}

	// Probe relays
	probed := ProbeRelays(prober, e.relays)
	e.relays = probed

	// Probe P2P
	p2pLat, _ := prober.ProbePeer(peer)

	decision := SelectTransport(e.transportCfg, p2pLat, probed)
	e.decision = &decision

	// Start continuous monitoring for Dynamic mode
	if e.transportCfg.Mode == ModeDynamic {
		e.StopMonitor() // stop any previous
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

// TransportDecisionResult returns the current transport decision (nil if
// Discover has not been called).
func (e *Endpoint) TransportDecisionResult() *TransportDecision {
	return e.decision
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
func (e *Endpoint) Addr() *EndpointAddr        { return e.addr }
func (e *Endpoint) Token() string               { return e.token }
func (e *Endpoint) State() uint8                { return e.state }
func (e *Endpoint) PublicKey() ed25519.PublicKey { return e.publicKey }
func (e *Endpoint) Relays() []RelayInfo         { return e.relays }
func (e *Endpoint) RegistrarKey() ed25519.PublicKey { return e.registrarKey }
