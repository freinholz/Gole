package swarm

// Endpoint represents a participant in the swarm (client or agent).
//
// Each endpoint owns an Ed25519 keypair. During registration, the controller
// verifies key ownership via challenge-response and issues a PASETO token
// binding the endpoint's ID to its public key. This prevents ID spoofing:
// an endpoint cannot use another's ID because it would need both the
// controller's signing key (to forge a token) and the victim's private key
// (to sign messages).

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// Endpoint is a swarm participant with cryptographic identity.
type Endpoint struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	addr       *EndpointAddr
	token      string
	state      uint8
}

// NewEndpoint creates a new endpoint with a fresh Ed25519 keypair.
func NewEndpoint() (*Endpoint, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate endpoint keypair: %w", err)
	}

	return &Endpoint{
		publicKey:  pub,
		privateKey: priv,
		state:      StateUnregistered,
	}, nil
}

// Register performs the full registration handshake with the controller:
//  1. Sends RegistrationRequest with public key, domain, group, role
//  2. Receives Challenge (32-byte nonce)
//  3. Signs the nonce with private key to prove ownership
//  4. Sends ChallengeResponse
//  5. Receives RegistrationResult with assigned ID and PASETO token
//
// State transitions: Unregistered -> Requesting -> ChallengeIssued ->
// ChallengeResponse -> Registered
func (e *Endpoint) Register(ctrl *SwarmController, domain DomainID, group GroupID, role uint8) error {
	if e.state != StateUnregistered {
		return fmt.Errorf("cannot register: current state is %s", StateName(e.state))
	}

	e.state = StateRequesting

	// Step 1: Request registration
	challenge, err := ctrl.RegisterRequest(RegistrationRequest{
		PublicKey: e.publicKey,
		Domain:    domain,
		Group:     group,
		Role:      role,
	})
	if err != nil {
		e.state = StateUnregistered
		return fmt.Errorf("registration request failed: %w", err)
	}

	e.state = StateChallengeIssued

	// Step 2: Prove key ownership by signing the challenge nonce
	signature := ed25519.Sign(e.privateKey, challenge.Nonce[:])
	e.state = StateChallengeResponse

	// Step 3: Submit proof
	result, err := ctrl.RegisterResponse(e.publicKey, ChallengeResponse{
		Signature: signature,
	})
	if err != nil {
		e.state = StateUnregistered
		return fmt.Errorf("registration response failed: %w", err)
	}

	e.addr = &EndpointAddr{
		Domain:   domain,
		Group:    group,
		Endpoint: result.ID,
		Role:     role,
	}
	e.token = result.Token
	e.state = StateRegistered

	return nil
}

// Activate transitions the endpoint to active state.
// The controller verifies the token before allowing activation.
//
// State transition: Registered -> Active
func (e *Endpoint) Activate(ctrl *SwarmController) error {
	if e.state != StateRegistered {
		return fmt.Errorf("cannot activate: current state is %s", StateName(e.state))
	}
	if e.addr == nil {
		return errors.New("cannot activate: endpoint not registered")
	}

	if err := ctrl.ActivateEndpoint(*e.addr, e.token); err != nil {
		return err
	}

	e.state = StateActive
	return nil
}

// PrepareMessage creates a signed, addressed SwarmMessage.
//
// The message includes:
//   - The sender's PASETO token (proves identity to the controller)
//   - An Ed25519 signature over the payload (proves the sender created this
//     specific message and it hasn't been tampered with)
func (e *Endpoint) PrepareMessage(to EndpointAddr, payload []byte) (*SwarmMessage, error) {
	if e.state != StateActive {
		return nil, fmt.Errorf("cannot send: current state is %s", StateName(e.state))
	}
	if e.addr == nil {
		return nil, errors.New("cannot send: endpoint not registered")
	}

	signature := ed25519.Sign(e.privateKey, payload)

	return &SwarmMessage{
		From:      *e.addr,
		To:        to,
		Token:     e.token,
		Payload:   payload,
		Signature: signature,
	}, nil
}

// Addr returns the endpoint's swarm address (nil if not registered).
func (e *Endpoint) Addr() *EndpointAddr {
	return e.addr
}

// Token returns the endpoint's PASETO token (empty if not registered).
func (e *Endpoint) Token() string {
	return e.token
}

// State returns the current registration state.
func (e *Endpoint) State() uint8 {
	return e.state
}

// PublicKey returns the endpoint's Ed25519 public key.
func (e *Endpoint) PublicKey() ed25519.PublicKey {
	return e.publicKey
}
