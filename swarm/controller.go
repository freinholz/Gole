package swarm

// SwarmController is the central authority for endpoint registration,
// identity binding, and flow policy enforcement.
//
// Security model:
//   - Controller holds an Ed25519 keypair. Its public key is the trust root.
//   - Registration uses challenge-response to prove key ownership before
//     assigning an EndpointID. The ID is then cryptographically bound to
//     the endpoint's public key via a PASETO v4.public token.
//   - Flow validation enforces: client-to-agent only, same domain, same group.
//   - Additional FlowPolicy rules can be layered on top.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SwarmController manages the swarm topology, endpoint lifecycle, and flow control.
type SwarmController struct {
	mu sync.RWMutex

	// Controller's Ed25519 keypair — the trust root for all tokens.
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	// Registered endpoints: domain -> group -> endpointID -> info
	endpoints map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint

	// Pending registrations keyed by public key fingerprint
	pending map[string]*PendingRegistration

	// Flow policies (evaluated in addition to built-in rules)
	policies []FlowPolicy

	// Next endpoint ID hint per domain+group (allocation optimization)
	nextID map[DomainID]map[GroupID]uint8

	// Token validity duration
	tokenTTL time.Duration
}

// RegisteredEndpoint holds the state of a registered endpoint.
type RegisteredEndpoint struct {
	Addr      EndpointAddr
	PublicKey ed25519.PublicKey
	State     uint8
	Token     string
}

// PendingRegistration tracks an in-progress registration handshake.
type PendingRegistration struct {
	Request   RegistrationRequest
	Challenge [32]byte
	State     uint8
}

// NewSwarmController creates a new controller with a fresh Ed25519 keypair.
func NewSwarmController(tokenTTL time.Duration) (*SwarmController, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate controller keypair: %w", err)
	}

	return &SwarmController{
		publicKey:  pub,
		privateKey: priv,
		endpoints:  make(map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint),
		pending:    make(map[string]*PendingRegistration),
		policies:   make([]FlowPolicy, 0),
		nextID:     make(map[DomainID]map[GroupID]uint8),
		tokenTTL:   tokenTTL,
	}, nil
}

// PublicKey returns the controller's public key (distributed to all endpoints
// so they can verify tokens).
func (c *SwarmController) PublicKey() ed25519.PublicKey {
	return c.publicKey
}

// RegisterRequest begins the registration handshake.
//
// The controller validates the request, checks capacity, and issues a
// random 32-byte challenge nonce. The endpoint must sign this nonce
// with its private key to prove ownership.
//
// State transition: (new) -> StateChallengeIssued
func (c *SwarmController) RegisterRequest(req RegistrationRequest) (*Challenge, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if req.Role != RoleClient && req.Role != RoleAgent {
		return nil, errors.New("invalid role: must be client or agent")
	}

	if len(req.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key: expected %d bytes, got %d", ed25519.PublicKeySize, len(req.PublicKey))
	}

	fingerprint := keyFingerprint(req.PublicKey)

	if _, exists := c.pending[fingerprint]; exists {
		return nil, errors.New("registration already pending for this key")
	}

	if c.isKeyRegistered(req.PublicKey) {
		return nil, errors.New("public key already registered")
	}

	// uint8 endpoint IDs: 1-254 usable, 0 reserved = max 254 per group
	if c.countEndpoints(req.Domain, req.Group) >= 254 {
		return nil, errors.New("group endpoint capacity reached (max 254)")
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate challenge nonce: %w", err)
	}

	c.pending[fingerprint] = &PendingRegistration{
		Request:   req,
		Challenge: nonce,
		State:     StateChallengeIssued,
	}

	return &Challenge{Nonce: nonce}, nil
}

// RegisterResponse completes the registration handshake.
//
// The controller verifies the endpoint's Ed25519 signature over the challenge
// nonce, allocates a unique EndpointID, and issues a PASETO v4.public token
// that cryptographically binds the ID to the endpoint's public key.
//
// State transition: StateChallengeIssued -> StateRegistered
func (c *SwarmController) RegisterResponse(publicKey ed25519.PublicKey, resp ChallengeResponse) (*RegistrationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fingerprint := keyFingerprint(publicKey)
	pending, exists := c.pending[fingerprint]
	if !exists {
		return nil, errors.New("no pending registration for this key")
	}

	if pending.State != StateChallengeIssued {
		return nil, fmt.Errorf("invalid registration state: expected %s, got %s",
			StateName(StateChallengeIssued), StateName(pending.State))
	}

	// Verify the endpoint owns the private key
	if !ed25519.Verify(publicKey, pending.Challenge[:], resp.Signature) {
		delete(c.pending, fingerprint)
		return nil, errors.New("challenge verification failed: invalid signature")
	}

	// Allocate a unique endpoint ID
	id, err := c.allocateID(pending.Request.Domain, pending.Request.Group)
	if err != nil {
		delete(c.pending, fingerprint)
		return nil, fmt.Errorf("allocate endpoint ID: %w", err)
	}

	addr := EndpointAddr{
		Domain:   pending.Request.Domain,
		Group:    pending.Request.Group,
		Endpoint: id,
		Role:     pending.Request.Role,
	}

	// Issue PASETO token binding ID <-> public key
	now := time.Now()
	claims := &TokenClaims{
		EndpointID: id,
		Domain:     pending.Request.Domain,
		Group:      pending.Request.Group,
		Role:       pending.Request.Role,
		PublicKey:  []byte(publicKey),
		IssuedAt:   now,
		ExpiresAt:  now.Add(c.tokenTTL),
		Issuer:     "gole-swarm-controller",
	}

	token, err := SignToken(claims, c.privateKey)
	if err != nil {
		delete(c.pending, fingerprint)
		return nil, fmt.Errorf("sign token: %w", err)
	}

	c.storeEndpoint(addr, publicKey, token)
	delete(c.pending, fingerprint)

	return &RegistrationResult{ID: id, Token: token}, nil
}

// ActivateEndpoint transitions a registered endpoint to active state.
// The endpoint must present its valid token.
//
// State transition: StateRegistered -> StateActive
func (c *SwarmController) ActivateEndpoint(addr EndpointAddr, token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	claims, err := VerifyToken(token, c.publicKey)
	if err != nil {
		return fmt.Errorf("activation denied: %w", err)
	}

	if claims.EndpointID != addr.Endpoint ||
		claims.Domain != addr.Domain ||
		claims.Group != addr.Group ||
		claims.Role != addr.Role {
		return errors.New("activation denied: token does not match endpoint address")
	}

	ep := c.getEndpoint(addr)
	if ep == nil {
		return errors.New("activation denied: endpoint not found")
	}

	if ep.State != StateRegistered {
		return fmt.Errorf("activation denied: endpoint state is %s, expected %s",
			StateName(ep.State), StateName(StateRegistered))
	}

	ep.State = StateActive
	return nil
}

// RevokeEndpoint revokes an endpoint, preventing further communication.
//
// State transition: any -> StateRevoked
func (c *SwarmController) RevokeEndpoint(addr EndpointAddr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	ep := c.getEndpoint(addr)
	if ep == nil {
		return errors.New("endpoint not found")
	}

	ep.State = StateRevoked
	return nil
}

// ValidateFlow checks whether a communication flow from -> to is allowed.
//
// Enforced rules:
//  1. Sender token must be valid and match the sender address
//  2. Only clients can initiate communication
//  3. Destination must be an agent
//  4. Same domain only (business-level isolation)
//  5. Same group only (group-level isolation)
//  6. Destination must exist and be active
//  7. All custom FlowPolicy rules must pass
func (c *SwarmController) ValidateFlow(from, to EndpointAddr, fromToken string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Verify sender's token
	claims, err := VerifyToken(fromToken, c.publicKey)
	if err != nil {
		return fmt.Errorf("flow denied: invalid sender token: %w", err)
	}

	if claims.EndpointID != from.Endpoint ||
		claims.Domain != from.Domain ||
		claims.Group != from.Group ||
		claims.Role != from.Role {
		return errors.New("flow denied: token does not match sender address")
	}

	return c.checkFlowRules(from, to)
}

// VerifyMessage performs full verification of an incoming SwarmMessage:
//  1. Verifies the sender's PASETO token (controller signature + expiry)
//  2. Confirms the token matches the claimed sender address
//  3. Verifies the payload signature against the public key in the token
//  4. Enforces all flow rules (role, domain, group, policies)
func (c *SwarmController) VerifyMessage(msg *SwarmMessage) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Step 1: Verify the PASETO token
	claims, err := VerifyToken(msg.Token, c.publicKey)
	if err != nil {
		return fmt.Errorf("message denied: invalid token: %w", err)
	}

	// Step 2: Token must match the claimed sender
	if claims.EndpointID != msg.From.Endpoint ||
		claims.Domain != msg.From.Domain ||
		claims.Group != msg.From.Group ||
		claims.Role != msg.From.Role {
		return errors.New("message denied: token does not match sender address")
	}

	// Step 3: Verify payload signature with the public key bound in the token
	if !ed25519.Verify(ed25519.PublicKey(claims.PublicKey), msg.Payload, msg.Signature) {
		return errors.New("message denied: invalid payload signature")
	}

	// Step 4: Enforce flow rules
	return c.checkFlowRules(msg.From, msg.To)
}

// AddPolicy adds a custom flow policy evaluated during flow validation.
func (c *SwarmController) AddPolicy(policy FlowPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies = append(c.policies, policy)
}

// GetEndpointInfo returns info about a registered endpoint (nil if not found).
func (c *SwarmController) GetEndpointInfo(addr EndpointAddr) *RegisteredEndpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ep := c.getEndpoint(addr)
	if ep == nil {
		return nil
	}
	// Return a copy to prevent external mutation
	copy := *ep
	return &copy
}

// ListEndpoints returns all registered endpoints in a domain+group.
func (c *SwarmController) ListEndpoints(domain DomainID, group GroupID) []RegisteredEndpoint {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []RegisteredEndpoint
	if dg, ok := c.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			for _, ep := range ge {
				result = append(result, *ep)
			}
		}
	}
	return result
}

// --- internal helpers ---

// checkFlowRules enforces built-in and custom flow policies.
// Caller must hold at least a read lock.
func (c *SwarmController) checkFlowRules(from, to EndpointAddr) error {
	// Rule 1: Only clients can initiate
	if from.Role != RoleClient {
		return errors.New("flow denied: only clients can initiate communication")
	}

	// Rule 2: Destination must be an agent
	if to.Role != RoleAgent {
		return errors.New("flow denied: destination must be an agent")
	}

	// Rule 3: Same domain
	if from.Domain != to.Domain {
		return fmt.Errorf("flow denied: cross-domain communication not allowed (domain %d -> %d)", from.Domain, to.Domain)
	}

	// Rule 4: Same group
	if from.Group != to.Group {
		return fmt.Errorf("flow denied: cross-group communication not allowed (group %d -> %d)", from.Group, to.Group)
	}

	// Rule 5: Destination must exist and be active
	ep := c.getEndpoint(to)
	if ep == nil {
		return errors.New("flow denied: destination endpoint not found")
	}
	if ep.State != StateActive {
		return fmt.Errorf("flow denied: destination endpoint state is %s", StateName(ep.State))
	}

	// Rule 6: Custom policies
	for _, policy := range c.policies {
		if err := policy.Evaluate(from, to); err != nil {
			return fmt.Errorf("flow denied: policy violation: %w", err)
		}
	}

	return nil
}

func (c *SwarmController) allocateID(domain DomainID, group GroupID) (EndpointID, error) {
	if _, ok := c.nextID[domain]; !ok {
		c.nextID[domain] = make(map[GroupID]uint8)
	}

	hint := c.nextID[domain][group]
	if hint == 0 {
		hint = 1 // ID 0 is reserved
	}

	// Scan for the next available ID (wrapping around)
	for i := uint8(0); i < 254; i++ {
		candidate := hint + i
		if candidate == 0 {
			candidate = 1
		}
		// Avoid overflow past 254
		if candidate > 254 {
			candidate = candidate - 254
		}
		eid := EndpointID(candidate)
		if !c.isIDTaken(domain, group, eid) {
			next := candidate + 1
			if next > 254 {
				next = 1
			}
			c.nextID[domain][group] = next
			return eid, nil
		}
	}

	return 0, errors.New("no available endpoint IDs in group")
}

func (c *SwarmController) isIDTaken(domain DomainID, group GroupID, id EndpointID) bool {
	if dg, ok := c.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			_, taken := ge[id]
			return taken
		}
	}
	return false
}

func (c *SwarmController) isKeyRegistered(key []byte) bool {
	for _, groups := range c.endpoints {
		for _, endpoints := range groups {
			for _, ep := range endpoints {
				if bytes.Equal(ep.PublicKey, key) {
					return true
				}
			}
		}
	}
	return false
}

func (c *SwarmController) countEndpoints(domain DomainID, group GroupID) int {
	if dg, ok := c.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			return len(ge)
		}
	}
	return 0
}

func (c *SwarmController) storeEndpoint(addr EndpointAddr, publicKey ed25519.PublicKey, token string) {
	if _, ok := c.endpoints[addr.Domain]; !ok {
		c.endpoints[addr.Domain] = make(map[GroupID]map[EndpointID]*RegisteredEndpoint)
	}
	if _, ok := c.endpoints[addr.Domain][addr.Group]; !ok {
		c.endpoints[addr.Domain][addr.Group] = make(map[EndpointID]*RegisteredEndpoint)
	}

	c.endpoints[addr.Domain][addr.Group][addr.Endpoint] = &RegisteredEndpoint{
		Addr:      addr,
		PublicKey: publicKey,
		State:     StateRegistered,
		Token:     token,
	}
}

func (c *SwarmController) getEndpoint(addr EndpointAddr) *RegisteredEndpoint {
	if dg, ok := c.endpoints[addr.Domain]; ok {
		if ge, ok := dg[addr.Group]; ok {
			return ge[addr.Endpoint]
		}
	}
	return nil
}

func keyFingerprint(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}
