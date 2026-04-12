package swarm

// Registrar is the central registration authority (broker).
//
// All endpoints — clients, agents, and relays — register here via
// Ed25519 challenge-response. The registrar issues PASETO v4.public
// tokens binding each endpoint's ID to its public key.
//
// The registrar is the single source of truth for:
//   - Endpoint identity and state
//   - Which relays are available per domain
//   - The trust root (registrar public key) for token verification

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

const maxEndpointsPerGroup = 65534 // uint16 IDs 1..65534, 0 reserved

// Registrar handles endpoint registration and relay discovery.
type Registrar struct {
	mu sync.RWMutex

	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	// domain -> group -> endpointID -> info
	endpoints map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint

	pending map[string]*PendingRegistration

	nextID map[DomainID]map[GroupID]uint16

	tokenTTL time.Duration
}

// PendingRegistration tracks an in-progress handshake.
type PendingRegistration struct {
	Request   RegistrationRequest
	Challenge [32]byte
	State     uint8
}

// NewRegistrar creates a registrar with a fresh Ed25519 keypair.
func NewRegistrar(tokenTTL time.Duration) (*Registrar, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate registrar keypair: %w", err)
	}

	return &Registrar{
		publicKey:  pub,
		privateKey: priv,
		endpoints:  make(map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint),
		pending:    make(map[string]*PendingRegistration),
		nextID:     make(map[DomainID]map[GroupID]uint16),
		tokenTTL:   tokenTTL,
	}, nil
}

// PublicKey returns the registrar's public key — the trust root.
// Distributed to all endpoints, controllers, and relays so they can
// verify any PASETO token.
func (r *Registrar) PublicKey() ed25519.PublicKey {
	return r.publicKey
}

// RegisterRequest begins the challenge-response handshake.
func (r *Registrar) RegisterRequest(req RegistrationRequest) (*Challenge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	role := RoleOf(req.RoleFlags)
	if role != RoleClient && role != RoleAgent && role != RoleRelay {
		return nil, errors.New("invalid role: must be client, agent, or relay")
	}
	if len(req.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key: expected %d bytes, got %d",
			ed25519.PublicKeySize, len(req.PublicKey))
	}

	fp := keyFingerprint(req.PublicKey)
	if _, exists := r.pending[fp]; exists {
		return nil, errors.New("registration already pending for this key")
	}
	if r.isKeyRegistered(req.PublicKey) {
		return nil, errors.New("public key already registered")
	}
	if r.countEndpoints(req.Domain, req.Group) >= maxEndpointsPerGroup {
		return nil, fmt.Errorf("group capacity reached (max %d)", maxEndpointsPerGroup)
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	r.pending[fp] = &PendingRegistration{
		Request:   req,
		Challenge: nonce,
		State:     StateChallengeIssued,
	}

	return &Challenge{Nonce: nonce}, nil
}

// RegisterResponse completes the handshake: verifies signature, allocates ID,
// issues PASETO token.
func (r *Registrar) RegisterResponse(publicKey ed25519.PublicKey, resp ChallengeResponse) (*RegistrationResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fp := keyFingerprint(publicKey)
	pending, exists := r.pending[fp]
	if !exists {
		return nil, errors.New("no pending registration for this key")
	}
	if pending.State != StateChallengeIssued {
		return nil, fmt.Errorf("invalid state: expected %s, got %s",
			StateName(StateChallengeIssued), StateName(pending.State))
	}

	if !ed25519.Verify(publicKey, pending.Challenge[:], resp.Signature) {
		delete(r.pending, fp)
		return nil, errors.New("challenge verification failed: invalid signature")
	}

	id, err := r.allocateID(pending.Request.Domain, pending.Request.Group)
	if err != nil {
		delete(r.pending, fp)
		return nil, fmt.Errorf("allocate ID: %w", err)
	}

	addr := EndpointAddr{
		Domain:    pending.Request.Domain,
		Group:     pending.Request.Group,
		Endpoint:  id,
		RoleFlags: pending.Request.RoleFlags,
	}

	now := time.Now()
	claims := &TokenClaims{
		EndpointID: id,
		Domain:     pending.Request.Domain,
		Group:      pending.Request.Group,
		RoleFlags:  pending.Request.RoleFlags,
		PublicKey:  []byte(publicKey),
		IssuedAt:   now,
		ExpiresAt:  now.Add(r.tokenTTL),
		Issuer:     "gole-swarm-registrar",
	}

	token, err := SignToken(claims, r.privateKey)
	if err != nil {
		delete(r.pending, fp)
		return nil, fmt.Errorf("sign token: %w", err)
	}

	r.storeEndpoint(addr, publicKey, token)
	delete(r.pending, fp)

	return &RegistrationResult{ID: id, Token: token}, nil
}

// ActivateEndpoint transitions Registered -> Active.
func (r *Registrar) ActivateEndpoint(addr EndpointAddr, token string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	claims, err := VerifyToken(token, r.publicKey)
	if err != nil {
		return fmt.Errorf("activation denied: %w", err)
	}

	if claims.EndpointID != addr.Endpoint ||
		claims.Domain != addr.Domain ||
		claims.Group != addr.Group ||
		claims.RoleFlags != addr.RoleFlags {
		return errors.New("activation denied: token does not match address")
	}

	ep := r.getEndpoint(addr)
	if ep == nil {
		return errors.New("activation denied: endpoint not found")
	}
	if ep.State != StateRegistered {
		return fmt.Errorf("activation denied: state is %s, expected %s",
			StateName(ep.State), StateName(StateRegistered))
	}

	ep.State = StateActive
	return nil
}

// RevokeEndpoint transitions any -> Revoked.
func (r *Registrar) RevokeEndpoint(addr EndpointAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ep := r.getEndpoint(addr)
	if ep == nil {
		return errors.New("endpoint not found")
	}
	ep.State = StateRevoked
	return nil
}

// GetEndpointInfo returns a copy of a registered endpoint's info.
func (r *Registrar) GetEndpointInfo(addr EndpointAddr) *RegisteredEndpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ep := r.getEndpoint(addr)
	if ep == nil {
		return nil
	}
	c := *ep
	return &c
}

// ListEndpoints returns all registered endpoints in a domain+group.
func (r *Registrar) ListEndpoints(domain DomainID, group GroupID) []RegisteredEndpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []RegisteredEndpoint
	if dg, ok := r.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			for _, ep := range ge {
				out = append(out, *ep)
			}
		}
	}
	return out
}

// ListRelays returns all active relay endpoints in a domain.
// Relays can serve any group within the domain, so they are listed
// across all groups.
func (r *Registrar) ListRelays(domain DomainID) []RelayInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []RelayInfo
	if dg, ok := r.endpoints[domain]; ok {
		for _, ge := range dg {
			for _, ep := range ge {
				if ep.Addr.Role() == RoleRelay && ep.State == StateActive {
					out = append(out, RelayInfo{Addr: ep.Addr})
				}
			}
		}
	}
	return out
}

// FullRegistrationInfo builds the complete info bundle returned to an
// endpoint after registration + activation.
func (r *Registrar) FullRegistrationInfo(addr EndpointAddr) (*RegistrationInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ep := r.getEndpoint(addr)
	if ep == nil {
		return nil, errors.New("endpoint not found")
	}
	if ep.State != StateActive {
		return nil, fmt.Errorf("endpoint not active: %s", StateName(ep.State))
	}

	return &RegistrationInfo{
		ID:           ep.Addr.Endpoint,
		Token:        ep.Token,
		RegistrarKey: r.publicKey,
		Relays:       r.listRelaysLocked(addr.Domain),
	}, nil
}

func (r *Registrar) listRelaysLocked(domain DomainID) []RelayInfo {
	var out []RelayInfo
	if dg, ok := r.endpoints[domain]; ok {
		for _, ge := range dg {
			for _, ep := range ge {
				if ep.Addr.Role() == RoleRelay && ep.State == StateActive {
					out = append(out, RelayInfo{Addr: ep.Addr})
				}
			}
		}
	}
	return out
}

// --- internal helpers ---

func (r *Registrar) allocateID(domain DomainID, group GroupID) (EndpointID, error) {
	if _, ok := r.nextID[domain]; !ok {
		r.nextID[domain] = make(map[GroupID]uint16)
	}

	hint := r.nextID[domain][group]
	if hint == 0 {
		hint = 1
	}

	for i := uint16(0); i < maxEndpointsPerGroup; i++ {
		candidate := hint + i
		if candidate == 0 {
			candidate = 1
		}
		if candidate > maxEndpointsPerGroup {
			candidate = candidate - maxEndpointsPerGroup
		}
		eid := EndpointID(candidate)
		if !r.isIDTaken(domain, group, eid) {
			next := candidate + 1
			if next > maxEndpointsPerGroup {
				next = 1
			}
			r.nextID[domain][group] = next
			return eid, nil
		}
	}
	return 0, errors.New("no available endpoint IDs")
}

func (r *Registrar) isIDTaken(domain DomainID, group GroupID, id EndpointID) bool {
	if dg, ok := r.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			_, taken := ge[id]
			return taken
		}
	}
	return false
}

func (r *Registrar) isKeyRegistered(key []byte) bool {
	for _, groups := range r.endpoints {
		for _, eps := range groups {
			for _, ep := range eps {
				if bytes.Equal(ep.PublicKey, key) {
					return true
				}
			}
		}
	}
	return false
}

func (r *Registrar) countEndpoints(domain DomainID, group GroupID) int {
	if dg, ok := r.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			return len(ge)
		}
	}
	return 0
}

func (r *Registrar) storeEndpoint(addr EndpointAddr, pk ed25519.PublicKey, token string) {
	if _, ok := r.endpoints[addr.Domain]; !ok {
		r.endpoints[addr.Domain] = make(map[GroupID]map[EndpointID]*RegisteredEndpoint)
	}
	if _, ok := r.endpoints[addr.Domain][addr.Group]; !ok {
		r.endpoints[addr.Domain][addr.Group] = make(map[EndpointID]*RegisteredEndpoint)
	}
	r.endpoints[addr.Domain][addr.Group][addr.Endpoint] = &RegisteredEndpoint{
		Addr:      addr,
		PublicKey: pk,
		State:     StateRegistered,
		Token:     token,
	}
}

func (r *Registrar) getEndpoint(addr EndpointAddr) *RegisteredEndpoint {
	if dg, ok := r.endpoints[addr.Domain]; ok {
		if ge, ok := dg[addr.Group]; ok {
			return ge[addr.Endpoint]
		}
	}
	return nil
}

func keyFingerprint(key []byte) string {
	return base64.RawURLEncoding.EncodeToString(key)
}
