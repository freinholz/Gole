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
//   - Endpoint reachability (direct P2P address + relay route)
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

// Registrar handles endpoint registration, reachability, and relay discovery.
type Registrar struct {
	mu sync.RWMutex

	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	// domain -> group -> endpointID -> info
	endpoints map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint

	pending map[string]*PendingRegistration

	nextID map[DomainID]map[GroupID]uint16

	// Reachability records: AddrKey -> info
	// Each endpoint publishes how to reach it (direct P2P + relay route).
	reachability map[string]*ReachabilityInfo

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
		publicKey:    pub,
		privateKey:   priv,
		endpoints:    make(map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint),
		pending:      make(map[string]*PendingRegistration),
		nextID:       make(map[DomainID]map[GroupID]uint16),
		reachability: make(map[string]*ReachabilityInfo),
		tokenTTL:     tokenTTL,
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

// RevokeEndpoint transitions any -> Revoked and clears reachability.
func (r *Registrar) RevokeEndpoint(addr EndpointAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ep := r.getEndpoint(addr)
	if ep == nil {
		return errors.New("endpoint not found")
	}
	ep.State = StateRevoked
	delete(r.reachability, addr.AddrKey())
	return nil
}

// --- Reachability ---

// ObserveEndpoint records an endpoint's public address as seen by the
// broker from the endpoint's connection. The endpoint doesn't know its
// own NAT-mapped address — the broker observes it.
func (r *Registrar) ObserveEndpoint(addr EndpointAddr, observedAddr, proto string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	ep := r.getEndpoint(addr)
	if ep == nil {
		return errors.New("observe denied: endpoint not found")
	}
	if ep.State != StateActive {
		return fmt.Errorf("observe denied: state is %s", StateName(ep.State))
	}

	info := r.getOrCreateReachability(addr)
	info.Direct = &DirectRoute{ObservedAddr: observedAddr, Proto: proto}
	info.UpdatedAt = time.Now()
	return nil
}

// SetRelayRoute records which relay an endpoint is connected to.
// Called by the endpoint after connecting to a relay. Token-guarded:
// an endpoint can only update its own relay route.
func (r *Registrar) SetRelayRoute(addr EndpointAddr, token string, relayAddr EndpointAddr) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	claims, err := VerifyToken(token, r.publicKey)
	if err != nil {
		return fmt.Errorf("relay route update denied: %w", err)
	}
	if claims.EndpointID != addr.Endpoint ||
		claims.Domain != addr.Domain ||
		claims.Group != addr.Group {
		return errors.New("relay route update denied: token does not match address")
	}

	ep := r.getEndpoint(addr)
	if ep == nil {
		return errors.New("relay route update denied: endpoint not found")
	}
	if ep.State != StateActive {
		return fmt.Errorf("relay route update denied: state is %s", StateName(ep.State))
	}

	info := r.getOrCreateReachability(addr)
	info.Relay = &RelayRoute{RelayAddr: relayAddr}
	info.UpdatedAt = time.Now()
	return nil
}

// LookupReachability returns how to reach a target endpoint.
// Returns (nil, nil) if no reachability info exists yet.
func (r *Registrar) LookupReachability(target EndpointAddr) (*ReachabilityInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, ok := r.reachability[target.AddrKey()]
	if !ok {
		return nil, nil
	}

	ep := r.getEndpoint(info.Addr)
	if ep == nil || ep.State != StateActive {
		return nil, nil
	}

	c := *info
	return &c, nil
}

// RequestPunch initiates a P2P rendezvous between two endpoints.
// Returns PunchRequests for both sides: each gets the other's observed
// public address so they can hole-punch simultaneously.
func (r *Registrar) RequestPunch(clientAddr, agentAddr EndpointAddr, clientToken string) (*PunchRequest, *PunchRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Verify client token
	claims, err := VerifyToken(clientToken, r.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("punch denied: %w", err)
	}
	if claims.EndpointID != clientAddr.Endpoint ||
		claims.Domain != clientAddr.Domain ||
		claims.Group != clientAddr.Group {
		return nil, nil, errors.New("punch denied: token does not match client address")
	}

	// Look up both sides' observed addresses
	clientInfo, ok := r.reachability[clientAddr.AddrKey()]
	if !ok || clientInfo.Direct == nil {
		return nil, nil, errors.New("punch denied: client has no observed address")
	}
	agentInfo, ok := r.reachability[agentAddr.AddrKey()]
	if !ok || agentInfo.Direct == nil {
		return nil, nil, errors.New("punch denied: agent has no observed address")
	}

	// Check both are active
	clientEp := r.getEndpoint(clientAddr)
	agentEp := r.getEndpoint(agentAddr)
	if clientEp == nil || clientEp.State != StateActive {
		return nil, nil, errors.New("punch denied: client not active")
	}
	if agentEp == nil || agentEp.State != StateActive {
		return nil, nil, errors.New("punch denied: agent not active")
	}

	// Each side gets the other's observed address
	forClient := &PunchRequest{
		PeerAddr:     agentAddr,
		ObservedAddr: agentInfo.Direct.ObservedAddr,
		Proto:        agentInfo.Direct.Proto,
	}
	forAgent := &PunchRequest{
		PeerAddr:     clientAddr,
		ObservedAddr: clientInfo.Direct.ObservedAddr,
		Proto:        clientInfo.Direct.Proto,
	}

	return forClient, forAgent, nil
}

// ClearReachability removes reachability records for an endpoint.
func (r *Registrar) ClearReachability(addr EndpointAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.reachability, addr.AddrKey())
}

func (r *Registrar) getOrCreateReachability(addr EndpointAddr) *ReachabilityInfo {
	key := addr.AddrKey()
	info, ok := r.reachability[key]
	if !ok {
		info = &ReachabilityInfo{Addr: addr}
		r.reachability[key] = info
	}
	return info
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
