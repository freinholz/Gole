package swarm

// Registrar is the central enrollment authority (broker).
//
// Three-phase zero-touch enrollment:
//   Phase 1 — Enroll:   endpoint sends (PublicKey, Fingerprint, RoleFlags)
//                       broker returns (RequestID, Challenge)
//   Phase 2 — Confirm:  endpoint sends signed challenge
//                       broker: if pre-approved or relay → immediately Registered
//                               else Pending (awaits admin approval)
//   Phase 3 — Poll:     endpoint polls with signed (RequestID|poll) nonce
//                       broker returns current state + Result when approved
//
// Address assignment:
//   - All endpoints get domain, group, endpoint_id from the broker
//   - Relays auto-approved, assigned to reserved domain 0, group 0
//   - Pre-approved fingerprints auto-approve to the (domain, group) in PreApprove()
//   - Admin-approved enrollments take (domain, group) from ApproveEnrollment()

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

// Reserved address space for relay infrastructure.
const (
	RelayDomain DomainID = 0
	RelayGroup  GroupID  = 0
)

// Registrar handles endpoint enrollment, reachability, and relay discovery.
type Registrar struct {
	mu sync.RWMutex

	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	// Registered endpoints: domain -> group -> endpointID -> info
	endpoints map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint

	// Pending/completed enrollments: RequestID -> state
	pending map[string]*pendingEnroll

	// Idempotency: fingerprint -> current RequestID
	byFingerprint map[string]string

	// Pre-approval allowlist: fingerprint -> (domain, group)
	preApproved map[string]addrMapping

	// ID allocation hint per domain+group
	nextID map[DomainID]map[GroupID]uint16

	// Reachability: AddrKey -> info
	reachability map[string]*ReachabilityInfo

	tokenTTL time.Duration
}

// pendingEnroll is the broker-side record for an in-progress enrollment.
type pendingEnroll struct {
	RequestID   string
	PublicKey   ed25519.PublicKey
	Fingerprint string
	RoleFlags   uint8
	Challenge   [32]byte
	CreatedAt   time.Time

	State uint8 // StateChallengeIssued / StatePending / StateRegistered / StateDenied

	// Populated once Registered:
	Address EndpointAddr
	Token   string
}

type addrMapping struct {
	Domain DomainID
	Group  GroupID
}

// NewRegistrar creates a registrar with a fresh Ed25519 keypair.
func NewRegistrar(tokenTTL time.Duration) (*Registrar, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate registrar keypair: %w", err)
	}

	return &Registrar{
		publicKey:     pub,
		privateKey:    priv,
		endpoints:     make(map[DomainID]map[GroupID]map[EndpointID]*RegisteredEndpoint),
		pending:       make(map[string]*pendingEnroll),
		byFingerprint: make(map[string]string),
		preApproved:   make(map[string]addrMapping),
		nextID:        make(map[DomainID]map[GroupID]uint16),
		reachability:  make(map[string]*ReachabilityInfo),
		tokenTTL:      tokenTTL,
	}, nil
}

// PublicKey returns the registrar's public key — the trust root.
func (r *Registrar) PublicKey() ed25519.PublicKey {
	return r.publicKey
}

// --- Enrollment: Phase 1 ---

// Enroll starts a new enrollment. Returns a RequestID and challenge.
// Relays must pass empty Fingerprint; client/agent must pass non-empty.
func (r *Registrar) Enroll(req EnrollRequest) (*EnrollResponse, error) {
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
	if role != RoleRelay && req.Fingerprint == "" {
		return nil, errors.New("fingerprint required for client/agent")
	}

	// Idempotent: if fingerprint already has an active enrollment, return it.
	if req.Fingerprint != "" {
		if rid, ok := r.byFingerprint[req.Fingerprint]; ok {
			if existing, ok := r.pending[rid]; ok {
				return &EnrollResponse{
					RequestID: existing.RequestID,
					Challenge: existing.Challenge,
				}, nil
			}
		}
	}

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}

	rid, err := randomRequestID()
	if err != nil {
		return nil, err
	}

	pe := &pendingEnroll{
		RequestID:   rid,
		PublicKey:   ed25519.PublicKey(req.PublicKey),
		Fingerprint: req.Fingerprint,
		RoleFlags:   req.RoleFlags,
		Challenge:   nonce,
		CreatedAt:   time.Now(),
		State:       StateChallengeIssued,
	}

	r.pending[rid] = pe
	if req.Fingerprint != "" {
		r.byFingerprint[req.Fingerprint] = rid
	}

	return &EnrollResponse{RequestID: rid, Challenge: nonce}, nil
}

// --- Enrollment: Phase 2 ---

// ConfirmEnrollment verifies the challenge signature and transitions to:
//   - Registered if relay, pre-approved fingerprint, or fingerprint previously registered
//   - Pending otherwise (admin must call ApproveEnrollment)
func (r *Registrar) ConfirmEnrollment(c EnrollConfirm) (*EnrollStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pe, ok := r.pending[c.RequestID]
	if !ok {
		return nil, errors.New("unknown request ID")
	}
	if pe.State != StateChallengeIssued {
		// Already confirmed; return current state (idempotent)
		return r.statusFor(pe), nil
	}

	if !ed25519.Verify(pe.PublicKey, pe.Challenge[:], c.Signature) {
		delete(r.pending, c.RequestID)
		if pe.Fingerprint != "" {
			delete(r.byFingerprint, pe.Fingerprint)
		}
		return nil, errors.New("challenge verification failed")
	}

	// Decide auto-approval path
	role := RoleOf(pe.RoleFlags)
	if role == RoleRelay {
		// Relays are infrastructure: auto-approved to reserved domain/group
		if err := r.registerApproved(pe, RelayDomain, RelayGroup); err != nil {
			return nil, err
		}
		return r.statusFor(pe), nil
	}

	if mapping, ok := r.preApproved[pe.Fingerprint]; ok {
		if err := r.registerApproved(pe, mapping.Domain, mapping.Group); err != nil {
			return nil, err
		}
		return r.statusFor(pe), nil
	}

	// No auto-approval: wait for admin
	pe.State = StatePending
	return r.statusFor(pe), nil
}

// --- Enrollment: Phase 3 ---

// PollEnrollment returns the current state of an enrollment.
// Signature must be Ed25519 over (RequestID || "|poll") to prove the
// poller is the legitimate enrolling endpoint.
func (r *Registrar) PollEnrollment(requestID string, signature []byte) (*EnrollStatus, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	pe, ok := r.pending[requestID]
	if !ok {
		return nil, errors.New("unknown request ID")
	}

	msg := []byte(requestID + "|poll")
	if !ed25519.Verify(pe.PublicKey, msg, signature) {
		return nil, errors.New("poll signature invalid")
	}

	return r.statusFor(pe), nil
}

// --- Admin API ---

// PreApprove allows a fingerprint to auto-enroll into (domain, group).
// Call this before the endpoint enrolls for truly zero-touch deployment.
func (r *Registrar) PreApprove(fingerprint string, domain DomainID, group GroupID) error {
	if fingerprint == "" {
		return errors.New("empty fingerprint")
	}
	if domain == RelayDomain {
		return errors.New("domain 0 reserved for relays")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preApproved[fingerprint] = addrMapping{Domain: domain, Group: group}
	return nil
}

// ApproveEnrollment approves a specific pending enrollment into (domain, group).
func (r *Registrar) ApproveEnrollment(requestID string, domain DomainID, group GroupID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pe, ok := r.pending[requestID]
	if !ok {
		return errors.New("unknown request ID")
	}
	if pe.State != StatePending {
		return fmt.Errorf("cannot approve: state is %s", StateName(pe.State))
	}
	if domain == RelayDomain {
		return errors.New("domain 0 reserved for relays")
	}
	return r.registerApproved(pe, domain, group)
}

// DenyEnrollment rejects a pending enrollment.
func (r *Registrar) DenyEnrollment(requestID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	pe, ok := r.pending[requestID]
	if !ok {
		return errors.New("unknown request ID")
	}
	if pe.State != StatePending && pe.State != StateChallengeIssued {
		return fmt.Errorf("cannot deny: state is %s", StateName(pe.State))
	}
	pe.State = StateDenied
	return nil
}

// ListPending returns all enrollments awaiting admin decision.
func (r *Registrar) ListPending() []PendingEnrollment {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []PendingEnrollment
	for _, pe := range r.pending {
		if pe.State == StatePending {
			out = append(out, PendingEnrollment{
				RequestID:   pe.RequestID,
				Fingerprint: pe.Fingerprint,
				RoleFlags:   pe.RoleFlags,
				PublicKey:   []byte(pe.PublicKey),
				CreatedAt:   pe.CreatedAt,
				State:       pe.State,
			})
		}
	}
	return out
}

// --- Activation / Revocation ---

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

// ObserveEndpoint records an endpoint's public address as seen by the broker.
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
func (r *Registrar) RequestPunch(clientAddr, agentAddr EndpointAddr, clientToken string) (*PunchRequest, *PunchRequest, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	claims, err := VerifyToken(clientToken, r.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("punch denied: %w", err)
	}
	if claims.EndpointID != clientAddr.Endpoint ||
		claims.Domain != clientAddr.Domain ||
		claims.Group != clientAddr.Group {
		return nil, nil, errors.New("punch denied: token does not match client address")
	}

	clientInfo, ok := r.reachability[clientAddr.AddrKey()]
	if !ok || clientInfo.Direct == nil {
		return nil, nil, errors.New("punch denied: client has no observed address")
	}
	agentInfo, ok := r.reachability[agentAddr.AddrKey()]
	if !ok || agentInfo.Direct == nil {
		return nil, nil, errors.New("punch denied: agent has no observed address")
	}

	clientEp := r.getEndpoint(clientAddr)
	agentEp := r.getEndpoint(agentAddr)
	if clientEp == nil || clientEp.State != StateActive {
		return nil, nil, errors.New("punch denied: client not active")
	}
	if agentEp == nil || agentEp.State != StateActive {
		return nil, nil, errors.New("punch denied: agent not active")
	}

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

// ClearReachability removes reachability records.
func (r *Registrar) ClearReachability(addr EndpointAddr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.reachability, addr.AddrKey())
}

// --- Info queries ---

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

// ListRelays returns all active relay endpoints. Relays live in the
// reserved RelayDomain/RelayGroup and serve all business domains.
func (r *Registrar) ListRelays(_ DomainID) []RelayInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []RelayInfo
	if dg, ok := r.endpoints[RelayDomain]; ok {
		if ge, ok := dg[RelayGroup]; ok {
			for _, ep := range ge {
				if ep.State == StateActive {
					out = append(out, RelayInfo{Addr: ep.Addr})
				}
			}
		}
	}
	return out
}

// FullRegistrationInfo builds the complete info bundle for an active endpoint.
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
		Relays:       r.listRelaysLocked(),
	}, nil
}

// --- internal helpers ---

func (r *Registrar) statusFor(pe *pendingEnroll) *EnrollStatus {
	s := &EnrollStatus{State: pe.State}
	if pe.State == StateRegistered {
		s.Result = &EnrollResult{Address: pe.Address, Token: pe.Token}
	}
	return s
}

// registerApproved finalises a pending enrollment: allocates ID, issues
// token, stores endpoint, updates pending record. Caller holds write lock.
func (r *Registrar) registerApproved(pe *pendingEnroll, domain DomainID, group GroupID) error {
	// Idempotent: if this fingerprint is already registered, reuse existing endpoint
	if existingAddr, existingEp := r.findByFingerprint(pe.Fingerprint); existingEp != nil {
		pe.Address = existingAddr
		pe.Token = existingEp.Token
		pe.State = StateRegistered
		return nil
	}

	if r.countEndpoints(domain, group) >= maxEndpointsPerGroup {
		return fmt.Errorf("group capacity reached (max %d)", maxEndpointsPerGroup)
	}

	id, err := r.allocateID(domain, group)
	if err != nil {
		return fmt.Errorf("allocate ID: %w", err)
	}

	addr := EndpointAddr{
		Domain:    domain,
		Group:     group,
		Endpoint:  id,
		RoleFlags: pe.RoleFlags,
	}

	now := time.Now()
	claims := &TokenClaims{
		EndpointID:  id,
		Domain:      domain,
		Group:       group,
		RoleFlags:   pe.RoleFlags,
		PublicKey:   []byte(pe.PublicKey),
		Fingerprint: pe.Fingerprint,
		IssuedAt:    now,
		ExpiresAt:   now.Add(r.tokenTTL),
		Issuer:      "gole-swarm-registrar",
	}

	token, err := SignToken(claims, r.privateKey)
	if err != nil {
		return fmt.Errorf("sign token: %w", err)
	}

	r.storeEndpoint(addr, pe.PublicKey, token, pe.Fingerprint)
	pe.Address = addr
	pe.Token = token
	pe.State = StateRegistered
	return nil
}

func (r *Registrar) findByFingerprint(fp string) (EndpointAddr, *RegisteredEndpoint) {
	if fp == "" {
		return EndpointAddr{}, nil
	}
	for _, groups := range r.endpoints {
		for _, eps := range groups {
			for _, ep := range eps {
				if ep.Fingerprint == fp && ep.State != StateRevoked {
					return ep.Addr, ep
				}
			}
		}
	}
	return EndpointAddr{}, nil
}

func (r *Registrar) listRelaysLocked() []RelayInfo {
	var out []RelayInfo
	if dg, ok := r.endpoints[RelayDomain]; ok {
		if ge, ok := dg[RelayGroup]; ok {
			for _, ep := range ge {
				if ep.State == StateActive {
					out = append(out, RelayInfo{Addr: ep.Addr})
				}
			}
		}
	}
	return out
}

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

func (r *Registrar) countEndpoints(domain DomainID, group GroupID) int {
	if dg, ok := r.endpoints[domain]; ok {
		if ge, ok := dg[group]; ok {
			return len(ge)
		}
	}
	return 0
}

func (r *Registrar) storeEndpoint(addr EndpointAddr, pk ed25519.PublicKey, token, fingerprint string) {
	if _, ok := r.endpoints[addr.Domain]; !ok {
		r.endpoints[addr.Domain] = make(map[GroupID]map[EndpointID]*RegisteredEndpoint)
	}
	if _, ok := r.endpoints[addr.Domain][addr.Group]; !ok {
		r.endpoints[addr.Domain][addr.Group] = make(map[EndpointID]*RegisteredEndpoint)
	}
	r.endpoints[addr.Domain][addr.Group][addr.Endpoint] = &RegisteredEndpoint{
		Addr:        addr,
		PublicKey:   pk,
		State:       StateRegistered,
		Token:       token,
		Fingerprint: fingerprint,
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

func (r *Registrar) getOrCreateReachability(addr EndpointAddr) *ReachabilityInfo {
	key := addr.AddrKey()
	info, ok := r.reachability[key]
	if !ok {
		info = &ReachabilityInfo{Addr: addr}
		r.reachability[key] = info
	}
	return info
}

// Quiet unused-import warnings for helpers that moved.
var _ = bytes.Equal
var _ = base64.RawURLEncoding

func randomRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random request ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
