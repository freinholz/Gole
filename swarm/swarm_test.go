package swarm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

const testTokenTTL = 1 * time.Hour

func setupRegistrar(t *testing.T) *Registrar {
	t.Helper()
	reg, err := NewRegistrar(testTokenTTL)
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	return reg
}

func registerAndActivate(t *testing.T, reg *Registrar, domain DomainID, group GroupID, roleFlags uint8) *Endpoint {
	t.Helper()
	ep, err := NewEndpoint()
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if err := ep.Register(reg, domain, group, roleFlags); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ep.Activate(reg); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return ep
}

// ============================================================
// Registration Tests
// ============================================================

func TestRegistrationHappyPath(t *testing.T) {
	reg := setupRegistrar(t)

	ep, _ := NewEndpoint()
	if ep.State() != StateUnregistered {
		t.Fatalf("initial state: got %s", StateName(ep.State()))
	}

	if err := ep.Register(reg, 1, 1, RoleClient); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if ep.State() != StateRegistered {
		t.Fatalf("after register: got %s", StateName(ep.State()))
	}
	if ep.Addr().Endpoint == 0 {
		t.Fatal("ID must be non-zero")
	}
	if ep.Token() == "" {
		t.Fatal("token must not be empty")
	}

	if err := ep.Activate(reg); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if ep.State() != StateActive {
		t.Fatalf("after activate: got %s", StateName(ep.State()))
	}
	if ep.RegistrarKey() == nil {
		t.Fatal("registrar key must be set after activation")
	}
}

func TestRegistrationUniqueIDs(t *testing.T) {
	reg := setupRegistrar(t)
	seen := make(map[EndpointID]bool)

	for i := 0; i < 20; i++ {
		ep := registerAndActivate(t, reg, 1, 1, RoleAgent)
		if seen[ep.Addr().Endpoint] {
			t.Fatalf("duplicate ID: %d", ep.Addr().Endpoint)
		}
		seen[ep.Addr().Endpoint] = true
	}
}

func TestRegistrationDuplicateKey(t *testing.T) {
	reg := setupRegistrar(t)

	ep, _ := NewEndpoint()
	_ = ep.Register(reg, 1, 1, RoleClient)

	_, err := reg.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(), Domain: 1, Group: 1, RoleFlags: RoleClient,
	})
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestRegistrationInvalidRole(t *testing.T) {
	reg := setupRegistrar(t)
	ep, _ := NewEndpoint()
	err := ep.Register(reg, 1, 1, 0x00) // invalid role
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestRelayRegistration(t *testing.T) {
	reg := setupRegistrar(t)

	relay := registerAndActivate(t, reg, 1, 1, RoleRelay)
	if relay.Addr().Role() != RoleRelay {
		t.Fatalf("expected relay role, got %s", RoleName(relay.Addr().Role()))
	}

	// Relay should appear in ListRelays
	relays := reg.ListRelays(1)
	if len(relays) != 1 {
		t.Fatalf("expected 1 relay, got %d", len(relays))
	}
	if relays[0].Addr.Endpoint != relay.Addr().Endpoint {
		t.Fatal("relay ID mismatch")
	}
}

func TestFullRegistrationInfo(t *testing.T) {
	reg := setupRegistrar(t)

	// Register a relay first
	registerAndActivate(t, reg, 1, 1, RoleRelay)

	// Register a client
	client := registerAndActivate(t, reg, 1, 1, RoleClient)

	if len(client.Relays()) != 1 {
		t.Fatalf("expected 1 relay in info, got %d", len(client.Relays()))
	}
	if !bytes.Equal(client.RegistrarKey(), reg.PublicKey()) {
		t.Fatal("registrar key mismatch")
	}
}

// ============================================================
// Challenge-Response Security
// ============================================================

func TestChallengeResponseWrongKey(t *testing.T) {
	reg := setupRegistrar(t)

	ep, _ := NewEndpoint()
	ch, _ := reg.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(), Domain: 1, Group: 1, RoleFlags: RoleClient,
	})

	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	badSig := ed25519.Sign(attackerPriv, ch.Nonce[:])

	_, err := reg.RegisterResponse(ep.PublicKey(), ChallengeResponse{Signature: badSig})
	if err == nil {
		t.Fatal("expected challenge failure with wrong key")
	}
}

func TestChallengeResponseGarbage(t *testing.T) {
	reg := setupRegistrar(t)
	ep, _ := NewEndpoint()
	_, _ = reg.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(), Domain: 1, Group: 1, RoleFlags: RoleClient,
	})

	_, err := reg.RegisterResponse(ep.PublicKey(), ChallengeResponse{
		Signature: make([]byte, ed25519.SignatureSize),
	})
	if err == nil {
		t.Fatal("expected failure with garbage signature")
	}
}

// ============================================================
// PASETO Token Tests
// ============================================================

func TestPASETOSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &TokenClaims{
		EndpointID: 42, Domain: 1, Group: 2, RoleFlags: RoleClient,
		PublicKey: pub, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Issuer: "test",
	}
	token, err := SignToken(claims, priv)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	v, err := VerifyToken(token, pub)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if v.EndpointID != 42 || v.Domain != 1 || v.Group != 2 {
		t.Fatalf("claims mismatch: %+v", v)
	}
}

func TestPASETOWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	claims := &TokenClaims{
		EndpointID: 1, Domain: 1, Group: 1, RoleFlags: RoleClient,
		PublicKey: make([]byte, 32), IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), Issuer: "test",
	}
	token, _ := SignToken(claims, priv)
	_, err := VerifyToken(token, wrongPub)
	if err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestPASETOExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &TokenClaims{
		EndpointID: 1, Domain: 1, Group: 1, RoleFlags: RoleClient,
		PublicKey: make([]byte, 32), IssuedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), Issuer: "test",
	}
	token, _ := SignToken(claims, priv)
	_, err := VerifyToken(token, pub)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestPASETOTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	claims := &TokenClaims{
		EndpointID: 1, Domain: 1, Group: 1, RoleFlags: RoleClient,
		PublicKey: make([]byte, 32), IssuedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), Issuer: "test",
	}
	token, _ := SignToken(claims, priv)
	tampered := []byte(token)
	if len(tampered) > 15 {
		tampered[15] ^= 0x01
	}
	_, err := VerifyToken(string(tampered), pub)
	if err == nil {
		t.Fatal("expected failure for tampered token")
	}
}

// ============================================================
// Flow Validation (Controller)
// ============================================================

func TestFlowClientToAgent(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	if err := ctrl.VerifyMessage(msg); err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
}

func TestFlowAgentToClientBlocked(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	msg, _ := agent.PrepareMessage(*client.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected denial: agent cannot initiate")
	}
}

func TestFlowClientToClientBlocked(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	c1 := registerAndActivate(t, reg, 1, 1, RoleClient)
	c2 := registerAndActivate(t, reg, 1, 1, RoleClient)

	msg, _ := c1.PrepareMessage(*c2.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected denial: client-to-client")
	}
}

func TestFlowCrossDomainBlocked(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 2, 1, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected cross-domain denial")
	}
}

func TestFlowCrossGroupBlocked(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 2, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected cross-group denial")
	}
}

func TestFlowToRelaySameDomain(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	relay := registerAndActivate(t, reg, 1, 1, RoleRelay)

	// Client -> relay in same domain: allowed
	err := ctrl.ValidateFlow(*client.Addr(), *relay.Addr(), client.Token())
	if err != nil {
		t.Fatalf("expected relay flow allowed: %v", err)
	}
}

func TestFlowToRelayCrossDomainBlocked(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	relay := registerAndActivate(t, reg, 2, 1, RoleRelay)

	err := ctrl.ValidateFlow(*client.Addr(), *relay.Addr(), client.Token())
	if err == nil {
		t.Fatal("expected cross-domain relay denial")
	}
}

// ============================================================
// ID Spoofing Prevention
// ============================================================

func TestIDSpoofingFakeToken(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedClaims := &TokenClaims{
		EndpointID: client.Addr().Endpoint, Domain: 1, Group: 1,
		RoleFlags: RoleClient, PublicKey: client.PublicKey(),
		IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
		Issuer: "gole-swarm-registrar",
	}
	forgedToken, _ := SignToken(forgedClaims, attackerPriv)

	msg := &SwarmMessage{
		From: *client.Addr(), To: *agent.Addr(), Token: forgedToken,
		Payload: []byte("spoofed"), Signature: ed25519.Sign(attackerPriv, []byte("spoofed")),
	}
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected rejection of forged token")
	}
}

func TestIDSpoofingStolenToken(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	msg := &SwarmMessage{
		From: *client.Addr(), To: *agent.Addr(), Token: client.Token(),
		Payload: []byte("spoofed"), Signature: ed25519.Sign(attackerPriv, []byte("spoofed")),
	}
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected rejection: wrong payload signature")
	}
}

func TestIDSpoofingModifiedAddress(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	msg.From.Endpoint = 9999
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected rejection: address mismatch")
	}
}

func TestMessageIntegrity(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("original"))
	msg.Payload = []byte("tampered")
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected rejection: tampered payload")
	}
}

// ============================================================
// Revocation
// ============================================================

func TestRevokedEndpoint(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	_ = reg.RevokeEndpoint(*agent.Addr())

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected denial: destination revoked")
	}
}

// ============================================================
// Multi-Domain / Multi-Group Isolation
// ============================================================

func TestMultiDomainIsolation(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	c1 := registerAndActivate(t, reg, 1, 1, RoleClient)
	a1 := registerAndActivate(t, reg, 1, 1, RoleAgent)
	c2 := registerAndActivate(t, reg, 2, 1, RoleClient)
	a2 := registerAndActivate(t, reg, 2, 1, RoleAgent)

	// Same domain OK
	m1, _ := c1.PrepareMessage(*a1.Addr(), []byte("d1"))
	if err := ctrl.VerifyMessage(m1); err != nil {
		t.Fatalf("same domain: %v", err)
	}
	m2, _ := c2.PrepareMessage(*a2.Addr(), []byte("d2"))
	if err := ctrl.VerifyMessage(m2); err != nil {
		t.Fatalf("same domain: %v", err)
	}

	// Cross domain blocked
	m3, _ := c1.PrepareMessage(*a2.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(m3); err == nil {
		t.Fatal("expected cross-domain denial")
	}
}

func TestMultiGroupIsolation(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	c1 := registerAndActivate(t, reg, 1, 1, RoleClient)
	a1 := registerAndActivate(t, reg, 1, 1, RoleAgent)
	c2 := registerAndActivate(t, reg, 1, 2, RoleClient)
	a2 := registerAndActivate(t, reg, 1, 2, RoleAgent)

	m1, _ := c1.PrepareMessage(*a1.Addr(), []byte("g1"))
	if err := ctrl.VerifyMessage(m1); err != nil {
		t.Fatalf("same group: %v", err)
	}
	m2, _ := c2.PrepareMessage(*a2.Addr(), []byte("g2"))
	if err := ctrl.VerifyMessage(m2); err != nil {
		t.Fatalf("same group: %v", err)
	}

	m3, _ := c1.PrepareMessage(*a2.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(m3); err == nil {
		t.Fatal("expected cross-group denial")
	}
}

// ============================================================
// Policies
// ============================================================

func TestDenyEndpointPolicy(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	ctrl.AddPolicy(&DenyEndpointPolicy{Blocked: []EndpointAddr{*client.Addr()}})

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected policy denial")
	}
}

func TestAllowListPolicy(t *testing.T) {
	reg := setupRegistrar(t)
	ctrl := NewController(reg)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	// Only allow domain 2 flows
	ctrl.AddPolicy(&AllowListPolicy{
		Rules: []FlowRule{{FromDomain: 2, FromGroup: 1, FromRole: RoleClient,
			ToDomain: 2, ToGroup: 1, ToRole: RoleAgent}},
	})

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("x"))
	if err := ctrl.VerifyMessage(msg); err == nil {
		t.Fatal("expected allow-list denial")
	}
}

// ============================================================
// RoleFlags
// ============================================================

func TestRoleFlags(t *testing.T) {
	flags := MakeRoleFlags(RoleClient, FlagRelayEligible|FlagPriority)
	if RoleOf(flags) != RoleClient {
		t.Fatalf("role: got %d", RoleOf(flags))
	}
	if !HasFlag(flags, FlagRelayEligible) {
		t.Fatal("expected RelayEligible flag")
	}
	if !HasFlag(flags, FlagPriority) {
		t.Fatal("expected Priority flag")
	}
	if HasFlag(flags, 0x10) {
		t.Fatal("unexpected flag")
	}
}

func TestEndpointAddrString(t *testing.T) {
	a := EndpointAddr{Domain: 1, Group: 2, Endpoint: 300, RoleFlags: RoleClient}
	if got := a.String(); got != "client@1.2.300" {
		t.Fatalf("got %q", got)
	}
	a.RoleFlags = RoleAgent
	if got := a.String(); got != "agent@1.2.300" {
		t.Fatalf("got %q", got)
	}
	a.RoleFlags = RoleRelay
	if got := a.String(); got != "relay@1.2.300" {
		t.Fatalf("got %q", got)
	}
}

// ============================================================
// Transport Mode Selection (Discovery)
// ============================================================

func TestSelectTransportModeRelay(t *testing.T) {
	cfg := TransportConfig{Mode: ModeRelay}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 20 * time.Millisecond},
		{Addr: EndpointAddr{Endpoint: 11}, Latency: 5 * time.Millisecond},
	}
	d := SelectTransport(cfg, 1*time.Millisecond, relays)
	if !d.UseRelay {
		t.Fatal("relay mode must use relay")
	}
	// Should pick best (lowest latency)
	if d.RelayAddr.Endpoint != 11 {
		t.Fatalf("expected best relay 11, got %d", d.RelayAddr.Endpoint)
	}
}

func TestSelectTransportPinnedSpecific(t *testing.T) {
	pinned := EndpointAddr{Endpoint: 10}
	cfg := TransportConfig{Mode: ModePinned, PinnedRelay: &pinned}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 50 * time.Millisecond},
		{Addr: EndpointAddr{Endpoint: 11}, Latency: 5 * time.Millisecond}, // better but not pinned
	}
	d := SelectTransport(cfg, 1*time.Millisecond, relays)
	if !d.UseRelay {
		t.Fatal("pinned mode must use relay")
	}
	if d.RelayAddr.Endpoint != 10 {
		t.Fatalf("pinned mode must use specific relay 10, got %d", d.RelayAddr.Endpoint)
	}
}

func TestSelectTransportPinnedMissing(t *testing.T) {
	pinned := EndpointAddr{Endpoint: 99}
	cfg := TransportConfig{Mode: ModePinned, PinnedRelay: &pinned}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 5 * time.Millisecond},
	}
	d := SelectTransport(cfg, 1*time.Millisecond, relays)
	if !d.UseRelay {
		t.Fatal("pinned mode must use relay even if not in list")
	}
	if d.RelayAddr.Endpoint != 99 {
		t.Fatalf("should return pinned relay 99, got %d", d.RelayAddr.Endpoint)
	}
	if d.RelayLatency != 0 {
		t.Fatal("missing relay should have 0 latency")
	}
}

func TestSelectTransportPinnedNil(t *testing.T) {
	cfg := TransportConfig{Mode: ModePinned} // PinnedRelay is nil
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 5 * time.Millisecond},
	}
	d := SelectTransport(cfg, 1*time.Millisecond, relays)
	if !d.UseRelay {
		t.Fatal("pinned nil fallback must use relay")
	}
	// Falls back to best relay
	if d.RelayAddr.Endpoint != 10 {
		t.Fatalf("expected fallback to best relay 10, got %d", d.RelayAddr.Endpoint)
	}
}

func TestSelectTransportPeer(t *testing.T) {
	cfg := TransportConfig{Mode: ModePeer}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 5 * time.Millisecond},
	}
	d := SelectTransport(cfg, 50*time.Millisecond, relays)
	if d.UseRelay {
		t.Fatal("peer mode must not use relay")
	}
}

func TestSelectTransportDynamicPrefersP2P(t *testing.T) {
	cfg := TransportConfig{Mode: ModeDynamic, Threshold: 50 * time.Millisecond}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 30 * time.Millisecond},
	}
	// P2P (20ms) is better than relay (30ms), within threshold
	d := SelectTransport(cfg, 20*time.Millisecond, relays)
	if d.UseRelay {
		t.Fatal("dynamic: P2P is better, should stay P2P")
	}
}

func TestSelectTransportDynamicSwitchesToRelay(t *testing.T) {
	cfg := TransportConfig{Mode: ModeDynamic, Threshold: 10 * time.Millisecond}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 20 * time.Millisecond},
	}
	// P2P (100ms) is much worse than relay (20ms) + threshold (10ms)
	d := SelectTransport(cfg, 100*time.Millisecond, relays)
	if !d.UseRelay {
		t.Fatal("dynamic: P2P is degraded, should switch to relay")
	}
}

func TestSelectTransportDynamicNoRelay(t *testing.T) {
	cfg := TransportConfig{Mode: ModeDynamic, Threshold: 10 * time.Millisecond}
	d := SelectTransport(cfg, 100*time.Millisecond, nil)
	if d.UseRelay {
		t.Fatal("no relays available, must use P2P")
	}
}

func TestSelectTransportDynamicNoP2P(t *testing.T) {
	cfg := TransportConfig{Mode: ModeDynamic, Threshold: 10 * time.Millisecond}
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 10}, Latency: 20 * time.Millisecond},
	}
	// P2P latency 0 = not available
	d := SelectTransport(cfg, 0, relays)
	if !d.UseRelay {
		t.Fatal("P2P unavailable, should use relay")
	}
}

func TestRankRelays(t *testing.T) {
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 1}, Latency: 0}, // unprobed
		{Addr: EndpointAddr{Endpoint: 2}, Latency: 50 * time.Millisecond},
		{Addr: EndpointAddr{Endpoint: 3}, Latency: 10 * time.Millisecond},
	}
	ranked := RankRelays(relays)
	if ranked[0].Addr.Endpoint != 3 {
		t.Fatalf("best relay should be endpoint 3, got %d", ranked[0].Addr.Endpoint)
	}
	if ranked[1].Addr.Endpoint != 2 {
		t.Fatalf("second should be endpoint 2, got %d", ranked[1].Addr.Endpoint)
	}
	if ranked[2].Addr.Endpoint != 1 {
		t.Fatalf("unprobed should be last, got %d", ranked[2].Addr.Endpoint)
	}
}

// ============================================================
// Transport Monitor
// ============================================================

// mockProber returns fixed latency values, safe for concurrent use.
type mockProber struct {
	mu         sync.Mutex
	peerLat    time.Duration
	relayLat   time.Duration
	probeCount int
}

func (m *mockProber) ProbePeer(_ EndpointAddr) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probeCount++
	return m.peerLat, nil
}

func (m *mockProber) ProbeRelay(_ EndpointAddr) (time.Duration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probeCount++
	return m.relayLat, nil
}

func (m *mockProber) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.probeCount
}

func TestTransportMonitorDynamic(t *testing.T) {
	prober := &mockProber{peerLat: 10 * time.Millisecond, relayLat: 30 * time.Millisecond}
	cfg := TransportConfig{
		Mode:          ModeDynamic,
		ProbeInterval: 50 * time.Millisecond, // fast for testing
		Threshold:     10 * time.Millisecond,
	}
	relays := []RelayInfo{{Addr: EndpointAddr{Endpoint: 10}}}
	peer := EndpointAddr{Endpoint: 20}

	changes := make(chan TransportDecision, 10)
	mon := NewTransportMonitor(cfg, prober, peer, relays, func(d TransportDecision) {
		changes <- d
	})
	mon.Start()

	// Wait for initial probe
	time.Sleep(80 * time.Millisecond)

	// P2P (10ms) is better → should not use relay
	d := mon.Current()
	if d.UseRelay {
		t.Fatal("P2P is better, should not use relay")
	}

	// Degrade P2P
	prober.mu.Lock()
	prober.peerLat = 200 * time.Millisecond
	prober.mu.Unlock()

	// Wait for re-probe
	time.Sleep(120 * time.Millisecond)

	d = mon.Current()
	if !d.UseRelay {
		t.Fatal("P2P degraded, should switch to relay")
	}

	mon.Stop()

	if prober.count() < 4 {
		t.Fatalf("expected at least 4 probes, got %d", prober.count())
	}
}

// ============================================================
// Endpoint Discovery Integration
// ============================================================

func TestEndpointDiscover(t *testing.T) {
	reg := setupRegistrar(t)
	registerAndActivate(t, reg, 1, 1, RoleRelay)

	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	client.SetTransportConfig(TransportConfig{
		Mode: ModeDynamic, Threshold: 10 * time.Millisecond,
	})

	prober := &mockProber{peerLat: 15 * time.Millisecond, relayLat: 20 * time.Millisecond}
	peer := EndpointAddr{Domain: 1, Group: 1, Endpoint: 99}

	d, err := client.Discover(prober, peer, nil) // nil registrar = no broker lookup
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	// P2P (15ms) vs relay (20ms) + threshold (10ms) = 30ms → P2P wins
	if d.UseRelay {
		t.Fatal("expected P2P")
	}

	client.StopMonitor()
}

// ============================================================
// Relay Server (wire protocol, net.Pipe)
// ============================================================

func TestRelayAuthAndForward(t *testing.T) {
	reg := setupRegistrar(t)

	ep1 := registerAndActivate(t, reg, 1, 1, RoleClient)
	ep2 := registerAndActivate(t, reg, 1, 1, RoleAgent)

	relay := NewRelayServer(reg.PublicKey())

	// Create pipe pairs: endpoint <-> relay
	c1Client, c1Relay := net.Pipe()
	c2Client, c2Relay := net.Pipe()

	var wg sync.WaitGroup

	// Run relay for both connections
	wg.Add(2)
	go func() { defer wg.Done(); relay.HandleConn(c1Relay) }()
	go func() { defer wg.Done(); relay.HandleConn(c2Relay) }()

	// Authenticate both endpoints
	errCh := make(chan error, 4)

	go func() {
		errCh <- WriteAuthFrame(c1Client, ep1.Token())
	}()
	go func() {
		errCh <- WriteAuthFrame(c2Client, ep2.Token())
	}()

	// Read auth responses
	go func() {
		hdr, _, err := ReadRelayFrame(c1Client)
		if err != nil {
			errCh <- err
			return
		}
		if hdr.Type != FrameAuthOK {
			errCh <- fmt.Errorf("ep1: expected AuthOK, got 0x%02x", hdr.Type)
			return
		}
		errCh <- nil
	}()
	go func() {
		hdr, _, err := ReadRelayFrame(c2Client)
		if err != nil {
			errCh <- err
			return
		}
		if hdr.Type != FrameAuthOK {
			errCh <- fmt.Errorf("ep2: expected AuthOK, got 0x%02x", hdr.Type)
			return
		}
		errCh <- nil
	}()

	for i := 0; i < 4; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("auth: %v", err)
		}
	}

	// Wait briefly for both sessions to register
	time.Sleep(20 * time.Millisecond)

	if sc := relay.SessionCount(); sc != 2 {
		t.Fatalf("expected 2 sessions, got %d", sc)
	}

	// ep1 sends data to ep2 via relay
	payload := []byte("hello via relay")
	go func() {
		WriteDataFrame(c1Client, *ep2.Addr(), payload)
	}()

	hdr, data, err := ReadRelayFrame(c2Client)
	if err != nil {
		t.Fatalf("read forwarded: %v", err)
	}
	if hdr.Type != FrameData {
		t.Fatalf("expected Data frame, got 0x%02x", hdr.Type)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("payload mismatch: %q vs %q", data, payload)
	}
	// Header should carry source endpoint info
	if EndpointID(hdr.DstEndpoint) != ep1.Addr().Endpoint {
		t.Fatalf("source endpoint mismatch: %d vs %d", hdr.DstEndpoint, ep1.Addr().Endpoint)
	}

	c1Client.Close()
	c2Client.Close()
	wg.Wait()
}

func TestRelayPingPong(t *testing.T) {
	reg := setupRegistrar(t)
	ep := registerAndActivate(t, reg, 1, 1, RoleClient)

	relay := NewRelayServer(reg.PublicKey())
	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); relay.HandleConn(server) }()

	// Auth
	WriteAuthFrame(client, ep.Token())
	hdr, _, _ := ReadRelayFrame(client)
	if hdr.Type != FrameAuthOK {
		t.Fatalf("expected AuthOK, got 0x%02x", hdr.Type)
	}

	// Ping
	nonce := []byte("testping")
	WritePingFrame(client, nonce)

	hdr, pong, err := ReadRelayFrame(client)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if hdr.Type != FramePong {
		t.Fatalf("expected Pong, got 0x%02x", hdr.Type)
	}
	if !bytes.Equal(pong, nonce) {
		t.Fatalf("pong payload mismatch")
	}

	client.Close()
	wg.Wait()
}

func TestRelayRejectsInvalidToken(t *testing.T) {
	reg := setupRegistrar(t)
	relay := NewRelayServer(reg.PublicKey())

	client, server := net.Pipe()

	done := make(chan error, 1)
	go func() { done <- relay.HandleConn(server) }()

	WriteAuthFrame(client, "v4.public.garbage")
	hdr, _, _ := ReadRelayFrame(client)
	if hdr.Type != FrameAuthFail {
		t.Fatalf("expected AuthFail, got 0x%02x", hdr.Type)
	}

	client.Close()
	<-done
}

func TestRelayNoRoute(t *testing.T) {
	reg := setupRegistrar(t)
	ep := registerAndActivate(t, reg, 1, 1, RoleClient)

	relay := NewRelayServer(reg.PublicKey())
	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); relay.HandleConn(server) }()

	WriteAuthFrame(client, ep.Token())
	ReadRelayFrame(client) // auth OK

	// Send to non-existent destination
	nonExistent := EndpointAddr{Domain: 1, Group: 1, Endpoint: 9999}
	WriteDataFrame(client, nonExistent, []byte("hello"))

	hdr, _, _ := ReadRelayFrame(client)
	if hdr.Type != FrameNoRoute {
		t.Fatalf("expected NoRoute, got 0x%02x", hdr.Type)
	}

	client.Close()
	wg.Wait()
}

// ============================================================
// Reachability
// ============================================================

func TestObserveAndLookupReachability(t *testing.T) {
	reg := setupRegistrar(t)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)
	relayEp := registerAndActivate(t, reg, 1, 1, RoleRelay)

	// Broker observes agent's public address from connection
	err := reg.ObserveEndpoint(*agent.Addr(), "203.0.113.5:48291", "udp")
	if err != nil {
		t.Fatalf("ObserveEndpoint: %v", err)
	}

	// Agent tells broker which relay it connected to
	err = agent.SetRelayRoute(reg, *relayEp.Addr())
	if err != nil {
		t.Fatalf("SetRelayRoute: %v", err)
	}

	info, err := reg.LookupReachability(*agent.Addr())
	if err != nil {
		t.Fatalf("LookupReachability: %v", err)
	}
	if info == nil {
		t.Fatal("expected reachability info")
	}
	if info.Direct == nil || info.Direct.ObservedAddr != "203.0.113.5:48291" {
		t.Fatalf("direct route mismatch: %+v", info.Direct)
	}
	if info.Direct.Proto != "udp" {
		t.Fatalf("proto mismatch: %s", info.Direct.Proto)
	}
	if info.Relay == nil || info.Relay.RelayAddr.Endpoint != relayEp.Addr().Endpoint {
		t.Fatal("relay route mismatch")
	}
	if info.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt should be set")
	}
}

func TestReachabilityNotPublished(t *testing.T) {
	reg := setupRegistrar(t)
	registerAndActivate(t, reg, 1, 1, RoleAgent)

	target := EndpointAddr{Domain: 1, Group: 1, Endpoint: 999}
	info, err := reg.LookupReachability(target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Fatal("expected nil for unpublished endpoint")
	}
}

func TestReachabilityAfterRevoke(t *testing.T) {
	reg := setupRegistrar(t)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	reg.ObserveEndpoint(*agent.Addr(), "1.2.3.4:5000", "tcp")
	reg.RevokeEndpoint(*agent.Addr())

	info, _ := reg.LookupReachability(*agent.Addr())
	if info != nil {
		t.Fatal("expected nil after revocation")
	}
}

func TestRelayRouteTokenValidation(t *testing.T) {
	reg := setupRegistrar(t)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)
	other := registerAndActivate(t, reg, 1, 1, RoleClient)
	relayEp := registerAndActivate(t, reg, 1, 1, RoleRelay)

	// Try to update agent's relay route with other's token
	err := reg.SetRelayRoute(*agent.Addr(), other.Token(), *relayEp.Addr())
	if err == nil {
		t.Fatal("expected rejection: wrong token")
	}
}

func TestEndpointSetRelayRoute(t *testing.T) {
	reg := setupRegistrar(t)
	ep := registerAndActivate(t, reg, 1, 1, RoleClient)
	relayEp := registerAndActivate(t, reg, 1, 1, RoleRelay)

	err := ep.SetRelayRoute(reg, *relayEp.Addr())
	if err != nil {
		t.Fatalf("SetRelayRoute: %v", err)
	}

	info, _ := ep.LookupTarget(reg, *ep.Addr())
	if info == nil || info.Relay == nil {
		t.Fatal("expected relay route")
	}
	if info.Relay.RelayAddr.Endpoint != relayEp.Addr().Endpoint {
		t.Fatal("relay endpoint mismatch")
	}
}

func TestClearReachability(t *testing.T) {
	reg := setupRegistrar(t)
	ep := registerAndActivate(t, reg, 1, 1, RoleAgent)

	reg.ObserveEndpoint(*ep.Addr(), "1.2.3.4:5000", "tcp")
	reg.ClearReachability(*ep.Addr())

	info, _ := reg.LookupReachability(*ep.Addr())
	if info != nil {
		t.Fatal("expected nil after clear")
	}
}

func TestRequestPunch(t *testing.T) {
	reg := setupRegistrar(t)
	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	// Broker observes both endpoints' public addresses
	reg.ObserveEndpoint(*client.Addr(), "198.51.100.10:40000", "udp")
	reg.ObserveEndpoint(*agent.Addr(), "203.0.113.20:50000", "udp")

	// Client requests P2P rendezvous
	forClient, forAgent, err := reg.RequestPunch(*client.Addr(), *agent.Addr(), client.Token())
	if err != nil {
		t.Fatalf("RequestPunch: %v", err)
	}

	// Client gets agent's address
	if forClient.ObservedAddr != "203.0.113.20:50000" {
		t.Fatalf("client should get agent's addr, got %s", forClient.ObservedAddr)
	}
	if forClient.PeerAddr.Endpoint != agent.Addr().Endpoint {
		t.Fatal("client peer addr mismatch")
	}

	// Agent gets client's address
	if forAgent.ObservedAddr != "198.51.100.10:40000" {
		t.Fatalf("agent should get client's addr, got %s", forAgent.ObservedAddr)
	}
	if forAgent.PeerAddr.Endpoint != client.Addr().Endpoint {
		t.Fatal("agent peer addr mismatch")
	}
}

func TestRequestPunchNoObservedAddr(t *testing.T) {
	reg := setupRegistrar(t)
	client := registerAndActivate(t, reg, 1, 1, RoleClient)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)

	// Only client has observed address, agent doesn't
	reg.ObserveEndpoint(*client.Addr(), "1.2.3.4:5000", "tcp")

	_, _, err := reg.RequestPunch(*client.Addr(), *agent.Addr(), client.Token())
	if err == nil {
		t.Fatal("expected error: agent has no observed address")
	}
}

// ============================================================
// Discover with Broker Lookup
// ============================================================

func TestDiscoverWithBrokerLookup(t *testing.T) {
	reg := setupRegistrar(t)

	relayEp := registerAndActivate(t, reg, 1, 1, RoleRelay)
	agent := registerAndActivate(t, reg, 1, 1, RoleAgent)
	client := registerAndActivate(t, reg, 1, 1, RoleClient)

	// Agent tells broker it's connected to relayEp
	agent.SetRelayRoute(reg, *relayEp.Addr())

	client.SetTransportConfig(TransportConfig{Mode: ModeRelay})

	prober := &mockProber{peerLat: 10 * time.Millisecond, relayLat: 15 * time.Millisecond}

	d, err := client.Discover(prober, *agent.Addr(), reg)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !d.UseRelay {
		t.Fatal("ModeRelay should use relay")
	}
	// The agent's relay should have been prioritized
	if d.RelayAddr == nil {
		t.Fatal("expected relay addr")
	}
}

// ============================================================
// Relay Router Interface
// ============================================================

func TestRelayLocalRouter(t *testing.T) {
	reg := setupRegistrar(t)
	ep1 := registerAndActivate(t, reg, 1, 1, RoleClient)
	ep2 := registerAndActivate(t, reg, 1, 1, RoleAgent)

	relay := NewRelayServer(reg.PublicKey())

	c1Client, c1Relay := net.Pipe()
	c2Client, c2Relay := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); relay.HandleConn(c1Relay) }()
	go func() { defer wg.Done(); relay.HandleConn(c2Relay) }()

	// Auth both
	WriteAuthFrame(c1Client, ep1.Token())
	WriteAuthFrame(c2Client, ep2.Token())
	ReadRelayFrame(c1Client)
	ReadRelayFrame(c2Client)

	// Send through LocalRouter
	go WriteDataFrame(c1Client, *ep2.Addr(), []byte("routed"))
	hdr, data, err := ReadRelayFrame(c2Client)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if hdr.Type != FrameData || !bytes.Equal(data, []byte("routed")) {
		t.Fatal("LocalRouter forwarding failed")
	}

	c1Client.Close()
	c2Client.Close()
	wg.Wait()
}

func TestRelaySetCustomRouter(t *testing.T) {
	reg := setupRegistrar(t)
	relay := NewRelayServer(reg.PublicKey())

	// Set MeshRouter (currently same behavior as LocalRouter)
	mesh := NewMeshRouter(relay)
	relay.SetRouter(mesh)

	// Verify it's set by running a basic test
	ep := registerAndActivate(t, reg, 1, 1, RoleClient)
	client, server := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); relay.HandleConn(server) }()

	WriteAuthFrame(client, ep.Token())
	hdr, _, _ := ReadRelayFrame(client)
	if hdr.Type != FrameAuthOK {
		t.Fatalf("expected AuthOK, got 0x%02x", hdr.Type)
	}

	// Send to non-existent → MeshRouter falls through to NoRoute
	WriteDataFrame(client, EndpointAddr{Endpoint: 9999}, []byte("test"))
	hdr, _, _ = ReadRelayFrame(client)
	if hdr.Type != FrameNoRoute {
		t.Fatalf("expected NoRoute from MeshRouter, got 0x%02x", hdr.Type)
	}

	client.Close()
	wg.Wait()
}

// ============================================================
// PrioritizeRelay
// ============================================================

func TestPrioritizeRelay(t *testing.T) {
	relays := []RelayInfo{
		{Addr: EndpointAddr{Endpoint: 1}, Latency: 10 * time.Millisecond},
		{Addr: EndpointAddr{Endpoint: 2}, Latency: 20 * time.Millisecond},
	}

	// Prioritize existing relay
	result := PrioritizeRelay(relays, EndpointAddr{Endpoint: 2})
	if result[0].Addr.Endpoint != 2 {
		t.Fatalf("expected endpoint 2 first, got %d", result[0].Addr.Endpoint)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 relays, got %d", len(result))
	}

	// Prioritize new relay not in list
	result = PrioritizeRelay(relays, EndpointAddr{Endpoint: 99})
	if result[0].Addr.Endpoint != 99 {
		t.Fatalf("expected endpoint 99 first, got %d", result[0].Addr.Endpoint)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 relays, got %d", len(result))
	}
}

// ============================================================
// PAE
// ============================================================

func TestPAEDistinct(t *testing.T) {
	a := pae([]byte("a"), []byte("bc"))
	b := pae([]byte("ab"), []byte("c"))
	if bytes.Equal(a, b) {
		t.Fatal("PAE must distinguish different splits")
	}
}

// ============================================================
// Config Loading
// ============================================================

func TestLoadClientConfig(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/client.json")
	if err != nil {
		t.Fatalf("LoadEndpointConfig: %v", err)
	}

	if cfg.Role != "client" {
		t.Fatalf("role: got %q", cfg.Role)
	}
	if cfg.Domain != 1 || cfg.Group != 1 {
		t.Fatalf("domain/group: %d.%d", cfg.Domain, cfg.Group)
	}
	if !cfg.RelayEligible {
		t.Fatal("expected relay_eligible")
	}
	// No registrar_addr in config — resolved via SRV
	if cfg.RegistrarAddr != "" {
		t.Fatalf("expected empty registrar_addr, got %s", cfg.RegistrarAddr)
	}

	rf, err := cfg.RoleFlags()
	if err != nil {
		t.Fatalf("RoleFlags: %v", err)
	}
	if RoleOf(rf) != RoleClient {
		t.Fatalf("role bits: %d", RoleOf(rf))
	}
	if !HasFlag(rf, FlagRelayEligible) {
		t.Fatal("expected relay eligible flag")
	}

	tc, err := cfg.TransportConfig()
	if err != nil {
		t.Fatalf("TransportConfig: %v", err)
	}
	if tc.Mode != ModeDynamic {
		t.Fatalf("mode: %s", tc.Mode)
	}
	if tc.ProbeInterval != 5*time.Minute {
		t.Fatalf("probe_interval: %v", tc.ProbeInterval)
	}
	if tc.Threshold != 50*time.Millisecond {
		t.Fatalf("threshold: %v", tc.Threshold)
	}
}

func TestLoadAgentConfig(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/agent.json")
	if err != nil {
		t.Fatalf("LoadEndpointConfig: %v", err)
	}
	if cfg.Role != "agent" {
		t.Fatalf("role: %q", cfg.Role)
	}
	if !cfg.Priority {
		t.Fatal("expected priority flag")
	}

	rf, _ := cfg.RoleFlags()
	if RoleOf(rf) != RoleAgent {
		t.Fatalf("role bits: %d", RoleOf(rf))
	}
	if !HasFlag(rf, FlagPriority) {
		t.Fatal("expected priority flag in roleflags")
	}
}

func TestLoadPinnedConfig(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/client-pinned.json")
	if err != nil {
		t.Fatalf("LoadEndpointConfig: %v", err)
	}

	tc, err := cfg.TransportConfig()
	if err != nil {
		t.Fatalf("TransportConfig: %v", err)
	}
	if tc.Mode != ModePinned {
		t.Fatalf("mode: %s", tc.Mode)
	}
	if tc.PinnedRelay == nil {
		t.Fatal("expected pinned relay")
	}
	if tc.PinnedRelay.Domain != 1 || tc.PinnedRelay.Group != 1 || tc.PinnedRelay.Endpoint != 5 {
		t.Fatalf("pinned relay addr: %s", tc.PinnedRelay)
	}
}

func TestLoadRelayConfig(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/relay.json")
	if err != nil {
		t.Fatalf("LoadEndpointConfig: %v", err)
	}

	rf, _ := cfg.RoleFlags()
	if RoleOf(rf) != RoleRelay {
		t.Fatalf("role bits: %d", RoleOf(rf))
	}

	tc, _ := cfg.TransportConfig()
	if tc.Mode != ModePeer {
		t.Fatalf("relay transport mode: %s", tc.Mode)
	}
}

func TestResolveRegistrarDirectOverride(t *testing.T) {
	cfg := &EndpointConfig{RegistrarAddr: "10.0.0.1:7000"}
	addr, err := cfg.ResolveRegistrar()
	if err != nil {
		t.Fatalf("ResolveRegistrar: %v", err)
	}
	if addr != "10.0.0.1:7000" {
		t.Fatalf("expected direct override, got %s", addr)
	}
}

func TestResolveRegistrarDevConfig(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/client-dev.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	addr, err := cfg.ResolveRegistrar()
	if err != nil {
		t.Fatalf("ResolveRegistrar: %v", err)
	}
	if addr != "127.0.0.1:7000" {
		t.Fatalf("expected 127.0.0.1:7000, got %s", addr)
	}
}

func TestDefaultBrokerSRV(t *testing.T) {
	if DefaultBrokerSRV != "_swarmbroker._tcp.wixcloud.de" {
		t.Fatalf("unexpected default SRV: %s", DefaultBrokerSRV)
	}
}

func TestConfigRelayMode(t *testing.T) {
	cfg, err := LoadEndpointConfig("examples/client-relay.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tc, _ := cfg.TransportConfig()
	if tc.Mode != ModeRelay {
		t.Fatalf("expected relay mode, got %s", tc.Mode)
	}
}
