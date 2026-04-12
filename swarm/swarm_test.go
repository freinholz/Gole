package swarm

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

const testTokenTTL = 1 * time.Hour

func setupController(t *testing.T) *SwarmController {
	t.Helper()
	ctrl, err := NewSwarmController(testTokenTTL)
	if err != nil {
		t.Fatalf("NewSwarmController: %v", err)
	}
	return ctrl
}

func registerAndActivate(t *testing.T, ctrl *SwarmController, domain DomainID, group GroupID, role uint8) *Endpoint {
	t.Helper()
	ep, err := NewEndpoint()
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if err := ep.Register(ctrl, domain, group, role); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := ep.Activate(ctrl); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	return ep
}

// --- Registration Tests ---

func TestRegistrationHappyPath(t *testing.T) {
	ctrl := setupController(t)

	ep, err := NewEndpoint()
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}

	// Verify initial state
	if ep.State() != StateUnregistered {
		t.Fatalf("expected state Unregistered, got %s", StateName(ep.State()))
	}

	// Register
	err = ep.Register(ctrl, DomainID(1), GroupID(1), RoleClient)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if ep.State() != StateRegistered {
		t.Fatalf("expected state Registered, got %s", StateName(ep.State()))
	}
	if ep.Addr() == nil {
		t.Fatal("expected non-nil address after registration")
	}
	if ep.Addr().Domain != 1 || ep.Addr().Group != 1 || ep.Addr().Role != RoleClient {
		t.Fatalf("unexpected address: %s", ep.Addr())
	}
	if ep.Addr().Endpoint == 0 {
		t.Fatal("expected non-zero endpoint ID")
	}
	if ep.Token() == "" {
		t.Fatal("expected non-empty token")
	}

	// Activate
	err = ep.Activate(ctrl)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if ep.State() != StateActive {
		t.Fatalf("expected state Active, got %s", StateName(ep.State()))
	}
}

func TestRegistrationUniqueIDs(t *testing.T) {
	ctrl := setupController(t)
	seen := make(map[EndpointID]bool)

	for i := 0; i < 10; i++ {
		ep := registerAndActivate(t, ctrl, 1, 1, RoleAgent)
		if seen[ep.Addr().Endpoint] {
			t.Fatalf("duplicate endpoint ID: %d", ep.Addr().Endpoint)
		}
		seen[ep.Addr().Endpoint] = true
	}
}

func TestRegistrationCapacity(t *testing.T) {
	ctrl := setupController(t)

	// Fill up a group (254 max)
	for i := 0; i < 254; i++ {
		ep, err := NewEndpoint()
		if err != nil {
			t.Fatalf("NewEndpoint %d: %v", i, err)
		}
		if err := ep.Register(ctrl, 1, 1, RoleAgent); err != nil {
			t.Fatalf("Register %d: %v", i, err)
		}
	}

	// 255th should fail
	ep, _ := NewEndpoint()
	err := ep.Register(ctrl, 1, 1, RoleAgent)
	if err == nil {
		t.Fatal("expected capacity error, got nil")
	}
}

func TestRegistrationDuplicateKey(t *testing.T) {
	ctrl := setupController(t)

	ep, _ := NewEndpoint()
	if err := ep.Register(ctrl, 1, 1, RoleClient); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// Try to register again with the same key (new Endpoint wrapping same key)
	_, err := ctrl.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(),
		Domain:    1,
		Group:     1,
		Role:      RoleClient,
	})
	if err == nil {
		t.Fatal("expected error for duplicate key registration")
	}
}

func TestRegistrationInvalidRole(t *testing.T) {
	ctrl := setupController(t)

	ep, _ := NewEndpoint()
	err := ep.Register(ctrl, 1, 1, 0x99) // invalid role
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

// --- Challenge-Response Security Tests ---

func TestChallengeResponseWrongKey(t *testing.T) {
	ctrl := setupController(t)

	// Start registration with one key
	ep, _ := NewEndpoint()
	challenge, err := ctrl.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(),
		Domain:    1,
		Group:     1,
		Role:      RoleClient,
	})
	if err != nil {
		t.Fatalf("RegisterRequest: %v", err)
	}

	// Sign with a DIFFERENT key (attacker scenario)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	badSig := ed25519.Sign(attackerPriv, challenge.Nonce[:])

	_, err = ctrl.RegisterResponse(ep.PublicKey(), ChallengeResponse{Signature: badSig})
	if err == nil {
		t.Fatal("expected challenge verification failure")
	}
}

func TestChallengeResponseInvalidSignature(t *testing.T) {
	ctrl := setupController(t)

	ep, _ := NewEndpoint()
	_, err := ctrl.RegisterRequest(RegistrationRequest{
		PublicKey: ep.PublicKey(),
		Domain:    1,
		Group:     1,
		Role:      RoleClient,
	})
	if err != nil {
		t.Fatalf("RegisterRequest: %v", err)
	}

	// Submit garbage signature
	_, err = ctrl.RegisterResponse(ep.PublicKey(), ChallengeResponse{
		Signature: make([]byte, ed25519.SignatureSize),
	})
	if err == nil {
		t.Fatal("expected challenge verification failure for garbage signature")
	}
}

// --- PASETO Token Tests ---

func TestPASETOTokenSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	claims := &TokenClaims{
		EndpointID: 42,
		Domain:     1,
		Group:      2,
		Role:       RoleClient,
		PublicKey:  pub,
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		Issuer:     "test",
	}

	token, err := SignToken(claims, priv)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	verified, err := VerifyToken(token, pub)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}

	if verified.EndpointID != 42 || verified.Domain != 1 || verified.Group != 2 {
		t.Fatalf("claims mismatch: %+v", verified)
	}
}

func TestPASETOTokenWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)

	claims := &TokenClaims{
		EndpointID: 1,
		Domain:     1,
		Group:      1,
		Role:       RoleClient,
		PublicKey:   make([]byte, 32),
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		Issuer:     "test",
	}

	token, _ := SignToken(claims, priv)

	_, err := VerifyToken(token, wrongPub)
	if err == nil {
		t.Fatal("expected signature verification failure with wrong key")
	}
}

func TestPASETOTokenExpired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	claims := &TokenClaims{
		EndpointID: 1,
		Domain:     1,
		Group:      1,
		Role:       RoleClient,
		PublicKey:  make([]byte, 32),
		IssuedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // expired
		Issuer:     "test",
	}

	token, _ := SignToken(claims, priv)

	_, err := VerifyToken(token, pub)
	if err == nil {
		t.Fatal("expected token expiry error")
	}
}

func TestPASETOTokenTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	claims := &TokenClaims{
		EndpointID: 1,
		Domain:     1,
		Group:      1,
		Role:       RoleClient,
		PublicKey:  make([]byte, 32),
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		Issuer:     "test",
	}

	token, _ := SignToken(claims, priv)

	// Tamper with the token (flip a character in the payload)
	tampered := []byte(token)
	// Modify a byte in the base64 payload area
	if len(tampered) > 15 {
		tampered[15] ^= 0x01
	}

	_, err := VerifyToken(string(tampered), pub)
	if err == nil {
		t.Fatal("expected verification failure for tampered token")
	}
}

// --- Flow Validation Tests ---

func TestFlowClientToAgent(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	msg, err := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	if err != nil {
		t.Fatalf("PrepareMessage: %v", err)
	}

	if err := ctrl.VerifyMessage(msg); err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
}

func TestFlowAgentToClientBlocked(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Agent tries to send to client — should be blocked
	msg, err := agent.PrepareMessage(*client.Addr(), []byte("hello"))
	if err != nil {
		t.Fatalf("PrepareMessage: %v", err)
	}

	err = ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: agent cannot initiate to client")
	}
}

func TestFlowClientToClientBlocked(t *testing.T) {
	ctrl := setupController(t)

	client1 := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	client2 := registerAndActivate(t, ctrl, 1, 1, RoleClient)

	msg, _ := client1.PrepareMessage(*client2.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: client cannot send to client")
	}
}

func TestFlowCrossDomainBlocked(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 2, 1, RoleAgent) // different domain

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: cross-domain communication not allowed")
	}
}

func TestFlowCrossGroupBlocked(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 2, RoleAgent) // same domain, different group

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: cross-group communication not allowed")
	}
}

// --- ID Spoofing Prevention Tests ---

func TestIDSpoofingWithFakeToken(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Attacker creates a message claiming to be the client but with a forged token
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	forgedClaims := &TokenClaims{
		EndpointID: client.Addr().Endpoint,
		Domain:     1,
		Group:      1,
		Role:       RoleClient,
		PublicKey:  client.PublicKey(),
		IssuedAt:   time.Now(),
		ExpiresAt:  time.Now().Add(time.Hour),
		Issuer:     "gole-swarm-controller",
	}

	// Sign with attacker's key (not the controller's)
	forgedToken, _ := SignToken(forgedClaims, attackerPriv)

	msg := &SwarmMessage{
		From:      *client.Addr(),
		To:        *agent.Addr(),
		Token:     forgedToken,
		Payload:   []byte("spoofed"),
		Signature: ed25519.Sign(attackerPriv, []byte("spoofed")),
	}

	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected verification failure for forged token")
	}
}

func TestIDSpoofingWithStolenToken(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Attacker steals the client's token but signs with their own key
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)

	msg := &SwarmMessage{
		From:      *client.Addr(),
		To:        *agent.Addr(),
		Token:     client.Token(), // stolen token
		Payload:   []byte("spoofed"),
		Signature: ed25519.Sign(attackerPriv, []byte("spoofed")), // wrong key
	}

	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected verification failure: payload signature doesn't match token's public key")
	}
}

func TestIDSpoofingWithModifiedAddress(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Client creates valid message but modifies the From address
	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))

	// Modify From to claim a different endpoint ID
	msg.From.Endpoint = EndpointID(99)

	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected verification failure: modified sender address doesn't match token")
	}
}

// --- Revocation Tests ---

func TestRevokedEndpointCannotCommunicate(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Revoke the agent
	if err := ctrl.RevokeEndpoint(*agent.Addr()); err != nil {
		t.Fatalf("RevokeEndpoint: %v", err)
	}

	// Client tries to send — should fail because agent is revoked
	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: destination is revoked")
	}
}

func TestActivateFromWrongState(t *testing.T) {
	ctrl := setupController(t)

	ep := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Try to activate again (already active)
	err := ctrl.ActivateEndpoint(*ep.Addr(), ep.Token())
	if err == nil {
		t.Fatal("expected error: cannot activate from Active state")
	}
}

// --- Policy Tests ---

func TestDenyEndpointPolicy(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Add a policy that blocks this specific client
	ctrl.AddPolicy(&DenyEndpointPolicy{
		Blocked: []EndpointAddr{*client.Addr()},
	})

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: client is blocked by policy")
	}
}

func TestAllowListPolicy(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Add an allow-list that only permits domain 2 flows (not domain 1)
	ctrl.AddPolicy(&AllowListPolicy{
		Rules: []FlowRule{
			{FromDomain: 2, FromGroup: 1, FromRole: RoleClient,
				ToDomain: 2, ToGroup: 1, ToRole: RoleAgent},
		},
	})

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("hello"))
	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected flow denial: not in allow list")
	}
}

// --- Message Integrity Tests ---

func TestMessageIntegrity(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	agent := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	msg, _ := client.PrepareMessage(*agent.Addr(), []byte("original"))

	// Tamper with the payload
	msg.Payload = []byte("tampered")

	err := ctrl.VerifyMessage(msg)
	if err == nil {
		t.Fatal("expected verification failure: payload was tampered")
	}
}

// --- Inactive Endpoint Tests ---

func TestMessageToInactiveEndpoint(t *testing.T) {
	ctrl := setupController(t)

	client := registerAndActivate(t, ctrl, 1, 1, RoleClient)

	// Create agent but don't activate it
	agent, _ := NewEndpoint()
	if err := agent.Register(ctrl, 1, 1, RoleAgent); err != nil {
		t.Fatalf("Register agent: %v", err)
	}
	// agent is in Registered state, not Active

	err := ctrl.ValidateFlow(*client.Addr(), *agent.Addr(), client.Token())
	if err == nil {
		t.Fatal("expected flow denial: destination not active")
	}
}

// --- Multi-Domain/Group Isolation Tests ---

func TestMultiDomainIsolation(t *testing.T) {
	ctrl := setupController(t)

	// Domain 1
	c1 := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	a1 := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	// Domain 2
	c2 := registerAndActivate(t, ctrl, 2, 1, RoleClient)
	a2 := registerAndActivate(t, ctrl, 2, 1, RoleAgent)

	// Same-domain flows should work
	msg1, _ := c1.PrepareMessage(*a1.Addr(), []byte("d1"))
	if err := ctrl.VerifyMessage(msg1); err != nil {
		t.Fatalf("same-domain flow failed: %v", err)
	}

	msg2, _ := c2.PrepareMessage(*a2.Addr(), []byte("d2"))
	if err := ctrl.VerifyMessage(msg2); err != nil {
		t.Fatalf("same-domain flow failed: %v", err)
	}

	// Cross-domain flows should be blocked
	msg3, _ := c1.PrepareMessage(*a2.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(msg3); err == nil {
		t.Fatal("expected cross-domain denial")
	}

	msg4, _ := c2.PrepareMessage(*a1.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(msg4); err == nil {
		t.Fatal("expected cross-domain denial")
	}
}

func TestMultiGroupIsolation(t *testing.T) {
	ctrl := setupController(t)

	// Same domain, different groups
	c1 := registerAndActivate(t, ctrl, 1, 1, RoleClient)
	a1 := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	c2 := registerAndActivate(t, ctrl, 1, 2, RoleClient)
	a2 := registerAndActivate(t, ctrl, 1, 2, RoleAgent)

	// Same-group flows should work
	msg1, _ := c1.PrepareMessage(*a1.Addr(), []byte("g1"))
	if err := ctrl.VerifyMessage(msg1); err != nil {
		t.Fatalf("same-group flow failed: %v", err)
	}

	msg2, _ := c2.PrepareMessage(*a2.Addr(), []byte("g2"))
	if err := ctrl.VerifyMessage(msg2); err != nil {
		t.Fatalf("same-group flow failed: %v", err)
	}

	// Cross-group flows should be blocked
	msg3, _ := c1.PrepareMessage(*a2.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(msg3); err == nil {
		t.Fatal("expected cross-group denial")
	}

	msg4, _ := c2.PrepareMessage(*a1.Addr(), []byte("cross"))
	if err := ctrl.VerifyMessage(msg4); err == nil {
		t.Fatal("expected cross-group denial")
	}
}

// --- Controller Info Tests ---

func TestListEndpoints(t *testing.T) {
	ctrl := setupController(t)

	registerAndActivate(t, ctrl, 1, 1, RoleClient)
	registerAndActivate(t, ctrl, 1, 1, RoleAgent)
	registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	eps := ctrl.ListEndpoints(1, 1)
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}

	// Different group should be empty
	eps = ctrl.ListEndpoints(1, 2)
	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints in group 2, got %d", len(eps))
	}
}

func TestGetEndpointInfo(t *testing.T) {
	ctrl := setupController(t)

	ep := registerAndActivate(t, ctrl, 1, 1, RoleAgent)

	info := ctrl.GetEndpointInfo(*ep.Addr())
	if info == nil {
		t.Fatal("expected endpoint info")
	}
	if info.State != StateActive {
		t.Fatalf("expected Active state, got %s", StateName(info.State))
	}

	// Modifying the copy shouldn't affect the original
	info.State = StateRevoked
	info2 := ctrl.GetEndpointInfo(*ep.Addr())
	if info2.State != StateActive {
		t.Fatal("GetEndpointInfo should return a copy")
	}
}

// --- State Machine Tests ---

func TestStateNames(t *testing.T) {
	tests := []struct {
		state uint8
		name  string
	}{
		{StateUnregistered, "unregistered"},
		{StateRequesting, "requesting"},
		{StateChallengeIssued, "challenge_issued"},
		{StateChallengeResponse, "challenge_response"},
		{StateRegistered, "registered"},
		{StateActive, "active"},
		{StateRevoked, "revoked"},
	}

	for _, tt := range tests {
		if got := StateName(tt.state); got != tt.name {
			t.Errorf("StateName(%d) = %q, want %q", tt.state, got, tt.name)
		}
	}
}

func TestEndpointAddrString(t *testing.T) {
	addr := EndpointAddr{Domain: 1, Group: 2, Endpoint: 3, Role: RoleClient}
	expected := "client@1.2.3"
	if got := addr.String(); got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}

	addr.Role = RoleAgent
	expected = "agent@1.2.3"
	if got := addr.String(); got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}

// --- Endpoint Cannot Send Before Active ---

func TestEndpointCannotSendBeforeActive(t *testing.T) {
	ctrl := setupController(t)

	ep, _ := NewEndpoint()
	if err := ep.Register(ctrl, 1, 1, RoleClient); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Registered but not Active — PrepareMessage should fail
	target := EndpointAddr{Domain: 1, Group: 1, Endpoint: 99, Role: RoleAgent}
	_, err := ep.PrepareMessage(target, []byte("hello"))
	if err == nil {
		t.Fatal("expected error: endpoint not active")
	}
}

// --- PAE Tests ---

func TestPAEDeterministic(t *testing.T) {
	a := pae([]byte("hello"), []byte("world"))
	b := pae([]byte("hello"), []byte("world"))

	if len(a) != len(b) {
		t.Fatal("PAE not deterministic")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("PAE not deterministic")
		}
	}
}

func TestPAEDistinctInputs(t *testing.T) {
	// PAE("a", "bc") must differ from PAE("ab", "c")
	a := pae([]byte("a"), []byte("bc"))
	b := pae([]byte("ab"), []byte("c"))

	equal := len(a) == len(b)
	if equal {
		for i := range a {
			if a[i] != b[i] {
				equal = false
				break
			}
		}
	}
	if equal {
		t.Fatal("PAE failed to distinguish different inputs")
	}
}
