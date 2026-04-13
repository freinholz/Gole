# Zero-Touch Deployment: CLI Role + Fingerprint + Broker-Assigned Address

## Context

Currently `role` is in config and the endpoint declares its own `domain`/`group`. This is neither zero-touch nor safe for multi-tenant deployments. New model:

- **Role** is a CLI arg, not in config
- **Identity** is a `fingerprint = HMAC(machine_id + primary_MAC, local_id + role)`:
  - `machine_id` derived at runtime from OS
  - `local_id` from config (distinguishes multiple instances on one machine)
- **Address** (domain, group, endpoint_id) is **fully broker-assigned**
- **Enrollment** is a pending-approval workflow:
  1. Endpoint sends fingerprint + public key + role → broker stores as pending
  2. Challenge-response proves key ownership upfront
  3. Admin approves (or auto-approves via pre-provisioned fingerprint allowlist)
  4. Endpoint polls every few seconds; on approval receives address + token
- **Relay** skips fingerprint + is auto-approved (infrastructure)

This matches the pattern used by Tailscale node-join, Kubernetes kubeadm join, and certificate enrollment systems.

## State Machine

```
Unregistered → Requesting → ChallengeIssued → ChallengeResponse → Pending → Registered → Active
                                                                      ↓
                                                                   Denied
                                                             Any state → Revoked
```

New states:
- `StatePending    uint8 = 0x06` (key proven, awaiting admin approval)
- `StateDenied     uint8 = 0x07` (admin rejected)

## Enrollment Protocol

Three phases, each is a single broker call. Endpoint polls between phase 2 and 3.

### Phase 1: Enroll (`RegisterRequest` → repurposed)

```go
type EnrollRequest struct {
    PublicKey   []byte
    Fingerprint string // empty for relays
    RoleFlags   uint8
}

type EnrollResponse struct {
    RequestID string   // opaque handle for polling
    Challenge [32]byte // sign to prove key ownership
}
```

Broker stores pending enrollment, returns challenge.

### Phase 2: Confirm key ownership (`RegisterResponse` → repurposed)

```go
type EnrollConfirm struct {
    RequestID string
    Signature []byte // ed25519 over Challenge
}

type EnrollStatus struct {
    State   uint8           // StatePending / StateRegistered / StateDenied
    Result  *EnrollResult   // populated when State == StateRegistered
}

type EnrollResult struct {
    Address EndpointAddr // broker-assigned (domain, group, endpoint_id, roleflags)
    Token   string
}
```

If the fingerprint is on the pre-approved allowlist (or role is relay), broker immediately transitions to `StateRegistered` and returns the token. Otherwise returns `StatePending`.

### Phase 3: Poll (new)

```go
func (r *Registrar) PollEnrollment(requestID string, signature []byte) (*EnrollStatus, error)
```

Signature is ed25519 over `requestID + "|poll"` (prevents request ID guessing). Returns current state; once admin approves, returns result. Endpoint calls every few seconds with exponential backoff.

## Admin API

```go
// Pre-approve a fingerprint: next enrollment with matching fingerprint auto-completes.
func (r *Registrar) PreApprove(fingerprint string, domain DomainID, group GroupID) error

// Manually approve a specific pending enrollment.
func (r *Registrar) ApproveEnrollment(requestID string, domain DomainID, group GroupID) error

// Reject a pending enrollment.
func (r *Registrar) DenyEnrollment(requestID string) error

// List pending enrollments awaiting approval.
func (r *Registrar) ListPending() []PendingEnrollment

type PendingEnrollment struct {
    RequestID   string
    Fingerprint string
    RoleFlags   uint8
    CreatedAt   time.Time
    PublicKey   []byte
}
```

## Changes

### 1. Config — `swarm/config.go`

```go
type EndpointConfig struct {
    LocalID       string `json:"local_id"`       // distinguishes instances on same machine
    RelayEligible bool   `json:"relay_eligible"`
    Priority      bool   `json:"priority"`
    RegistrarAddr string `json:"registrar_addr,omitempty"`
    RegistrarSRV  string `json:"registrar_srv,omitempty"`
    Transport     TransportModeConfig `json:"transport"`
    // Role, Domain, Group REMOVED — all broker-assigned
}
```

`RoleFlags()` → `BuildRoleFlags(role string, cfg *EndpointConfig) (uint8, error)`

### 2. Machine ID — `swarm/machineid.go` (new)

```go
func MachineID() (string, error)   // machineid.ProtectedID("gole-swarm@wixcloud.de")
func PrimaryMAC() (string, error)  // primary wired Ethernet MAC
func Fingerprint(machineID, mac, localID, role string) string // HMAC-SHA256 → base62
```

Wired interface detection: prefer `eth*`, `en*`, `eno*`, `enp*`; skip loopback, `docker*`, `veth*`, `br-*`, `virbr*`, `vboxnet*`, `lxcbr*`, `tailscale*`, `wg*`, `tun*`, `tap*`, `wlan*`, `wlp*`.

### 3. Registration protocol — `swarm/types.go`, `swarm/paseto.go`

- Rename `RegistrationRequest` → `EnrollRequest`, add `Fingerprint`
- Rename `RegistrationResult` → `EnrollResult`, address now broker-assigned
- New `EnrollResponse` (Phase 1), `EnrollConfirm`/`EnrollStatus` (Phase 2), polling (Phase 3)
- `TokenClaims` gets `Fingerprint string "fp,omitempty"`
- Add states `StatePending`, `StateDenied`

### 4. Broker — `swarm/registrar.go`

- New fields:
  - `pending map[string]*PendingEnrollment` — RequestID → enrollment
  - `byFingerprint map[string]string` — fingerprint → RequestID (idempotency)
  - `preApproved map[string]preApprovedMapping` — fingerprint → (domain, group)
- Three-phase API: `Enroll()`, `ConfirmEnrollment()`, `PollEnrollment()`
- Admin API: `PreApprove()`, `ApproveEnrollment()`, `DenyEnrollment()`, `ListPending()`
- Idempotency: if fingerprint already has an approved endpoint, re-enrollment returns the same endpoint's token (restart-safe)
- Relays: role == RoleRelay → auto-approved, allocated into a dedicated "infra" domain/group (e.g., domain 0, group 0 reserved for relays)

### 5. Endpoint — `swarm/endpoint.go`

```go
// Full zero-touch flow with polling. Blocks until approved, denied, or ctx done.
func (e *Endpoint) AutoEnroll(ctx context.Context, reg *Registrar, role uint8, cfg *EndpointConfig, pollInterval time.Duration) error
```

Internally:
1. Derive fingerprint (skip for relays)
2. Phase 1: Enroll → get RequestID + challenge
3. Phase 2: Sign challenge → Confirm → if approved, done; else go to step 4
4. Phase 3: Poll every `pollInterval` (default 5s, exponential backoff up to 60s)
5. On approval: store address + token, transition to Registered
6. Activate → Active

### 6. Examples — `swarm/examples/*.json`

All configs collapse to a single template:

```json
{
    "local_id": "svc-a",
    "relay_eligible": true,
    "priority": false,
    "transport": {
        "mode": "dynamic",
        "probe_interval": "5m",
        "threshold": "50ms"
    }
}
```

Separate example configs illustrate transport modes (peer, relay, pinned, dynamic) and dev overrides.

### 7. Tests — `swarm/swarm_test.go`

New:
- `TestMachineIDStable` / `TestPrimaryMACBestEffort`
- `TestFingerprintDistinctByLocalID` / `TestFingerprintDistinctByRole`
- `TestEnrollmentPendingThenApprove` — full flow: enroll → confirm → poll → admin approves → poll returns registered
- `TestEnrollmentPreApproved` — fingerprint on allowlist → immediately registered
- `TestEnrollmentDenied` — admin denies → poll returns denied
- `TestEnrollmentIdempotent` — same fingerprint re-enrolls → same endpoint_id
- `TestEnrollmentRelayAutoApproved` — relay skips fingerprint and admin approval
- `TestPollRequiresValidSignature` — poll with wrong key is rejected
- `TestAdminListPending` — admin can see pending enrollments
- `TestAutoEnrollBlocksUntilApproved` — endpoint-side polling works with mock broker

Updates: all existing config tests (remove Role/Domain/Group assertions).

### 8. Dependencies — `go.mod`

Add: `github.com/denisbrodbeck/machineid v1.0.1`

## Critical Files to Modify

| File | Change |
|------|--------|
| `swarm/config.go` | Remove Role/Domain/Group; add LocalID |
| `swarm/machineid.go` | NEW: MachineID, PrimaryMAC, Fingerprint |
| `swarm/types.go` | Enrollment protocol types, new states, remove domain/group from registration |
| `swarm/paseto.go` | TokenClaims gets Fingerprint |
| `swarm/registrar.go` | Three-phase enrollment + admin API + polling |
| `swarm/endpoint.go` | AutoEnroll with polling loop |
| `swarm/examples/*.json` | Remove role/domain/group, add local_id |
| `swarm/swarm_test.go` | Enrollment lifecycle tests, admin tests |
| `go.mod` / `go.sum` | machineid dep |

## Verification

1. `go mod tidy && go build ./...` — compiles
2. `go test ./swarm/ -v -count=1` — all existing + ~10 new enrollment tests pass
3. Zero-touch flow:
   - Endpoint starts with same config on two machines
   - Both enroll, show up in `reg.ListPending()`
   - Admin calls `reg.ApproveEnrollment(...)` for each
   - Endpoints' next poll returns their assigned address + token
4. Idempotent restart:
   - Endpoint registers, gets ID=7
   - Endpoint restarts → re-enrolls with same fingerprint → gets ID=7 again
5. Multi-instance same machine:
   - Two configs with `local_id: "a"` and `local_id: "b"` → different fingerprints → different endpoint IDs
6. Relay: starts without machine_id, immediately registered (no pending state)
