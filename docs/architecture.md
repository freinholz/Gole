# Swarm Architecture

The `swarm/` package is a zero-touch endpoint management system used by
the `gole-swarm` binary. It is separate from the original `gole` tunnel
CLI.

## Core concepts

- **Broker (Registrar)** — central authority. Assigns addresses, issues
  PASETO v4.public tokens, approves enrollments, stores reachability.
- **Endpoint** — a swarm participant: client, agent, or relay. Generates
  an Ed25519 keypair on first start and enrolls with the broker.
- **Controller** — enforces flow rules (who may talk to whom).
- **Relay** — infrastructure endpoint that forwards encrypted traffic.
  Lives in reserved `domain 0, group 0`; available to all domains.

## Address scheme

An `EndpointAddr` is `(domain, group, endpoint_id, role_flags)`:

- `domain: uint8` — tenant / deployment
- `group: uint8` — subdivision within a domain
- `endpoint_id: uint16` — unique per (domain, group), 1..65534
- `role_flags: uint8` — role (client/agent/relay) + flags (relay-eligible, priority)

Everything except `role_flags` is assigned by the broker — endpoints do
not choose their own address.

## Identity

- **Public key**: Ed25519, generated locally, never leaves the endpoint.
- **Fingerprint**: `HMAC-SHA256(machine_id || primary_MAC, local_id || "|" || role)`,
  base62-encoded. Stable across restarts. Distinguishes multiple
  instances on one machine via `local_id`.
- **Token**: PASETO v4.public, signed by the broker. Binds
  `endpoint_id + domain + group + role_flags + public_key + fingerprint`.

## Zero-touch enrollment (three phases)

```
Endpoint                              Broker
   |                                     |
   |--- Enroll(pubkey, fp, role) ------->|  stores pending, state=ChallengeIssued
   |<-- (request_id, challenge) ---------|
   |                                     |
   |--- Confirm(sig over challenge) ---->|  verify signature; if pre-approved
   |<-- {state, result?} ----------------|  → Registered, else Pending
   |                                     |
   |--- Poll(sig over "req_id|poll") --->|  (repeated with backoff)
   |<-- {state, result?} ----------------|  until Registered or Denied
```

Auto-approval paths:
- **Relay** — skips fingerprint, auto-registered into `domain 0, group 0`.
- **Pre-approved fingerprint** — broker admin calls
  `PreApprove(fingerprint, domain, group)` before the endpoint enrolls.
- Otherwise the enrollment sits `Pending` until an admin calls
  `ApproveEnrollment(request_id, domain, group)` or `DenyEnrollment(...)`.

## State machine

```
Unregistered → Requesting → ChallengeIssued → ChallengeResponse →
  Pending → Registered → Active
    ↓
  Denied                       (any state) → Revoked
```

## Transport

After activation an endpoint discovers the best route to a peer. Four
modes controlled via config:

- `peer` — direct P2P only.
- `relay` — always via relay.
- `pinned` — always via a specific relay.
- `dynamic` — probe both, pick the winner, re-evaluate every
  `probe_interval`.

Probing uses `Prober` (pluggable; mockable in tests). Decisions
re-emit on a channel so the caller can react to drift without
manual re-invocation.

## Reachability

Endpoints don't know their own NAT-mapped address. The broker observes
the public address when the endpoint connects, stores it, and returns
it to peers on lookup. For P2P rendezvous, `RequestPunch` returns each
side the other's observed address so they can hole-punch
simultaneously.

## Binary

`gole-swarm` (built from `cmd/swarm/`) exposes:

- `fingerprint` — print the machine fingerprint for a (local_id, role) pair
- `config validate` — parse and check a config file
- `demo` — in-process broker+endpoint enrollment lifecycle
- `version`

Network-facing `broker`, `endpoint`, and `admin` subcommands are pending
the wire-protocol layer — today the broker is in-process only.

## Implementation map

| File                 | Responsibility                                       |
|----------------------|------------------------------------------------------|
| `swarm/types.go`     | Address, state constants, protocol messages          |
| `swarm/machineid.go` | MachineID, PrimaryMAC, Fingerprint                   |
| `swarm/paseto.go`    | Token sign/verify (PASETO v4.public)                 |
| `swarm/registrar.go` | Broker: enroll/confirm/poll, admin API, reachability |
| `swarm/endpoint.go`  | Endpoint: AutoEnroll, Activate, Discover             |
| `swarm/controller.go`| Flow rule enforcement                                |
| `swarm/discovery.go` | Transport mode selection + monitor                   |
| `swarm/relay.go`     | Relay wire protocol + router                         |
| `swarm/policy.go`    | Pluggable flow policies                              |
| `swarm/config.go`    | JSON config loader, broker resolution (DNS SRV)      |
