package swarm

import (
	"fmt"
	"time"
)

// Registration states (uint8 state machine).
//
//	Unregistered -> Requesting -> ChallengeIssued -> ChallengeResponse -> Registered -> Active
//	Any state -> Revoked.
const (
	StateUnregistered      uint8 = 0x00
	StateRequesting        uint8 = 0x01
	StateChallengeIssued   uint8 = 0x02
	StateChallengeResponse uint8 = 0x03
	StateRegistered        uint8 = 0x04
	StateActive            uint8 = 0x05
	StateRevoked           uint8 = 0xFF
)

// Role values occupy the lower 2 bits of the RoleFlags byte.
const (
	RoleClient uint8 = 0x01 // Initiates flows to agents
	RoleAgent  uint8 = 0x02 // Receives flows from clients
	RoleRelay  uint8 = 0x03 // Transport relay: verifies PASETO, forwards data
	RoleMask   uint8 = 0x03 // Lower 2 bits
)

// Flag bits occupy the upper 6 bits of the RoleFlags byte.
const (
	FlagRelayEligible uint8 = 0x04 // Bit 2: may fall back to relay
	FlagPriority      uint8 = 0x08 // Bit 3: high-priority endpoint
	// Bits 4-7 reserved
)

// RoleOf extracts the role (lower 2 bits) from a RoleFlags byte.
func RoleOf(flags uint8) uint8 { return flags & RoleMask }

// HasFlag checks whether a specific flag bit is set.
func HasFlag(flags, flag uint8) bool { return flags&flag != 0 }

// MakeRoleFlags combines a role with flag bits.
func MakeRoleFlags(role uint8, flags uint8) uint8 {
	return (role & RoleMask) | (flags & ^RoleMask)
}

// EndpointID uniquely identifies an endpoint within a group (uint16, 1-65534).
type EndpointID uint16

// DomainID identifies a business domain.
type DomainID uint8

// GroupID identifies an isolation group within a domain.
type GroupID uint8

// EndpointAddr is the full swarm address: domain.group.endpoint + role/flags.
type EndpointAddr struct {
	Domain    DomainID
	Group     GroupID
	Endpoint  EndpointID
	RoleFlags uint8
}

func (a EndpointAddr) Role() uint8  { return RoleOf(a.RoleFlags) }
func (a EndpointAddr) String() string {
	return fmt.Sprintf("%s@%d.%d.%d", RoleName(a.Role()), a.Domain, a.Group, a.Endpoint)
}
func (a EndpointAddr) AddrKey() string {
	return fmt.Sprintf("%d.%d.%d", a.Domain, a.Group, a.Endpoint)
}

// StateName returns a human-readable name for a registration state.
func StateName(s uint8) string {
	switch s {
	case StateUnregistered:
		return "unregistered"
	case StateRequesting:
		return "requesting"
	case StateChallengeIssued:
		return "challenge_issued"
	case StateChallengeResponse:
		return "challenge_response"
	case StateRegistered:
		return "registered"
	case StateActive:
		return "active"
	case StateRevoked:
		return "revoked"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}

// RoleName returns a human-readable name for a role.
func RoleName(r uint8) string {
	switch r {
	case RoleClient:
		return "client"
	case RoleAgent:
		return "agent"
	case RoleRelay:
		return "relay"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// --- Registration protocol messages ---

type RegistrationRequest struct {
	PublicKey []byte // Ed25519 public key (32 bytes)
	Domain    DomainID
	Group     GroupID
	RoleFlags uint8
}

type Challenge struct {
	Nonce [32]byte
}

type ChallengeResponse struct {
	Signature []byte
}

type RegistrationResult struct {
	ID    EndpointID
	Token string
}

// RegistrationInfo is the full response a registrar returns to an endpoint
// after successful registration and activation. It includes everything the
// endpoint needs: its identity token, the trust root for verifying peers,
// and available relays for transport.
type RegistrationInfo struct {
	ID           EndpointID
	Token        string
	RegistrarKey []byte      // Ed25519 public key of the registrar (trust root)
	Relays       []RelayInfo // Available relays in the endpoint's domain
}

// RegisteredEndpoint holds the state of a registered endpoint.
type RegisteredEndpoint struct {
	Addr      EndpointAddr
	PublicKey []byte // Ed25519 public key
	State     uint8
	Token     string
}

// --- Transport modes ---

// TransportMode controls how an endpoint routes traffic.
type TransportMode uint8

const (
	ModePinned  TransportMode = 0x01 // Use a SPECIFIC relay (PinnedRelay in config)
	ModeRelay   TransportMode = 0x02 // Use the BEST available relay
	ModePeer    TransportMode = 0x03 // Always P2P hole-punching
	ModeDynamic TransportMode = 0x04 // Choose best, re-evaluate continuously
)

func (m TransportMode) String() string {
	switch m {
	case ModePinned:
		return "pinned"
	case ModeRelay:
		return "relay"
	case ModePeer:
		return "peer"
	case ModeDynamic:
		return "dynamic"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// TransportConfig controls transport selection behaviour.
type TransportConfig struct {
	Mode          TransportMode
	PinnedRelay   *EndpointAddr // Required for ModePinned: which specific relay to use
	ProbeInterval time.Duration // Re-probe interval for dynamic mode (default 5m)
	Threshold     time.Duration // Latency difference to trigger switch in dynamic mode
}

// DefaultTransportConfig returns a sensible default transport configuration.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		Mode:          ModeDynamic,
		ProbeInterval: 5 * time.Minute,
		Threshold:     50 * time.Millisecond,
	}
}

// TransportDecision is the outcome of transport selection.
type TransportDecision struct {
	UseRelay     bool
	RelayAddr    *EndpointAddr // nil if P2P
	P2PLatency   time.Duration // measured, 0 if unavailable
	RelayLatency time.Duration // best relay latency, 0 if unavailable
}

// RelayInfo describes a relay endpoint available for transport.
type RelayInfo struct {
	Addr    EndpointAddr
	Latency time.Duration // last measured latency (0 = not yet probed)
}

// --- Messages ---

type SwarmMessage struct {
	From      EndpointAddr
	To        EndpointAddr
	Token     string // Sender's PASETO token
	Payload   []byte
	Signature []byte // Ed25519 signature over payload
}

// --- Relay wire protocol ---

const (
	FrameAuth     uint8 = 0x01 // Endpoint -> Relay: PASETO token in payload
	FrameAuthOK   uint8 = 0x02 // Relay -> Endpoint: accepted
	FrameAuthFail uint8 = 0x03 // Relay -> Endpoint: rejected
	FrameData     uint8 = 0x10 // Bidirectional: forwarded data
	FrameNoRoute  uint8 = 0x11 // Relay -> Endpoint: destination not connected
	FramePing         uint8 = 0x20 // Latency probe request (payload = 8-byte nonce)
	FramePong         uint8 = 0x21 // Latency probe response (echoes nonce)
	FrameRelayForward uint8 = 0x30 // Reserved: future relay-to-relay transit
)

// RelayFrameHeader is a compact 9-byte binary header.
//
//	[1] Type  [1] DstDomain  [1] DstGroup  [2] DstEndpoint  [4] PayloadLen
type RelayFrameHeader struct {
	Type        uint8
	DstDomain   uint8
	DstGroup    uint8
	DstEndpoint uint16
	PayloadLen  uint32
}

const RelayFrameHeaderSize = 9
const MaxRelayPayload = 1 << 20 // 1 MB

// --- Reachability ---

// ReachabilityInfo describes how to reach an endpoint.
// The broker maintains this: the direct route is observed from the
// endpoint's connection to the broker (NAT-mapped public address),
// and the relay route is set when the endpoint connects to a relay.
type ReachabilityInfo struct {
	Addr      EndpointAddr
	Direct    *DirectRoute // broker-observed public address for P2P
	Relay     *RelayRoute  // which relay the endpoint is connected to
	UpdatedAt time.Time
}

// DirectRoute holds the endpoint's observed public address as seen by
// the broker. The endpoint itself doesn't know this (it's behind NAT).
// The broker records it from the endpoint's connection.
type DirectRoute struct {
	ObservedAddr string // NAT-mapped public address (e.g. "203.0.113.5:48291")
	Proto        string // "tcp" or "udp"
}

// RelayRoute records which relay an endpoint is connected to.
type RelayRoute struct {
	RelayAddr EndpointAddr
}

// PunchRequest is returned by the broker when a client requests P2P
// rendezvous. Both sides get each other's observed address and punch
// simultaneously.
type PunchRequest struct {
	PeerAddr     EndpointAddr // the other side's swarm address
	ObservedAddr string       // the other side's observed public address
	Proto        string       // "tcp" or "udp"
}

// --- Relay routing ---

// RelayRouter decides how to deliver a frame to a destination.
// Default: LocalRouter (local sessions only).
// Future: MeshRouter (relay-to-relay transit via hyperscaler networks).
type RelayRouter interface {
	// Route attempts to deliver a frame. Returns true if handled
	// (delivered or forwarded), false if no route exists.
	Route(src *RelaySession, dst EndpointAddr, hdr RelayFrameHeader, payload []byte) (handled bool, err error)
}
