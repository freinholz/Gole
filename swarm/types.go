package swarm

import "fmt"

// Registration states (uint8 state machine).
// Endpoints transition through these states during registration.
//
//	Unregistered -> Requesting -> ChallengeIssued -> ChallengeResponse -> Registered -> Active
//	Any state can transition to Revoked.
const (
	StateUnregistered     uint8 = 0x00
	StateRequesting       uint8 = 0x01
	StateChallengeIssued  uint8 = 0x02
	StateChallengeResponse uint8 = 0x03
	StateRegistered       uint8 = 0x04
	StateActive           uint8 = 0x05
	StateRevoked          uint8 = 0xFF
)

// Endpoint roles determine communication direction.
// Only clients may initiate flows; only agents may receive them.
const (
	RoleClient uint8 = 0x01
	RoleAgent  uint8 = 0x02
)

// EndpointID uniquely identifies an endpoint within a group (1-254, 0 reserved).
type EndpointID uint8

// DomainID identifies a business domain. Endpoints in different domains cannot communicate.
type DomainID uint8

// GroupID identifies an isolation group within a domain.
// Provides finer-grained isolation than domain alone.
type GroupID uint8

// EndpointAddr is the full swarm address of an endpoint: domain.group.endpoint + role.
type EndpointAddr struct {
	Domain   DomainID
	Group    GroupID
	Endpoint EndpointID
	Role     uint8
}

func (a EndpointAddr) String() string {
	role := "client"
	if a.Role == RoleAgent {
		role = "agent"
	}
	return fmt.Sprintf("%s@%d.%d.%d", role, a.Domain, a.Group, a.Endpoint)
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
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// RegistrationRequest is sent by an endpoint to begin registration.
type RegistrationRequest struct {
	PublicKey []byte   // Ed25519 public key (32 bytes)
	Domain    DomainID
	Group     GroupID
	Role      uint8
}

// Challenge is sent by the controller to verify key ownership.
type Challenge struct {
	Nonce [32]byte
}

// ChallengeResponse proves the endpoint owns the private key.
type ChallengeResponse struct {
	Signature []byte // Ed25519 signature over the challenge nonce
}

// RegistrationResult is returned after successful registration.
type RegistrationResult struct {
	ID    EndpointID
	Token string // PASETO v4.public token binding ID to public key
}

// SwarmMessage represents an authenticated, addressed message in the swarm.
type SwarmMessage struct {
	From      EndpointAddr
	To        EndpointAddr
	Token     string // Sender's PASETO token (signed by controller)
	Payload   []byte
	Signature []byte // Ed25519 signature over payload (signed by sender)
}
