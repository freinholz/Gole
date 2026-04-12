package swarm

// Controller defines and evaluates flow policies.
//
// It is separate from the Registrar: the registrar handles identity,
// the controller handles authorization. The controller uses the
// registrar's public key to verify tokens and the registrar reference
// to look up endpoint state.

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

// Controller evaluates flow policies and message authenticity.
type Controller struct {
	mu           sync.RWMutex
	registrar    *Registrar
	registrarKey ed25519.PublicKey
	policies     []FlowPolicy
}

// NewController creates a controller that trusts the given registrar.
func NewController(reg *Registrar) *Controller {
	return &Controller{
		registrar:    reg,
		registrarKey: reg.PublicKey(),
		policies:     make([]FlowPolicy, 0),
	}
}

// AddPolicy adds a custom flow policy.
func (c *Controller) AddPolicy(p FlowPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies = append(c.policies, p)
}

// ValidateFlow checks whether from->to is allowed.
//
// Checks: token validity, token-address match, flow rules, custom policies.
func (c *Controller) ValidateFlow(from, to EndpointAddr, fromToken string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	claims, err := VerifyToken(fromToken, c.registrarKey)
	if err != nil {
		return fmt.Errorf("flow denied: invalid sender token: %w", err)
	}
	if claims.EndpointID != from.Endpoint ||
		claims.Domain != from.Domain ||
		claims.Group != from.Group ||
		claims.RoleFlags != from.RoleFlags {
		return errors.New("flow denied: token does not match sender address")
	}

	return c.checkFlowRules(from, to)
}

// VerifyMessage performs full verification of an incoming SwarmMessage:
//  1. PASETO token validity (registrar signature + expiry)
//  2. Token matches claimed sender address
//  3. Payload signature matches the public key in the token
//  4. Flow rules and custom policies
func (c *Controller) VerifyMessage(msg *SwarmMessage) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	claims, err := VerifyToken(msg.Token, c.registrarKey)
	if err != nil {
		return fmt.Errorf("message denied: invalid token: %w", err)
	}
	if claims.EndpointID != msg.From.Endpoint ||
		claims.Domain != msg.From.Domain ||
		claims.Group != msg.From.Group ||
		claims.RoleFlags != msg.From.RoleFlags {
		return errors.New("message denied: token does not match sender")
	}
	if !ed25519.Verify(ed25519.PublicKey(claims.PublicKey), msg.Payload, msg.Signature) {
		return errors.New("message denied: invalid payload signature")
	}

	return c.checkFlowRules(msg.From, msg.To)
}

// checkFlowRules enforces built-in rules + custom policies.
func (c *Controller) checkFlowRules(from, to EndpointAddr) error {
	fromRole := from.Role()
	toRole := to.Role()

	// Relay destination: any authenticated endpoint may route to a relay
	// in the same domain. The relay itself only checks token validity.
	if toRole == RoleRelay {
		if from.Domain != to.Domain {
			return errors.New("flow denied: relay must be in same domain")
		}
		ep := c.registrar.GetEndpointInfo(to)
		if ep == nil {
			return errors.New("flow denied: relay not found")
		}
		if ep.State != StateActive {
			return fmt.Errorf("flow denied: relay state is %s", StateName(ep.State))
		}
		return nil
	}

	// Standard: client -> agent, same domain, same group.
	if fromRole != RoleClient {
		return errors.New("flow denied: only clients can initiate communication")
	}
	if toRole != RoleAgent {
		return errors.New("flow denied: destination must be an agent")
	}
	if from.Domain != to.Domain {
		return fmt.Errorf("flow denied: cross-domain not allowed (%d -> %d)",
			from.Domain, to.Domain)
	}
	if from.Group != to.Group {
		return fmt.Errorf("flow denied: cross-group not allowed (%d -> %d)",
			from.Group, to.Group)
	}

	ep := c.registrar.GetEndpointInfo(to)
	if ep == nil {
		return errors.New("flow denied: destination not found")
	}
	if ep.State != StateActive {
		return fmt.Errorf("flow denied: destination state is %s", StateName(ep.State))
	}

	for _, p := range c.policies {
		if err := p.Evaluate(from, to); err != nil {
			return fmt.Errorf("flow denied: policy: %w", err)
		}
	}

	return nil
}
