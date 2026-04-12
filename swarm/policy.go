package swarm

import (
	"errors"
	"fmt"
)

// FlowPolicy is an interface for custom flow control rules.
// Policies are evaluated after the built-in rules (client-to-agent,
// same domain, same group). A policy returns nil to allow the flow
// or an error to deny it.
type FlowPolicy interface {
	Evaluate(from, to EndpointAddr) error
}

// AllowListPolicy permits only explicitly listed flow patterns.
// If any rule matches, the flow is allowed. If no rule matches, it is denied.
type AllowListPolicy struct {
	Rules []FlowRule
}

// FlowRule defines a permitted communication pattern.
type FlowRule struct {
	FromDomain DomainID
	FromGroup  GroupID
	FromRole   uint8
	ToDomain   DomainID
	ToGroup    GroupID
	ToRole     uint8
}

func (p *AllowListPolicy) Evaluate(from, to EndpointAddr) error {
	for _, r := range p.Rules {
		if r.FromDomain == from.Domain &&
			r.FromGroup == from.Group &&
			r.FromRole == from.Role &&
			r.ToDomain == to.Domain &&
			r.ToGroup == to.Group &&
			r.ToRole == to.Role {
			return nil
		}
	}
	return errors.New("flow not in allow list")
}

// DenyEndpointPolicy blocks specific source endpoints from communicating.
type DenyEndpointPolicy struct {
	Blocked []EndpointAddr
}

func (p *DenyEndpointPolicy) Evaluate(from, to EndpointAddr) error {
	for _, b := range p.Blocked {
		if from.Domain == b.Domain &&
			from.Group == b.Group &&
			from.Endpoint == b.Endpoint {
			return fmt.Errorf("endpoint %s is blocked", from.String())
		}
	}
	return nil
}

// MaxConnectionsPolicy limits how many distinct agents a single client
// can communicate with (useful for enforcing least-privilege).
// Note: this is a stateless check placeholder. A production implementation
// would track active connections.
type MaxConnectionsPolicy struct {
	MaxTargets int
}

func (p *MaxConnectionsPolicy) Evaluate(from, to EndpointAddr) error {
	// Stateless placeholder — a real implementation would track
	// active connection counts in the controller.
	return nil
}
