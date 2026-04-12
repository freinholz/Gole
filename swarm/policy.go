package swarm

import (
	"errors"
	"fmt"
)

// FlowPolicy is evaluated after built-in flow rules.
// Return nil to allow, error to deny.
type FlowPolicy interface {
	Evaluate(from, to EndpointAddr) error
}

// AllowListPolicy permits only explicitly listed flow patterns.
type AllowListPolicy struct {
	Rules []FlowRule
}

// FlowRule defines a permitted communication pattern.
type FlowRule struct {
	FromDomain DomainID
	FromGroup  GroupID
	FromRole   uint8 // role bits only (lower 2 bits)
	ToDomain   DomainID
	ToGroup    GroupID
	ToRole     uint8
}

func (p *AllowListPolicy) Evaluate(from, to EndpointAddr) error {
	for _, r := range p.Rules {
		if r.FromDomain == from.Domain &&
			r.FromGroup == from.Group &&
			r.FromRole == from.Role() &&
			r.ToDomain == to.Domain &&
			r.ToGroup == to.Group &&
			r.ToRole == to.Role() {
			return nil
		}
	}
	return errors.New("flow not in allow list")
}

// DenyEndpointPolicy blocks specific source endpoints.
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
