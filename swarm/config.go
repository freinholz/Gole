package swarm

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// Default SRV record for broker discovery.
const DefaultBrokerSRV = "_swarmbroker._tcp.wixcloud.de"

// EndpointConfig is the JSON-loadable configuration for a swarm endpoint.
//
// Zero-touch design: the config carries only environment-specific
// preferences. Role comes from the CLI. Domain, group, endpoint ID are
// all broker-assigned. LocalID distinguishes multiple instances on the
// same machine (optional for single-instance case).
type EndpointConfig struct {
	// Identity
	LocalID string `json:"local_id,omitempty"` // distinguishes instances on same machine

	// Flags
	RelayEligible bool `json:"relay_eligible"` // may fall back to relay
	Priority      bool `json:"priority"`       // high-priority endpoint

	// Broker discovery — resolved in order:
	//   1. registrar_addr if set (direct override)
	//   2. registrar_srv if set (custom SRV record)
	//   3. default: _swarmbroker._tcp.wixcloud.de
	RegistrarAddr string `json:"registrar_addr,omitempty"`
	RegistrarSRV  string `json:"registrar_srv,omitempty"`

	// Transport
	Transport TransportModeConfig `json:"transport"`
}

// TransportModeConfig is the transport section of an endpoint config.
type TransportModeConfig struct {
	Mode          string `json:"mode"`                     // "pinned", "relay", "peer", "dynamic"
	PinnedRelay   string `json:"pinned_relay,omitempty"`   // "domain.group.endpoint" for pinned mode
	ProbeInterval string `json:"probe_interval,omitempty"` // duration string, e.g. "5m"
	Threshold     string `json:"threshold,omitempty"`      // duration string, e.g. "50ms"
}

// LoadEndpointConfig reads and parses a JSON config file.
func LoadEndpointConfig(path string) (*EndpointConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	var cfg EndpointConfig
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// ResolveRegistrar resolves the broker address.
func (c *EndpointConfig) ResolveRegistrar() (string, error) {
	if c.RegistrarAddr != "" {
		return c.RegistrarAddr, nil
	}
	srv := c.RegistrarSRV
	if srv == "" {
		srv = DefaultBrokerSRV
	}
	return ResolveSRV(srv)
}

// ResolveSRV performs a DNS SRV lookup.
func ResolveSRV(name string) (string, error) {
	_, addrs, err := net.LookupSRV("", "", name)
	if err != nil {
		return "", fmt.Errorf("SRV lookup %q: %w", name, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("SRV lookup %q: no records", name)
	}
	best := addrs[0]
	host := best.Target
	if len(host) > 0 && host[len(host)-1] == '.' {
		host = host[:len(host)-1]
	}
	return fmt.Sprintf("%s:%d", host, best.Port), nil
}

// ParseRole converts a role string ("client", "agent", "relay") to a role byte.
func ParseRole(role string) (uint8, error) {
	switch role {
	case "client":
		return RoleClient, nil
	case "agent":
		return RoleAgent, nil
	case "relay":
		return RoleRelay, nil
	default:
		return 0, fmt.Errorf("unknown role: %q", role)
	}
}

// BuildRoleFlags combines a role string with config flags into a RoleFlags byte.
func BuildRoleFlags(role string, cfg *EndpointConfig) (uint8, error) {
	r, err := ParseRole(role)
	if err != nil {
		return 0, err
	}
	var flags uint8
	if cfg != nil {
		if cfg.RelayEligible {
			flags |= FlagRelayEligible
		}
		if cfg.Priority {
			flags |= FlagPriority
		}
	}
	return MakeRoleFlags(r, flags), nil
}

// TransportConfig converts the JSON transport section to a TransportConfig.
func (c *EndpointConfig) TransportConfig() (TransportConfig, error) {
	cfg := DefaultTransportConfig()

	switch c.Transport.Mode {
	case "pinned":
		cfg.Mode = ModePinned
	case "relay":
		cfg.Mode = ModeRelay
	case "peer":
		cfg.Mode = ModePeer
	case "dynamic", "":
		cfg.Mode = ModeDynamic
	default:
		return cfg, fmt.Errorf("unknown transport mode: %q", c.Transport.Mode)
	}

	if c.Transport.PinnedRelay != "" {
		var d, g uint8
		var e uint16
		_, err := fmt.Sscanf(c.Transport.PinnedRelay, "%d.%d.%d", &d, &g, &e)
		if err != nil {
			return cfg, fmt.Errorf("invalid pinned_relay format (want domain.group.endpoint): %w", err)
		}
		addr := EndpointAddr{
			Domain:    DomainID(d),
			Group:     GroupID(g),
			Endpoint:  EndpointID(e),
			RoleFlags: RoleRelay,
		}
		cfg.PinnedRelay = &addr
	}

	if c.Transport.ProbeInterval != "" {
		d, err := time.ParseDuration(c.Transport.ProbeInterval)
		if err != nil {
			return cfg, fmt.Errorf("invalid probe_interval: %w", err)
		}
		cfg.ProbeInterval = d
	}
	if c.Transport.Threshold != "" {
		d, err := time.ParseDuration(c.Transport.Threshold)
		if err != nil {
			return cfg, fmt.Errorf("invalid threshold: %w", err)
		}
		cfg.Threshold = d
	}
	return cfg, nil
}
