package swarm

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// EndpointConfig is the JSON-loadable configuration for a swarm endpoint.
type EndpointConfig struct {
	// Identity
	Role   string `json:"role"`   // "client", "agent", or "relay"
	Domain uint8  `json:"domain"` // business domain (1-255)
	Group  uint8  `json:"group"`  // isolation group within domain (1-255)

	// Flags
	RelayEligible bool `json:"relay_eligible"` // may fall back to relay
	Priority      bool `json:"priority"`       // high-priority endpoint

	// Broker/Registrar
	RegistrarAddr string `json:"registrar_addr"` // how to reach the broker (ip:port)

	// Transport
	Transport TransportModeConfig `json:"transport"`
}

// TransportModeConfig is the transport section of an endpoint config.
type TransportModeConfig struct {
	Mode          string `json:"mode"`                    // "pinned", "relay", "peer", "dynamic"
	PinnedRelay   string `json:"pinned_relay,omitempty"`  // "domain.group.endpoint" for pinned mode
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

// RoleFlags returns the packed role+flags byte from the config.
func (c *EndpointConfig) RoleFlags() (uint8, error) {
	var role uint8
	switch c.Role {
	case "client":
		role = RoleClient
	case "agent":
		role = RoleAgent
	case "relay":
		role = RoleRelay
	default:
		return 0, fmt.Errorf("unknown role: %q", c.Role)
	}

	var flags uint8
	if c.RelayEligible {
		flags |= FlagRelayEligible
	}
	if c.Priority {
		flags |= FlagPriority
	}

	return MakeRoleFlags(role, flags), nil
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
