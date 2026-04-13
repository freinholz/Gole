package main

import (
	"flag"
	"fmt"

	"github.com/shawwwn/gole/swarm"
)

// runConfig validates an endpoint config file: parses JSON, validates the
// transport section, and (optionally) attempts broker resolution.
//
//   swarm config validate path/to/config.json [--resolve]
func runConfig(args []string) {
	if len(args) == 0 {
		fatalf("usage: swarm config <subcommand> [args]\n  subcommands: validate")
	}
	switch args[0] {
	case "validate":
		runConfigValidate(args[1:])
	default:
		fatalf("unknown config subcommand %q", args[0])
	}
}

func runConfigValidate(args []string) {
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	resolve := fs.Bool("resolve", false, "attempt to resolve broker address (DNS SRV lookup)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: swarm config validate <path> [--resolve]")
		fs.PrintDefaults()
	}
	usageOnError(fs, args)

	if fs.NArg() != 1 {
		fs.Usage()
		fatalf("expected exactly one config path")
	}
	path := fs.Arg(0)

	cfg, err := swarm.LoadEndpointConfig(path)
	if err != nil {
		fatalf("load: %v", err)
	}

	tc, err := cfg.TransportConfig()
	if err != nil {
		fatalf("transport: %v", err)
	}

	fmt.Printf("config:        %s\n", path)
	fmt.Printf("local_id:      %q\n", cfg.LocalID)
	fmt.Printf("relay_eligible: %v\n", cfg.RelayEligible)
	fmt.Printf("priority:      %v\n", cfg.Priority)
	fmt.Printf("transport:     %s\n", tc.Mode)
	if tc.PinnedRelay != nil {
		fmt.Printf("pinned_relay:  %s\n", tc.PinnedRelay)
	}
	if tc.ProbeInterval > 0 {
		fmt.Printf("probe_interval: %s\n", tc.ProbeInterval)
	}
	if tc.Threshold > 0 {
		fmt.Printf("threshold:     %s\n", tc.Threshold)
	}

	if *resolve {
		addr, err := cfg.ResolveRegistrar()
		if err != nil {
			fmt.Printf("broker:        unresolved (%v)\n", err)
		} else {
			fmt.Printf("broker:        %s\n", addr)
		}
	}

	fmt.Println("OK")
}
