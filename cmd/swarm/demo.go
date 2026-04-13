package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/shawwwn/gole/swarm"
)

// runDemo spins up an in-process broker and walks an endpoint through
// the full zero-touch enrollment lifecycle. Useful for sanity-checking
// the swarm package without any network setup.
//
//   swarm demo                 # auto-approve via PreApprove
//   swarm demo --pending       # leave endpoint in pending, simulate admin approval after delay
//   swarm demo --denied        # simulate admin denial
func runDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	pending := fs.Bool("pending", false, "skip pre-approval; admin approves after a delay")
	denied := fs.Bool("denied", false, "skip pre-approval; admin denies after a delay")
	role := fs.String("role", "agent", "role: client | agent | relay")
	localID := fs.String("local-id", "demo", "local instance ID")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: swarm demo [--pending|--denied] [--role R] [--local-id ID]")
		fs.PrintDefaults()
	}
	usageOnError(fs, args)

	if *pending && *denied {
		fatalf("--pending and --denied are mutually exclusive")
	}

	roleFlag, err := swarm.ParseRole(*role)
	if err != nil {
		fatalf("invalid role: %v", err)
	}

	fmt.Println("==> spinning up in-process broker")
	reg, err := swarm.NewRegistrar(time.Hour)
	if err != nil {
		fatalf("new registrar: %v", err)
	}

	cfg := &swarm.EndpointConfig{
		LocalID:       *localID,
		RelayEligible: true,
	}

	fp, err := swarm.DeriveFingerprint(*localID, *role)
	if err != nil {
		fatalf("derive fingerprint: %v", err)
	}
	fmt.Printf("    fingerprint: %s\n", fp)

	// Pre-approval path (default): broker auto-completes
	if !*pending && !*denied && roleFlag != swarm.RoleRelay {
		fmt.Println("==> pre-approving fingerprint into domain 1, group 1")
		if err := reg.PreApprove(fp, 1, 1); err != nil {
			fatalf("pre-approve: %v", err)
		}
	}

	ep, err := swarm.NewEndpoint()
	if err != nil {
		fatalf("new endpoint: %v", err)
	}

	// Run admin actions concurrently for pending/denied scenarios
	if *pending || *denied {
		go func() {
			time.Sleep(2 * time.Second)
			pendings := reg.ListPending()
			if len(pendings) == 0 {
				fmt.Println("    [admin] no pending enrollments yet")
				return
			}
			pe := pendings[0]
			if *denied {
				fmt.Printf("    [admin] denying %s (fp=%s)\n", pe.RequestID, pe.Fingerprint)
				if err := reg.DenyEnrollment(pe.RequestID); err != nil {
					fmt.Printf("    [admin] deny error: %v\n", err)
				}
			} else {
				fmt.Printf("    [admin] approving %s (fp=%s) into 2.3\n", pe.RequestID, pe.Fingerprint)
				if err := reg.ApproveEnrollment(pe.RequestID, 2, 3); err != nil {
					fmt.Printf("    [admin] approve error: %v\n", err)
				}
			}
		}()
	}

	fmt.Println("==> running AutoEnroll")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := ep.AutoEnroll(ctx, reg, roleFlag, cfg, 500*time.Millisecond); err != nil {
		fatalf("AutoEnroll failed: %v", err)
	}

	fmt.Printf("==> registered as %s\n", ep.Addr())
	fmt.Printf("    state: %s\n", swarm.StateName(ep.State()))
	fmt.Printf("    token: %s...\n", truncate(ep.Token(), 40))

	if err := ep.Activate(reg); err != nil {
		fatalf("activate: %v", err)
	}
	fmt.Printf("==> activated, state: %s\n", swarm.StateName(ep.State()))

	if len(ep.Relays()) == 0 {
		fmt.Println("    relays available: 0")
	} else {
		fmt.Printf("    relays available: %d\n", len(ep.Relays()))
		for _, r := range ep.Relays() {
			fmt.Printf("      - %s\n", r.Addr)
		}
	}

	fmt.Println("==> done")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
