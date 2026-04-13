package main

import (
	"flag"
	"fmt"

	"github.com/shawwwn/gole/swarm"
)

// runFingerprint prints the machine fingerprint that this host would
// present during zero-touch enrollment for the given (local_id, role).
//
//   swarm fingerprint --local-id svc-a --role agent
func runFingerprint(args []string) {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	localID := fs.String("local-id", "", "local instance ID (distinguishes multiple endpoints on one machine)")
	role := fs.String("role", "client", "role: client | agent | relay")
	verbose := fs.Bool("v", false, "print machine_id and primary MAC alongside fingerprint")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: swarm fingerprint [--local-id ID] [--role R] [-v]")
		fs.PrintDefaults()
	}
	usageOnError(fs, args)

	if _, err := swarm.ParseRole(*role); err != nil {
		fatalf("invalid role %q: %v", *role, err)
	}

	if *role == "relay" {
		fmt.Println("(relays do not use fingerprints — they auto-enroll into reserved domain 0)")
		return
	}

	mid, err := swarm.MachineID()
	if err != nil {
		fatalf("machine id: %v", err)
	}
	mac, _ := swarm.PrimaryMAC()
	fp := swarm.Fingerprint(mid, mac, *localID, *role)

	if *verbose {
		fmt.Printf("machine_id:  %s\n", mid)
		if mac == "" {
			fmt.Println("primary_mac: (none detected)")
		} else {
			fmt.Printf("primary_mac: %s\n", mac)
		}
		fmt.Printf("local_id:    %q\n", *localID)
		fmt.Printf("role:        %s\n", *role)
		fmt.Printf("fingerprint: %s\n", fp)
		return
	}
	fmt.Println(fp)
}
