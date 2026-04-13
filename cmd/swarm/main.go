// Command swarm is the dedicated CLI for the gole swarm system.
//
// Subcommands:
//   fingerprint   Print the machine fingerprint for a (local_id, role) pair
//   config        Validate an endpoint configuration file
//   demo          Run an in-process broker + endpoint to exercise the
//                 zero-touch enrollment flow end-to-end
//   version       Print version information
//
// Subcommands `broker`, `endpoint`, and `admin` are placeholders pending
// the wire-protocol layer that exposes the in-process Registrar API
// over the network.
package main

import (
	"flag"
	"fmt"
	"os"
)

const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "fingerprint", "fp":
		runFingerprint(args)
	case "config":
		runConfig(args)
	case "demo":
		runDemo(args)
	case "version", "-v", "--version":
		fmt.Printf("gole swarm v%s\n", Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `gole swarm — zero-touch swarm CLI

Usage:
    swarm <command> [flags]

Commands:
    fingerprint   Print this machine's enrollment fingerprint
    config        Validate an endpoint configuration file
    demo          Run an in-process broker + endpoint demo
    version       Print version information
    help          Show this message

Run "swarm <command> -h" for command-specific flags.
`)
}

// fatalf prints to stderr and exits non-zero.
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	if len(format) == 0 || format[len(format)-1] != '\n' {
		fmt.Fprintln(os.Stderr)
	}
	os.Exit(1)
}

// usageOnError prints subcommand usage if -h is requested.
func usageOnError(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
}
