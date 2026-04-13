# Documentation

- [`architecture.md`](architecture.md) — swarm system design: addressing, identity, enrollment flow, state machine, transport modes, reachability, and file layout.
- [`zero-touch-enrollment-plan.md`](zero-touch-enrollment-plan.md) — original implementation plan for the zero-touch enrollment refactor. Captures the rationale, API surface, state transitions, and task breakdown.

The binary CLI docs live alongside the command source:

- [`../cmd/swarm/README.md`](../cmd/swarm/README.md) — `gole-swarm` subcommands and usage.

The swarm package itself (`../swarm/`) has godoc comments on every
exported type — run `go doc github.com/shawwwn/gole/swarm` or open
`https://pkg.go.dev/github.com/shawwwn/gole/swarm` for the full API.
