# gole swarm — dedicated CLI

The swarm system is a separate binary from the original `gole` tunnel.
This directory builds `gole-swarm`, a single binary that exposes the
swarm package's zero-touch enrollment and config validation.

## Build

```
make swarm        # produces ./gole-swarm
# or
go build -o gole-swarm ./cmd/swarm
```

## Subcommands

### `swarm fingerprint`

Prints the machine fingerprint that this host would present during
enrollment. Useful for pre-approving a fingerprint on the broker
before deploying the endpoint.

```
swarm fingerprint --local-id svc-a --role agent
swarm fingerprint --local-id svc-a --role agent -v   # also prints machine_id, MAC
```

### `swarm config validate`

Loads and validates an endpoint configuration JSON file.

```
swarm config validate swarm/examples/client.json
swarm config validate ./my-config.json --resolve     # also resolves broker via DNS SRV
```

### `swarm demo`

Runs an in-process broker plus an endpoint through the full enrollment
lifecycle. No network setup required.

```
swarm demo                          # auto-approve via PreApprove
swarm demo --pending                # admin approves after a 2s delay
swarm demo --denied                 # admin denies after a 2s delay
swarm demo --role relay             # relay path: auto-approved into reserved domain
```

### `swarm version`

Prints the binary version.

## Not yet implemented

Subcommands `broker`, `endpoint`, and `admin` are pending the wire-protocol
layer that exposes the in-process `Registrar` API over the network.
Today the swarm package's broker is in-process only.
