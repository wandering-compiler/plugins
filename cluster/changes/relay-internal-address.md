### A caller in the relay's own stack reaches it without leaving the host

A grant now carries, beside the public address (`address`), the relay's
address on its own network (`TaskGranted.internal_address`). The deploy block
sets it with `RELAY_INTERNAL_ADDRESS` to the callers port on the stack's
network, and a relay run by hand takes `--internal-address`.
`lib/relaydial.DialGranted` dials the internal address first and falls back
to the public one, each pinned to the grant's fingerprint.

Before, a caller in the same stack (another domain leasing browsers) could
only dial the public address. That is the host's own public IP, which Docker
does not translate back into the stack. On a host whose firewall denies
incoming traffic by default the call was dropped, and the lease failed, while
the deploy reported the worker admitted. A caller that keeps dialling
`address` itself still needs the host rule `allow in on docker_gwbridge to
any port <published port>`.
