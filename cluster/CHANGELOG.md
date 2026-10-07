# cluster — changelog

## 0.2.0-rc.10

### The relay and a worker can be deployed beside the project

The manifest declares a `deploy:` block: the relay (built from this plugin's source), a worker whose image the project chooses, the identities a deploy mints for them, and the row that registers the relay as `local`. A project runs them on its own machine by naming the worker's image in its lock, for example `w17ctl infra update --plugin prod:codegen.worker=bundle:<bundle>`. Only the relay's caller port is published; management, attach and tunnels stay on the internal network, and every connection stays TLS with certificates the deploy mints.

The swarm target renders it. The aws-ecs and gcp-cloudrun targets refuse it, because Fargate and Cloud Run have no shared host.

When an environment stops deploying it, the next deploy deletes the `local` row.

Needs w17 platform 1.8 (`requires_w17: ">=1.8"`). Nothing changes for a project that does not deploy the activation. A relay on another machine is still run by hand and registered in the admin.

## 0.2.0-rc.9

### A relay address with an IPv6 zone is refused

0.2.0-rc.8 accepted an IPv6 address with a zone (`[fe80::1%eth0]:13444`), but gRPC cannot dial one: the target fails to parse, so every placement on that relay failed. The zone is no longer accepted. A link-local address means nothing to a relay on another machine; use a routable address or a DNS name.

A project that vendors this release needs a schema migration (the `url` CHECK changes). If a stored relay has a zone in its address, the migration refuses and names the constraint; that relay could never be reached, so fix or delete the row.

## 0.2.0-rc.8

### Register a relay from the admin

The Relays admin page can now create a relay: name, management address and certificate fingerprint, over `RelayMutation.CreateRelay`. Use it for a relay on another machine. A relay deployed beside the control plane is registered by its deployment and does not need the form.

The new endpoint adds a permission, so a project that vendors this release needs a schema migration (`w17ctl migrate generate`).

### The relay's address and fingerprint are validated when written

- `url` must be a bare `host:port`:
  - the host can be a DNS name (a public name, an internal service name such as `clusterrelay:13444`, or a swarm `<stack>_<service>` name), an IPv4 address, or a bracketed IPv6 address;
  - the port must be 1–65535;
  - a scheme such as `https://` is refused, because the value is dialled as a gRPC target.
- `cert_fingerprint` must be 64 lowercase hex characters. Colons, capitals and short values are refused.

Before this release, both kinds of mistake were stored and failed only on the first dial, as a connection error or a pin mismatch.

The rules are checked twice:
- The create and update requests check them first, so a bad value is refused on that field with a message that names the expected shape.
- The table also gets CHECK constraints. If an existing row violates one, the migration refuses to apply and names the constraint; fix the row first.

## 0.2.0-rc.7

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
- A generated `go.mod` may keep a `replace` line for the old path beside the new one. It is harmless, and you may delete it.
- Hand-written code that imports the plugin's packages directly (a `lib/…` package, say) must change its import paths. It must also change any `replace` directive in its own `go.mod` that names the old module path.

### Behaviour an operator will notice
- **The relay refuses to start on a malformed `RELAY_*` value**, naming the variable. Before:
  - `RELAY_TICKET_TTL=60` (no unit) ran with a 30 s TTL;
  - a negative `RELAY_CAPACITY` meant no ceiling;
  - `8x` was read as 8.

  Flags are parsed first: `-h` always shows usage, and a flag given explicitly excuses its own variable. Stray arguments are refused.
- **A new worker whose name or device id breaks the claim rule is refused at enrolment** with `WORKER_CLAIM_INVALID`. The rule:
  - at most 128 characters;
  - valid UTF-8;
  - no control characters and no invisible format characters (so multi-part emoji, which contain zero-width joiners, are refused).

  Already-enrolled workers keep attaching; their claims are cleaned instead.
- **`CheckWorkersResp` gains `skipped_workers`.**

### Fixes
- **A registry failure during fleet discovery is no longer blamed on the relay.** Before, a failure to write a worker marked a healthy relay unreachable and wrote the database error onto its row. Now:
  - a refusal is classified by gRPC code;
  - a database outage aborts the sweep;
  - a worker refused for its own data is skipped.
- **A worker the registry refuses for its own data is skipped and logged.** A refusal of a relay-level field (`relay_id`, `cert_fingerprint`) counts as that relay failing.
- **The control plane cleans every reported claim before recording it**, whatever the relay version.
- **The client certificate and key are checked as a pair at boot**, both by the plugin and by the relay's identity. Before, a truncated or mismatched key was found only when dialling.
- **The tunnel's HTTP/2 handshake is bounded at 20 s.** Before, a relay that vanished mid-handshake held the worker for 120 s.
- **A refused control-plane connection is logged by the relay** with the presented and expected fingerprints, and where the pin is set.
- **A start that fails part-way closes the ports it had already bound.**
