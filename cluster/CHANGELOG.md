# cluster — changelog

## 0.2.0-rc.7

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
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
- **A registry refusal during fleet discovery is classified by gRPC code.** A database outage aborts the sweep. Before, it looked like every worker being refused, and the sweep returned OK with nothing recorded.
- **A worker the registry refuses for its own data is skipped and logged.** A refusal of a relay-level field (`relay_id`, `cert_fingerprint`) counts as that relay failing.
- **The control plane cleans every reported claim before recording it**, whatever the relay version.
- **The client certificate and key are checked as a pair at boot**, both by the plugin and by the relay's identity. Before, a truncated or mismatched key was found only when dialling.
- **The tunnel's HTTP/2 handshake is bounded at 20 s.** Before, a relay that vanished mid-handshake held the worker for 120 s.
- **A refused control-plane connection is logged by the relay** with the presented and expected fingerprints, and where the pin is set.
- **A start that fails part-way closes the ports it had already bound.**
