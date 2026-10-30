### The spent ticket stops at the relay, and two mistyped settings are refused at boot

- The proxy no longer forwards the `w17-cluster-ticket` header to the worker:
  the relay consumed it. Every other header the caller sends still reaches the
  worker.
- A relay whose `--control-plane-fingerprint` is not 64 hex characters (a
  colon-separated openssl fingerprint, a truncated paste) refuses to start. It
  used to start and refuse every control plane.
- A negative `dial_timeout_seconds` is refused at boot instead of becoming
  5 s. Zero, the unset value, still means 5 s.
- Contract comments no longer promise a ledger or an audit trail the plugin
  does not keep.
