# cluster

A placement broker for a pool of workers. The control plane registers relays,
picks one, and hands the caller an address, a pinned certificate and a
single-use ticket. The relay proxies one gRPC call to a worker for that ticket.

The plugin never sees the work: it has no task table, no result and no retry.
What a call does, and what happens when it fails, is the caller's and the
worker's business. Activate it once per pool, under the pool's name:

```proto
plugins: [ { source_name: "cluster", registered_as: "codegen" } ]
```

It has three programs:

- the **control plane**, the handlers staged into the project that activates
  the plugin;
- the **relay** (`src/cmd/relay`), a separate binary that holds the queue and
  is the certificate authority for its own workers;
- the **worker library** (`src/lib/workerconn`), which a worker program links
  to enrol, attach and serve work over a reverse tunnel.

[SPEC.md](SPEC.md) states the security, consistency and failure properties an
application built on it relies on.
