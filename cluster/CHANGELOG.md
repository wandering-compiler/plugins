# cluster — changelog

## 0.1.0-rc.20

### The relay and the control plane log a ban set's first delivery

A relay now logs the first ban set it receives after start (`workeradmit: received the first ban set since start (version N, M banned)`), and every change after it; the unchanged set every management call carries stays silent. Until then the startup line `no saved ban set: workers are refused…` was the last word in the log and read as the current state long after a set arrived. A relay that restarted with a saved set logs when a control plane first confirms it.

The control plane logs its first successful delivery to each relay (`cluster: relay "edge" took the ban set (the first delivery to it from this control plane)`). It logged only failures and recoveries, so "delivery works" and "delivery never ran" read the same.

### Banning or unbanning an unknown worker id is refused

`BanWorkers` and `UnbanWorkers` now resolve every selected id before writing. A selection holding an id the registry does not hold (a stale list, a mistyped id in an API call) is refused `NOT_FOUND`, naming the id, and nothing is decided. Until now the update matched no row for that id and the call answered success, so the admin reported a ban that never happened.

### A relay enrols no worker until it holds the ban set

`Enroll` now refuses with `BAN_SET_UNKNOWN` (`UNAVAILABLE`) while the relay holds no ban set — after a restart without a saved set, before a control plane has called it — as attach, tunnels and renewal already did. Until then a banned key holding a valid registration code was issued a fresh 30-day certificate in that window. The refusal does not spend the code, and a worker retries it with the same code at its usual pace instead of stopping.

### Concurrent ban decisions on lagging replicas no longer share a version

A control-plane replica whose clock is behind the newest ban decision moved its own decision exactly 1 ms past it, so two such replicas deciding at once recorded the same ban-set version, and a relay could apply the set one of them read between the two commits — lifting the other's ban until the next set arrived (seconds, at most the 5-minute delivery). The step now carries a random microsecond part, which makes the collision rare; the residual case is stated as a gap in the SPEC.

### Organization, not tenant

- The documentation, comments and tests say organization where they said tenant. No
  behaviour changes.

### The relay's identity and CA are written whole or not at all

The relay key and certificate and the CA key and certificate were written with plain file writes, so a disk filling up during the first start could leave a truncated key; the next start then refused the half-written pair, and the operator following the message lost the identity. Each file is now written to a temp file, synced and renamed into place, key first, so a failed write leaves nothing and the next start mints a fresh pair. The worker's own key and certificate already were.

### The relay no longer forwards gateway-owned metadata to workers (read first)

Behaviour change. The relay's callers port now removes every metadata key only a
gateway may write — `x-w17-*` (the identity envelope and scopes), `w17-label-*`,
`w17-tx-id`, `w17-conn-id` and their grpc-gateway spellings — before a call reaches
the worker, as it already removed the ticket. A ticket holder could send them and
the worker received them as if a gateway had stamped them. Every other header still
travels. A worker that read a principal from those keys gets none now; the caller's
remaining metadata is the caller's word, never a verified identity.

### Answers given before anything was done may be retried by w17 clients

The control plane's `UNAVAILABLE` answers that come before it has called a relay or written anything — the ban set or the relay registry could not be read, the worker registry could not be read while a ban decision checked its ids, no enabled relay is registered — are now marked replay-safe, so a w17 client sends the call again as it does for a transport failure. Every other `UNAVAILABLE` (an unreachable relay, `NO_RELAY` after relays were tried, a sweep that already recorded workers) is still returned to the caller. Needs the SDK release that carries `grpcerr.ReplaySafe`.

### A reservation can name the engine its work needs

`ReserveTaskReq.engine` names what the work needs the worker to run, an opaque string the pool's user defines. For a codegen pool it is the codegen engine's version. The pool compares the strings and interprets nothing.

- **Ticket.** A ticket carries its reservation's engine. The proxy refuses a call whose `w17-cluster-engine` header names another engine, with `ENGINE_MISMATCH`, and the ticket stays unspent. A call naming no engine is let through, so a client from before engines keeps working. The caller's header never reaches the worker: the relay drops it and forwards the reservation's engine under the same key, or none for a reservation that bound none. The worker routes on the relay's word, so a caller cannot pick an engine the control plane did not bind. `tunnel.Backend.Set` carries the keys a picker vouches for.
- **Workers.** A worker announces the engines it runs in `AttachReq.engines` (`workerconn.Config.Engines`). The proxy hands a ticket only to a worker that runs its engine. A worker naming none takes any work, as before.
- **Relay.** A relay refuses a reservation for an engine no attached worker runs, with `ENGINE_NOT_CARRIED`. The control plane falls through to the next relay. A relay with nobody attached still queues the reservation, as it queues any.

An empty engine binds nothing, so a control plane and workers from before the field behave as they always did. Capacity is still the sum over the fleet; per-engine queues are not part of this.

### A panic on a relay or worker server no longer ends the process

The relay's management, worker-attach and proxy servers and the worker's server on its tunnel are built by hand, and carried no panic recovery: grpc-go lets a handler's panic end the process, so one bad request took a relay down with every queue, ticket, reservation, attached worker and running call on it. Each server now answers such a panic `INTERNAL` (the method name only), logs it with its stack, and keeps serving. A project passing its own options to `workerconn.ServeTunnel` keeps them; the recovery runs outside them.

## 0.1.0-rc.19

### The relay reads return their whole row

`RelayQuery.GetRelay` and `ListRelays` now select `removed_at` and
`ended_key`. A generated query fills every field of its response: that is a
codegen warning in this compiler release and an error in the next.

## 0.1.0-rc.18

### `DeleteRelay` ends a relay instead of deleting it; `Worker.relay_id` is a foreign key

`RelayMutation.DeleteRelay` keeps its name and its request (callers, and the Relays page's delete, need no change), but it no longer deletes the row: it **ends** the relay — `Relay.removed_at` is stamped and the new `Relay.ended_key` takes the row's own id. The row stays, with its name, address, pin and observed state, as the record of what was registered. Ending an ended or unknown relay changes nothing and is not an error, as deleting a missing row was not.

An ended relay is invisible to every read: `ListRelays` (both forms) and `GetRelay` read live relays only, so placement, the worker sweep, reservations (a handle naming an ended relay polls as `expired`), registration codes, drain, the ban delivery and the admin pages never see it. `UpdateRelay`, `RecordRelayReached` and `RecordRelayFailed` write live relays only.

`RecordWorker` files a worker only under a live relay: a relay ended between the sweep's relay list and the write is refused (`InvalidArgument`, `RELAY_ENDED`, on `relay_id`), and the sweep reports that relay as failed rather than each of its workers as refused.

**Registering a relay again** under the name of an ended one creates a new row with a new id; the ended row is never revived. `Relay.name` is now unique together with `ended_key` (`''` on every live row) instead of on its own, so two live relays still cannot share a name. Workers recorded under the old id keep pointing at the ended row until the next "Check for workers" files them under the new one.

**`Worker.relay_id` is a foreign key** to the activation's `Relay` (`fk: "@module.Relay"`), `ON DELETE RESTRICT` (`deletion_rule: BLOCK`). A worker recorded for a relay id that does not exist is refused instead of stored.

The deploy block follows: `register` upserts on `(name, ended_key)` and `unregister_sql` ends the row `local` instead of deleting it. **A seed or script of your own that upserts relays with `ON CONFLICT (name)` must now name `(name, ended_key)`** — the single-column unique index is gone, and Postgres refuses a conflict target no unique index matches.

**Before you deploy it.** The foreign key is added over existing rows, and a database whose relays were deleted before this release holds `Worker` rows naming relays that no longer exist. Adding the key over them needs the w17 platform release that adds a foreign key over existing rows `NOT VALID` and reports the orphans (`migrate apply --checks`) instead of failing the migration — the console deployed with w17ctl v0.1.0-rc.98 and later; do not apply this version with an older one. Repaired, the key can be validated (`ALTER TABLE … VALIDATE CONSTRAINT`). To repair the orphans without deleting anything, give each missing relay a row that is already ended (table names are `<registered_as>_<model>`; `codegen` here):

```sql
INSERT INTO codegen_relay (id, name, url, cert_fingerprint, enabled, removed_at, ended_key, last_error)
SELECT DISTINCT w.relay_id, 'missing-' || w.relay_id, 'missing:1', repeat('0', 64), false, NOW(), w.relay_id::text, ''
FROM codegen_worker w
WHERE NOT EXISTS (SELECT 1 FROM codegen_relay r WHERE r.id = w.relay_id);
```

## 0.1.0-rc.17

### The relay sandbox builds in the project

The `clusterrelay` sandbox now declares `build: { context: ., dockerfile: sandboxes/relay/Dockerfile }`, and the release ships the Dockerfile. A project's `compose.w17.yaml` builds the relay image from the vendored plugin (`<proto_dir>/plugins/cluster`) instead of trying to pull a tag no registry publishes; the build uses the plugin's generated pb, which `w17ctl codegen` writes there. Needs w17 platform 1.17 (`requires_w17: ">=1.17"`).

## 0.1.0-rc.16

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

## 0.1.0-rc.15

### A stalled ban-set delivery recovers, and says so

- The periodic delivery of the ban set (`KeepBansDelivered`, every 5 minutes) no longer stops for good when the control plane's database stops answering. Its registry reads ran with no deadline, so one statement that never returned — a database stalled on a full disk — held that delivery, and every later one, until the control plane was restarted. Meanwhile each relay refused every worker (`no ban set received since this relay started`). The reads are now bounded (`BanReadTimeout`, default 30 s), and the first round after the database answers again delivers.
- The periodic delivery logs a change of state. A relay, or the ban/relay registry read, that starts failing is logged once with its error, and its recovery is logged once. A relay that is deliberately down is not repeated every 5 minutes. Before, the periodic delivery logged nothing at all, and the only visible line was the relay's.
- A relay's refusals (`BAN_SET_UNKNOWN`, `BAN_SET_STALE`, a refused tunnel) now name the control plane as the one that owes the relay its ban set, and point at the control plane's log.

## 0.1.0-rc.14

### The relay sandbox builds from a fresh clone, and a volume works

- The relay image's build stops with the command to run when the generated pb is missing (`w17ctl plugin gen-pb cluster`; `src/gen` is never committed), and the build instructions in `plugin.yaml` and the Dockerfile name that step. It used to fail inside `go build` with "no required module provides package …/cluster/gen/pb".
- The image creates `/var/lib/relay` owned by the relay user (uid 10001), so a volume mounted there is writable. Docker used to create the missing path as root's, and the relay could not write its key.
- `plugin.yaml` says where the plugin runs: in the domain's storage bundle, which serves ClusterService and reads `client_cert_path` / `client_key_path`.

## 0.1.0-rc.13

### A ban ends running work, and a relay without a ban set admits nobody

- **A ban cancels the work running on the banned worker.** The relay closes the worker's tunnel as soon as it applies the ban, and every call running on it ends `WORKER_LOST` (retryable through a new placement). The admin's ban confirmation now says so.
- **A tunnel ends with its certificate.** When the certificate a tunnel was opened with (or its CA) expires, the tunnel takes no new work and stops counting toward capacity. Work already running on it gets up to `--drain-timeout` to finish, then the tunnel is closed.
- **A worker moves to a new tunnel when it renews.** `ServeTunnel` checks the certificate on disk every `RetryInterval`. When it has been renewed, the worker opens a new tunnel with it and keeps answering on the old one. A relay given a newer tunnel from the same key sends new work to the new tunnel. It no longer closes the old one: the old tunnel closes when its last call ends, or at its own certificate's expiry plus `--drain-timeout`. So a worker that renews in time keeps its capacity and its running work across the old certificate's expiry. Upgrade workers and relays together; an older worker keeps one tunnel and drops out at each expiry. A ban still closes every tunnel of the banned key at once.
- **A relay with no ban set refuses workers.** A relay holds no ban set if it was started without `--identity-dir`, or has never saved one there (a fresh deploy, or the first start after this upgrade). Until a control plane delivers a set, the relay refuses attach, tunnels and renewals with `BAN_SET_UNKNOWN` (`UNAVAILABLE`, retryable; workers retry on their own). Control planes now deliver the set every 5 minutes, so expect up to 5 minutes with no capacity after such a start. A relay with a saved set admits workers at once.
- **Every registered relay gets the ban set every 5 minutes,** enabled or not, from every control-plane replica, in addition to the delivery when a decision is taken. Each delivery is new load: per replica, every 5 minutes, the ban-set read (`FingerprintsByState` between two `BanSetVersion` reads), one `ListRelays`, and one `RelayStats` call to every registered relay over the replica's shared connection to it (see the connection reuse entry). No new query definitions, and nothing to migrate. The loop stops at the bundle's shutdown.
- **Renewal needs a recent ban set.** A relay renews a certificate only if a control plane delivered the ban set within `--ban-set-max-age` (new flag, `RELAY_BAN_SET_MAX_AGE`, default `1h`, at least `10m`). Otherwise it refuses with `BAN_SET_STALE` (retryable). Workers renew a third of the certificate's lifetime early, so a control plane that is down for hours costs nothing. If the control plane is down for longer than that early-renewal margin, certificates expire and the workers need new registration codes.
- **Upgrade the control plane together with the relays.** A relay at this version needs the periodic delivery to keep renewing.
- Clients that branch on refusal reasons gain `BAN_SET_UNKNOWN` and `BAN_SET_STALE`. Both are answered to workers only.

### `src/gen` is generated, not shipped

- **Needs w17ctl v0.1.0-rc.75 or newer.** The release no longer carries `src/gen` (the pb, the `EnvConfig` / `ClientSet` / `HandlerRegistry` contract and the feature constants). A consumer's staging generates all of it for each activation from `plugin.yaml` and the protos, and w17ctl does that from rc.75 on. An older w17ctl expects the release to carry the contract; upgrade it before you take this release.
- Nothing in your project changes: the same activation, the same env variables, the same configuration, no migration.

### Placements reuse relay connections, the ban set travels once per version, and one caller gets a share of the queue

- **One connection per relay, shared.** A control-plane replica keeps one management connection to each relay and uses it for every placement, reservation, poll, operator action and ban delivery. Before, every placement opened a new mutual-TLS connection to every enabled relay and every poll opened another. A relay row edited to a new url or fingerprint gets a new connection at once. A relay that fails gets a fresh dial on the next call; a caller that cancels or times out is not counted as the relay failing. Connections to deleted relays close at the next ban delivery (within 5 minutes). All of them close at the bundle's shutdown. A reconnect resumes the TLS session instead of doing a full handshake, and the fingerprint pin still holds on a resumed session.
- **Placements no longer wait for the relay row's observed state.** `last_seen_at` and `last_error` are written in the background after a placement or poll. A state that has not changed (still reached, or still failing with the same error) is written at most every 30 seconds per replica. Before, every placement wrote one row per relay first. A row can now lag a placement by the time one write takes. Operator actions (Check for workers, Issue a registration code, Drain) still write at once.
- **The ban set is sent once per version, not on every call.** A relay at this version answers with the ban-set version it holds (`w17-cluster-banned-held`). After that, the control plane sends that relay only the version. A relay that holds an older set refuses the call with `BAN_SET_NEEDED` before running it, and the control plane resends the call with the set. Callers never see `BAN_SET_NEEDED`. Older relays keep getting the set on every call, as before. The ban set cache also checks the version before re-reading the set, so the full set is read from the database only when a decision changed it. The decision push and the delivery every 5 minutes still send the complete set to every relay, over the shared connection, so a relay replaced by an older release at the same address is corrected within 5 minutes. A reconnect also makes the next call send the set. Bans are never pruned: the set still holds every ban ever taken, but it only travels when it changes.
- **New relay flag `--max-queue-per-caller`** (env `RELAY_MAX_QUEUE_PER_CALLER`, default `0` = half of `--max-queue`, at most `--max-queue`). It limits how many places one caller can hold in a relay's queue. Past it, the relay refuses with `CALLER_QUEUE_FULL` (`RESOURCE_EXHAUSTED`) while other callers can still queue. Granted places do not count. A caller is the signed-in user. All calls with no principal (the project's own code) are one caller, so a project that queues more than half of `--max-queue` from its own code on one relay should raise the flag. The control plane tries the next relay on `CALLER_QUEUE_FULL`. If no relay takes the request, it answers `CALLER_QUEUE_FULL` and not `NO_RELAY`. Clients that branch on refusal reasons gain `CALLER_QUEUE_FULL`: wait for the places you already hold, or cancel some.
- **`ScheduleTask` now names its caller to the relay,** like reservations already did, so streaming waiters count against the same share. As a result, `ScheduleTask` refuses a principal that names no user, or that cannot be read, with `UNAUTHENTICATED`, as `ReserveTask` already did.
- Upgrade relays and control planes in either order: each side works with the other's older version. The new share limit applies only to callers of an upgraded control plane. No new query definitions, no schema change, nothing to migrate.

### The relay enforces whom a reservation belongs to

The relay that holds a reservation records whom it was made for, so a reservation handle that leaks is useless to whoever finds it, even if they rewrite any part of it.

- **The relay records the owner.** The control plane sends a hash of the reserving caller on every reservation call. The relay keeps it with the reservation and answers a poll or cancel under any other owner exactly like an id it never issued: `expired` (`RESERVATION_UNKNOWN`), or a cancel that succeeds and leaves the place. A stranger's poll neither keeps the reservation alive nor starts its claim window. The hash is a stable pseudonym per user, not a secret: it keeps user ids out of relay memory, not out of reach of the operator who runs the relays.
- **Upgrade the relays together with the control plane.** A control plane at this version refuses a relay that does not confirm the binding: it gives that relay's place back and tries the next. If no relay takes the reservation, `ReserveTask` answers `NO_RELAY` and names every relay that must be upgraded. `ScheduleTask` is not affected. A relay at this version still serves an older control plane, unbound as before.
- **Handles in flight across the upgrade do not survive it.** Reservations live in relay memory and last seconds without a poll, so a relay restart drops them anyway. A client polling across the deploy sees `expired` and reserves again.

### Built on SDK go/v0.1.0-rc.24

- **The plugin's module requires `github.com/wandering-compiler/sdk/go` v0.1.0-rc.24.** A w17ctl that knows the request data annotations (`gdpr`, `sensitive`) generates a redaction plan next to every pb file of the plugin's `src/gen`, and that plan imports the SDK's `lib/redact`, which rc.24 is the first to have. The plugin's own code does not change.
- Nothing in your project changes: the same activation, the same env variables, no migration. Your project's own `go.mod` moves to rc.24 with the same w17ctl.

### A reservation handle works only for the caller it was handed to

A reservation handle was an unguessable credential, but anyone holding it, for example one that leaked through a log or a client, could poll the reservation, collect its grant or cancel the place. Now only the caller that reserved can.

- **Who the caller is:** the signed-in user (read from the gateway envelope, field 2), or, for a call with no envelope, the project's own code. The two never mix: a handle reserved by project code works only for calls with no principal, and one reserved by a user only for that user. An envelope that is present but unreadable, or names no user, is refused (`Unauthenticated`) instead of being treated as a call with no principal.
- **The relay holding the place enforces it** (see "The relay enforces whom a reservation belongs to"). The control plane still stores nothing.
- **The handle gains a third part:** a tag computed from the caller and the rest of the handle, which lets the control plane turn away another caller's handle without contacting the relay. The tag is not what keeps a leaked handle from working; the relay's check is.
- **Poll from the identity you reserved under.** Project code that reserves while serving a user's request carries that user's principal, so a job that later polls without it sees the place as gone. Reserve from a context without the user's principal when something else will poll.
- **Another caller's handle answers like a reservation the relay forgot.** A poll reads it as expired (`RESERVATION_UNKNOWN`), and a cancel succeeds without touching the place, so the answer does not confirm the handle was real.
- **Handles minted by an earlier version** (two parts) are refused as malformed. Reservations are short-lived, so one in flight across the upgrade has to be made again.

### Placement and polling cost less

- **The ban set is cached for two seconds** instead of being read from the registry on every relay-bound call. A decision through a replica drops that replica's cache at once, and the replica pushes the new set to every relay.
- **`Worker.state` and `Worker.decided_at` are indexed.** The ban set is read by state and its version is `MAX(decided_at)`, and worker rows are never deleted. Generate a migration as usual.
- **A placement writes a reachable relay's `last_seen_at` at most every 30 seconds per replica,** not once per relay on every placement. A failure is still recorded every time, and the next success after it is recorded at once. Operator actions (Check for workers, Issue a registration code, Drain) still record every time. The writes a placement does make run in parallel, so a slow database delays it by one write timeout, not one per relay.


### Bans reach every relay, in order, and survive a relay restart

Three gaps let a banned worker keep working or renewing:

- **An older ban set could overwrite a newer one.** Control-plane replicas read the set at different moments. The set now carries a version (`w17-cluster-banned-version`: the time of the newest ban or unban decision, from the new `WorkerQuery.BanSetVersion`), and a relay ignores a set older than one it has applied. A decision is never recorded older than the newest one (its time is moved just past it), so a replica whose clock runs behind cannot lower the version. A control plane that sends no version is applied as before. The version is read before and after the set, and a pair is sent only when the two agree, so a decision landing mid-read cannot label a newer set with an older version.
- **A restarted relay knew no bans** until the control plane next called it, and a banned worker could renew its certificate in that window. With `--identity-dir` (the sandbox sets it), the relay keeps the set in `bans.json` there and loads it at start. An unreadable file refuses the start.
- **A disabled relay never heard of a ban,** because nothing reaches a disabled relay, and its workers went on renewing. A ban or unban is now delivered to every registered relay at once, enabled or not, in parallel, so the operator waits at most one dial timeout (best effort; an unreachable relay gets it with its next call, which for a disabled one is only a reservation poll).

### A ban cuts the banned worker's open tunnel

A ban stopped new work at the next check, but the tunnel a worker had already opened stayed connected, and the call running on it finished. The admin's ban confirmation says connections are dropped.

- **The relay closes a banned worker's tunnel as soon as the ban set reaches it** (`workeradmit.Registry.OnBansChanged` → `Backends.DropWhere`). Closing the connection ends the calls still running on it.
- **The attach stream** still ends at its next poll, as before.
- **A call cut that way ends with `WORKER_LOST`** (Unavailable) at the caller, not a `Canceled` that read as the caller's own doing, and its ticket's slot is returned.
- **A tunnel that was opening when the ban arrived** is closed too: admission is checked again once the tunnel is registered.
- **A worker banned and unbanned before its attach stream noticed** keeps its announced capacity when it reconnects its tunnel.

### A worker's announced slot count is capped

A worker's slot count is its own claim, and nothing checked it. One key could announce enough slots to drain a relay's whole queue, and a count above the int32 range made `RelayStats` report a negative capacity.

- **New relay flag `--max-worker-slots`** (env `RELAY_MAX_WORKER_SLOTS`, default 64, allowed 1–65536; any other value fails at start).
- **A higher announced count is held to the cap**, and the attach admission reports the slots the worker actually got.
- **`RelayStats` holds every count at the int32 maximum** instead of wrapping, so a large fleet can no longer report a negative capacity either.

### `ticket_ttl_seconds` is removed

The manifest described it as how long a granted ticket stays claimable, but nothing read it. The claim window is the relay's `--ticket-ttl` (`RELAY_TICKET_TTL`), which the relay that holds the slot decides. A project that sets the old variable loses nothing. Set the relay flag instead.

### A relay's queue of waiting callers is bounded

The relay queued every caller that asked for a slot, without limit and in strict order, and it scanned the whole queue for each position report. A flood of reservations grew memory and timers without end.

- **New relay flag `--max-queue`** (env `RELAY_MAX_QUEUE`, default 1000, at least 1). Past it, a new waiter is refused with `RESOURCE_EXHAUSTED` and the reason `QUEUE_FULL`. A caller that gets a slot at once never counts against the queue.
- **The control plane falls through to the next relay on `QUEUE_FULL`**, as on a draining one. When every relay's queue is full, its caller is told `NO_RELAY` (retryable), as for any pool with nothing placeable.

## 0.1.0-rc.12

Dependencies only: `golang.org/x/net` v0.60.0, which fixes GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610 and GO-2026-6603, together with `golang.org/x/sys` and `x/text`. Nothing in the plugin's behaviour changes. Take it with `w17ctl plugin update cluster`.

## 0.1.0-rc.11

The same plugin as 0.2.0-rc.10, back on the version line every plugin and the platform share: `0.1.0-rc.N`. The 0.2.0 releases were a numbering mistake, not a break with 0.1.0 — nothing about them is a second line.

Move with `w17ctl plugin update cluster --to v0.1.0-rc.11`: the 0.2.0 tags still exist for now, and `update` without `--to` takes the highest release, which is still a 0.2.0 one until they are removed. Nothing in the plugin changes.

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
