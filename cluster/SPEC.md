# cluster — behaviour specification

This document says what the `cluster` plugin does and what it must never do:
the security, consistency, performance and failure properties an application
built on it relies on. It is the reference the plugin's tests and the example
projects are measured against. A property listed here without a proof is a
gap, not a promise.

It covers plugin version 0.1.0-rc.12.

## What the plugin is, and what it is not

`cluster` is a **placement broker** for a pool of workers. It has three
programs:

- the **control plane**: the handlers staged into the activating project. They
  keep the relay and worker registries, choose a relay, and hand the caller an
  address, a pinned certificate fingerprint and a single-use **ticket**;
- the **relay**: a separate binary built from the plugin (`cmd/relay`). It
  holds the queue, the capacity and the tickets in memory, is a certificate
  authority for its own workers, and proxies a caller's gRPC call to a worker
  without decoding it;
- the **worker library** (`lib/workerconn`): what a worker program links to
  enrol, renew its certificate, attach, and serve work over a reverse tunnel.

The plugin never sees the work. It has no task table, no task identity, no
result, no retry and no redelivery. One ticket buys one proxied gRPC call on
one worker, at most once; what the call does and what happens when it fails is
the caller's and the worker's business. Several properties that a job queue
would have to guarantee (results accepted once, poison-task quarantine, retry
limits) are therefore out of scope here, and the invariants below state the
narrower contract the plugin actually offers: **slots, not tasks**.

The plugin is activated once per pool under the pool's name
(`registered_as: codegen`, `registered_as: browser`), which prefixes its
tables. There is no tenant or organization dimension anywhere in it.

## How to read it

- Every **invariant** is one MUST or MUST NOT statement about observable
  behaviour, with a stable id (`base/<name>`, `interaction/<a>-<b>-<name>`,
  `cluster/<name>`). Ids do not change when the wording does, so tests and
  examples can cite them.
- **Categories:** Security · Consistency & concurrency · Performance · Failure &
  configuration.
- **Proof** names the unit tests in `cluster/src/handlers`, `cluster/src/lib/…`
  and `cluster/src/cmd/relay` that demonstrate the invariant. The handler tests
  run against in-memory fakes of the generated storage clients, and against
  real relay servers stood up in-process over real TLS. The relay-side tests
  (`relaycore`, `relayserver`, `workerconn`, `cmd/relay`) exercise the real
  code paths, including real TLS handshakes and real tunnels, because the relay
  has no database. What only a database can enforce (a unique index, a CHECK
  constraint, an `UPSERT … ON CONFLICT`, a `WHERE id IN (…)` update) is marked
  **unit (mock) only** with what a live test would have to show. `none` means
  nothing proves it yet.
- The plugin declares **no REST endpoints** and **no events**. Every surface is
  gRPC (`ClusterService`, plus the generated `RelayQuery`/`RelayMutation`/
  `WorkerQuery`/`WorkerMutation` storage services and the admin preset that
  calls them). Who may call each RPC is decided by the project's gateway ACL;
  the plugin adds no authorization of its own except where stated.
- **Gaps / suspected defects** after each area are what the code does not
  enforce although the invariant requires it, found by reading the code. The
  ones re-checked against the code are collected under
  [Verified findings](#verified-findings).

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| (base tier) | always | — | — |

The manifest declares no features. A ledger feature was once declared and was
removed before it shipped because nothing was staged behind it. Two contract
comments still refer to it (see `base` registry gap 3). No `go_files_combined`.

**Env knobs (control plane).** `client_cert_path`, `client_key_path`
(required; loaded and parsed as a pair at boot), `dial_timeout_seconds`
(default 5; `<= 0` uses 5). The claim window of a ticket is the relay's
`--ticket-ttl`, not a control-plane knob (finding 6).

**Relay configuration** (flags, each defaulted from a `RELAY_*` variable):
listeners `--listen` (management, 13444), `--attach-listen` (13446),
`--tunnel-listen` (13445), `--proxy-listen` (callers, 9000); `--proxy-address`
and `--control-plane-fingerprint` (required); identity `--cert/--key` or
`--identity-dir`; worker CA `--ca-cert/--ca-key` or `--identity-dir`;
`--capacity` (optional ceiling, 0 = none), `--max-worker-slots` (64, 1–65536:
the most slots one worker is credited with), `--max-queue` (1000, at least 1),
`--ticket-ttl` (30s),
`--poll-interval` (3s), `--poll-timeout` (10s, at least twice the interval),
`--registration-code-ttl` (15m), `--worker-cert-lifetime` (30 days),
`--drain-timeout` (15m). Subcommands `mint` and `issue-worker`.

**Sandbox.** `clusterrelay`: the relay image, minting its identity and worker
CA inside the container, with `RELAY_CONTROL_PLANE_FINGERPRINT` empty on
purpose so it refuses to start until set.

**Deploy block.** A relay service (only the callers port published), a worker
service whose image the project chooses, three identities minted at deploy time
(relay with CA, control plane, worker issued directly from the relay CA), and
a `register`/`unregister_sql` pair that maintains the relay row `local`.

**Admin preset.** Relays page (list, detail, create, update, delete; actions
"Issue a registration code" with a secret result, and "Drain"). Workers page
(list, detail, no edit or delete; actions "Check for workers", "Ban", "Unban").

## Verified findings

Gaps confirmed by re-reading the code. Each is a defect to fix, or a contract
to state, before an example may claim the invariant; the invariant id says
which.

| # | finding | invariants | where |
|---|---|---|---|
| 1 | The reservation handle is a bearer credential that the plugin does not bind to the principal that created it. Any caller the ACL lets reach `GetReservation` collects the grant (address and ticket) of any handle it holds, and any caller of `CancelReservation` gives away another caller's place. The proto says the binding is the caller's job, but no hook or principal check exists for a project to use. Guessing is infeasible (256 random bits plus the relay id); the exposure is a leaked handle, for example in a log or a shared client. | `base/reservation-handle-bound` | `src/handlers/reservation.go` (`GetReservation`, `CancelReservation`, `resolveHandle`) |
| 2 | **Bound fixed; fairness open.** `--max-queue` (default 1000) now caps a relay's waiters: past it `Pool.Reserve` and `Pool.Wait` refuse with `QUEUE_FULL`, a control plane falls through to the next relay, and an all-full pool answers `NO_RELAY`; the cost of the linear scans is bounded by the cap. Still open: no limit per caller. As found: nothing bounded the queue. `Pool.Reserve` and `Pool.Wait` appended to an unbounded slice and map, with no limit per relay and none per caller. A caller allowed `ReserveTask` can add reservations as fast as it can call (each lives 10 s unpolled, indefinitely when polled), which grows relay memory and pushes every later caller back in a strict FIFO. Queue position and change notification are linear scans, so the cost per mutation and per poll grows with the queue. | `base/queue-bounded`, `cluster/fairness` | `src/lib/relaycore/relaycore.go` (`Reserve`, `enqueueLocked`, `positionLocked`, `notifyLocked`); `src/handlers/reservation.go` (`ReserveTask`) |
| 4 | A ban ends the worker's attach stream and stops new work reaching it, but neither its tunnel nor the work already running on it. The tunnel is checked against bans and certificate validity only when it is accepted, so a tunnel opened before a ban (or before the certificate expired) stays a connected backend until the worker hangs up. The admin's ban confirmation says relays "drop their connections". | `base/ban-ends-running-work`, `base/tunnel-revalidated` | `src/lib/relayserver/tunnellistener.go` (`acceptTunnel`), `workerattach.go` (`holdAdmitted`) |
| 5 | Bans reach a relay only as the complete set on the next control-plane call, and the relay replaces its set wholesale with whatever arrives, with no version. (a) Two console replicas can deliver an older set after a newer one, lifting a fresh ban until the next call. (b) A restarted relay holds no bans until its first contact, and in that window a banned key can attach and **renew its certificate** (`Renew` checks only the in-memory set). (c) A disabled relay is never contacted (`ListEnabled`), so it never learns bans taken after it was disabled and keeps renewing those workers' certificates. | `base/ban-reaches-every-relay`, `base/banned-key-cannot-renew` | `src/lib/workeradmit/workeradmit.go` (`SetBanned`), `src/lib/relayserver/enroll.go` (`Renew`), `src/handlers/schedule_task.go` (`placeable`), `check_workers.go` (`CheckWorkers`) |
| 6 | **Fixed (removed).** `ticket_ttl_seconds` was inert. The manifest described it as "how long a granted ticket stays claimable", but `RegisterPlugin` never read it and the generated config called it advisory, so an operator who set it changed nothing. The knob is gone from `plugin.yaml` and `EnvConfig`; the claim window is the relay's `--ticket-ttl`. | `cluster/boot-no-inert-knob` | `plugin.yaml` (`env`), `src/gen/interfaces.go` (`EnvConfig`) |
| 7 | Every `ScheduleTask` and `ReserveTask` opens a new TLS connection (full handshake: a fresh `tls.Config` and no session cache per dial) to **every** enabled relay and writes one `UPDATE` per enabled relay row (`RecordRelayReached` or `RecordRelayFailed`). Those writes run one after another, before the placement proceeds, each with its own 5 s timeout, so a slow database delays every placement by up to 5 s per relay even though a failed write is ignored. Every `GetReservation` poll (default every 3 s per waiting client) reads the full ban set and opens a new TLS connection. The cost of one placement is linear in the number of relays, in handshakes and in database writes. | `base/placement-cost-bounded`, `base/observed-state-off-hot-path` | `src/handlers/schedule_task.go` (`placeable`, `poll`, `noteOK`, `dialReady`), `reservation.go` (`GetReservation`), `src/lib/relaydial/relaydial.go` (`Dial`) |
| 8 | The ban-set read behind every relay-bound call (`FingerprintsByState`) filters `Worker.state`, which has no index, and returns the whole set. The set is sent in one `w17-cluster-banned` header. Bans never expire and Worker rows are never deleted, so both the scan and the header grow without bound for the life of the pool. | `cluster/lookups-indexed`, `cluster/ban-set-bounded` | `proto/queries/worker_query.proto` (`FingerprintsByState`), `proto/types/models.proto` (`Worker.state`), `src/lib/workeradmit/workeradmit.go` (`WithBans`) |

## Per feature

### (base tier)

- **Purpose.** Everything the plugin does: the relay registry, placement, the
  relay's queue and tickets, the proxy, worker identity and admission, the ban
  registry, drain and shutdown. Always present. It is described below by area.
- **Adds.** Tables `Relay` (`name` SLUG unique; `url` CHECK `host:port`, no
  scheme, no IPv6 zone; `cert_fingerprint` CHECK 64 lowercase hex; `enabled`
  default true; observed `last_seen_at`, `last_error`) and `Worker`
  (`cert_fingerprint` unique, the SPKI hash of the worker key; claims `name`,
  `device_id`; `state` ENROLLED or BANNED; `relay_id` indexed, not a foreign
  key; `decided_at`, `decided_by`). Queries `ListRelays`, `GetRelay`,
  `ListWorkers`, `GetWorker`, `FingerprintsByState`, `CountWorkersByState`.
  Mutations `CreateRelay`, `UpdateRelay`, `DeleteRelay`, `RecordRelayReached`,
  `RecordRelayFailed`, `RecordWorker` (UPSERT on fingerprint), `BanWorkers`,
  `UnbanWorkers`. Service `ClusterService`: `ScheduleTask` (server stream),
  `ReserveTask`, `GetReservation`, `CancelReservation`, `CheckWorkers`,
  `IssueRegistrationCode`, `BanWorkers`, `UnbanWorkers`, `DrainRelay`; the
  relay-only `ExchangeWorkers` and `RelayStats` answer Unimplemented on the
  control plane, and the control-plane-only `CheckWorkers`, `BanWorkers`,
  `UnbanWorkers` answer Unimplemented on a relay. Worker protocol
  (`workerpb`, not staged into the project): `WorkerEnrollment.Enroll`,
  `WorkerEnrollment.Renew`, `WorkerAttach.Attach`. No REST endpoints, no
  events, no MCP tools.
- **Requires / conflicts / combined files.** None. The ban and unban actions
  need a verified principal envelope carrying a user id at field 2 (the auth
  plugin's `AuthResp.user_id`), see `interaction/auth-cluster-decided-by`.

#### Relay registry

| id | invariant | category | proof |
|---|---|---|---|
| `base/relay-dialled-only-if-registered` | The control plane MUST dial only `url`s held in the registry, and for placement only rows with `enabled = true`. Nothing a caller sends may name a relay address. | Security | `TestRelayStore_ListEnabledAsksForEnabledOnlyAndMapsTheRow`. **Unit (mock) only** for the `enabled` predicate: a live test would disable a row and assert no placement and no dial reaches that relay. |
| `base/relay-pinned` | Every connection to a relay MUST verify the relay's leaf certificate against the row's `cert_fingerprint`, on full and on resumed TLS handshakes. A row with an empty pin MUST NOT be dialled. Chain validation is replaced by the pin, never by nothing. | Security | `TestDial_RefusesARelayThatIsNotThePinnedOne`, `TestPinnedVerifier_RefusesAnotherValidCertificate`, `TestPinnedConnectionVerifier_HoldsOnAResumedSession`, `TestDial_RefusesAnEmptyPin`, `TestScheduleTask_AnUnpinnedRowIsSkippedAndSaysWhy`, `TestPinnedVerifier_RefusesAnEmptyChain` |
| `base/relay-row-validated` | A `url` that is not a bare `host:port` (scheme, zone, bad port) and a `cert_fingerprint` that is not 64 lowercase hex MUST be refused at the write, by the request validation and by a CHECK constraint. | Failure & configuration | `TestARelayAddressTheFormAcceptsCanBeDialled`, `TestARelayFingerprintIsSixtyFourLowercaseHex` (the declared patterns). **Unit (mock) only** for the constraint: a live test would insert a row that bypasses request validation and expect the CHECK violation. |
| `base/relay-name-unique` | Two relays MUST NOT share a `name`; the guarantee comes from the unique index. | Consistency & concurrency | none (schema only) |
| `base/observation-cannot-reconfigure` | `RecordRelayReached` and `RecordRelayFailed` MUST change only `last_seen_at` and `last_error`; they MUST NOT touch `url`, `cert_fingerprint` or `enabled`. A failure MUST NOT move `last_seen_at`; a success MUST clear `last_error`. | Consistency & concurrency | `TestRelayStore_RecordsReachedAndFailed` (request shape). The column lists are DQL only. |
| `base/observed-state-not-truth` | Scheduling MUST NOT read `last_seen_at` or `last_error`. Placement learns a relay's state by asking it. | Consistency & concurrency | `TestScheduleTask_PlacesOnTheLeastLoadedRelay`, `TestScheduleTask_FallsThroughAnUnreachableRelay` (placement driven by live stats) |
| `base/relay-service-path` | Every call to a relay MUST use the relay's own service path (`/w17.contrib.cluster.ClusterService/…`), not the staged package name of the activation. | Failure & configuration | `TestRelayService_IsTheServiceTheRelayRegisters`, `TestHandlers_NeverDialARelayThroughTheGeneratedClient` |
| `base/one-side-answers` | A method answered by one side MUST return Unimplemented on the other, never a plausible answer. | Failure & configuration | `TestHandlers_RelayOnlyMethodsAreUnimplemented`, `TestServer_CheckWorkersIsNotARelaysMethod` |

**Gaps / suspected defects**

1. **No audit of registry edits.** Rotating a relay's pin is described as
   "the audit trail a CA-issued swap would not leave", but the plugin keeps no
   history and emits no event: an edit overwrites the previous fingerprint and
   records neither who nor when.
2. **Delete is not referential.** `DeleteRelay` leaves every `Worker.relay_id`
   that named it dangling. This is deliberate (the column is a location
   refreshed by the next sweep), but `ListWorkers` then shows ids that resolve
   to nothing until a sweep runs.
3. **Stale contract comments.** `Relay` says its history survives "if the
   ledger is on" and `ScheduleTaskReq.label` says it is "recorded by the
   ledger when that feature is on". No ledger exists, and `label` is passed to
   the relay and read by nothing.
4. **Unpaged lists.** `ListRelays` and `ListWorkers` return every row. The
   Workers page loads the whole fleet, including every banned worker ever
   recorded.

#### Placement (`ScheduleTask`)

| id | invariant | category | proof |
|---|---|---|---|
| `base/least-loaded-placement` | A placement MUST ask every enabled relay for fresh `RelayStats` and place on the relay with the lowest `(in_use + reserved + queued) / capacity`. A relay with zero capacity sorts last. Ties MUST rotate, so an idle pool spreads consecutive tasks across relays. | Performance | `TestScheduleTask_PlacesOnTheLeastLoadedRelay`, `TestScheduleTask_AQueueCountsAsLoad`, `TestScheduleTask_IdlePoolSpreadsAcrossRelays` |
| `base/unreachable-falls-through` | A relay that cannot be reached within `dial_timeout_seconds`, or that refuses with `RELAY_DRAINING`, `RELAY_MISCONFIGURED` or `QUEUE_FULL`, MUST be skipped for the next candidate. A black-holed relay MUST NOT hold the caller until its own deadline. | Failure & configuration | `TestScheduleTask_FallsThroughAnUnreachableRelay`, `TestScheduleTask_ABlackHoledRelayIsSkippedWithinTheDialTimeout`, `TestScheduleTask_SkipsADrainingRelay`, `TestScheduleTask_RelayDrainingIsFallThrough`, `TestScheduleTask_AFullQueueFallsThrough`, `TestReserveTask_AFullQueueFallsThroughThenNoRelay`, `TestFallsThrough_AFullQueue`, `TestDialReady_AShutDownConnectionIsUnreachable` |
| `base/answered-relay-is-final` | Once a relay has accepted the stream and answered (queued, or refused with any other reason), its answer MUST be final for that request: the control plane MUST NOT re-place it elsewhere, and a queued caller MUST NOT be migrated to another relay. | Consistency & concurrency | `TestScheduleTask_DoesNotRetryAfterARelayHasAnswered`, `TestScheduleTask_ACallerThatCannotBeReachedIsNotReplaced` |
| `base/grant-is-terminal` | `granted` MUST be the last event; the stream MUST close after it. A relay stream that ends without a grant MUST surface as an error, never as success. | Consistency & concurrency | `TestScheduleTask_GrantedEndsTheStream`, `TestScheduleTask_AStreamThatEndsWithoutAGrantIsAnError` |
| `base/relay-name-stamped` | Every `queued` and `granted` event MUST carry the relay's registry name, stamped by the control plane. A relay MUST NOT invent one. | Consistency & concurrency | `TestScheduleTask_StampsTheRelayNameOnEveryEvent`, `TestEndToEnd_TheGrantThatArrivesIsTheOneTheRelayMinted`, `TestEndToEnd_QueuePositionFlowsThroughTheProxy` |
| `base/caller-presence-holds-place` | A caller closing the stream (cancel, crash, deadline, `max_wait_seconds`) MUST give its queue place back at once, and MUST stop the search for a relay. A grant that crossed the cancellation MUST be released. | Consistency & concurrency | `TestScheduleTask_MaxWaitBoundsTheQueue`, `TestWait_ACancelledWaiterLeavesNothingBehind`, `TestServer_ScheduleTaskCallerLeavingIsTheCallersStatus`, `TestServer_ScheduleTaskSendFailureGivesThePlaceBack`, `TestReserveTask_TheCallerLeavingStopsTheSearch` |
| `base/no-relay-is-reasoned` | An empty pool, an unreadable registry, or every relay failing MUST answer Unavailable; an empty or all-failing pool (every queue full included) MUST carry the reason `NO_RELAY`, never one relay's `QUEUE_FULL`. | Failure & configuration | `TestScheduleTask_EmptyPoolSaysWhatToDo`, `TestScheduleTask_NothingPlaceableIsUnavailable`, `TestScheduleTask_EveryQueueFullIsNoRelay`, `TestReserveTask_AFullQueueFallsThroughThenNoRelay`, `TestHandlers_AnUnreadableRegistryIsUnavailable` |
| `base/placement-cost-bounded` | One placement MUST cost a bounded, small number of round trips. It MUST NOT perform a full TLS handshake to every relay per request. | Performance | none (finding 7) |
| `base/observed-state-off-hot-path` | The observed-state cache MUST NOT add a database write per relay to every placement; failures to write it MUST NOT fail the placement. | Performance | Failure isolation: none (both helpers discard the error by construction). Write volume: none (finding 7). |

**Gaps / suspected defects**

1. **A grant whose delivery fails keeps its slot until the ticket expires.**
   If the relay's send of the `granted` event fails, the reservation has
   already been returned, so its claim window runs and the slot is held for
   up to `--ticket-ttl`. Bounded, but invisible to the caller who lost it.
2. **No connection reuse across placements.** Each placement dials and closes
   every relay (finding 7). A pool of many relays under load pays a full mTLS
   handshake per relay per placement, plus the poll RPC.

#### Reservations (`ReserveTask`, `GetReservation`, `CancelReservation`)

| id | invariant | category | proof |
|---|---|---|---|
| `base/one-queue` | A reservation and a streaming wait MUST stand in the same relay queue, ordered by arrival, and receive slots under the same rule. | Consistency & concurrency | `TestServer_ReservationsQueueGrantAndCancel`, `TestReserve_QueuesAndPollReportsPositionThenGrant` |
| `base/reservation-handle-routes` | The control plane's handle MUST be `<relay_id>.<relay_reservation_id>` so that any replica routes a poll with no state of its own. A malformed handle MUST be InvalidArgument; a handle whose relay row is gone MUST read `expired` (`RESERVATION_UNKNOWN`). | Consistency & concurrency | `TestReserveTask_TheHandleRoutesThePollToTheRelayHoldingThePlace`, `TestGetReservation_AMalformedHandleIsInvalid`, `TestGetReservation_GoneIsExpired`, `TestGetReservation_StampsTheRelaysAnswer` |
| `base/reservation-handle-secret` | A reservation id MUST be 256 bits from a CSPRNG. An unknown, abandoned, cancelled, redeemed or expired reservation MUST read identically. | Security | `TestServer_GetReservationUnknownIsExpired` (uniform answer). Entropy: none. |
| `base/reservation-handle-bound` | Only the principal that created a reservation MUST be able to poll it, collect its grant or cancel it. | Security | none (finding 1) |
| `base/abandonment` | A reservation not polled within `--poll-timeout` MUST be released, queue place or unseen grant alike. A poll MUST keep it alive. | Failure & configuration | `TestPoll_AnUnpolledReservationIsAbandoned`, `TestPoll_KeepsAReservationAlive`, `TestPoll_AnUnseenGrantIsReturnedWhenItsClientStopsPolling` |
| `base/claim-window-starts-when-seen` | A grant's ticket expiry MUST start when a poll first returns it, not when the slot was granted. Every later poll MUST return the same grant until it is redeemed or expires. | Consistency & concurrency | `TestPoll_TheClaimWindowStartsWhenTheGrantIsFirstReturned`, `TestPoll_AReturnedGrantExpiresUnclaimed`, `TestGetReservation_QueuedThenGranted` |
| `base/unreachable-is-not-expired` | A poll that cannot reach the relay MUST be an error, not `expired`. A transient failure MUST NOT cost a client its place. | Failure & configuration | `TestGetReservation_AnUnreachableRelayIsNotExpired` |
| `base/cancel-idempotent` | `CancelReservation` MUST give back the place or the unredeemed grant, and MUST succeed for an unknown or already gone handle. | Consistency & concurrency | `TestCancelReservation_FreesThePlace`, `TestCancel_ReleasesTheSlotOrThePlace`, `TestCancelReservation_GoneAndMalformed` |
| `base/reserve-falls-through` | `ReserveTask` MUST fall through exactly the failures `ScheduleTask` falls through, and MUST treat a refusal about the request as final. | Failure & configuration | `TestReserveTask_ANotHereRefusalFallsThrough`, `TestReserveTask_ARefusalAboutTheRequestIsFinal`, `TestReserveTask_AFailureWithoutAReasonIsUnreachable`, `TestReserveTask_EveryRelayFailingIsNoRelay`, `TestReserveTask_NoPlaceableRelayIsNoRelay`, `TestReserveTask_DrainingRelaysAreSkippedAndTheirQueueExpires` |

**Gaps / suspected defects**

1. **Poll cost.** Each poll reads the full ban set and opens a new pinned
   connection (finding 7). Polling clients therefore generate one database
   read and one TLS handshake every `poll_after_ms` each.
2. **A disabled relay still serves its reservations.** `resolveHandle` uses
   `Get`, which ignores `enabled`. That is reasonable (the place exists), but
   it is not stated, and a disabled relay receives bans only through these
   polls.

#### Relay queue, capacity and tickets (`relaycore`)

| id | invariant | category | proof |
|---|---|---|---|
| `base/ticket-single-use` | A ticket MUST be redeemable exactly once, at the relay that minted it, before its expiry. A replayed, expired or invented ticket MUST get one identical refusal (`TICKET_NOT_REDEEMABLE`). | Security | `TestClaim_IsSingleUseAndIndiscriminate`, `TestTunnel_ATicketIsSpentOnFirstUse`, `TestTicketPicker_AnInventedOrSpentTicketIsRefused` |
| `base/ticket-entropy` | A ticket MUST be 256 bits from a CSPRNG. Entropy failure MUST stop the relay rather than mint a weaker ticket. | Security | none (`randomID` panics by construction; untested) |
| `base/grant-targets-one-waiter` | A freed slot MUST go to the head of the queue alone. Two waiters MUST NOT both receive it. | Consistency & concurrency | `TestWait_AFreedSlotGoesToExactlyOneWaiter`, `TestWait_QueuesThenGrantsWhenTheSlotComesBack` |
| `base/capacity-from-fleet` | Capacity MUST be the sum of the slots of attached, admitted and ready workers, capped by `--capacity` when set. A relay with no such worker MUST grant nothing. | Consistency & concurrency | `TestWait_AnEmptyRelayGrantsNothing`, `TestSetCapacity_CeilingCapsTheFleet`, `TestSetCapacity_AttachingAWorkerPromotesTheQueue`, `TestBackends_CapacityIsTheSumOfTheFleet`, `TestAttachment_CapacityNeedsApprovalAndReadinessBoth` |
| `base/shrink-revokes-nothing` | Capacity shrinking below what is held MUST stop new grants and MUST NOT revoke an outstanding grant or running work. | Consistency & concurrency | `TestSetCapacity_ShrinkingStopsGrantingAndRevokesNothing` |
| `base/unclaimed-ticket-returns-slot` | A ticket not redeemed within `--ticket-ttl` MUST return its slot and promote the next waiter. | Failure & configuration | `TestWait_AnUnclaimedTicketReturnsItsSlot`, `TestPoll_AReturnedGrantExpiresUnclaimed` |
| `base/slot-released-once` | The slot of a redeemed ticket MUST be returned exactly once when its proxied call ends, however it ends, both to the pool and to the worker that ran it. | Consistency & concurrency | `TestTicketPicker_ReleaseIsExactlyOnce`, `TestTunnel_TheSlotComesBackWhenTheCallEnds`, `TestBackends_ReleaseReturnsTheSlot`, `TestHandler_ADeadBackendIsWorkerLostAndReleased` |
| `base/position-only-falls` | A queued caller MUST be told its 1-based position on every change, and the position MUST never rise. An immediate grant MUST produce no position event. | Consistency & concurrency | `TestWait_PositionUpdatesAsTheQueueShortens`, `TestWait_ImmediateGrantReportsNoPosition` |
| `base/stats-separate-held` | `RelayStats` MUST report running and promised slots separately, and the queue, so a control plane counts promised slots as load. | Performance | `TestStats_SeparatesRunningFromReserved`, `TestServer_RelayStatsReportsThePoolAndTheFleet`, `TestEndToEnd_RelayStatsReportsThePool` |
| `base/queue-bounded` | The queue MUST have a bound (`--max-queue`, at least 1): past it a new waiter, polled or streaming, MUST be refused `RESOURCE_EXHAUSTED` with `QUEUE_FULL`. Only waiters count: an immediate grant never queues, and a promoted, cancelled or abandoned waiter MUST free its place. A single caller MUST NOT be able to grow relay memory without limit. | Performance | `TestReserve_TheQueueIsBounded`, `TestWait_TheQueueIsBoundedAndAGrantFreesAPlace`, `TestServer_AFullQueueIsQueueFull`, `TestNew_RefusesANegativeQueueLimit`, `TestNew_ZeroQueueLimitIsTheDefault`. Per caller: none (finding 2) |
| `base/state-is-volatile` | Queue, tickets, reservations, registration codes and the ban set MUST live in memory only and MUST be lost on restart. A restarted relay MUST NOT honour a ticket, reservation or code minted before it. | Failure & configuration | none (by construction; no restart test) |

**Gaps / suspected defects**

1. **No fairness** (finding 2). The queue is bounded (`--max-queue`) but
   strict FIFO across every caller of the pool, so one caller can fill it.
2. **Linear queue bookkeeping.** `positionLocked` and `notifyLocked` scan the
   whole queue under the pool mutex on every poll and every mutation; the
   queue bound caps that cost.

#### Proxy (callers listener)

| id | invariant | category | proof |
|---|---|---|---|
| `base/proxy-needs-ticket` | A call reaching the proxy without a ticket MUST be refused (`TICKET_MISSING`) before any worker is picked. | Security | `TestTicketPicker_NoTicketIsRefused`, `TestTunnel_NoTicketIsRefused` |
| `base/proxy-tls` | The callers listener MUST serve TLS 1.3 only, with the relay certificate whose fingerprint the grant carried, so the caller can pin it. A grant MUST NOT be issued by a relay that cannot name its work address and fingerprint (`RELAY_MISCONFIGURED`), and the refusal MUST NOT take a slot. | Security | `TestServer_AMisconfiguredRelayRefusesWithoutTakingASlot`, `TestScheduleTask_AMisconfiguredRelayRefusesWithAReason`, `TestServe_TheWholeRelayCarriesWorkEndToEnd` |
| `base/proxy-opaque-payload` | The proxy MUST forward frames without decoding them, preserving order, half-close, caller cancellation and the worker's status, message and reason. | Consistency & concurrency | `TestHandler_AUnaryCallRoundTripsWithItsMetadata`, `TestHandler_AServerStreamArrivesInOrder`, `TestHandler_TheCallersCloseSendReachesTheWorker`, `TestHandler_CallerCancellationReachesTheWorker`, `TestHandler_AWorkerErrorKeepsItsCodeMessageAndReason`, `TestHandler_APickerRefusalReachesTheCallerAsIs` |
| `base/message-cap` | Every hop MUST cap a single message at `MaxMessage` (256 MiB) in both directions; a message under the cap but above gRPC's default MUST cross. | Performance | `TestHandler_AMessageOverTheDefaultCapCrosses`, `TestTunnel_AMessageOverTheDefaultCapCrossesBothWays` |
| `base/no-worker-returns-slot` | A redeemed ticket with no admitted ready worker to run it MUST be refused (`NO_WORKER`) and its slot returned at once. A worker whose tunnel fails to open the call MUST be reported `WORKER_LOST` and its slot returned. | Failure & configuration | `TestTicketPicker_NoWorkerReturnsTheSlot`, `TestHandler_ADeadBackendIsWorkerLostAndReleased` |
| `base/no-automatic-redelivery` | Neither the relay nor the control plane MUST re-run a call on another worker after it was handed to one. A retry is a new placement by the caller. | Consistency & concurrency | `TestHandler_ADeadBackendIsWorkerLostAndReleased` (no retry on the proxy), `TestScheduleTask_DoesNotRetryAfterARelayHasAnswered` |

**Gaps / suspected defects**

1. **Caller metadata reaches the worker unfiltered.** The proxy copies every
   incoming header to the worker, including the spent ticket and any
   authorization header the caller sent. The ticket is useless once spent,
   but a caller that sends a bearer token for another service hands it to a
   machine on the public internet. Strip `w17-cluster-ticket` and document
   that headers are forwarded.
2. **No connection limit on the callers port.** It is the only port the deploy
   block publishes. TLS handshakes are bounded at 20 s, but nothing limits
   concurrent unauthenticated connections or failed ticket attempts per
   address.

#### Worker enrolment and certificates

| id | invariant | category | proof |
|---|---|---|---|
| `base/regcode-single-use` | A registration code MUST be redeemable once, before its expiry (default 15 min), at the relay that minted it. Unknown, spent and expired codes MUST get one identical refusal (`REGISTRATION_CODE_INVALID`). | Security | `TestRedeem_IsSingleUse`, `TestRedeem_ExpiresAndIsIndiscriminate`, `TestEnroll_ACodeIsSingleUse`, `TestRun_ARefusedCodeStops` |
| `base/regcode-entropy-and-at-rest` | A code MUST carry 120 random bits. The relay MUST hold only its SHA-256, and the control plane MUST NOT store it. It is shown once, as a secret action result. | Security | `TestIssue_CodesAreDistinctAndReadable`, `TestIssueRegistrationCode_TheCodeIsTheRelays` (pass-through only). Hash-only storage: none. |
| `base/enrol-proves-key` | Enrolment MUST verify the CSR's signature and issue a certificate for that key only, with the client-auth usage, chained to this relay's CA. The private key MUST NOT leave the worker. | Security | `TestEnroll_ACodeBuysACertificateForTheWorkersKey`, `TestParseCSR_RefusesGarbageAndAForgedSignature`, `TestRun_EnrolsWithACodeThenAttaches` |
| `base/enrol-checks-before-spending` | A malformed request, a banned key and an unrecordable claim MUST be refused **before** the code is spent, in that order (ban before claims). | Consistency & concurrency | `TestEnroll_AMalformedRequestDoesNotSpendTheCode`, `TestEnroll_ABannedKeyIsRefused`, `TestEnroll_ABannedKeyHearsTheBanBeforeItsClaims`, `TestEnroll_AClaimTheRegistryCannotRecordIsRefused` |
| `base/cert-short-lived` | A worker certificate MUST expire (default 30 days) and MUST NOT outlive the CA. | Security | `TestIssueClientCert_LifetimeIsPositiveAndBoundedByTheCA` |
| `base/renew-same-key-same-ca` | Renewal MUST require a presented, unexpired certificate from this relay's CA and a CSR for the same key. It MUST keep the worker id (the SPKI hash) stable. | Security | `TestRenew_KeepsTheIdentity`, `TestRenew_Refusals`, `TestRenew_AMalformedRequestIsInvalidArgument`, `TestRun_RenewsBeforeExpiryKeepingTheIdentity`, `TestWorkerID_IsStableAcrossRenewal`, `TestCA_VerifyRefusesAnotherCAAndExpiry` |
| `base/banned-key-cannot-renew` | A banned key MUST NOT renew, at any relay, at any time after the ban was taken. | Security | `TestRun_ABannedWorkerCannotRenew`, `TestKeepRenewed_ABanStopsTheLoop` (once the relay holds the ban). The windows of finding 5: none. |
| `base/identity-files-protected` | Relay keys, the CA key and worker keys MUST be written owner-only and atomically. A corrupt key MUST be reported, never silently replaced. | Security | `TestLoadOrCreateIdentity_KeyIsNotWorldReadable`, `TestLoadOrCreateWorkerKey_ACorruptKeyIsReportedNotReplaced`, `TestSaveWorkerCertificate_RefusesAndReplacesAtomically`, `TestLoadOrCreateCA_RefusesAHalfWrittenCA`, `TestLoadOrCreateIdentity_RefusesAHalfWrittenIdentity` |
| `base/issue-worker-needs-existing-ca` | The `issue-worker` subcommand MUST issue from an existing CA and MUST NOT mint one. | Failure & configuration | `TestIssueWorker_RefusesToMintACA`, `TestIssueWorker_FromAMountedCA`, `TestIssueWorker_Refusals` |

**Gaps / suspected defects**

1. **No limit on outstanding codes or on enrolment attempts.** Codes are
   minted only on an operator's request, so this is low risk; but the attach
   listener accepts certificate-less handshakes from anyone, and `Enroll`
   attempts are not rate-limited per address.
2. **`issue-worker` bypasses the ban set.** A deploy issuing a worker
   certificate directly from the CA does not consult bans. The ban is by key
   and the deploy generates a new key, so this is a fresh identity, not a
   bypass of an existing ban; it is stated here so it is not mistaken for
   one.

#### Worker attach, tunnels and the fleet (`relayserver`)

| id | invariant | category | proof |
|---|---|---|---|
| `base/worker-identity-is-the-key` | A worker MUST be identified only by the SPKI fingerprint of the key its TLS handshake proved. `name` and `device_id` MUST authorise nothing. | Security | `TestWorkerID_IsStableAcrossRenewal`, `TestMet_LatestClaimsWin` |
| `base/attach-needs-relay-cert` | Attach MUST refuse a connection with no certificate or with a certificate from another relay's CA. The tunnel listener MUST require and verify a relay-CA certificate, and MUST fail closed if built without that rule. | Security | `TestAttach_WithoutACertificateIsUnauthenticated`, `TestAttach_AnotherRelaysCertificateIsRefused`, `TestServeTunnels_APlainConnectionIsRefusedAndClosed`, `TestServeTunnels_FailsClosedOnAListenerThatDoesNotVerify`, `TestServeTunnels_AFailedHandshakeIsRefused`, `TestTunnel_OnlyThisRelaysUnbannedWorkersBecomeBackends` |
| `base/worker-pins-relay` | A worker MUST pin its relay by fingerprint on enrolment, attach and tunnel, on full and resumed handshakes, and MUST refuse to run with no pin. | Security | `TestRun_RefusesARelayThatIsNotThePinnedOne`, `TestRun_RefusesWithNoRelayPin`, `TestServeTunnel_Refusals` |
| `base/ban-bites-connected-worker` | A ban MUST stop a connected worker receiving new work at the next pick, and MUST end its attach stream within one check interval. A banned worker's new tunnel MUST be refused. | Security | `TestTicketPicker_SkipsABannedWorker`, `TestTunnel_RevokingAWorkerStopsItReceivingWork`, `TestBackends_TakeSkipsAWorkerThatIsNoLongerAdmitted`, `TestAttach_ABanWhileAttachedEndsTheStream`, `TestServeTunnels_ABannedWorkersTunnelIsRefused`, `TestServe_ABanOnAManagementCallRemovesTheWorker` |
| `base/ban-ends-running-work` | A ban MUST close the banned worker's tunnel, and SHOULD end the work running on it, or the contract MUST say it does not. | Security | `TestBackends_DropWhereClosesTheSelectedTunnels`, `TestBackends_DropWhereUnderARunningCallReleasesItsSlot`, `TestHandler_ATunnelClosedMidCallEndsTheWorkAndIsWorkerLost`, `TestOnBansChanged_RunsWithTheNewSet` |
| `base/tunnel-revalidated` | A tunnel MUST stop being a backend when the certificate it was opened with expires. | Security | none (finding 4) |
| `base/attach-expiry-ends-stream` | An attach stream MUST end when the worker's certificate expires, so the worker reconnects with the renewed one. | Security | `TestAttach_CertificateExpiryEndsTheStream`, `TestRun_StopsOnceTheCertificateRunsOutUnrenewed` |
| `base/capacity-needs-admission-and-readiness` | A worker MUST contribute capacity only while admitted, attached, holding a tunnel and reporting READY. A worker that announces DRAINING or UNHEALTHY MUST never be counted ready, and MUST keep its tunnel for the work already running. | Consistency & concurrency | `TestAttachment_CapacityNeedsApprovalAndReadinessBoth`, `TestBackends_AnUnadmittedWorkerAddsNoCapacity`, `TestAttach_AnnouncedDrainingIsNeverReady`, `TestAttach_AWorkerThatStartsDrainingIsNeverCountedReady`, `TestBackends_DrainingTakesNoWorkButKeepsItsTunnel`, `TestBackends_ATunnelWithoutAnAnnouncementCarriesNothing`, `TestAttach_ReadinessDrivesCapacityForTheLifeOfTheStream` |
| `base/worker-slots-bounded` | A worker's declared slots MUST be bounded, and the relay's reported capacity MUST NOT overflow. | Security | `TestAttach_SlotsAboveTheCapAreHeldToIt`, `TestServer_RelayStatsCapacityDoesNotWrap`, `TestParseConfig_MaxWorkerSlots` |
| `base/pick-most-room` | A redeemed ticket MUST go to the admitted ready worker with the most free slots, MUST NOT exceed any worker's declared slots, and MUST alternate between equals. | Performance | `TestBackends_TakePrefersTheWorkerWithTheMostRoom` (most room and the slot bound; no test has two workers with equal room, so alternation is unproven) |
| `base/reconnect-generations` | A worker reconnecting MUST replace its old tunnel and attachment. A late unwind of the old one MUST NOT erase the new profile, free a slot booked on the new tunnel, or remove the new tunnel. | Consistency & concurrency | `TestAttach_AReconnectSurvivesTheOldStreamsUnwind`, `TestBackends_AStaleReleaseDoesNotFreeTheNewTunnel`, `TestBackends_AStaleClearDoesNotEraseTheNewAttachment`, `TestBackends_AStaleStatusDoesNotOverwriteTheNewAttachment`, `TestBackends_AnOldTunnelClosingKeepsTheNewOne` |
| `base/dead-tunnel-leaves` | A tunnel that dies (hang-up, black hole, no HTTP/2) MUST stop being a backend and MUST remove its capacity, without deadlocking the relay. | Failure & configuration | `TestTunnel_ADeadTunnelStopsBeingABackend`, `TestBackends_ADeadTunnelLeavesTheCapacity`, `TestTunnel_ABlackHoledTunnelStopsBeingABackend`, `TestTunnel_ARelayThatNeverSpeaksHTTP2EndsTheWorkersTunnel`, `TestTunnel_ABlackHoledRelayEndsTheWorkersTunnel`, `TestBackends_AWorkerHangingUpDoesNotDeadlockTheRelay`, `TestClientOverConn_ADeadTunnelFiresTheHookOnceAndIsNeverRedialled` |
| `base/capacity-publish-ordered` | Concurrent fleet changes MUST leave the pool with the current total. A stale publish MUST NOT overwrite a newer one. | Consistency & concurrency | `TestBackends_ConcurrentChangesPublishTheCurrentTotal`, `TestBackends_CapacityChangesArePublished` |
| `base/keepalive-compatible` | Every hop MUST ping on one schedule that every server accepts, so an idle tunnel survives and a dead one is detected. | Failure & configuration | `TestKeepalive_ClientsPingNoFasterThanServersAllow`, `TestTunnel_AnIdleTunnelSurvivesTheRelaysPings` |
| `base/claims-recordable` | A new worker whose name or device id is over 128 characters, invalid UTF-8, or contains a control or format character MUST be refused at enrolment (`WORKER_CLAIM_INVALID`). An already enrolled worker's claims MUST be sanitized, not refused. | Failure & configuration | `TestCheckClaims`, `TestSanitizeClaim`, `TestEnroll_AClaimTheRegistryCannotRecordIsRefused`, `TestAttach_AClaimTheRegistryCannotRecordIsSanitizedNotRefused`, `TestRun_AnUnrecordableClaimEndsBeforeEnrolling`, `TestRun_AnEnrolledWorkerWithAnOverLongNameKeepsAttaching` |
| `base/banned-worker-still-seen` | A banned worker that keeps attaching MUST still be reported to the control plane. | Security | `TestAttach_ABannedWorkerIsRefusedButStillSeen`, `TestAttach_ABannedWorkerWithAnOverLongClaimIsStillSeen` |

**Gaps / suspected defects**

1. **Bans do not cut tunnels or running work** (finding 4).
2. **A worker sees the work in clear.** TLS ends at the relay and is
   re-established on the tunnel; the relay and the worker both see the
   payload. That is inherent to the design, but a project that places
   sensitive input must treat every enrolled machine as trusted with it.

#### Worker registry and bans (control plane)

| id | invariant | category | proof |
|---|---|---|---|
| `base/record-keeps-decision` | `RecordWorker` MUST be idempotent by fingerprint. It MUST refresh `relay_id` and MUST NOT change `state`, `decided_at`, `decided_by`, `name` or `device_id` of an existing row, so a sweep never lifts a ban. | Security | `TestWorkerStore_RecordCarriesTheRelayAndTheClaims` (request shape). **Unit (mock) only:** a live test would ban a worker, sweep again with different claims, and assert `state = BANNED` and the original claims. |
| `base/decision-by-verified-caller` | A ban or unban MUST be recorded under the user id of the verified principal, never one taken from the request. With no principal it MUST be refused. | Security | `TestDecideWorkers_RecordsTheSignedInCaller`, `TestDecideWorkers_RefusesWithoutACaller`, `TestDecideWorkers_EmptySelectionAndRefusedDecision` |
| `base/ban-set-on-every-call` | Every control-plane call to a relay MUST carry the complete ban set in `w17-cluster-banned`; an empty set MUST travel as an empty value. | Security | `TestEveryRelayCallCarriesTheBanSet`, `TestCheckWorkers_BansReachTheRelay`, `TestWithBans_RoundTrips` |
| `base/ban-set-fails-closed` | A ban set that cannot be read MUST refuse the call. It MUST NOT be sent as empty. | Security | `TestWithBans_AnUnreadableBanSetRefusesTheCall`, `TestHandlers_AnUnreadableBanSetRefusesEveryCall`, `TestWorkerStore_AnUnreadableBanSetIsAnError`, `TestCheckWorkers_RefusesWithNoRegistry` |
| `base/absent-header-changes-nothing` | A relay MUST replace its ban set with a received set, and MUST leave it unchanged when the header is absent. Only the pinned control plane can reach the interceptor that applies it. | Security | `TestBansFrom_EmptyIsAnAnswerAbsentIsNot`, `TestSetBanned_ReplacesRatherThanMerges`, `TestBanInterceptors_ApplyOnlyWhatWasSent`, `TestBanServerOptions_ApplyTheBanSetOnUnaryAndStreamingCalls` |
| `base/ban-reaches-every-relay` | A ban MUST take effect at every relay that could admit or renew that key, and a newer ban set MUST NOT be overwritten by an older one. | Consistency & concurrency | none (finding 5) |
| `base/ban-is-global` | A key banned through any relay's row MUST be refused at every relay. | Security | `TestWorkerStore_BannedAndEnrolledAskForTheirState` (no relay filter in the request) |
| `base/sweep-isolates-failures` | `CheckWorkers` MUST report an unreachable relay and continue; MUST skip and count a worker refused for its own data; MUST blame the relay for a refusal of a relay-supplied field; and MUST abort, without blaming any relay, when the registry cannot write. | Failure & configuration | `TestCheckWorkers_AnUnreachableRelayIsReportedNotFatal`, `TestCheckWorkers_AWorkerTheRegistryRefusesDoesNotHideTheFleet`, `TestCheckWorkers_ARelayTheRegistryRefusesIsTheRelaysFailure`, `TestCheckWorkers_ARefusedFingerprintIsTheRelaysFailure`, `TestCheckWorkers_ARegistryOutageKeepsWhatTheSweepFound`, `TestCheckWorkers_ARegistryWriteFailureIsNotTheRelays`, `TestCheckWorkers_AnAbortStillLogsTheWorkersAlreadyRefused`, `TestCheckWorkers_EveryWorkerOfARelayRefusedIsSaidAboutTheRelay`, `TestClassifyRecordError` |
| `base/sweep-sanitizes` | The control plane MUST sanitize every reported claim before recording it, whatever the relay version, and MUST skip a worker without a fingerprint. | Failure & configuration | `TestCheckWorkers_ClaimsTheRelayDidNotSanitizeAreSanitizedHere`, `TestCheckWorkers_SkipsAWorkerWithoutAFingerprint` |
| `base/sweep-counts-honest` | `discovered` MUST be the enrolled count after minus before, never negative; two concurrent sweeps MUST NOT both count the same worker as new. | Consistency & concurrency | `TestCheckWorkers_Counts`. **Unit (mock) only** for concurrency: a live test would run two sweeps at once and assert the sum of `discovered` equals the rows created. |
| `base/registration-code-one-relay` | `IssueRegistrationCode` MUST target exactly one registered relay and MUST return the fingerprint the control plane pinned on that connection, not the one the relay reports. | Security | `TestIssueRegistrationCode_ExactlyOneRelay`, `TestIssueRegistrationCode_TheCodeIsTheRelays`, `TestIssueRegistrationCode_UnreachableAndRefused`, `TestServer_IssueRegistrationCode` |

**Gaps / suspected defects**

1. **Propagation windows** (finding 5).
2. **Decision history is overwritten.** `decided_at`/`decided_by` hold only
   the last decision; an unban erases who banned. No event records either.
3. **A ban needs a sweep first.** A worker can only be banned once a
   `CheckWorkers` has recorded it. Between enrolment and the first sweep there
   is nothing to ban from the admin.
4. **The ban set is unbounded** (finding 8).

#### Drain and shutdown

| id | invariant | category | proof |
|---|---|---|---|
| `base/drain-keeps-promises` | Draining MUST refuse new waits and reservations (`RELAY_DRAINING`), MUST release every queued place at once, and MUST keep every outstanding grant and running call. It is one-way until restart. | Failure & configuration | `TestDrain_RefusesNewWorkReleasesTheQueueAndKeepsPromises`, `TestDrain_AGrantedReservationKeepsItsGrant`, `TestDrain_AQueuedReservationIsToldToPlaceAgain`, `TestDrain_Twice`, `TestServer_DrainExpiresPolledPlacesAndRefusesNewOnes`, `TestServer_ScheduleTaskOnADrainingRelayIsRelayDraining`, `TestServe_DrainRefusesNewPlacements` |
| `base/drain-selection-whole` | `DrainRelay` on the control plane MUST resolve every id before touching any relay, so one stale id drains nothing; an unreachable relay MUST be reported, not fatal. | Consistency & concurrency | `TestDrainRelay_OneStaleIDDrainsNothing`, `TestDrainRelay_UnknownIDIsNotFound`, `TestDrainRelay_UnreachableRelaysAreReportedSorted`, `TestEndToEnd_DrainRelayDrainsTheRelay` |
| `base/sigterm-drains-bounded` | On SIGTERM a relay MUST drain, wait until nothing is held or `--drain-timeout` passes, then stop each server within a bounded time. | Failure & configuration | `TestShutdown_DrainsWaitsForTheWorkThenStops`, `TestShutdown_IsBounded` |

**Gaps / suspected defects**

1. **Work still running at the drain timeout is cut.** The supervisor's kill
   timeout must exceed `--drain-timeout` plus the stop timeouts; the deploy
   block does not derive one from the other.

#### Configuration that must fail at boot

| id | invariant | category | proof |
|---|---|---|---|
| `base/boot-control-plane-identity` | `RegisterPlugin` MUST refuse to start without `client_cert_path` and `client_key_path`, or when they do not parse as a matching key pair. | Failure & configuration | `TestRegisterPlugin_RefusesAnUnusableConfiguration`, `TestRegisterPlugin_NeedsARegistryAndClients`, `TestDial_RefusesAnUnusableClientIdentity` |
| `base/boot-relay-required` | A relay MUST refuse to start without `--proxy-address` or `--control-plane-fingerprint`, without an identity, without a worker CA, with both explicit and minted identity or CA, with `--poll-timeout` under twice `--poll-interval`, or with `--max-queue` under 1. | Failure & configuration | `TestServe_RefusesToStartMisconfigured`, `TestServe_ExplicitCertificateAndCA`, `TestNew_RefusesAConfigThatCannotWork`, `TestParseConfig_RefusesAQueueBelowOne` |
| `base/boot-relay-env-strict` | A set `RELAY_*` variable that does not parse (a negative count, a duration without a unit, trailing characters) MUST refuse the start, unless its flag was given explicitly. A stray argument MUST refuse the start. | Failure & configuration | `TestParseConfig_RefusesAMalformedVariable`, `TestParseConfig_AnExplicitFlagExcusesItsOwnVariable`, `TestParseConfig_RefusesAStrayArgument`, `TestParseConfig_ReadsTheEnvironment`, `TestParseConfig_Defaults`, `TestParseConfig_HelpIsUsageWhateverTheEnvironment` |
| `base/boot-failure-releases-ports` | A start that fails part-way MUST close every listener it had bound. | Failure & configuration | `TestServe_AFailedStartReleasesWhatItBound` |
| `base/control-plane-pinned-by-relay` | A relay's management listener MUST accept only the client certificate whose fingerprint is `--control-plane-fingerprint`, on full and resumed handshakes, and MUST log the presented and expected fingerprints on refusal. | Security | `TestServe_ManagementRefusesAnyOtherControlPlane`, `TestRegisterPlugin_AnotherIdentityIsRefusedByTheRelay`, `TestRegisterPlugin_TheRegisteredHandlerReachesAPinnedRelay`, `TestControlPlaneRefused_NamesThePinAndWhereItIsSet` |

**Gaps / suspected defects**

1. `dial_timeout_seconds <= 0` silently becomes 5 s instead of refusing.
2. `--control-plane-fingerprint` is not checked for shape at boot; a mistyped
   value fails closed (nothing can manage the relay) but only shows up as
   refused handshakes in the log.
3. Fixed: `ticket_ttl_seconds`, which was accepted and ignored, is removed (finding 6).

---

## Across features

The plugin has a single tier, so this section covers the surfaces of the
plugin that share state or override each other, and the platform pieces and
other plugins it meets.

### Interaction matrix

| | ScheduleTask | Reservations | Ban registry | Drain | Relay registry | Second activation | auth plugin | deploy block |
|---|---|---|---|---|---|---|---|---|
| **ScheduleTask** | — | one queue | bans on every call | falls through | `ListEnabled` | separate tables | — | — |
| **Reservations** | one queue | — | bans on every poll | queued places expire | `Get` ignores `enabled` | handles name a relay id | — | — |
| **Ban registry** | | | — | — | disabled relays get no bans | separate ban sets | `decided_by` | `issue-worker` |
| **Drain** | | | | — | not persisted | — | — | relay restart undoes it |
| **Relay registry** | | | | | — | separate tables | — | `local` row upsert |

### Interaction invariants

| id | surfaces | MUST hold | proof |
|---|---|---|---|
| `interaction/schedule-reserve-one-queue` | ScheduleTask × Reservations | A streaming wait and a polled reservation on one relay share one FIFO queue and one capacity. Neither may overtake the other, and a slot freed by one goes to the head of the queue whichever kind it is. | `TestServer_ReservationsQueueGrantAndCancel`, `TestWait_AFreedSlotGoesToExactlyOneWaiter` (no test mixes the two kinds) |
| `interaction/bans-every-relay-call` | Ban registry × every relay-bound RPC | ScheduleTask, ReserveTask, GetReservation, CancelReservation, CheckWorkers, IssueRegistrationCode and DrainRelay each read the ban set first and refuse when it cannot be read. | `TestEveryRelayCallCarriesTheBanSet`, `TestHandlers_AnUnreadableBanSetRefusesEveryCall` |
| `interaction/drain-reservations-place-again` | Drain × Reservations | A queued reservation on a draining relay reads `expired` with `RELAY_DRAINING` once, then is forgotten. A granted one keeps its grant. A new reservation falls through to another relay. | `TestDrain_AQueuedReservationIsToldToPlaceAgain`, `TestDrain_AGrantedReservationKeepsItsGrant`, `TestReserveTask_DrainingRelaysAreSkippedAndTheirQueueExpires` |
| `interaction/registry-disable-bans` | Relay registry × Ban registry | A disabled relay keeps running and keeps renewing certificates, but receives no ban set. Disabling a relay MUST NOT leave a banned key able to renew there. | none (finding 5c) |
| `interaction/registry-delete-reservations` | Relay registry × Reservations | Deleting a relay row turns its outstanding handles into `expired` on the next poll, while the relay itself keeps the places until abandonment. | `TestGetReservation_GoneIsExpired`, `TestCancelReservation_GoneAndMalformed` |
| `interaction/activation-activation-isolation` | Two activations of the plugin | Two pools in one project (for example `codegen` and `browser`) have separate tables, separate registries and separate ban sets. A relay registered in one pool is never dialled by the other, and a worker banned in one is not banned in the other. | none. A live test would activate the plugin twice, register one relay per pool, and assert placement, bans and admin pages stay within their pool. |
| `interaction/auth-cluster-decided-by` | auth × Ban registry | `BanWorkers`/`UnbanWorkers` read the user id from the gateway's verified principal envelope (field 2). Without a principal (no auth plugin, or an unauthenticated route) every decision is refused. | `TestDecideWorkers_RecordsTheSignedInCaller`, `TestDecideWorkers_RefusesWithoutACaller` |
| `interaction/gateway-acl-only-gate` | Gateway ACL × every RPC | The plugin authorizes no caller itself: ScheduleTask, the reservation RPCs, IssueRegistrationCode, CheckWorkers, DrainRelay and the registry mutations are protected only by the project's ACL. A project MUST gate the operator RPCs (registration codes, drain, ban, relay CRUD) to operators, and MUST NOT expose them to the callers that place work. | none (live only) |
| `interaction/deploy-registers-local` | deploy block × Relay registry | A deploy upserts the row `local` with the minted fingerprint, refreshes it on re-mint, and deletes it when the environment stops deploying the relay. | none (live only) |
| `interaction/deploy-issue-worker-fresh-key` | deploy block × Ban registry | A worker issued by `issue-worker` gets a new key and therefore a new identity, so a ban on the previous worker's key does not carry to it. | none |

### Cross-cutting invariants

#### Delivery semantics

| id | MUST hold | proof |
|---|---|---|
| `cluster/slots-not-tasks` | The plugin hands out slots. It MUST NOT be relied on for task identity, result delivery, deduplication or retries. One ticket buys at most one proxied call on one worker. | `TestTunnel_ATicketIsSpentOnFirstUse` |
| `cluster/at-most-once-per-ticket` | A call MUST reach at most one worker, once. If the worker or its tunnel fails mid-call, the caller gets an error (`WORKER_LOST`, or the transport's status), the slot is returned, and nothing is re-run. Whether the work ran partly is unknown to the plugin; a retry is a new placement and may run the work twice, so the work must be idempotent or the caller must deduplicate. | `TestHandler_ADeadBackendIsWorkerLostAndReleased`, `TestHandler_CallerCancellationReachesTheWorker` |
| `cluster/no-concurrent-double-run` | Two workers MUST NOT run the same ticket. A ticket cannot be claimed twice, and a claimed ticket is bound to one picked worker. | `TestClaim_IsSingleUseAndIndiscriminate`, `TestTicketPicker_ReleaseIsExactlyOnce` |
| `cluster/time-to-claim-not-time-to-run` | A ticket's expiry MUST bound only the gap between the grant and the call. A running call MUST NOT be cut by any plugin timer; it holds its slot until its connection ends. | `TestTunnel_TheSlotComesBackWhenTheCallEnds` (no wall-clock cap); none for a call outliving the TTL |
| `cluster/failure-matrix` | Worker crash mid-call: the call fails, the slot returns, the worker's capacity leaves. Relay restart: tickets, reservations, codes and bans are lost; running calls are cut; queued callers see an error or `expired`; workers reconnect by themselves. Control-plane restart: open ScheduleTask streams end and their queue places are released at the relay; granted tickets stay valid until expiry. Network partition between control plane and relay: placements skip that relay within the dial timeout; polls on its reservations return Unavailable until the relay abandons them. | `TestHandler_ADeadBackendIsWorkerLostAndReleased`, `TestTunnel_ADeadTunnelStopsBeingABackend`, `TestScheduleTask_ABlackHoledRelayIsSkippedWithinTheDialTimeout`, `TestGetReservation_AnUnreachableRelayIsNotExpired`, `TestWait_ACancelledWaiterLeavesNothingBehind`. Relay restart: none. |

#### Isolation, fairness and backpressure

| id | MUST hold | proof |
|---|---|---|
| `cluster/no-tenant-dimension` | A pool is shared by every caller its RPCs admit. The plugin MUST NOT be assumed to isolate tenants or organizations: there is no per-tenant queue, capacity, worker set or ban. A project that needs isolation activates one pool per isolation boundary, or gates the RPCs. | — (statement of scope) |
| `cluster/fairness` | No single caller MUST be able to occupy a relay's whole queue or keep others waiting without bound. | none (finding 2) |
| `cluster/backpressure` | Overload MUST surface as queueing with a visible position, and refusal as a reasoned status (`NO_RELAY`, `NO_WORKER`, `RELAY_DRAINING`, `QUEUE_FULL`). Memory on the relay MUST stay bounded under any request rate. | Queueing and reasons: `TestWait_PositionUpdatesAsTheQueueShortens`, `TestScheduleTask_EmptyPoolSaysWhatToDo`, `TestTicketPicker_NoWorkerReturnsTheSlot`. Bounded queue: `TestReserve_TheQueueIsBounded`, `TestServer_AFullQueueIsQueueFull`. Bounded per caller: none (finding 2). |

#### Secrets and credentials

| Secret | Held as | ID / proof |
|---|---|---|
| Ticket | 256 random bits, relay memory only, single use, forgotten when redeemed or expired. Travels in the `w17-cluster-ticket` header over TLS to a pinned relay. Typed SECRET in the API. | `cluster/ticket` — `TestClaim_IsSingleUseAndIndiscriminate`, `TestTunnel_ATicketIsSpentOnFirstUse` |
| Reservation handle | 256 random bits plus the relay id; relay memory only; a bearer for the grant. Not bound to its creator (finding 1). | `cluster/reservation-handle` — `TestServer_GetReservationUnknownIsExpired` |
| Registration code | 120 random bits; the relay keeps its SHA-256 in memory; single use; 15 min. Shown once in the admin as a secret action result; the control plane does not store it. | `cluster/regcode` — `TestRedeem_IsSingleUse`, `TestRedeem_ExpiresAndIsIndiscriminate` |
| Control-plane private key | A file on the control plane's machine, named by `client_key_path`; never in the database or the environment. | `cluster/control-plane-key` — `TestRegisterPlugin_RefusesAnUnusableConfiguration` |
| Relay key and worker CA key | Files in the relay's state directory or mounted secrets, owner-only. | `cluster/relay-keys` — `TestLoadOrCreateIdentity_KeyIsNotWorldReadable` |
| Worker key | Generated on the worker, never sent; only a CSR leaves the machine. | `cluster/worker-key` — `TestEnroll_ACodeBuysACertificateForTheWorkersKey`, `TestWorkerCredentials_KeyIsKeptAndForeignCertsRefused` |
| Fingerprints (`Relay.cert_fingerprint`, `Worker.cert_fingerprint`) | Public by design: a fingerprint says which certificate to expect and grants nothing. | — |

#### Enumeration

| id | MUST hold | proof |
|---|---|---|
| `cluster/uniform-refusals` | A spent, expired and invented ticket get one refusal; so do an unknown, abandoned, cancelled, redeemed and expired reservation; so do an unknown, spent and expired registration code. None of these answers reveals whether the value ever existed. | `TestClaim_IsSingleUseAndIndiscriminate`, `TestRedeem_ExpiresAndIsIndiscriminate`, `TestServer_GetReservationUnknownIsExpired` |
| `cluster/reasons-are-stable` | Every refusal a relay or the control plane makes MUST carry `ErrorInfo{domain: "cluster.w17", reason}`. Reason strings are a wire contract and MUST NOT be renamed. | `TestReasonOf_ReadsTheReasonBack`, `TestReasonOf_IgnoresOtherDomainsAndPlainErrors` |

#### Events

| id | MUST hold | proof |
|---|---|---|
| `cluster/no-events` | The plugin emits no events. Relay registration, pin rotation, enable or disable, ban, unban, drain and registration-code issue leave no event and no history beyond the current row. A project that needs an audit trail must add it around the RPCs. | — (gap: decisions and pin rotations are not auditable) |

#### Transactions

There are none. Every mutation is a single statement. `CheckWorkers` writes
one `RecordWorker` per reported worker outside any transaction on purpose: an
aborted sweep keeps what it recorded, and pressing again is the retry.
`BanWorkers`/`UnbanWorkers` change every selected row in one `UPDATE … WHERE
id IN (…)`.

| id | MUST hold | proof |
|---|---|---|
| `cluster/decide-one-statement` | A ban or unban of a selection MUST apply to every selected row or none. | **Unit (mock) only** (`TestWorkerStore_DecideRoutesBanAndUnban`): a live test would ban three ids and assert all three rows changed. |

#### Performance

| id | MUST hold | proof |
|---|---|---|
| `cluster/lookups-indexed` | Every lookup on a request path MUST be served by a key or index: `Relay.id`, `Relay.name`, `Worker.id`, `Worker.cert_fingerprint` (the UPSERT conflict target), and `Worker.state` for the ban set and counts read on every relay-bound call. | none. `Worker.state` has no index (finding 8). |
| `cluster/ban-set-bounded` | The ban set read and sent on every relay call MUST stay bounded in size. | none (finding 8) |
| `cluster/no-push-into-control-plane` | Nothing MUST dial into the control plane: relays are polled for stats, and workers dial into relays. | By construction (no listener in the control plane's half). |
| `cluster/no-background-sweep` | The control plane MUST NOT run a background sweep (the console may run several replicas); fleet discovery is an operator action. | By construction. |
| `cluster/counts-in-sql` | Counting workers MUST be a `COUNT` in the database, not a list measured in the handler. | none (DQL only) |

#### Configuration that must fail at boot

| id | Condition | Enforced | Proof |
|---|---|---|---|
| `cluster/boot-identity` | Missing or unusable `client_cert_path`/`client_key_path` | `RegisterPlugin` | `TestRegisterPlugin_RefusesAnUnusableConfiguration` |
| `cluster/boot-relay` | Relay without proxy address, control-plane pin, identity or CA; conflicting identity sources; malformed `RELAY_*`; poll timeout under twice the interval | relay `serve`, `parseConfig` | `TestServe_RefusesToStartMisconfigured`, `TestParseConfig_RefusesAMalformedVariable` |
| `cluster/boot-no-inert-knob` | A knob the manifest documents MUST have the documented effect, or refuse | — | none (the inert `ticket_ttl_seconds` was removed; the claim window is the relay's `--ticket-ttl`) |
| **Not** boot-checked (gaps) | `dial_timeout_seconds <= 0` (becomes 5 s); a malformed `--control-plane-fingerprint` (fails closed at every handshake) | — | none |

---

### How to prove it — live-only coverage

A unit test against a fake store cannot prove the invariants below. An example
project's end-to-end suite should cover them, against a real database, the
real gateway, the real relay binary and a real worker.

**What the example needs.**

- **The relay image**, built from the plugin directory with
  `cluster/sandboxes/relay/Dockerfile` and wired as the `clusterrelay`
  sandbox. It refuses to start until `RELAY_CONTROL_PLANE_FINGERPRINT` is set,
  so the example's setup must mint the control plane's identity first
  (`relay mint --dir … --name control-plane`), point `client_cert_path` /
  `client_key_path` at it, set the relay's pin to its fingerprint, and then
  register the relay row with the fingerprint the relay prints at startup. The
  sandbox keeps its identity and CA inside the container, so a recreated relay
  needs a new row edit and re-enrolled workers.
- **A worker image.** The plugin ships no worker. The example must build a
  small worker on `lib/workerconn` (for example an echo service that also
  reports a configurable readiness and slot count) and start two or more of
  them, enrolled with registration codes issued through the admin action, or
  issued directly with `relay issue-worker` against the relay's CA.
- **A second relay**, to cover placement spread, fall-through and drain.
- **A caller** that holds the ScheduleTask stream, and one that uses the
  reservation RPCs, each dialling the granted address with the ticket header
  and pinning the granted fingerprint.

**What the suite must show.**

1. **Database constraints and conditional writes:** a relay `url` with a
   scheme or a zone and a fingerprint with colons are refused by the CHECK
   when written around the request validation (`base/relay-row-validated`);
   two relays with one name are refused (`base/relay-name-unique`); a banned
   worker stays banned, with its original claims, after another sweep
   (`base/record-keeps-decision`); two concurrent sweeps create one row per
   worker and their `discovered` counts add up (`base/sweep-counts-honest`); a
   ban of a selection changes every selected row (`cluster/decide-one-statement`).
2. **Ticket and slot semantics end to end:** a ticket works once and the
   replay is refused with `TICKET_NOT_REDEEMABLE`; a ticket not used within
   `--ticket-ttl` is refused and its slot goes to the next waiter; a call that
   runs longer than the TTL is not cut (`cluster/time-to-claim-not-time-to-run`);
   with capacity N, the (N+1)th caller is queued and granted when one call ends.
3. **Reservations:** a polled reservation is granted, a stopped poller is
   abandoned within `--poll-timeout`, the claim window starts at the first
   returned grant, a handle polled through a second console replica routes to
   the right relay. Handle binding is expected red until finding 1 is fixed: a
   second principal polling the first one's handle must be refused.
4. **Bans:** after a ban in the admin, the next placement stops work reaching
   the worker, its attach stream ends with `WORKER_BANNED`, it cannot renew,
   and a new tunnel from it is refused. Expected red until finding 4 is fixed:
   its existing tunnel is closed. Expected red until finding 5 is fixed: a
   relay restarted with no placement since does not let the banned key renew;
   a disabled relay does not either.
5. **Failure matrix:** kill a worker mid-call (the caller gets an error, the
   slot and the worker's capacity return); restart a relay (outstanding
   tickets and reservations are refused or `expired`, workers reattach, the
   ban set is restored by the next placement before any work is placed);
   black-hole one relay (placements succeed on the other within
   `dial_timeout_seconds`); restart the control plane during a ScheduleTask
   stream (the relay's queue place is released).
6. **Drain:** drain a relay from the admin while a call runs and a caller is
   queued; the queued caller is re-placed on the other relay, the running call
   finishes, new placements avoid the drained relay; SIGTERM on a relay with a
   running call waits for it within `--drain-timeout`.
7. **Pins:** a relay row with a wrong fingerprint is never used and its
   `last_error` names the mismatch; a control plane with another identity is
   refused by the relay; a worker pointed at an impostor relay refuses it.
8. **Capacity truth:** a worker announcing DRAINING contributes nothing and
   keeps its running call; a relay with no ready worker grants nothing. A
   worker announcing an absurd slot count is admitted with, and credited
   only, `--max-worker-slots`.
9. **Two activations:** `codegen` and `browser` pools in one project keep
   separate registries, placements and bans
   (`interaction/activation-activation-isolation`).
10. **ACL:** a caller allowed only to place work cannot issue registration
    codes, drain relays, ban workers or edit relays
    (`interaction/gateway-acl-only-gate`).
11. **Cost:** with K relays registered, measure database writes and TLS
    handshakes per placement and per poll; the current figures are K writes
    and K full handshakes per placement, and one ban-set scan and one
    handshake per poll (findings 7 and 8).
12. **Deploy:** a swarm deploy registers `local` with the minted fingerprint,
    a re-mint updates it, and removing the relay from the environment deletes
    the row (`interaction/deploy-registers-local`).
