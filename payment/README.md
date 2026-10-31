# payment plugin

Provider-agnostic billing primitives for w17 projects. The public proto
surface (models / service / events) names no provider; the concrete
gateway plugs in behind an internal `backend.Backend` interface selected
by the `payment_provider` env. **The core ships with one driver, Stripe.**

## What the core provides

- **Models** — `Customer` (principal ↔ provider-customer link),
  `Payment` (one charge, provider-owned status), `Refund`,
  `ProcessedWebhookEvent` (inbound idempotency ledger).
- **PaymentService** (turnkey, hand-written handlers):
  - `CreateCustomer` — provider customer + local link; idempotent per
    principal (an existing link is returned).
  - `CreatePayment` — ensure customer, create the provider payment
    (idempotency-keyed), persist the local `Payment`. Returns the
    provider `client_secret` for frontend confirmation. A retry with the
    same `idempotency_key` returns the payment the first attempt recorded;
    a key already used for another payment is `AlreadyExists`. A key is the
    caller's own: the same key from another user, or for a top-up, is a
    separate charge. An empty
    key gets a random one (no retry safety — send a stable key for that).
  - `RefundPayment` — reverse a payment (full or partial) via the
    provider + record a local `Refund`. The `idempotency_key` names ONE
    refund across all payments (it is the provider's idempotency key,
    sent verbatim): a retry with the same key, payment and amount returns
    the recorded refund; the same key with another amount is
    `AlreadyExists`, on another payment `InvalidArgument`. The key is kept
    and looked up before the provider is asked, and it also rides in the
    provider refund's metadata (`w17_refund`), which the plugin searches
    before refunding: a retry after the provider has forgotten its
    idempotency key does not refund twice, even when the first attempt's
    local record failed. A refund made before rc.5 carries no such
    metadata. The provider's answer is recorded as the refund's `status`
    (`PENDING`, `SUCCEEDED`, `FAILED`, `CANCELED`); a refund that fails
    later is settled by the refund webhooks below.
    Before any provider is asked, the refund is checked against the plugin's
    own records under the payment's row lock: a payment that failed or was
    canceled is refused (`FailedPrecondition`), one whose success webhook has
    not arrived is read from the provider first, and an amount past what
    remains (the payment less its pending and succeeded refunds) is refused
    (`InvalidArgument`). Two refunds of one payment run one after the other,
    so together they never exceed it.
    Privileged / internal (not REST-exposed).
  - `IngestStripe` — webhook sink (gated `stripe_webhooks`): verify the
    `Stripe-Signature` HMAC (constant-time, multi-`v1`) + timestamp
    tolerance (5-min replay window), dispatch the terminal state to
    `MarkPaymentSucceeded` / `MarkPaymentFailed` / `MarkPaymentCanceled`
    (`payment_intent.canceled`) (transition-guarded, so a redelivered or
    out-of-order event changes and emits nothing; CANCELED is terminal, and
    an older subscription event never overwrites a newer one), then record
    the event id. A refund event (`charge.refunded`, `refund.created`,
    `refund.updated`, `refund.failed`, `charge.refund.updated`) makes the
    plugin read the payment's refunds from the provider and reconcile
    them: a refund it does not know (made at the provider directly) is
    recorded, a known one takes the provider's outcome (`FAILED` and
    `CANCELED` never move back), and the payment moves to `REFUNDED` when
    the pending and succeeded refunds reach its amount — and back to
    `SUCCEEDED` (`PaymentRefundReversed`) when one that completed it
    fails; the status always follows the local refund rows, never one
    read of the provider. Subscribe the endpoint to the `refund.*` and
    `charge.dispute.*` events: without the first a refund's later failure
    is seen only on the next `charge.refunded`, without the second no
    dispute is recorded. `charge.dispute.*` records a `Dispute` (see
    "Refunding a top-up"). Every object the
    plugin creates carries `metadata[w17_payment]` (what it is) and
    `metadata[w17_install]` (which installation made it: a keyed hash of
    the webhook signing secret); an event for an object THIS installation
    made with no local row yet is answered `NotFound` and NOT recorded, so
    the provider redelivers it. An event for an object it did not make (a
    subscription invoice's payment, a dashboard charge, another
    installation sharing the provider account) is acknowledged. Rotating
    the signing secret changes the installation id: rotate while no
    charge is in flight.

**Errors.** A provider failure maps by class: a declined card →
`FailedPrecondition`; a request the provider (or the driver) refuses as
invalid — an amount the currency cannot carry, a refund above what is
left, an idempotency key reused with other parameters → `InvalidArgument`;
anything else (network, 5xx, rate limit) → `Unavailable`, retryable; a
call the caller cancelled → `Canceled`. The caller gets the class and a fixed
sentence; the provider's own text (endpoint, diagnostics, a masked key) is
logged, not returned. The provider's reason code (`INSUFFICIENT_FUNDS`,
`CHARGE_ALREADY_REFUNDED`, …) reaches the caller as the `w17.ErrorDetail`
code. Amounts are validated against the `NUMERIC(20,4)` columns (≤ 16 integer,
≤ 4 fractional digits) and currencies must be 3-letter codes (ISK and UGX
are whole units only; the three-decimal BHD/JOD/KWD/OMR/TND are refused) —
before any provider call.

**Reads.** The REST reads (`GET /payments/{id}`, `/credit/balance`,
`/usage/{meter}/{period}`, `/subscriptions/{id}`) are served by
`PaymentService.GetMy*`, which answer only with the signed-in caller's
rows (see "Who a request acts for"). The storage `PaymentQuery` tier
takes any id and is for the project's own code only.
- **Events** — `PaymentCreated`, `PaymentSucceeded`, `PaymentAmountMismatch`, `PaymentFailed`,
  `PaymentCanceled`, `PaymentRefunded`, `PaymentRefundReversed`,
  `RefundCreated` (a refund this plugin made, partial or full),
  `ProviderRefundRecorded` (one made at the provider directly, found by the
  webhook or the reconciliation), `RefundStatusChanged` (a refund's outcome)
  and, with `stripe_webhooks`, `DisputeOpened` / `DisputeClosed` (WON or
  LOST), all provider-neutral and each emitted once by the write that records
  the fact. A subscriber that wants every refund listens to both refund
  events. A payment
  reads `REFUNDED` once its pending and succeeded refunds reach its amount:
  `RefundPayment` sets it when its refund completes the amount, and the
  refund webhooks settle it otherwise; a failed or canceled refund does not
  count.
  A success is checked first: a payment the provider reports took another
  amount or currency than its row holds (its intent was changed at the
  provider) is held at `AMOUNT_MISMATCH` instead, with what it took
  (`received_amount`, `received_currency`), and `PaymentAmountMismatch` says
  so — no `PaymentSucceeded`, no top-up credit. An operator decides;
  `RefundPayment` returns up to what it took.
- **Stripe driver** (`src/lib/backend/stripe`) — `EnsureCustomer`,
  `CreatePayment`, `RefundPayment`, `FindRefund` (and the subscription
  calls below), `ListRefunds` over the Stripe REST API (no vendored SDK), plus webhook
  signature verification. Exact money handling
  (decimal string → integer minor units, no float64).

## Upgrading from 0.1.0-rc.2 or earlier

**Module path.** The Go module path changed from `github.com/wandering-compiler/platform/plugins/payment` to `github.com/wandering-compiler/plugins/payment`. Generated code needs nothing: `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports. Hand-written code that imports the plugin's packages directly must update its import paths, and any `replace` directive in its own `go.mod`.

- **Do not run mixed versions.** Stop or drain every rc.2 (or earlier)
  replica before an instance of this version serves traffic — a rolling
  deploy that runs both side by side is not safe. This version recognises
  a credit grant / spend or a usage report that an earlier version made by
  READING under the raw key before it applies under the scoped one; an
  earlier replica still writing raw keys can record the same request (a
  client retry routed to it) after that read, and it is then applied
  twice — credit granted or spent twice, usage counted twice.
- **Migration.** New nullable columns: `Refund.idempotency_key` (the kept
  refund key) and `Subscription.provider_event_at` (event ordering). Rows
  written before the upgrade hold NULL there. The `Subscription.status`
  enum (and the column's CHECK) is widened — new values below. The
  `SubscriptionStarted` event gains a `status` field (field 6,
  `Subscription.Status`); a consumer decoding it with an older schema just
  ignores it, but one that grants entitlements on the event should start
  reading it (see the subscriptions section).
- **Three-decimal currencies are refused** (BHD, JOD, KWD, OMR, TND —
  earlier versions sent them as two-decimal amounts, ten times off). A
  payment made in one of them before the upgrade cannot be refunded
  through the plugin; refund it in the provider dashboard.
- **UGX payments made by earlier versions were charged at 1/100** of the
  amount asked (UGX went out as a zero-decimal amount; the provider takes
  it in hundredths). Their local rows hold the amount asked, and a refund
  through the plugin is computed from it: a full refund asks for 100× what
  was charged and is refused, a partial one refunds the wrong amount.
  Refund them in the provider dashboard.
- **Subscription status values added** — `INCOMPLETE`, `PAUSED`, `UNPAID`,
  `UNRECOGNIZED_STATUS` (5–8; existing numbers unchanged). Earlier versions
  stored `incomplete` / `paused` / unknown provider statuses as `ACTIVE` and
  `unpaid` as `PAST_DUE`; such a row keeps that status until the provider's
  next `customer.subscription.*` event for it. Only `TRIALING` and `ACTIVE`
  mean paid up.
- **Refund keys.** A refund made before the upgrade has no stored key: a
  retry of it within the provider's 24h is still a provider replay (the
  key is sent verbatim, as before), returns the recorded refund, and
  stores the key on that row — from then on the retry is recognised
  locally, after the 24h too. A pre-upgrade refund that is NOT retried
  within the 24h never gets its key, and a retry after that is not
  recognised (it refunds again). One refund key now names one refund
  across all payments — reusing it on another payment is
  `InvalidArgument`.
- **Credit and usage keys.** Grants, spends and usage reports are stored
  under a scoped key now; one made before the upgrade and retried after it
  is still recognised under its raw key (see the prepaid and usage
  sections).

## Who a request acts for

Every `/billing` endpoint acts on the signed-in caller's own billing:

- `CreateCustomer`, `CreatePayment`, `Subscribe` and `TopUpCredit` take the caller as the user. An empty `user_id` means the caller, and any other id is refused (`PERMISSION_DENIED`).
- `GET /payments/{id}`, `/subscriptions/{id}`, `/credit/balance` and `/usage/{meter}/{period}` are served by `PaymentService.GetMy*`. They answer only with the caller's rows; another person's id reads as not found.

The caller comes from the gateway's `x-w17-user` envelope, field 2 (`string user_id = 2`, which w17 requires of every auth method's response). An envelope that is present but empty, repeated or without a readable caller is refused (`UNAUTHENTICATED`). The project's own code calls the same business methods without an envelope and names the user itself. For reads it uses `PaymentQuery`. Don't expose `PaymentQuery`, `PaymentMutation`, `RefundPayment`, `GrantCredit`, `SpendCredit`, `ReportUsage` or `CreatePlan` on a client-facing surface: they trust the caller (`RefundPayment` refunds any payment by id).

**The envelope follows the request.** A project handler serving a signed-in person that calls `PaymentService` (in process, or over a dialled conn) carries that person's `x-w17-user`, so the call acts for that person: an empty `user_id` means them, and another user's id is `PERMISSION_DENIED`. Jobs, webhooks and event subscribers carry no envelope. Code that deliberately acts for someone else while serving a request (an admin action, an owner paying for a member) authorises that itself and removes the envelope before the call:

```go
md, _ := metadata.FromIncomingContext(ctx)
md = md.Copy()
md.Delete("x-w17-user")
ctx = metadata.NewIncomingContext(ctx, md)
```

## Money

Every monetary column is `type: DECIMAL` (string carrier,
`NUMERIC(20,4)`), never the double-carried `MONEY` preset — currency
must be exact. Amounts cross the API as decimal strings (`"19.99"`).

## Configuration (`env`)

Each entry's full text is its `description:` in `plugin.yaml`; the generated
`gen.EnvConfig` carries it as the field's comment. Secret entries arrive as
`secret.String`, revealed once, when `RegisterPlugin` builds the backend.

| env | secret | purpose |
|---|---|---|
| `payment_provider` | no | driver; v1: `stripe` (default) |
| `provider_api_key` | **yes** | Stripe secret key (`sk_…`) |
| `webhook_signing_secret` | **yes** while `stripe_webhooks` is on (the default); the bundle refuses to boot without it | webhook HMAC secret (`whsec_…`) |
| `provider_api_base` | no | root of a Stripe-compatible API instead of `https://api.stripe.com` (e.g. the `stripemock` sandbox, `http://stripemock:12111`); empty = the real API; test keys only |
| `default_currency` | no | ISO-4217 applied when a charge omits one |
| `previous_install_marks` | no | comma-separated installation marks written under earlier signing secrets (see below); a malformed one fails boot |

## Prepaid credit wallet (feature `prepaid`)

An append-only credit ledger keyed by the project principal — independent
of the provider (credits are local; `TopUpCredit` funds them with a provider
charge). Off by default.

- **Models** — `CreditLedger` (append-only signed deltas, unique
  idempotency key) + `CreditBalance` (materialized balance, non-negative
  CHECK).
- **`ApplyCredit` mutation** — appends the ledger row AND updates the
  materialized balance in ONE transaction (the balance row is made at zero
  when missing, then the delta is applied with an `UPDATE`). The CHECK
  rejects an overdraw → the whole transaction rolls back (concurrency-safe
  guard, not a racy read-then-write).
- **PaymentService** (gated `prepaid`):
  - `GrantCredit` / `SpendCredit` — apply a signed amount; idempotent on
    the key, scoped per principal and per operation (a retry is a no-op;
    the same key on another principal, or a spend reusing a grant's key,
    is a separate apply); `SpendCredit` returns `FailedPrecondition` when
    the balance is insufficient. An apply made by rc.2 or earlier (which
    stored the raw key) and retried after the upgrade is recognised — same
    principal, direction and amount under the raw key — and not applied
    again; this costs one extra ledger read per apply.
  - `TopUpCredit` — charge the user in `default_currency` and grant the
    same amount of credit when the provider confirms the payment (see
    "Cross-feature webhook wiring"). Refused without `stripe_webhooks`.
  - read the caller's balance via `GET /credit/balance` →
    `PaymentService.GetMyCreditBalance` (zero before the first credit);
    grant/spend/top-up are privileged business ops, not REST-exposed.
- **A top-up's credit is reconciled, not patched.** One rule decides what
  a top-up is worth: its amount, less its pending and succeeded refunds and
  its lost disputes, never below zero, and nothing until its payment has
  succeeded. After every change to those — the success, a refund (through
  `RefundPayment` or made at the provider directly), a refund's outcome, a
  dispute, a retry — the plugin moves the credit it holds for the top-up to
  that target. An increase cancels what the owner owes first, then adds
  spendable credit. A decrease takes only what the balance holds — never
  below zero; the rest is recorded as `CreditTopup.credit_owed`, credit the
  owner spent and now owes, taken later if the balance grows while the
  top-up is reconciled again. The plugin does not otherwise collect it;
  query `credit_owed > 0` to find owners who owe credit.
- **Refunding a top-up** — `RefundPayment` on a top-up payment takes the
  refunded amount from the owner's credit before the provider is asked.
  Credit already spent, or not granted yet, makes the refund
  `FailedPrecondition`; a refusal the provider will repeat gives the credit
  back, and so does a refund the provider fails later.
- **Refunds and disputes at the provider** (needs `stripe_webhooks`) — a
  refund made at the provider directly (its dashboard, its API), and a lost
  dispute, lower the top-up's target when their webhook arrives; a webhook
  cannot refuse, so spent credit is owed. An open dispute lowers nothing
  (most are won; the credit stays spendable until it is lost), and an
  inquiry, a won dispute or a refund first seen failed change nothing. A
  refund or dispute that arrives before the top-up's grant is simply left
  out of it. The ledger reasons `topup`, `topup-refund`,
  `topup-refund-refused` and `topup-reconcile` are the plugin's own:
  `GrantCredit` and `SpendCredit` refuse them.
- **Event** — `CreditApplied` (signed delta + new balance).

## Metered / pay-as-you-go (feature `usage`)

Append-only usage ledger + materialized per-period meter, keyed by the
principal. "Burning time" (a bare quantity) and "ordering a service" (a
quantity carrying `item_ref`/`metadata`) are the SAME operation — one
`UsageRecord` — differing only in payload. Off by default.

- **Models** — `UsageRecord` (append-only, unique idempotency key) +
  `UsageMeter` (materialized `total` per principal/meter/period,
  composite-unique; `reported_total` cursor for a future provider push).
- **`RecordUsage` mutation** — appends the record AND increments the
  meter in ONE transaction (UPSERT increment on the composite key).
- **PaymentService** (gated `usage`):
  - `ReportUsage` — record consumption; idempotent on the key, scoped per
    (principal, meter, period). A report made by rc.2 or earlier (which
    stored the raw key) and retried after the upgrade is recognised — same
    principal, meter, period and quantity under the raw key — and not
    counted again; this costs one extra record read per report. Internal /
    server-to-server (NOT REST-exposed — the service measuring usage
    reports it).
  - read the caller's total via `GET /usage/{meter}/{period}` →
    `PaymentService.GetMyUsageMeter` (zero before the first report).
- **Period** — an ISO 8601 window: a year `2026`, a month `2026-06`, an
  ISO week `2026-W23` (Monday to Sunday), a day `2026-06-15`, or N days from
  a day `2026-06-03/P7D` (1 to 366). It is stored in one canonical spelling,
  so every spelling of a window counts on one meter; any other spelling is
  refused (`InvalidArgument`). A rolling window starts where the caller says:
  the plugin keeps no anchor.
- **Event** — `UsageRecorded` (quantity + new total).

## Subscriptions (feature `subscriptions`)

Recurring plans. The **catalogue is locally authoritative** (the project
defines plans; the plugin pushes each to the provider and stamps the
returned `provider_price_id`); **subscription lifecycle status is
provider-authoritative** (created on subscribe, reconciled from
webhooks). Off by default. This is the one feature that extends
`backend.Backend` (`UpsertPlan`, `StartSubscription`, `FindSubscription`).

- **Models** — `Plan` (slug-keyed catalogue, `provider_price_id`) +
  `Subscription` (status enum, `current_period_end`). The status is the
  provider's, mapped one to one: `TRIALING`, `ACTIVE`, `INCOMPLETE` (first
  payment not made), `PAST_DUE`, `UNPAID`, `PAUSED`, `CANCELED` (also the
  provider's `incomplete_expired`; terminal), and `UNRECOGNIZED_STATUS` for
  a status this version does not know. **Only `TRIALING` and `ACTIVE` mean
  paid up** — grant access on those two, nothing else.
- **PaymentService** (gated `subscriptions`):
  - `CreatePlan` — define a plan + push the price to the provider
    (idempotent on slug when the terms match; a slug that exists with a
    different amount / currency / interval is `AlreadyExists`).
    Privileged / admin — NOT REST-exposed.
  - `Subscribe` — ensure the customer, start the provider subscription,
    persist the local record (`POST /subscriptions`). The
    `idempotency_key` rides in the subscription's metadata
    (`w17_subscribe`); before starting one the plugin looks for the
    customer's subscription under that key, in any status, so a retry
    after the provider has forgotten the key starts no second one. The
    same key with another plan is `AlreadyExists`.
  - read one of the caller's via `GET /subscriptions/{id}` →
    `PaymentService.GetMySubscription` (another customer's reads as not
    found).
- **`MarkSubscriptionStatus` mutation** — reconcile lifecycle from the
  provider's `customer.subscription.*` webhooks (CANCELED is terminal, and an
  older event never overwrites a newer one).
- **Events** — `SubscriptionStarted` (carries the `status` the subscription
  was created in) and `SubscriptionStatusChanged`. A new subscription is
  often NOT paid up: the provider's default creates it `INCOMPLETE` until
  the first invoice is paid. Grant plan entitlements only on `TRIALING` /
  `ACTIVE` — `SubscriptionStarted.status` when it already is one, otherwise
  the `SubscriptionStatusChanged` that moves it there; never on
  `SubscriptionStarted` alone.

## Reconciling with the provider (`ReconcileProvider`)

The webhooks keep the local rows in step with the provider, but two things
can lose a change for good: a local write that failed after the provider
call and was never retried (an intent, a refund, a subscription or a
customer with no row), and a webhook endpoint that was down or refusing for
longer than the provider redelivers (about three days), which leaves a row
whose status never moves again — a charge that reads pending although it was
paid, a top-up whose credit was never granted, a dashboard refund never
recorded.

`PaymentService.ReconcileProvider` (feature `stripe_webhooks`) closes both.
It walks the provider's customers, payment intents, refunds and (with
`subscriptions`) subscriptions created at or after `since`, and for every
object **this installation** made — recognised by the `w17_payment` /
`w17_install` marks the plugin writes — it records the missing row or brings
the lagging one up to date, through the same paths the create calls and the
webhook use. So the events fire as they would have (`PaymentSucceeded` once,
not on every run), a top-up's credit is granted or taken back once, and a
run is safe beside webhook deliveries and beside another run. Objects
without this installation's marks are counted `foreign` and left alone.
Nothing is ever deleted.

The plugin schedules nothing, and no preset exposes the method (it is not
for end users). Call it from your own code — a scheduled job, an operator
action — through the plugin's service in your bundle:

```go
req := &paymentpb.ReconcileProviderReq{Since: timestamppb.New(time.Now().Add(-96 * time.Hour))}
for {
	resp, err := payments.ReconcileProvider(ctx, req)
	if err != nil {
		return err // an invalid request, or no installation id
	}
	log(resp) // counts per kind: created, updated, in_sync, foreign, superseded, failed
	if resp.GetStopped() != "" {
		saveForLater(resp.GetNextCursor()) // a provider list failed: resume later, not now
		break
	}
	if resp.GetNextCursor() == "" {
		break
	}
	req = &paymentpb.ReconcileProviderReq{Cursor: resp.GetNextCursor()}
}
```

- **`since`** is required; `limit` caps the objects one call examines
  (default 1000, at most 10000); `next_cursor` continues the walk (send it
  alone — it carries its `since`).
- **A provider list that fails does not lose the walk.** A rate limit, a
  5xx or a timeout is retried three times (about five seconds, never past
  the call's deadline); a list that still fails, or that the provider
  refuses, ends the call with the counts so far, `stopped` saying which list,
  and `next_cursor` at the page that failed. A cursor whose object was since
  deleted at the provider continues from that object's creation time.
- **Suggested cadence:** hourly with `since` four days back (a little more
  than the provider's redelivery window, so a webhook still being retried is
  usually there first), and after any webhook outage once with `since` at the
  outage's start. Each run lists every object created since `since`, so keep
  the window as short as your outages allow.
- **`failed`** objects are logged server-side with their cause and retried
  by the next run; a count that stays above zero needs a look. `superseded`
  is a customer whose principal is already linked to another one (the loser
  of two concurrent first charges): harmless.
- **Rotating `webhook_signing_secret` changes the installation mark**
  (`w17_install` derives from it). Every object created before the rotation
  then reads as foreign: the reconciliation never touches it again, and its
  webhooks are acknowledged without effect. List the old mark — read it off
  any older object's metadata in the provider's dashboard — in
  `previous_install_marks` to keep those objects this installation's.
- **Not covered:** provider prices (`CreatePlan` is locally authoritative; an
  orphan price is never referenced and moves no money), disputes (only the
  webhook records them), and customers created before this version (they
  carry no marks and count as `foreign`; their payments are still matched).

## Audit tables are never pruned

`ProcessedWebhookEvent`, `CreditLedger`, `UsageRecord`, `Refund` and
`Dispute` are audit logs: the plugin never deletes a row from any table, and
does not expect you to. Archiving them at scale (partitioning, moving old
rows to cold storage) is a deployment concern.

## Features

- `stripe_webhooks` (default on) — the webhook ingestion surface
  (`IngestStripe` + `ProcessedWebhookEvent` + `MarkWebhookProcessed`), and
  `ReconcileProvider`.
- `prepaid` (default off) — the credit wallet. The wallet is local;
  `TopUpCredit` needs `stripe_webhooks` too (a top-up's credit is granted
  from the webhook) and refuses to charge without it.
- `usage` (default off) — metered / pay-as-you-go.
- `subscriptions` (default off) — recurring plans. Requires
  `stripe_webhooks` (the provider's webhook settles a subscription).

An activation that lists `features:` replaces the defaults, so a list
naming `subscriptions` must name `stripe_webhooks` too, and so must one
that uses `TopUpCredit`.

The baseline (customers / payments / refunds) carries no feature tag —
always present.

## Cross-feature webhook wiring

When `stripe_webhooks` runs alongside `prepaid` / `subscriptions`, the
webhook handler dispatches to feature logic via nil-checked hooks
(registered by each feature's `init()` — the same pattern auth uses, so
there is no compile coupling when a feature is absent):

- **Subscription lifecycle reconciliation** — `customer.subscription.*`
  events → `MarkSubscriptionStatus` (status + period end), emitting
  `SubscriptionStatusChanged`. The provider is authoritative for status.
- **Credit top-up** — `PaymentService.TopUpCredit` charges the principal
  in `default_currency` (credit has no currency of its own, so any other
  currency is refused) and records a pending `CreditTopup`; on
  `payment_intent.succeeded` the hook grants matching credit (idempotent —
  per-charge ledger key + `granted_at` guard) and stamps it granted. The
  hook runs on every delivery of the event until one completes, so a
  grant that failed transiently is retried by the provider's redelivery.

## Roadmap (follow-ups)

- **Usage → provider push** — the `reported_total` cursor → Stripe usage
  records (pairs with subscriptions).
- **More gateway drivers** — Paddle / Adyen / GoCardless behind
  `backend.Backend`.
- **Project-level e2e** — DQL→SQL migrations, live gateway, real Stripe
  (the standalone slices prove handler logic + the Stripe driver; the
  multi-op / UPSERT / CHECK DQL validates at project codegen).

## Generating `src/gen`

`src/gen` is generated and never committed: the pb, the contract
`RegisterPlugin` takes (`EnvConfig`, `ClientSet`, `HandlerRegistry`) and the
feature constants. After cloning, and after editing `plugin.yaml` or any
`proto/` file:

```
make gen PLUGIN=payment     # or: w17ctl plugin gen payment
```

It needs a reachable console (a w17ctl login). A consumer's staging generates
the same package for each activation, so nothing here is published.
