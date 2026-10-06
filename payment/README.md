# payment plugin

Provider-agnostic billing primitives for w17 projects. The public proto
surface (models / service / events) names no provider; the concrete
gateway plugs in behind an internal `backend.Backend` interface selected
by the `payment_provider` env. **Slice 1 ships the core + the Stripe
driver.**

## What Slice 1 (core) provides

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
    a key already used for another payment is `AlreadyExists`. An empty
    key gets a random one (no retry safety — send a stable key for that).
  - `RefundPayment` — reverse a payment (full or partial) via the
    provider + record a local `Refund`. The `idempotency_key` names ONE
    refund across all payments (it is the provider's idempotency key,
    sent verbatim): a retry with the same key, payment and amount returns
    the recorded refund; the same key with another amount is
    `AlreadyExists`, on another payment `InvalidArgument`. The key is kept
    and looked up before the provider is asked, so a retry after the
    provider has forgotten its idempotency key does not refund twice.
    Privileged / internal (not REST-exposed).
  - `IngestStripe` — webhook sink (gated `stripe_webhooks`): verify the
    `Stripe-Signature` HMAC (constant-time, multi-`v1`) + timestamp
    tolerance (5-min replay window), dispatch the terminal state to
    `MarkPaymentSucceeded` / `MarkPaymentFailed` (transition-guarded, so a
    redelivered or out-of-order event changes and emits nothing; CANCELED
    and REFUNDED are terminal, and an older subscription event never
    overwrites a newer one), then record the event id. Every object the
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
anything else (network, 5xx, rate limit) → `Unavailable`, retryable.
Amounts are validated against the `NUMERIC(20,4)` columns (≤ 16 integer,
≤ 4 fractional digits) and currencies must be 3-letter codes (ISK and UGX
are whole units only; the three-decimal BHD/JOD/KWD/OMR/TND are refused) —
before any provider call.

**Reads have no business handler.** Pure reads (`GET /payments/{id}`,
`/credit/balance`, `/usage/{meter}/{period}`, `/subscriptions/{id}`) are
REST presets pointing straight at the storage `PaymentQuery` tier — the
gateway fronts any service RPC, so a hand-written passthrough would add
nothing. Only operations with real logic (provider calls, signed-amount
credit, idempotency / error-contract mapping, webhook verify) keep a
`PaymentService` business handler.
- **Events** — `PaymentSucceeded`, `PaymentFailed` (provider-neutral),
  emitted from the reconciliation mutations after the provider confirms.
- **Stripe driver** (`src/lib/backend/stripe`) — `EnsureCustomer`,
  `CreatePayment`, `RefundPayment` over the Stripe REST API (no vendored
  SDK), plus webhook signature verification. Exact money handling
  (decimal string → integer minor units, no float64).

## Upgrading from 0.1.0-rc.2 or earlier

- **Migration.** New nullable columns: `Refund.idempotency_key` (the kept
  refund key) and `Subscription.provider_event_at` (event ordering). Rows
  written before the upgrade hold NULL there.
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
  key is sent verbatim, as before) and returns the recorded refund; a
  retry after that is not recognised. One refund key now names one refund
  across all payments — reusing it on another payment is
  `InvalidArgument`.
- **Credit and usage keys.** Grants, spends and usage reports are stored
  under a scoped key now; one made before the upgrade and retried after it
  is still recognised under its raw key (see the prepaid and usage
  sections).

## Money

Every monetary column is `type: DECIMAL` (string carrier,
`NUMERIC(20,4)`), never the double-carried `MONEY` preset — currency
must be exact. Amounts cross the API as decimal strings (`"19.99"`).

## Configuration (`env`)

| env | secret | purpose |
|---|---|---|
| `payment_provider` | no | driver; v1: `stripe` (default) |
| `provider_api_key` | **yes** | Stripe secret key (`sk_…`) |
| `webhook_signing_secret` | **yes** | webhook HMAC secret (`whsec_…`) |
| `default_currency` | no | ISO-4217 applied when a charge omits one |

## Prepaid credit wallet (feature `prepaid`, Slice 2)

An append-only credit ledger keyed by the project principal — independent
of the provider (credits are local; a Stripe top-up that funds them is a
follow-up). Off by default.

- **Models** — `CreditLedger` (append-only signed deltas, unique
  idempotency key) + `CreditBalance` (materialized balance, non-negative
  CHECK).
- **`ApplyCredit` mutation** — appends the ledger row AND updates the
  materialized balance in ONE transaction (UPSERT increment). The CHECK
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
  - read balance via `GET /credit/balance` → `PaymentQuery.GetCreditBalance`
    (storage-direct); grant/spend are privileged business ops.
- **Event** — `CreditApplied` (signed delta + new balance).

## Metered / pay-as-you-go (feature `usage`, Slice 3)

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
  - read the total via `GET /usage/{meter}/{period}` →
    `PaymentQuery.GetUsageMeter` (storage-direct).
- **Event** — `UsageRecorded` (quantity + new total).

## Subscriptions (feature `subscriptions`, Slice 4)

Recurring plans. The **catalogue is locally authoritative** (the project
defines plans; the plugin pushes each to the provider and stamps the
returned `provider_price_id`); **subscription lifecycle status is
provider-authoritative** (created on subscribe, reconciled from
webhooks). Off by default. This is the one feature that extends
`backend.Backend` (`UpsertPlan`, `StartSubscription`).

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
    persist the local record (`POST /subscriptions`).
  - read one via `GET /subscriptions/{id}` → `PaymentQuery.GetSubscription`
    (storage-direct).
- **`MarkSubscriptionStatus` mutation** — reconcile lifecycle from a
  provider webhook (ready; the webhook dispatch wiring is a follow-up).
- **Events** — `SubscriptionStarted`, `SubscriptionStatusChanged`.

## Features

- `stripe_webhooks` (default on) — the webhook ingestion surface
  (`IngestStripe` + `ProcessedWebhookEvent` + `MarkWebhookProcessed`).
- `prepaid` (default off) — the credit wallet.
- `usage` (default off) — metered / pay-as-you-go.
- `subscriptions` (default off) — recurring plans.

The baseline (customers / payments / refunds) carries no feature tag —
always present.

## Cross-feature webhook wiring (Slice 5)

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

## Regenerating the committed `src/gen/pb`

The `src/gen/pb/*.pb.go` stubs are author-only (the local `go test`
loop); the project codegen generates its own per-activation pb. After
editing any `proto/` file:

```
w17ctl plugin gen-pb plugins/payment
```
