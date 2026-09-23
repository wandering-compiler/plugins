# payment plugin

Provider-agnostic billing primitives for w17 projects. The public proto
surface (models / service / events) names no provider; the concrete
gateway plugs in behind an internal `backend.Backend` interface selected
by the `payment_provider` env. **Slice 1 ships the core + the Stripe
driver.**

Full design: [`docs/specs/plugins/payment.md`](../../docs/specs/plugins/payment.md).

## What Slice 1 (core) provides

- **Models** — `Customer` (principal ↔ provider-customer link),
  `Payment` (one charge, provider-owned status), `Refund`,
  `ProcessedWebhookEvent` (inbound idempotency ledger).
- **PaymentService** (turnkey, hand-written handlers):
  - `CreateCustomer` — provider customer + local link.
  - `CreatePayment` — ensure customer, create the provider payment
    (idempotency-keyed), persist the local `Payment`. Returns the
    provider `client_secret` for frontend confirmation.
  - `RefundPayment` — reverse a payment (full or partial) via the
    provider + record a local `Refund`. Privileged / internal (not
    REST-exposed).
  - `IngestStripe` — webhook sink (gated `stripe_webhooks`): verify the
    `Stripe-Signature` HMAC (constant-time, multi-`v1`) + timestamp
    tolerance (5-min replay window), dedup on the event id, dispatch the
    terminal state to `MarkPaymentSucceeded` / `MarkPaymentFailed`.

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
    the key (a retry is a no-op); `SpendCredit` returns
    `FailedPrecondition` when the balance is insufficient.
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
  - `ReportUsage` — record consumption; idempotent on the key. Internal /
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
  `Subscription` (status enum, `current_period_end`).
- **PaymentService** (gated `subscriptions`):
  - `CreatePlan` — define a plan + push the price to the provider
    (idempotent on slug). Privileged / admin — NOT REST-exposed.
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
  and records a pending `CreditTopup`; on `payment_intent.succeeded` the
  hook grants matching credit (idempotent — per-charge ledger key +
  `granted_at` guard) and stamps it granted.

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
