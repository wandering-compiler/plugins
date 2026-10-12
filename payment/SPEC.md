# payment — behaviour specification

This document says what the `payment` plugin does, feature by feature, and what
it must never do: the security, consistency, performance and failure
properties an application built on it relies on. It is the reference the
plugin's tests and the example projects are measured against. A property
listed here without a proof is a gap, not a promise.

It covers plugin version 0.1.0-rc.5.

## How to read it

- Every **invariant** is one MUST or MUST NOT statement about observable
  behaviour, with a stable id (`<feature>/<name>`, `interaction/<a>-<b>-<name>`,
  `payment/<name>`). Ids do not change when the wording does, so tests and
  examples can cite them.
- **Categories:** Security · Consistency & concurrency · Performance · Failure &
  configuration.
- **Proof** names the unit tests in `payment/src/handlers`,
  `payment/src/lib/backend/…` or `payment/src` that demonstrate the
  invariant. The handler tests run against two stateful fakes: `memStore`, an
  in-memory stand-in for the generated storage clients that honours every
  unique column, every transition-guarded `UPDATE`, the `CreditBalance`
  `balance >= 0` check, the two-statement transactions and the
  emit-on-success contract; and a stateful provider fake (`stripefake_test.go`)
  that replays idempotency keys, forgets them on demand and refuses
  over-refunds. They prove sequencing and wire shape, not what only the
  database or the real provider can enforce (a unique index, a conditional
  `UPDATE … RETURNING` under concurrency, a `CHECK`, a rollback, the
  provider's own idempotency window and refund cap). Such rows say
  **unit (mock) only** and name what a live test would have to show. `none`
  means nothing proves it yet.
- **bearer** means the REST preset endpoint requires the gateway's
  authentication. **public** means it takes no credential (`exclude_auth`).
  A public endpoint without `public_limit: failed_only` is charged to the
  gateway's per-address limiter for every request.
- **The provider** is the payment service behind `backend.Backend`. The only
  driver today speaks the Stripe REST API; the public protos name no
  provider.
- **Gaps / suspected defects** after each feature are what the code does not
  enforce although the invariant requires it, found by reading the code. The
  ones re-checked against the code are collected under
  [Verified findings](#verified-findings).

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| (base tier: customers, payments, refunds) | always | — | — |
| `stripe_webhooks` | on | — | — |
| `prepaid` | off | — (see finding 3) | — |
| `usage` | off | — | — |
| `subscriptions` | off | — (see finding 3) | — |

`go_files`: `handlers/webhook_stripe.go` (`stripe_webhooks`),
`handlers/prepaid.go` (`prepaid`), `handlers/usage.go` (`usage`),
`handlers/subscriptions.go` (`subscriptions`). No `go_files_combined`. Always
staged: `handlers/payment_service.go`, `handlers/errors.go` (amount, currency
and key helpers, error mapping) and `handlers/webhook_hooks.go` (the
cross-feature hook variables and the installation mark).

Sandbox: `stripemock` (a stateless mock of the provider API, dev-only). With
`provider_api_base` pointed at it and a test key, every provider call answers
with the real response shape and canned values. It keeps no state and sends no
webhooks.

## Verified findings

Gaps confirmed by re-reading the handlers, the DQL and the manifest. Each is a
defect to fix before an example may claim the invariant; the invariant id says
which.

| # | finding | invariants | where |
|---|---|---|---|
| 1 | **No ownership check anywhere.** No handler reads the gateway-stamped principal. `CreateCustomer`, `CreatePayment` and `Subscribe` act for whatever `user_id` the request body names, and the REST preset exposes all three as bearer endpoints with no binding of `user_id` to the caller. The four preset reads go straight to storage keyed only by caller-supplied values: `GetPayment` and `GetSubscription` by id (no owner predicate, and `Payment` has no user column to scope on), `GetCreditBalance` and `GetUsageMeter` by a `user_id` the client sends. Any authenticated caller can create a provider customer (with an e-mail of its choosing) and payment intents for another principal and receive their client secrets, subscribe another principal, and read any payment, subscription, balance or meter. | `base/caller-is-the-principal`, `base/read-own-payment-only`, `prepaid/read-own-balance-only`, `usage/read-own-meter-only`, `subscriptions/caller-is-the-principal` | `src/handlers/payment_service.go` (`CreateCustomer`, `CreatePayment`), `src/handlers/subscriptions.go` (`Subscribe`), `proto/queries/payment_query.proto` (`GetPayment`, `GetSubscription`, `GetCreditBalance`, `GetUsageMeter`), `plugin.yaml` (`presets.rest`) |
| 2 | **`webhook_signing_secret` is not checked at boot.** `stripe_webhooks` is on by default and its description calls the secret required, but `RegisterPlugin` and `ValidateConfig` check only the API key, the provider and the storage clients. A bundle without the secret boots, refuses every webhook as `Unauthenticated`, and creates provider objects with no installation mark, so their events are later treated as foreign (acknowledged) once a secret is set. | `stripe_webhooks/secret-required-at-boot` | `src/plugin.go` (`RegisterPlugin`), `src/handlers/payment_service.go` (`ValidateConfig`) |
| 3 | **`prepaid` and `subscriptions` do not require `stripe_webhooks`.** `TopUpCredit` charges the principal and records a pending `CreditTopup`; the only code that grants the credit is the payment-succeeded webhook hook. With `prepaid` on and `stripe_webhooks` off, a top-up takes money and never grants credit. Likewise a `Subscription` keeps the status it was created with forever (often `INCOMPLETE`, or `ACTIVE` after the provider has canceled it), because only the webhook hook calls `MarkSubscriptionStatus`. Neither the manifest nor the handlers refuse the combination. | `interaction/stripe_webhooks-prepaid-required-for-topup`, `interaction/stripe_webhooks-subscriptions-required-for-status` | `plugin.yaml` (`features`), `src/handlers/prepaid.go` (`TopUpCredit`) |
| 4 | **A refund is recorded only after the provider has made it.** `RefundPayment` looks the stored key up, calls the provider, then inserts the `Refund` row with the key. If that insert fails (store outage, timeout) the money has gone back but nothing local remembers the key. A retry within the provider's idempotency window is a replay and heals; a retry after it reaches the provider as a new refund and refunds a second time. `Subscribe` has the same window: a provider subscription whose local row failed and whose retry comes after the window becomes a second, billing subscription. | `base/refund-once-per-key`, `subscriptions/subscribe-once-per-key` | `src/handlers/payment_service.go` (`RefundPayment`), `src/handlers/subscriptions.go` (`Subscribe`) |
| 5 | **Refunding a top-up leaves the credit spendable.** `TopUpCredit` creates an ordinary `Payment`; `RefundPayment` (always staged) has no hook into `prepaid`, and no webhook handles refunds or disputes. A principal can top up, have the payment refunded, and keep the full credit. | `interaction/base-prepaid-refund-reverses-topup` | `src/handlers/payment_service.go` (`RefundPayment`), `src/handlers/prepaid.go` |
| 6 | **Payment status never reflects refunds or cancellation, and refund outcome is discarded.** No statement writes `REFUNDED`, and `CANCELED` is written only when the provider answers the create call with `canceled`. `RefundPayment` drops `RefundResult.Status`, and the webhook dispatch handles only `payment_intent.succeeded`, `payment_intent.payment_failed` and `customer.subscription.*`. A fully refunded payment reads `SUCCEEDED` on `GET /billing/payments/{id}`; a refund the provider later fails or leaves pending is recorded as done; a canceled intent stays `REQUIRES_ACTION`. The "terminal" guards on `CANCELED` and `REFUNDED` protect states nothing reaches. | `base/payment-status-reflects-provider`, `base/refund-outcome-recorded` | `src/handlers/payment_service.go` (`RefundPayment`, `mapInitialStatus`), `src/handlers/webhook_stripe.go` (`reconcile`), `proto/mutations/payment_mutation.proto` |
| 7 | **The webhook endpoint is charged per address for every delivery.** `POST /webhooks/stripe` is public but declares no `public_limit: failed_only`. When the gateway's per-address limit is on, legitimate deliveries, which come from a small set of provider addresses, spend the same budget as forged ones, and a burst of real events is answered 429 and delayed by the provider's retry backoff. Signature verification is cheap; only failed (unauthenticated) deliveries should be charged. | `stripe_webhooks/provider-deliveries-not-throttled` | `plugin.yaml` (`presets.rest`, `/webhooks` group) |
| 8 | **Provider error text is returned verbatim to the caller.** `post` folds the provider's error message (or the transport error, which names the full request URL) into the error, and `providerFailure` returns it as the gRPC message. Over REST an end user sees provider object ids, the configured API root, and, for a rejected key, the provider's own message about it (which names a masked form of the key and its mode). | `payment/provider-errors-not-echoed` | `src/handlers/errors.go` (`providerFailure`), `src/lib/backend/stripe/stripe.go` (`post`) |

## Per feature

### (base tier)

- **Purpose.** The principal-to-provider customer link, one charge per
  `Payment`, and refunds. Always present.
- **Adds.** Tables `Customer` (`user_id` unique, `provider_customer_id`
  unique), `Payment` (`provider_payment_id` unique, `idempotency_key` unique,
  `amount` `DECIMAL(20,4)`, `currency` `CHAR(3)`, provider-owned `status`
  enum), `Refund` (`provider_refund_id` unique, nullable `idempotency_key`
  unique, stored as `"v2:" + sha256` of the caller's key). Queries
  `GetCustomerByUserId`, `GetPayment`, `GetPaymentByProviderId`,
  `GetRefundByProviderId`, `GetRefundByIdempotencyKey`. Mutations
  `CreateCustomer`, `CreatePayment`, `MarkPaymentSucceeded` (emits
  `PaymentSucceeded`), `MarkPaymentFailed` (emits `PaymentFailed`),
  `CreateRefund`, `SetRefundIdempotencyKey`. Service methods `CreateCustomer`,
  `CreatePayment`, `RefundPayment`. REST endpoints `POST /billing/customers`,
  `POST /billing/payments`, `GET /billing/payments/{id}` (storage query
  direct), all bearer. `RefundPayment` is not in the preset.
- **Env knobs.** `payment_provider` (only `stripe`; anything else fails
  `RegisterPlugin`), `provider_api_key` (secret, required), `provider_api_base`
  (test roots only), `default_currency` (default `usd`).
- **Requires / conflicts / combined files.** None.

| id | invariant | category | proof |
|---|---|---|---|
| `base/caller-is-the-principal` | `CreateCustomer` and `CreatePayment` MUST act only for the authenticated principal. A `user_id` sent by the client MUST NOT select another principal's customer. | Security | none. **Not guaranteed today** (finding 1). |
| `base/read-own-payment-only` | `GET /billing/payments/{id}` MUST answer only for a payment whose customer belongs to the caller, and MUST answer another principal's payment exactly like an unknown id. | Security | none. **Not guaranteed today** (finding 1). |
| `base/refund-privileged` | `RefundPayment` MUST NOT be reachable from the REST preset or any surface an end user can call. | Security | none (manifest only) |
| `base/money-exact` | Every amount MUST travel as a decimal string and be stored in `DECIMAL(20,4)`. It MUST be converted to the provider's integer minor units exactly, with no floating point, and a stored value read back with trailing zeros (`"12.3400"`) MUST convert to the same minor units as the original. | Consistency & concurrency | `TestToMinorUnits`, `TestToMinorUnits_AcceptsStoredScaleTrailingZeros`, `TestFlow_ChargeAmountNormalisation`, `TestSameDecimal`, `TestFlow_Refund_FullAndLostResponse` |
| `base/amount-valid-before-provider` | A charge or refund amount that is empty, whitespace, zero, negative, has a fifth fractional digit, more than 16 integer digits, or more fractional digits than the currency carries MUST be refused with `InvalidArgument` before any provider call. | Consistency & concurrency | `TestIsPositiveDecimal`, `TestCreatePayment_RejectsNonPositiveAmount`, `TestFlow_ChargeAmountAndCurrencyRefusals_NeverReachTheProvider`, `TestRefundPayment_ValidatesAmountBeforeTheBackend`, `TestFlow_Refund_RefusalsNeverReachTheProvider`, `TestDriver_NonPositiveAmountsNeverLeave`, `TestPositiveMinorUnits` |
| `base/minor-units-never-wrap` | An amount whose minor units do not fit a signed 64-bit integer MUST be refused. It MUST NOT be sent as a wrapped (tiny) value. | Consistency & concurrency | `TestToMinorUnits_RefusesOverflowInsteadOfWrapping`, `TestToMinorUnits_WholeUnitsOverflowOnTheWire` |
| `base/currency-scale` | Zero-decimal currencies MUST be sent as whole units, the currencies the provider takes as whole units ×100 (ISK, UGX) MUST be sent ×100 and refuse fractions, and three-decimal currencies (BHD, JOD, KWD, OMR, TND) MUST be refused. | Consistency & concurrency | `TestToMinorUnits`, `TestToMinorUnits_WholeUnitsSentAsCents`, `TestToMinorUnits_RefusesThreeDecimalCurrencies` |
| `base/currency-shape` | A currency MUST be three ASCII letters, stored lower-case. An omitted currency MUST become `default_currency`. | Consistency & concurrency | `TestIsCurrencyCode`, `TestCreatePayment_CreatesCustomerOnFirstCharge`, `TestCreatePayment_UsesExistingCustomerAndDefaultCurrency` |
| `base/refund-in-payment-currency` | A refund MUST be made and recorded in the currency of its payment. The request carries no currency, so it cannot differ. | Consistency & concurrency | `TestFlow_Refunds` (asserts the recorded currency) |
| `base/one-customer-per-principal` | A principal MUST have at most one `Customer` row, enforced by the unique `user_id`. A repeated `CreateCustomer` MUST return the existing link, and two concurrent first charges MUST both end on the winner's customer. | Consistency & concurrency | `TestFlow_CreateCustomer_IsIdempotentPerPrincipal`, `TestFlow_FirstChargeRace_AdoptsTheWinningCustomer`, `TestFlow_ChargesUseThePrincipalsOwnProviderCustomer`, `TestCreateCustomer`. **Unit (mock) only:** a live test would race N first charges for one principal and assert one `Customer` row and N payments on it. |
| `base/charge-idempotent` | Every provider create call for a charge MUST carry the idempotency key. A retry with the same key, including after a lost response, MUST return the payment the first attempt recorded, with its client secret, and MUST NOT create a second local row. | Consistency & concurrency | `TestFlow_ChargeRetryAfterLostResponse_ReturnsSamePayment`, `TestFlow_ChargeRepeatedAfterSuccess_IsIdempotent`, `TestFlow_TransientProviderFailure_RetrySucceedsOnce`, `TestCreatePayment` (driver sends the `Idempotency-Key` header) |
| `base/charge-key-scoped` | A charge key MUST be scoped by principal and by kind of charge (payment or top-up): the same key from another principal, or for the other kind, is a separate charge, never refused because someone used the key first and never answered with the other charge. A key the same principal reuses after the provider's idempotency window MUST be refused (`AlreadyExists`) without carrying another payment or its ids. A payment an earlier version stored under the caller's raw key MUST still answer the same principal's retry of it (one lookup by key per keyed charge), and MUST NOT answer a charge of the other kind under that key: a payment without the top-up description is no top-up, and one with it is a top-up when its `CreditTopup` row says so. Where the kind cannot be told, the raw key is kept: the provider then refuses a charge of the other kind, while scoping a genuine retry would create a second intent. | Security | `TestFlow_IdempotencyKeyReusedByAnotherUser_IsTheirOwnCharge`, `TestFlow_PaymentAndTopUpUnderOneKey_AreTwoCharges`, `TestFlow_RetryOfAPaymentStoredUnderTheRawKey_IsThatPayment`, `TestFlow_RetryOfATopUpStoredUnderTheRawKey_IsThatTopUp`, `TestFlow_OtherKindUnderAnEarlierRawKey_IsANewCharge` |
| `base/keyless-charges-independent` | A charge without a key MUST get a fresh random key, so two key-less charges never collide on the unique column. | Consistency & concurrency | `TestFlow_KeylessCharges_DoNotCollide`, `TestIdempotencyKeyOrNew` |
| `base/key-length` | An idempotency key longer than 255 bytes MUST be refused before any provider call. | Failure & configuration | `TestIdempotencyKeyTooLong`, `TestFlow_ChargeAmountAndCurrencyRefusals_NeverReachTheProvider` |
| `base/charge-failure-moves-no-money` | When the local insert fails after the provider created the payment intent, the caller MUST receive an error and no client secret, so the intent cannot be confirmed and no money moves. A retry with the same key MUST adopt that intent. | Failure & configuration | `TestFlow_ChargeRetryAfterLostResponse_ReturnsSamePayment` (the committed-row case only). **Unit (mock) only:** a live test would fail the insert before commit and assert no client secret and one intent after the retry. |
| `base/refund-key-names-one-refund` | `RefundPayment` MUST require a key. One key MUST name one refund across all payments: the same key, payment and amount returns the recorded refund; the same key with another amount is `AlreadyExists`; the same key on another payment is `InvalidArgument`. Two distinct keys for equal amounts MUST be two refunds. | Consistency & concurrency | `TestRefundPayment_RequiresIdempotencyKey`, `TestRefundPayment_DistinctKeysNotCollapsed`, `TestFlow_RefundKeyReusedForADifferentAmount_IsRefused`, `TestFlow_RefundKeyReusedOnAnotherPayment_IsRefused`, `TestFlow_Refund_ReplayLookupChecksThePayment`, `TestFlow_Refunds` |
| `base/refund-once-per-key` | A refund retried under its key MUST NOT return money a second time, also after the provider has forgotten the key and also when the first attempt's local write failed. | Consistency & concurrency | `TestFlow_RefundRetriedAfterTheProviderForgotTheKey_RefundsOnce`, `TestFlow_Refund_FullAndLostResponse`, `TestFlow_RefundKeyRace_ComparesTheRecordedRefund`, `TestFlow_RefundMadeBeforeTheUpgrade_RetriedAfterIt_RefundsOnce`, `TestFlow_RefundMadeBeforeTheUpgrade_StampOutcomes`. **Not guaranteed** when the insert failed and the retry comes after the provider's window (finding 4). |
| `base/refund-within-captured` | The sum of a payment's refunds MUST NOT exceed its captured amount, also for concurrent partial refunds under distinct keys. An over-refund MUST be `InvalidArgument` and leave no `Refund` row. | Consistency & concurrency | `TestFlow_Refunds` (the provider fake refuses). **Unit (mock) only:** the cap is the provider's; nothing local checks it. A live test needs a provider test-mode account (the `stripemock` sandbox keeps no state), firing concurrent partials whose sum exceeds the charge. |
| `base/refund-only-succeeded` | A refund MUST NOT be sent to the provider for a payment that is not `SUCCEEDED`. | Consistency & concurrency | none (the handler does not check the status; the provider refuses) |
| `base/refund-outcome-recorded` | A refund's provider status (pending, succeeded, failed, canceled) MUST be recorded and reconciled, so a refund the provider fails is not reported as done. | Consistency & concurrency | none. **Not guaranteed today** (finding 6). |
| `base/payment-status-reflects-provider` | `Payment.status` MUST follow the provider: initial status from the create response (unknown → `REQUIRES_ACTION`, never `SUCCEEDED` unless the provider said so), then `SUCCEEDED`, `FAILED`, `CANCELED` and `REFUNDED` from the provider's events. | Consistency & concurrency | `TestMapInitialStatus` (initial mapping only). **Not guaranteed** for `CANCELED` and `REFUNDED` (finding 6). |
| `base/provider-error-classes` | A declined payment MUST surface as `FailedPrecondition`, a request the provider or driver refuses as invalid (bad amount, over-refund, key reused with other parameters) as `InvalidArgument`, and only network, 5xx, 409, 429 and key failures as `Unavailable`, so automatic retries never loop on a request that cannot succeed. | Failure & configuration | `TestFlow_ProviderErrorMapping`, `TestProviderFailure_MapsByClass`, `TestPost_ClassifiesProviderErrors`, `TestCreatePayment_ProviderFailureIsUnavailable`, `TestDriver_EveryCallSurfacesProviderErrors` |
| `base/no-store-failure-swallowed` | A store failure on any lookup, including the replay lookup after a unique violation, MUST surface as that failure. It MUST NOT become `AlreadyExists` or a success. | Failure & configuration | `TestFlow_StoreReadFailuresSurface`, `TestFlow_ReplayLookupFailureSurfaces`, `TestFlow_RawKeyKindLookupFailureSurfaces` |
| `base/provider-call-bounded` | Every provider call MUST be bounded in time (20 s client timeout and the request context) and read at most 1 MiB of response. A response without an object id MUST be an error, not an empty id stored locally. | Performance | `TestNew_DefaultsAndOptions`, `TestDriver_RefusesResponsesWithoutAnID`, `TestPost_TransportAndDecodeFailures` |

**Gaps / suspected defects**

1. **No ownership.** See finding 1. `ChargeReq.user_id` and
   `NewCustomerReq.user_id` are documented as "stamped by the project's
   gateway", but the preset declares no binding and the handlers never read
   the principal. The safe shape is the one the auth plugin uses: take the
   user id from the gateway-stamped principal and ignore the body field, and
   give the reads a handler (or a scoped query joining `Customer.user_id`).
2. **A charge retried after the provider's window is not recognised.**
   Unlike refunds, `charge` looks a key up locally before calling the
   provider only to find a payment an earlier version stored under the
   caller's raw key, never under the scoped key it stores now. After the
   window the provider mints a new, unconfirmed intent (orphaned at the
   provider) and the caller gets `AlreadyExists` instead of its recorded
   payment. No money moves, but the retry promise in `ChargeReq` holds only
   inside the window. A `GetPaymentByIdempotencyKey` read of the scoped key
   before the provider call would close it.
3. **`EnsureCustomer` sends no idempotency key.** A retried or racing first
   charge leaves an unreferenced provider customer. Documented in the code,
   but it accumulates without bound.
4. **Refunds are not checked against the payment's state or remaining
   amount locally.** Both are left to the provider (see
   `base/refund-only-succeeded`, `base/refund-within-captured`); against the
   stateless sandbox nothing refuses them.
5. **The zero-decimal table is not exhaustive** and every currency not in it
   is treated as two-decimal. A zero-decimal currency missing from the table
   is charged at 1/100 of the amount or refused, depending on the provider.
6. **No event for a refund or for a created payment.** A consumer cannot
   learn that money went back except by polling.

---

### stripe_webhooks

- **Purpose.** Inbound provider webhook ingestion: verify, reconcile local
  state, record the event id.
- **Adds.** Table `ProcessedWebhookEvent` (`provider_event_id` primary key).
  Mutation `MarkWebhookProcessed`. Service method `IngestStripe`. REST
  endpoint `POST /webhooks/stripe` (**public**, charged on every request; the
  verbatim body lands in `raw_payload` via `raw_body_field`, and the
  `Stripe-Signature` header is forwarded as gRPC metadata). Dispatches
  `payment_intent.succeeded` → `MarkPaymentSucceeded` (then the `prepaid`
  hook), `payment_intent.payment_failed` → `MarkPaymentFailed`,
  `customer.subscription.*` → the `subscriptions` hook. Every other type is
  acknowledged and recorded.
- **Env knobs.** `webhook_signing_secret` (secret). It also derives the
  installation mark `w17_install = hex(HMAC-SHA256(secret, "w17-install-id"))[:16]`,
  written beside `w17_payment` (the origin) on every provider object the
  plugin creates.
- **Requires / conflicts / combined files.** None. Default on.

| id | invariant | category | proof |
|---|---|---|---|
| `stripe_webhooks/signature-required` | A delivery MUST be accepted only when one `v1` signature in the header equals HMAC-SHA256(secret, `"<t>.<raw body>"`), compared in constant time. `v0` and unknown parts MUST be ignored, and any one of several `v1` values (secret rotation) MUST suffice. | Security | `TestIngestStripe_AuthenticationRefusals`, `TestIngestStripe_RotatedSecretsAndExtraHeaderParts`, `TestVerifyAndParse_Valid`, `TestVerifyAndParse_BadSignature`, `TestVerifyAndParse_HeaderVariants`, `TestVerifyAndParse_MissingHeaderParts` |
| `stripe_webhooks/verify-before-any-work` | An unauthenticated delivery MUST NOT reach the store or parse the body for anything but the signature check. | Security | `TestIngestStripe_AuthenticationRefusals` (asserts no store call), `TestIngestStripe_BadSignature` |
| `stripe_webhooks/opaque-refusal` | Every refusal (no header, malformed header, wrong secret, tampered body, stale or future timestamp, missing id or type, non-JSON body) MUST answer the same `Unauthenticated` "invalid webhook signature". | Security | `TestIngestStripe_AuthenticationRefusals` |
| `stripe_webhooks/timestamp-tolerance` | A correctly signed delivery whose signed timestamp is more than 300 s from now, in either direction, or not numeric, MUST be refused. | Security | `TestVerifyAndParse_ToleranceBoundary`, `TestVerifyAndParse_TimestampTooOld`, `TestVerifyAndParse_NonNumericSignedTimestamp` |
| `stripe_webhooks/empty-secret-fails-closed` | With no signing secret, every delivery MUST be refused, including one signed with the empty key. | Security | `TestIngestStripe_UnconfiguredSecretFailsClosed`, `TestVerifyAndParse_EmptySecret` |
| `stripe_webhooks/secret-required-at-boot` | With `stripe_webhooks` on, a missing `webhook_signing_secret` MUST fail `RegisterPlugin`. | Failure & configuration | none. **Not guaranteed today** (finding 2). |
| `stripe_webhooks/event-id-and-type-required` | A signed event without an id or a type MUST be refused, so an empty id can never be recorded and later shadow every other id-less event. | Consistency & concurrency | `TestVerifyAndParse_RequiresIDAndType`, `TestIngestStripe_AuthenticationRefusals` |
| `stripe_webhooks/raw-body-verbatim` | The bytes verified MUST be exactly the bytes the provider sent: no re-encoding, whitespace or charset change between the HTTP body and `raw_payload`. | Security | none (depends on the gateway's `raw_body_field`; live only) |
| `stripe_webhooks/redelivery-no-second-effect` | A redelivered or replayed event MUST change nothing and emit nothing a second time. The guarantee MUST come from the transition guard on the reconciliation `UPDATE` (`status <> 3 …`), not from the ledger. | Consistency & concurrency | `TestIngestStripe_Redelivery_RunsNoSideEffectAndEmitsNothing`, `TestFlow_UnhandledEventTypes_AreAcknowledgedOnce`. **Unit (mock) only:** a live test would deliver one signed event twice and assert one status change and one `PaymentSucceeded` on the bus. |
| `stripe_webhooks/out-of-order-safe` | `SUCCEEDED` MUST absorb a later failure; `FAILED` MUST still move to `SUCCEEDED` (a retried confirmation); `CANCELED` and `REFUNDED` MUST NOT be left by any event. | Consistency & concurrency | `TestFlow_LateFailureAfterSuccess_IsAcknowledgedAndChangesNothing`, `TestFlow_FailureThenRetriedSuccess`, `TestFlow_ALateSuccessDoesNotResurrectACanceledPayment`, `TestIngestStripe_Succeeded`, `TestIngestStripe_Failed` |
| `stripe_webhooks/own-object-without-row-retried` | An event for an object this installation created (origin and installation mark both present and matching) whose local row has not landed MUST be answered `NotFound` and MUST NOT be recorded, so the provider redelivers until the row exists. | Failure & configuration | `TestFlow_WebhookOutrunsLocalRow_FailsUntilTheRowLands`, `TestIngestStripe_UnknownProviderPayment_MustNotAcknowledge`, `TestFlow_OwnInstallationsObjectWithoutRow_IsRetried` |
| `stripe_webhooks/foreign-object-acknowledged` | An event for an object with no origin mark, or another installation's mark, MUST be acknowledged once and change nothing. | Failure & configuration | `TestFlow_AForeignPaymentIsAcknowledgedOnce`, `TestFlow_AnotherInstallationsObject_IsAcknowledged`, `TestFlow_CreatedObjectsCarryTheOriginMark` |
| `stripe_webhooks/install-mark-not-a-secret` | The installation mark written to the provider MUST be a keyed one-way derivation of the signing secret (truncated HMAC), never the secret or a reversible form of it. An empty secret MUST write no mark. | Security | `TestInstallID` |
| `stripe_webhooks/transient-failure-not-recorded` | A failure in reconciliation, a hook or the ledger write MUST surface as an error and leave the event unrecorded, so redelivery runs the whole chain again. | Failure & configuration | `TestIngestStripe_SideEffectFailure_DoesNotStrand`, `TestFlow_TransientStoreFailures_AreNotAcknowledged` |
| `stripe_webhooks/concurrent-delivery-one-effect` | Two concurrent deliveries of one event MUST produce one transition, one event and two successful answers. | Consistency & concurrency | `TestFlow_TopUp_ConcurrentDuplicateDeliveries`. **Unit (mock) only:** a live test would post one signed event concurrently and assert one emitted event and two 2xx answers. |
| `stripe_webhooks/provider-deliveries-not-throttled` | Authentic deliveries MUST NOT spend the gateway's per-address budget; only failed ones MAY. | Failure & configuration | none. **Not guaranteed today** (finding 7). |
| `stripe_webhooks/hot-path-bounded` | One delivery MUST cost one HMAC, at most one guarded `UPDATE` and one primary-key lookup per object, the hook's bounded work, and one ledger insert. A forged delivery MUST cost one HMAC and nothing else. | Performance | none (structural) |

**Gaps / suspected defects**

1. **Narrow event coverage.** `payment_intent.canceled`, `charge.refunded`,
   `refund.updated` / `refund.failed` and dispute events are acknowledged and
   ignored (finding 6). A chargeback reverses money with no local trace.
2. **The event's amount and currency are not compared with the local row.**
   Reconciliation trusts the event type alone; `PaymentSucceeded` and the
   top-up grant use the locally recorded amount. An intent whose amount was
   changed at the provider is marked succeeded at the old amount.
3. **The ledger is never read.** Idempotency comes from the guards; the
   ledger only distinguishes `handled=false`. It grows by one row per event
   and nothing prunes it.
4. **Rotating the signing secret changes the installation mark.** An object
   created under the old mark whose row has not landed is treated as
   foreign and acknowledged. Documented: rotate while nothing is in flight.
5. **A replay inside the 300 s window is accepted** and re-runs the
   (guarded) reconciliation. Harmless by the guards, but nothing records the
   signed timestamp to refuse it outright.

---

### prepaid

- **Purpose.** A local credit wallet per principal: an append-only ledger and
  a materialized balance, funded directly (`GrantCredit`) or by a provider
  charge (`TopUpCredit`).
- **Adds.** Tables `CreditLedger` (signed `delta`, `idempotency_key` unique,
  `user_id` indexed), `CreditBalance` (`user_id` primary key, raw check
  `balance >= 0`), `CreditTopup` (`provider_payment_id` unique, nullable
  `granted_at`). Queries `GetCreditBalance`, `GetCreditLedgerByKey`,
  `GetCreditTopupByProviderId`. Mutations `ApplyCredit` (ledger insert, the
  balance row made at zero if absent, and the balance update, in one
  transaction; emits `CreditApplied`),
  `CreateCreditTopup`, `MarkTopupGranted` (guarded `granted_at IS NULL`).
  Service methods `GrantCredit`, `SpendCredit`, `TopUpCredit`. REST endpoint
  `GET /billing/credit/balance` (storage query direct, bearer). The
  payment-succeeded hook `grantTopupOnPaymentSuccess`.
- **Requires / conflicts / combined files.** None declared (see finding 3).

| id | invariant | category | proof |
|---|---|---|---|
| `prepaid/no-overdraw` | A balance MUST NOT go below zero, also under concurrent spends. The guarantee MUST come from the `balance >= 0` check rolling back the whole apply, not from a read before the write. An overdraw, including a spend by a principal who never had credit, MUST answer `FailedPrecondition`. The delta MUST be applied by an `UPDATE` of a row made at zero, never inserted: the database checks the row an INSERT proposes (balance = the negative delta) before an upsert resolves the conflict, so an inserted delta refuses every debit whatever the balance. | Consistency & concurrency | `TestSpendCredit_Insufficient`, `TestFlow_Credit_SpendGrantInvariants`, `TestFlow_Credit_ConcurrentSpendsNeverOverdraw`, `TestApplyCredit_ADebitNeverProposesANegativeRow` (holds the DQL to that shape, which no in-memory store can show). **Unit (mock) only:** a live test would fire N concurrent spends against a balance for N−k and assert exactly N−k succeed and the balance ends at zero. |
| `prepaid/ledger-and-balance-atomic` | The ledger row and the balance change MUST commit together or not at all. The balance MUST always equal the sum of the ledger's deltas for the principal. | Consistency & concurrency | `TestFlow_Credit_SpendGrantInvariants`. **Unit (mock) only:** a live test would compare `SUM(delta)` with `balance` after a mix of grants, refused spends and duplicate keys. |
| `prepaid/apply-idempotent` | A grant or spend retried with its key MUST apply once and answer the current balance. | Consistency & concurrency | `TestApplyCredit_IdempotentOnDuplicate`, `TestFlow_Credit_ApplyRetriedAcrossTheUpgrade_AppliesOnce` |
| `prepaid/key-scoped` | A key MUST be scoped by operation and principal, so the same key on another principal, or a spend reusing a grant's key, is a separate apply and never a silent no-op reported as done. A caller key shaped like a stored scoped or top-up key MUST NOT match one. | Consistency & concurrency | `TestFlow_Credit_KeyReuseAcrossPrincipalsAndKinds_IsNotASilentNoOp`, `TestFlow_Credit_CallerKeyShapedLikeAScopedKey_IsNotAMatch`, `TestScopedKey`, `TestScopedKey_PartsCannotShiftAcrossEachOther` |
| `prepaid/amount-unsigned` | Grant and spend MUST take an unsigned positive amount (validated after trimming) and apply the sign themselves. A key MUST be required. | Consistency & concurrency | `TestGrantCredit_ValidatesAmount`, `TestSpendCredit_NegatesDelta`, `TestApplyCredit_RequiresIdempotencyKey`, `TestGrantCredit` |
| `prepaid/grant-spend-privileged` | `GrantCredit`, `SpendCredit` and `TopUpCredit` MUST NOT be in the REST preset. | Security | none (manifest only) |
| `prepaid/read-own-balance-only` | `GET /billing/credit/balance` MUST answer only the caller's balance. | Security | none. **Not guaranteed today** (finding 1). |
| `prepaid/topup-default-currency` | A top-up MUST be charged in `default_currency` only, because credit has no currency and is granted 1:1. | Consistency & concurrency | `TestFlow_TopUp_RefusesAForeignCurrency` |
| `prepaid/topup-grants-once` | A top-up MUST grant its credit exactly once, under the key `topup:<provider payment id>`, however many times, and however concurrently, the success event arrives, including when the grant committed and the stamp failed. | Consistency & concurrency | `TestFlow_TopUpStampFailure_DoesNotDoubleGrant`, `TestFlow_TopUp_ConcurrentDuplicateDeliveries`, `TestIngestStripe_TopUpAlreadyGranted_NoOp`, `TestFlow_TopUpStampLostToAConcurrentDelivery_IsNotAFailure`, `TestFlow_TopUpGrantKeepsTheKeyEarlierVersionsWrote`. **Unit (mock) only** for the concurrent case. |
| `prepaid/topup-grant-not-lost` | A top-up whose grant failed transiently, or whose success arrived before its `CreditTopup` row, MUST be granted on a later delivery. | Failure & configuration | `TestFlow_TopUpGrant_SurvivesATransientFailure`, `TestFlow_TopUpSuccessBeforeItsTopupRow_IsRetriedNotLost`, `TestTopupHook_MissingRow_RetriedOnlyForThisInstallation`, `TestFlow_TopUpFailurePaths` |
| `prepaid/topup-grants-the-payer` | A top-up's success MUST credit the principal who paid, and only that top-up. | Security | `TestFlow_TopUp_GrantsOnlyThePayer`, `TestIngestStripe_TopUpSuccess_GrantsCredit`, `TestIngestStripe_SucceededNotATopUp_NoGrant` |
| `prepaid/topup-retry` | A retried top-up with the same key MUST answer the one payment and leave one pending top-up. | Consistency & concurrency | `TestFlow_TopUp_RetryAfterLostResponse`, `TestTopUpCredit` |
| `prepaid/balance-read-indexed` | Balance reads MUST be a primary-key lookup; ledger key and top-up lookups MUST use their unique indexes. | Performance | none (schema only) |

**Gaps / suspected defects**

1. **Every `INVALID_VALUE` reads as an overdraw.** `applyCredit` maps any
   `INVALID_VALUE` constraint code to "insufficient credit balance". A
   `reason` that is not a slug, or another field-level refusal that the
   storage tier reports with that code, would be told to the caller as a
   balance problem.
2. **No reversal path.** A refund or dispute of a top-up payment leaves the
   credit (finding 5). There is no `adjustment` operation other than a
   privileged spend.
3. **Mixed-version rollouts double-apply.** The README requires every older
   replica to be drained first; nothing enforces it.

---

### usage

- **Purpose.** Metered consumption: an append-only usage record and a
  materialized total per principal, meter and period.
- **Adds.** Tables `UsageRecord` (`idempotency_key` unique, `user_id`
  indexed), `UsageMeter` (unique `(user_id, meter, period)`, `total`,
  `reported_total`). Queries `GetUsageMeter`, `GetUsageRecordByKey`. Mutation
  `RecordUsage` (record insert and meter upsert in one transaction; emits
  `UsageRecorded`). Service method `ReportUsage`. REST endpoint
  `GET /billing/usage/{meter}/{period}` (storage query direct, bearer).
- **Requires / conflicts / combined files.** None.

| id | invariant | category | proof |
|---|---|---|---|
| `usage/record-and-meter-atomic` | The usage record and the meter increment MUST commit together or not at all. The meter MUST equal the sum of its records. | Consistency & concurrency | `TestReportUsage`. **Unit (mock) only:** a live test would compare `SUM(quantity)` with `total` after concurrent reports and duplicates. |
| `usage/report-idempotent` | A report retried with its key, also concurrently, MUST be counted once and answer the current total. | Consistency & concurrency | `TestReportUsage_IdempotentOnDuplicate`, `TestFlow_Usage_ConcurrentRetriesCountOnce`, `TestFlow_Usage_ReportRetriedAcrossTheUpgrade_CountsOnce`. **Unit (mock) only** for the concurrent case. |
| `usage/key-scoped` | A key MUST be scoped by principal, meter and period, so reuse elsewhere is a separate report and never a silent no-op. | Consistency & concurrency | `TestFlow_Usage_KeyReuseAcrossPrincipalsAndMeters_IsNotASilentNoOp`, `TestFlow_Usage_CallerKeyShapedLikeAScopedKey_IsNotAMatch` |
| `usage/report-valid` | A report MUST name a principal, meter, period, a positive quantity and a key of at most 255 bytes. | Consistency & concurrency | `TestReportUsage_Validates`, `TestRequiredFieldRefusals` |
| `usage/failure-surfaces` | A store failure MUST surface; it MUST NOT be answered as a duplicate. | Failure & configuration | `TestFlow_Usage_TransientFailureSurfaces` |
| `usage/report-privileged` | `ReportUsage` MUST NOT be in the REST preset: the measuring service reports usage, not the consumer. | Security | none (manifest only) |
| `usage/read-own-meter-only` | `GET /billing/usage/{meter}/{period}` MUST answer only the caller's meter. | Security | none. **Not guaranteed today** (finding 1). |
| `usage/meter-lookup-indexed` | Meter reads and upserts MUST use the composite unique index. | Performance | none (schema only) |

**Gaps / suspected defects**

1. **Usage is never billed.** `reported_total` is written as 0 and nothing
   pushes usage to the provider. The feature is a local meter only.
2. **No upper bound on `quantity`.** `total + quantity` can overflow the
   64-bit column; the database error would surface as an internal failure.
3. **`period` is free-form.** Two spellings of one billing window are two
   meters.

---

### subscriptions

- **Purpose.** A locally authoritative plan catalogue pushed to the provider,
  and subscriptions whose lifecycle status the provider owns.
- **Adds.** Tables `Plan` (`slug` unique, `provider_price_id`, `enabled`),
  `Subscription` (`provider_subscription_id` unique, `customer_id` indexed,
  status enum mapped one to one, `provider_event_at` for ordering). Queries
  `GetPlanBySlug`, `GetSubscription`, `GetSubscriptionByProviderId`. Mutations
  `CreatePlan`, `CreateSubscription` (emits `SubscriptionStarted` with
  `status`), `MarkSubscriptionStatus` (guarded `status <> 4` and
  `provider_event_at` not newer; emits `SubscriptionStatusChanged`). Service
  methods `CreatePlan`, `Subscribe`. REST endpoints `POST /billing/subscriptions`
  and `GET /billing/subscriptions/{id}` (storage query direct), bearer.
  `CreatePlan` is not in the preset. Extends the backend with `UpsertPlan` and
  `StartSubscription`. The subscription hook `reconcileSubscriptionWebhook`.
- **Requires / conflicts / combined files.** None declared (see finding 3).

| id | invariant | category | proof |
|---|---|---|---|
| `subscriptions/caller-is-the-principal` | `Subscribe` MUST subscribe only the authenticated principal, and `GET /billing/subscriptions/{id}` MUST answer only the caller's subscription. | Security | none. **Not guaranteed today** (finding 1). |
| `subscriptions/create-plan-privileged` | `CreatePlan` MUST NOT be in the REST preset. | Security | none (manifest only) |
| `subscriptions/status-one-to-one` | The provider status MUST be stored one to one, never rounded up to `ACTIVE`; `incomplete_expired` MUST become `CANCELED`; an unknown status MUST become `UNRECOGNIZED_STATUS`. Only `TRIALING` and `ACTIVE` are entitling. | Security | `TestMapSubscriptionStatus`, `TestFlow_SubscriptionStatus_NeverRoundedUpToActive`, `TestFlow_SubscriptionLifecycle_OutOfOrderAndUnknown` |
| `subscriptions/canceled-terminal` | A `CANCELED` subscription MUST NOT be moved by any later event, and no `SubscriptionStatusChanged` MUST be emitted for it. | Consistency & concurrency | `TestFlow_SubscriptionLifecycle_OutOfOrderAndUnknown`. **Unit (mock) only:** the guard is SQL. |
| `subscriptions/older-event-ignored` | An event the provider created before the one last applied MUST NOT overwrite the row. | Consistency & concurrency | `TestFlow_AnOlderSubscriptionEventDoesNotOverwriteANewerOne`. **Unit (mock) only.** |
| `subscriptions/own-subscription-without-row-retried` | An event for this installation's subscription with no local row MUST fail unrecorded; one for a subscription it did not create MUST be acknowledged. | Failure & configuration | `TestFlow_SubscriptionLifecycle_OutOfOrderAndUnknown`, `TestFlow_AnotherInstallationsObject_IsAcknowledged` |
| `subscriptions/subscribe-once-per-key` | `Subscribe` MUST require a key and send it to the provider. A retry with the same key MUST return the recorded subscription, only when it is this customer's, and MUST NOT create a second provider subscription, also when the first attempt's local write failed. | Consistency & concurrency | `TestSubscribe_RequiresIdempotencyKey`, `TestSubscribe_DistinctKeysNotCollapsed`, `TestFlow_Subscribe_RetryAfterLostResponse`, `TestFlow_Subscribe_ReplayLookupChecksTheCustomer`, `TestFlow_SubscriptionFailurePaths`. **Not guaranteed** after the provider's window when the insert failed (finding 4). |
| `subscriptions/plan-terms-immutable` | A plan's slug MUST name one set of terms. A repeated `CreatePlan` with the same terms MUST return the plan without a second provider price; different terms MUST be `AlreadyExists`. | Consistency & concurrency | `TestFlow_CreatePlan_IdempotentOnTermsNotJustSlug`, `TestCreatePlan_IdempotentReturnsExisting`, `TestCreatePlan` |
| `subscriptions/plan-valid` | A plan MUST have a slug, a positive amount, a three-letter currency and an interval of `month` or `year`, checked before the provider call. | Consistency & concurrency | `TestCreatePlan_ValidatesInterval`, `TestCreatePlan_RejectsNonPositiveAmount`, `TestFlow_CreatePlan_Refusals` |
| `subscriptions/plan-pushed-before-subscribe` | `Subscribe` MUST refuse an unknown plan (`NotFound`) and a plan without a provider price. | Failure & configuration | `TestSubscribe_PlanNotFound`, `TestSubscribe_PlanWithoutProviderPrice`, `TestSubscribe` |
| `subscriptions/started-carries-status` | `SubscriptionStarted` MUST carry the status the subscription was created in, so a consumer never grants entitlements on the event alone. | Security | `TestSubscriptionStarted_CarriesTheCreatedStatus`, `TestEventEmitPayloads_MapEveryEventFieldFromASourceOfItsType` |
| `subscriptions/lookups-indexed` | Plan, subscription-by-provider-id and subscription-by-customer lookups MUST use their unique or secondary indexes. | Performance | none (schema only) |

**Gaps / suspected defects**

1. **Nothing prevents duplicate subscriptions.** Two `Subscribe` calls with
   distinct keys for one principal and plan create two billing
   subscriptions.
2. **`Plan.enabled` is never read** and nothing can set it false; a retired
   plan can only be abandoned by slug.
3. **No way to pay the first invoice.** `Subscribe` returns no client secret
   for the subscription's first payment, and a customer the plugin created
   has no default payment method, so a new subscription typically stays
   `INCOMPLETE` until the provider expires it.
4. **`UpsertPlan` sends no idempotency key.** A retried or racing
   `CreatePlan` leaves an orphan provider price.
5. **Ordering is to the second.** Two events created in the same second
   apply in delivery order (`provider_event_at <= :provider_event_at`). An
   event without a creation time is stamped "now", which then refuses every
   genuinely later event created before that moment.
6. **Invoice payments are foreign.** The provider's invoice payment intents
   carry no origin mark, so they produce no `Payment` row and no
   `PaymentSucceeded`; renewals are visible only through subscription events.

## Across features

Every interaction goes through one of these mechanisms:

| Mechanism | Where | Rule |
|---|---|---|
| **Hook variable** (nil-checked, set in a feature file's `init()`) | `webhook_hooks.go`: `onPaymentSucceededWebhook` (set by `prepaid.go`), `onSubscriptionWebhook` (set by `subscriptions.go`) | The webhook calls through a nil hook as a no-op, so a feature that is off costs nothing and needs no compile coupling. |
| **Always-staged helpers** | `errors.go` (amount, currency, key and error helpers), `webhook_hooks.go` (`installID`, `madeHere`), `payment_service.go` (`charge`, `resolveCustomer`) | Anything two features call lives in an ungated file, so every feature combination builds. |
| **Feature-gated schema and RPCs** | `(w17.contrib.plugin_feature)` on messages, `(w17.contrib.plugin_feature_rpc)` on RPCs, `feature:` on preset endpoints and forwarded headers | A table, RPC or endpoint of feature X exists only when X is on. |
| **Provider metadata marks** | `w17_payment` (origin: `charge`, `topup`, `subscription`) and `w17_install` on every created payment intent and subscription | The webhook and both hooks tell "ours, row not landed" from "not ours" by these marks. |

---

### Feature interaction matrix

Abbreviations: **bt** base tier, **wh** stripe_webhooks, **pp** prepaid,
**us** usage, **sb** subscriptions.

Cell codes (row × column, upper triangle): **R** one requires the other ·
**R!** should require it and does not · **H** one feature's hook runs on the
other's path · **T** shared table or row (one writes what the other reads) ·
**Q** shared helper or query · **O** ordering constraint inside one request ·
**·** no interaction found.

|    | bt | wh | pp | us | sb |
|----|----|----|----|----|----|
| **bt** | — | T Q O | T Q | Q | T Q |
| **wh** | | — | R! H O | · | R! H |
| **pp** | | | — | Q | · |
| **us** | | | | — | · |
| **sb** | | | | | — |

`bt × us` and `pp × us` share only the key and amount helpers in `errors.go`
(`scopedKey`, `idempotencyKeyTooLong`). `us × sb`: `reported_total` is meant
for a future provider push paired with subscriptions; nothing connects them
today.

---

### Interaction invariants

Proof column: exact unit-test names, or `none`. A unit test that runs against
a fake store proves the handler's sequencing only.

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/base-stripe_webhooks-reconciles-base-rows` | bt wh | T O: the webhook updates `Payment` rows that `CreatePayment` inserted, and may arrive before the insert. | A success or failure event for a payment whose row has not landed is retried until it lands, then applied once. | `TestFlow_WebhookOutrunsLocalRow_FailsUntilTheRowLands`, `TestIngestStripe_UnknownProviderPayment_MustNotAcknowledge` |
| `interaction/base-stripe_webhooks-without-webhooks` | bt (wh off) | T: only the webhook moves `Payment.status`. | With `stripe_webhooks` off, `Payment.status` stays at its initial value and no `PaymentSucceeded` / `PaymentFailed` is ever emitted; the project must reconcile another way. | none |
| `interaction/stripe_webhooks-prepaid-required-for-topup` | wh pp | R!: `TopUpCredit` relies on the webhook hook to grant. | `prepaid` with `stripe_webhooks` off MUST NOT accept a top-up (refuse at codegen, at boot, or in `TopUpCredit`). **Not guaranteed today** (finding 3). | none |
| `interaction/stripe_webhooks-prepaid-hook-after-transition` | wh pp | H O: `grantTopupOnPaymentSuccess` runs after `MarkPaymentSucceeded`, also when the guard refused but the row exists. | The grant runs on every delivery until it has completed once, and grants once. | `TestFlow_TopUpGrant_SurvivesATransientFailure`, `TestFlow_TopUpStampFailure_DoesNotDoubleGrant`, `TestIngestStripe_TopUpSuccess_GrantsCredit` |
| `interaction/stripe_webhooks-prepaid-ordinary-payment-unblocked` | wh pp | H: the hook sees every success. | With `prepaid` on, the success of an ordinary charge (origin `charge`) is applied and acknowledged; it never waits for a top-up row. | `TestFlow_PrepaidOn_AnOrdinaryPaymentSucceeds`, `TestIngestStripe_SucceededNotATopUp_NoGrant` |
| `interaction/stripe_webhooks-prepaid-installation-scope` | wh pp | H: the hook reads `madeHere`. | A top-up success with no `CreditTopup` row is retried only when this installation made the intent; another installation's is acknowledged. | `TestTopupHook_MissingRow_RetriedOnlyForThisInstallation` |
| `interaction/base-prepaid-topup-is-a-payment` | bt pp | T Q: `TopUpCredit` uses `charge`, so a top-up is a `Payment` row. | A top-up's success emits `PaymentSucceeded` like any charge. The event carries no origin, so a consumer that fulfils orders on `PaymentSucceeded` must distinguish top-ups itself (description `credit top-up`). | `TestTopUpCredit` (no test asserts the event) |
| `interaction/base-prepaid-refund-reverses-topup` | bt pp | T: `RefundPayment` can refund a top-up payment. | Refunding a top-up MUST reverse (or refuse past) the credit it granted, and the balance check MUST bound the reversal. **Not guaranteed today** (finding 5). | none |
| `interaction/stripe_webhooks-subscriptions-required-for-status` | wh sb | R!: only the webhook hook calls `MarkSubscriptionStatus`. | `subscriptions` with `stripe_webhooks` off MUST be refused, or the status contract ("only `TRIALING` and `ACTIVE` entitle") cannot hold. **Not guaranteed today** (finding 3). | none |
| `interaction/stripe_webhooks-subscriptions-lifecycle-hook` | wh sb | H: `customer.subscription.*` → `reconcileSubscriptionWebhook`. | Lifecycle events update status and period end with the terminal and ordering guards; with `subscriptions` off they are acknowledged and change nothing. | `TestIngestStripe_SubscriptionEvent_Reconciles`, `TestFlow_SubscriptionLifecycle_OutOfOrderAndUnknown` (feature-off case: none) |
| `interaction/base-subscriptions-shared-customer` | bt sb | T Q: `Subscribe` and `CreatePayment` both go through `resolveCustomer`. | One principal has one provider customer for charges and subscriptions alike. | none (`TestFlow_ChargesUseThePrincipalsOwnProviderCustomer` covers charges only) |
| `interaction/base-stripe_webhooks-invoice-payments-foreign` | bt wh sb | T: subscription invoices create provider payment intents with no origin mark. | They are acknowledged and create no `Payment` row and no `PaymentSucceeded`. | `TestFlow_AForeignPaymentIsAcknowledgedOnce` |
| `interaction/prepaid-usage-independent` | pp us | ·: no shared table. | `ReportUsage` never spends credit; a project that bills usage from credit calls `SpendCredit` itself. | none |
| `interaction/every-combination-builds` | all | always-staged helpers | Every subset of features generates and builds; no gated file references a symbol that only another gated file declares. | none (checked by staging each combination, outside this module's tests) |

---

### Cross-cutting invariants

#### Ownership and privileged operations

| ID | MUST hold | Proof |
|---|---|---|
| `payment/principal-from-gateway` | Every end-user operation (create customer, charge, subscribe, read payment, subscription, balance or meter) takes the principal from the gateway-stamped identity and never from a request field. **Not guaranteed today** (finding 1). | none |
| `payment/privileged-rpcs-unexposed` | `RefundPayment`, `GrantCredit`, `SpendCredit`, `TopUpCredit`, `ReportUsage` and `CreatePlan` are absent from the REST preset. A project that exposes them on any transport must gate them with its own ACL. | none (manifest only) |

#### Money and currency

| ID | MUST hold | Proof |
|---|---|---|
| `payment/no-float-money` | No amount is ever a float: decimal strings on the wire, `DECIMAL(20,4)` at rest, integer minor units at the provider boundary, value comparison by normalised decimal (`"29.0000"` = `"29"`). | `TestToMinorUnits`, `TestSameDecimal`, `TestIsPositiveDecimal` |
| `payment/amounts-checked-before-provider` | Every amount and currency is validated against the column and the currency's scale before the provider is called, so a provider object is never created for a value the local row cannot hold. | `TestFlow_ChargeAmountAndCurrencyRefusals_NeverReachTheProvider`, `TestFlow_Refund_RefusalsNeverReachTheProvider`, `TestFlow_CreatePlan_Refusals` |

#### Idempotency keys

| Operation | Key | Sent to provider | Stored as | Scope |
|---|---|---|---|---|
| CreatePayment / TopUpCredit | caller key, or `auto:<random>` | `v2:sha256("charge", kind, user, key)`; `auto:` keys verbatim | same as sent, unique | principal × kind of charge (a payment an earlier version stored under the raw key keeps it) |
| RefundPayment | caller key (required) | verbatim | `v2:sha256("refund", key)` | one refund across all payments |
| Subscribe | caller key (required) | verbatim | not stored (provider id is unique) | provider window only |
| GrantCredit / SpendCredit | caller key (required) | — | `v2:sha256("credit", kind, user, key)` | principal × operation |
| Top-up grant | provider payment id | — | `topup:<id>` | charge |
| ReportUsage | caller key (required) | — | `v2:sha256("usage", user, meter, period, key)` | principal × meter × period |
| EnsureCustomer / UpsertPlan | none | none | — | (orphans possible) |

| ID | MUST hold | Proof |
|---|---|---|
| `payment/money-moving-calls-keyed` | Every provider call that can move money (refund, subscription start) carries a caller-owned stable key, and a key reused for a different operation is refused, never answered with another object. | `TestRefundPayment_RequiresIdempotencyKey`, `TestSubscribe_RequiresIdempotencyKey`, `TestFlow_RefundKeyReusedOnAnotherPayment_IsRefused`, `TestFlow_Subscribe_ReplayLookupChecksTheCustomer` |
| `payment/scoped-keys-unambiguous` | Scoped keys are length-prefixed hashes, so no two distinct part lists share a stored key, and caller keys in the reserved `v2:` / `topup:` namespaces never match a stored key. | `TestScopedKey_PartsCannotShiftAcrossEachOther`, `TestFlow_Credit_CallerKeyShapedLikeAScopedKey_IsNotAMatch`, `TestFlow_Usage_CallerKeyShapedLikeAScopedKey_IsNotAMatch` |

#### Source of truth and partial failure

| ID | MUST hold | Proof |
|---|---|---|
| `payment/provider-first-then-row` | Every provider-backed create calls the provider first and writes the local row second. The provider is the source of truth for status; the local row is the source of truth for keys, ownership and plan terms. | none (structural) |
| `payment/partial-write-recoverable` | A failure between the provider call and the local write is recovered by the caller's retry with the same key, or by webhook redelivery for an own object. Outside the provider's idempotency window, a money-moving retry whose first local write failed is not recognised (finding 4). | `TestFlow_ChargeRetryAfterLostResponse_ReturnsSamePayment`, `TestFlow_Refund_FullAndLostResponse`, `TestFlow_Subscribe_RetryAfterLostResponse` (each covers the committed-row case only) |
| `payment/no-orphan-reconciler` | **Gap:** nothing reconciles provider objects that never got a local row once the provider stops redelivering (customers, prices, refunds, subscriptions, intents). There is no background job and no listing query against the provider. | none |

#### Secrets and configuration

| ID | MUST hold | Proof |
|---|---|---|
| `payment/secrets-typed` | `provider_api_key` and `webhook_signing_secret` are `secret.String` (redacted in logs and traces, never a baked default) and revealed only into the driver and the verifier. The plugin itself logs nothing. | `TestRegisterPlugin_WiresConfigIntoTheHandler` |
| `payment/live-key-only-to-provider` | With `provider_api_base` set, a live key (`sk_live_`, `rk_live_`) fails boot, so a live key is never sent to a mock or test root. | `TestResolveBackend_ProviderAPIBaseRefusesLiveKey` |
| `payment/api-base-is-a-root` | `provider_api_base` must be an http(s) URL with a host and no credentials, query or fragment; the boot error never echoes credentials from it. | `TestResolveBackend_ProviderAPIBaseMustBeAURL`, `TestResolveBackend_AnUnparsableBaseIsNotEchoed`, `TestResolveBackend_ProviderAPIBase` |
| `payment/provider-errors-not-echoed` | The caller sees the failure class and a generic message; the provider's error text, request URL and anything about the key stay server-side. **Not guaranteed today** (finding 8). | none |
| `payment/client-secret-not-persisted` | The provider client secret is returned only to the create call (and its same-customer replay); it is in no column and no event. | none (schema and event catalogue) |

#### Configuration that must fail at boot

| ID | Condition | Enforced | Proof |
|---|---|---|---|
| `payment/boot-provider` | `payment_provider` is not `stripe` (case-insensitive; empty means `stripe`) | `RegisterPlugin` | `TestRegisterPlugin_UnknownProvider`, `TestRegisterPlugin_DefaultsToStripe` |
| `payment/boot-api-key` | `provider_api_key` is empty | `RegisterPlugin` | `TestRegisterPlugin_MissingAPIKey`, `TestRegisterPlugin_NilConfigFailsLoud` |
| `payment/boot-api-base` | `provider_api_base` is not an http(s) URL root, or is set with a live key | `RegisterPlugin` | `TestResolveBackend_ProviderAPIBaseMustBeAURL`, `TestResolveBackend_ProviderAPIBaseRefusesLiveKey` |
| `payment/boot-wiring` | no backend or no storage clients | `ValidateConfig` | `TestRegisterPlugin_UnwiredClientsFailLoud`, `TestValidateConfig`, `TestValidateConfigAndShutdown` |
| **Not** boot-checked (gaps) | `webhook_signing_secret` empty with `stripe_webhooks` on (finding 2); `default_currency` not a three-letter code or a refused three-decimal currency (every default-currency charge and every top-up is then refused at request time); a key that is not a secret or restricted key (a publishable key boots and every call fails `Unavailable`); a live-key prefix with surrounding whitespace escapes the live-key guard; `prepaid` or `subscriptions` without `stripe_webhooks` (finding 3) | — | none |

#### Events

| ID | MUST hold | Proof |
|---|---|---|
| `payment/events-no-secrets` | No event carries a client secret, an API key, a signing secret, an idempotency key, card or bank data, or an e-mail address. `PaymentSucceeded` carries local and provider ids, amount and currency; `PaymentFailed` ids only; `CreditApplied`, `UsageRecorded`, `SubscriptionStarted` and `SubscriptionStatusChanged` carry ids, amounts or quantities, and status. | `TestEventEmitPayloads_MapEveryEventFieldFromASourceOfItsType` (field mapping only; no test scans payloads for secrets) |
| `payment/events-once-per-transition` | Each event is emitted only by its own mutation, only when the mutation returned a row, so a refused guard or a duplicate key emits nothing. | `TestIngestStripe_Redelivery_RunsNoSideEffectAndEmitsNothing`, `TestFlow_TopUp_ConcurrentDuplicateDeliveries`, `TestEventEmitPayloads_MapEveryEventFieldFromASourceOfItsType` |
| `payment/events-after-commit` | An event is published only after its row commits; a rolled-back `ApplyCredit` or `RecordUsage` emits nothing. | none (live only) |
| `payment/events-internal-channel` | All six topics are on the `events` channel. They identify principals and amounts, so the channel must not be bridged to a client-visible event surface without per-principal filtering. | none |

#### Transactions (one unit of work)

No handler opens a transaction. Each local write is one generated mutation:

| Flow | Writes held together | Proof |
|---|---|---|
| ApplyCredit | CreditLedger insert · CreditBalance row at zero (`DO NOTHING`) · CreditBalance update (check) | `TestFlow_Credit_SpendGrantInvariants` (mock) |
| RecordUsage | UsageRecord insert · UsageMeter upsert | `TestReportUsage` (mock) |
| TopUpCredit | **Not together:** Payment insert, then CreditTopup insert. A success arriving between them is retried by the origin mark. | `TestFlow_TopUpSuccessBeforeItsTopupRow_IsRetriedNotLost` |
| Top-up grant | **Not together:** ApplyCredit, then MarkTopupGranted. A lost stamp is safe because the ledger key is the dedup. | `TestFlow_TopUpStampFailure_DoesNotDoubleGrant` |
| IngestStripe | **Not together:** reconciliation, hook, then ledger insert, in that order on purpose. | `TestIngestStripe_SideEffectFailure_DoesNotStrand` |

#### Performance

| ID | MUST hold | Proof |
|---|---|---|
| `payment/no-provider-call-in-transaction` | No provider call is made while a database transaction or row lock is held. Holds by construction today: every provider call precedes a single-statement (or single-mutation) write. | none (structural) |
| `payment/lookups-indexed` | Every lookup on a request or webhook path is served by a unique key or an index: `Customer.user_id`, `Customer.provider_customer_id`, `Payment.provider_payment_id`, `Payment.idempotency_key`, `Refund.provider_refund_id`, `Refund.idempotency_key`, `ProcessedWebhookEvent.provider_event_id`, `CreditBalance.user_id`, `CreditLedger.idempotency_key`, `CreditTopup.provider_payment_id`, `UsageRecord.idempotency_key`, `UsageMeter(user_id, meter, period)`, `Plan.slug`, `Subscription.provider_subscription_id`. `Payment.customer_id` and `Refund.payment_id` are unindexed; no query uses them today, and any per-customer listing or refund total added later needs them. | none (schema only) |
| `payment/reads-are-pure` | The four preset reads are single-row storage queries with no write. | none |
| `payment/unbounded-tables` | **Gap:** `ProcessedWebhookEvent` grows by one row per delivered event and nothing prunes it; the ledgers are append-only by design. | none |

---

### How to prove it — live-only coverage

A unit test against a fake store or a fake provider cannot prove the
invariants below. An example project's end-to-end suite, run against a real
database, the real gateway and the event bus, should cover them. The
`stripemock` sandbox answers every provider call with the real shape but keeps
no state, sends no webhooks and does not enforce idempotency or refund caps.
Webhooks are tested by posting payloads signed with the configured secret.
Properties of the provider itself (idempotent replay, refund cap, declines)
need a provider test-mode account or a stateful fake served at
`provider_api_base`.

1. **Ownership** (expected red, finding 1): principal A creates a payment, a
   subscription and a balance; principal B's bearer must get "not found" for
   each read and must not be able to charge, subscribe or create a customer
   for A by naming A's `user_id`.
2. **Database constraints under concurrency**: N concurrent first charges for
   one principal → one `Customer` row; N concurrent spends → never a negative
   balance (`prepaid/no-overdraw`); N concurrent duplicate usage reports →
   counted once; two concurrent refunds under one key → one `Refund` row.
3. **Transition guards in SQL**: deliver one signed `payment_intent.succeeded`
   twice and concurrently → one status change, one `PaymentSucceeded`; a late
   `payment_failed` after success → no change; a `customer.subscription.updated`
   after `deleted`, and one older than the last applied → no change.
4. **Transactions roll back on a real store**: an overdrawing spend leaves no
   ledger row and emits no `CreditApplied`; a duplicate usage key leaves the
   meter untouched.
5. **Webhook transport**: the gateway delivers the body byte for byte into
   `raw_payload` and forwards `Stripe-Signature` (sign a body with unusual
   whitespace and Unicode; it must verify); a forged, stale or tampered
   delivery gets 401 and touches nothing; with the per-address limit on,
   a burst of authentic deliveries must not get 429 (finding 7, expected red).
6. **Row-not-landed redelivery**: post a signed success for an own-marked
   intent before its row exists → non-2xx and unrecorded; after the row
   exists → applied. The same for a top-up whose `CreditTopup` row is
   missing.
7. **Partial writes** (expected red, finding 4): make the local refund insert
   fail after the provider refunded, let the provider forget the key, retry →
   must not refund twice.
8. **Boot checks**: `stripe_webhooks` on with no signing secret must refuse to
   start (finding 2, expected red); `provider_api_base` with a live key, a bad
   root, an unknown provider and an empty key must refuse to start.
9. **Feature combinations**: generate and build each subset of features;
   `prepaid` or `subscriptions` without `stripe_webhooks` must be refused
   (finding 3, expected red).
10. **Events on the bus**: every payment event arrives only for committed
    transitions; scan every payload for the client secret, the API key and the
    idempotency keys used in the run — none may appear.
11. **Error surface** (finding 8, expected red): configure a rejected key and
    an unreachable `provider_api_base`; the REST answer must not contain the
    provider's message, the URL or any part of the key.
