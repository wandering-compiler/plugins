# payment — changelog

## 0.1.0-rc.6

### A success for another amount than was asked is held, not trusted

- A payment the provider reports succeeded for another amount or currency
  than its row holds (its intent was changed at the provider by something
  other than this plugin) is held at the new status `AMOUNT_MISMATCH`, with
  what it took in `received_amount` / `received_currency`. It emits
  `PaymentAmountMismatch` once, and no `PaymentSucceeded`; a top-up grants no
  credit. The webhook and the provider reconciliation check the same way.
- What a payment took is read from the signed event (`amount_received`), or
  from the provider when the event does not say; a success nobody can check
  is redelivered, not trusted.
- No later event moves a held payment. `RefundPayment` returns up to what it
  took, in its currency, and takes back no credit for a held top-up.
- `Payment` gains `received_amount` and `received_currency`, and its status a
  value: consumer projects get a migration.

### Partial refunds, refund outcomes, new payments and disputes are announced on the bus

- `PaymentCreated` — a payment was recorded, at its initial status.
- `RefundCreated` — a refund this plugin made, partial or full, with the
  provider's outcome. `PaymentRefunded` still announces the whole amount.
- `ProviderRefundRecorded` — a refund made at the provider directly, found by
  the webhook or the reconciliation. A subscriber that wants every refund
  listens to both refund events.
- `RefundStatusChanged` — a refund succeeded, failed or was canceled.
- `DisputeOpened` / `DisputeClosed` (`stripe_webhooks`) — a dispute was
  recorded, and it ended WON or LOST.
- Each is emitted once, by the write that records the fact. `Dispute` gains
  `closed_at`, set when the dispute's closing is announced.

### Refunds are checked against the plugin's own records before any provider is asked

- A refund past what remains of the payment (its amount less its pending and
  succeeded refunds) is refused as `InvalidArgument`, before the provider is
  asked. Two refunds of one payment run one after the other under the
  payment's row lock, so together they never exceed it, whatever the gateway
  does.
- A refund of a failed or canceled payment is refused as `FailedPrecondition`.
  One whose success webhook has not arrived is read from the provider first
  and goes ahead only when the provider reports it succeeded.
- Concurrent refunds of one top-up no longer both pass the credit check.
- The backend interface gains `GetPayment`. A driver for another provider
  must implement it.
- The plugin now needs the bundle's distributed-transaction client; a bundle
  without one fails at boot.

### Retries after the provider forgets a key are recognised, and refusals say what they are

- A charge retried after the provider forgot its key is answered with the
  payment the key recorded, once that payment is past confirmation. It used to
  mint a second, unconfirmed intent at the provider and answer
  `AlreadyExists`. The same key with another amount or currency is
  `AlreadyExists` before the provider is asked.
- The provider customer and the plan's provider price are created under an
  idempotency key. A retried or racing create gets the object the first one
  made instead of leaving an orphan.
- Only the balance CHECKs read as "insufficient credit balance". Any other
  `INVALID_VALUE` on a credit apply goes back as the caller's input error.
- A usage report that would overflow the meter's total is refused as
  `FailedPrecondition` with a message that says so.
- The zero-decimal currency table is Stripe's whole documented list.

### A copy of a processed webhook event costs nothing

- After the signature, the webhook reads its ledger first: an event already
  processed in full — the provider's own redelivery, or a signed request
  replayed inside the signature's 300 s window — is acknowledged
  (`handled=false`) before any store or provider work. A delivery whose
  processing failed recorded nothing and still runs in full.

## 0.1.0-rc.5

### The provider's client secret stays out of every sink

`client_secret` (the token a browser confirms a charge with) is marked `sensitive` on both responses that return it. The response still carries it; telemetry and the request event stream no longer write it.

### `src/gen` is generated, not shipped

- **Needs w17ctl v0.1.0-rc.75 or newer.** The release no longer carries `src/gen` (the pb, the `EnvConfig` / `ClientSet` / `HandlerRegistry` contract and the feature constants). A consumer's staging generates all of it for each activation from `plugin.yaml` and the protos, and w17ctl does that from rc.75 on. An older w17ctl expects the release to carry the contract; upgrade it before you take this release.
- Nothing in your project changes: the same activation, the same env variables, the same configuration, no migration.

### `ReconcileProvider` records what the webhooks never brought in

A provider object whose local row never landed (a failed insert nobody retried), or a row whose webhook was lost for good (an endpoint down longer than the provider redelivers), stayed wrong forever: a paid charge read pending, a top-up's credit was never granted, a dashboard refund never recorded.

- **New method `PaymentService.ReconcileProvider(since, limit, cursor)`** (feature `stripe_webhooks`). It walks the provider's customers, payment intents, refunds and subscriptions created at or after `since`, and records every object this installation made that has no local row, and every status a row lags, through the same paths the create calls and the webhook use (events fire once; a top-up's credit is granted or taken back once). Objects of other installations or apps are left alone. It answers per-kind counts and a cursor when `limit` stopped it.
- **A provider list that fails keeps the walk.** Transient failures are retried briefly (within the call's deadline); a list that still fails ends the call with the counts so far, `stopped` and `next_cursor` at the failed page. A cursor whose object was deleted at the provider continues from that object's creation time. Stop your loop on `stopped` and resume later.
- **Rotating `webhook_signing_secret` changes the installation mark**, and every object made before the rotation then reads as foreign. The new env `previous_install_marks` (comma-separated, 16 hex characters each; read one off an older object's `w17_install` metadata) keeps those objects this installation's, for the webhook and the reconciliation.
- **The plugin schedules nothing and no preset exposes it.** Call it from your own code (a scheduled job, an operator action); the README suggests hourly with `since` four days back. Without a call nothing changes.
- **Provider customers are now marked** (`w17_payment=customer`, `w17_install`) like every other object the plugin creates. Customers made before this version are not recognised by the reconciliation.
- **A payment row the reconciliation records** carries a stand-in idempotency key; a caller's retry the provider replays onto that intent is answered with it.
- **Nothing is ever deleted.** `ProcessedWebhookEvent` and the ledgers are audit logs and are never pruned; archiving them at scale is a deployment concern.
- **Generated code.** New queries `GetCustomerByProviderId` (base) and `GetPlanByProviderPriceId` (`subscriptions`); `CreateSubscription` now also writes `provider_event_at` (an existing column). No new table, column or index, so no migration. Regenerate your project so the new method and queries are emitted. A custom `backend.Backend` driver must implement the four new `List*Page` methods.

### A refund's outcome is recorded, and a top-up's credit follows its refunds and disputes

A refund was recorded as done whatever the provider answered, and a refund that failed later still counted toward `REFUNDED`. A refund made in the provider's dashboard, or a lost dispute, left a top-up's credit spendable.

- **`Refund.status`** (`PENDING`, `SUCCEEDED`, `FAILED`, `CANCELED`) holds the provider's answer, and the refund webhooks keep it current. Only pending and succeeded refunds count toward `REFUNDED` (`SumRefundsForPayment`). `FAILED` and `CANCELED` never move back.
- **A payment whose completing refund fails goes back to `SUCCEEDED`** and emits the new event `PaymentRefundReversed` (`payment.payment.refund_reversed`). A subscriber that acted on `PaymentRefunded` undoes that there.
- **The webhook handles `refund.created`, `refund.updated`, `refund.failed` and `charge.refund.updated`** besides `charge.refunded`. Each one makes the plugin read the payment's refunds from the provider (one `GET /v1/refunds` per event) and record them; the payment's status is then derived from the local refund rows. **Subscribe your webhook endpoint to the `refund.*` and `charge.dispute.*` events.**
- **Disputes are recorded** in the new `Dispute` table (feature `stripe_webhooks`) from `charge.dispute.*` events.
- **A top-up's credit follows one rule.** It is worth its amount, less its pending and succeeded refunds (through `RefundPayment` or made at the provider) and its lost disputes, never below zero, and nothing until its payment has succeeded. After every change the plugin moves the credit it holds for the top-up to that value. A decrease takes only what the balance holds; the rest is recorded as `CreditTopup.credit_owed` (credit the owner spent and owes; the plugin does not collect it). An increase — a refund that failed — cancels what is owed first, then adds spendable credit. A refund or dispute that arrives before the grant is left out of the grant. A `CreditApplied` with delta `0` can appear when only what is owed changed.
- **The ledger reasons `topup`, `topup-refund`, `topup-refund-refused` and `topup-reconcile` are reserved**: `GrantCredit` and `SpendCredit` refuse them. A row your own code wrote earlier with one of these reasons and a payment id as its reference would now be counted as that top-up's credit; check your ledger if you ever used them.
- **Migration.** New columns `Refund.status` (enum, default `SUCCEEDED`, so existing rows keep meaning what they did), `CreditTopup.credit_owed` (nullable `DECIMAL(20,4)`) and `CreditTopup.reconciled_step` (integer, default 0); new table `Dispute` under `stripe_webhooks`. New mutations `RecordProviderRefund`, `MarkRefundStatus`, `MarkPaymentRefundReversed`, `CreateDispute`, `MarkDisputeStatus`, `SetTopupCreditOwed` and queries `GetDisputeByProviderId`, `SumLostDisputesForPayment`, `SumTopupCredit`. Generate a migration.

### Built on SDK go/v0.1.0-rc.24

- **The plugin's module requires `github.com/wandering-compiler/sdk/go` v0.1.0-rc.24.** A w17ctl that knows the request data annotations (`gdpr`, `sensitive`) generates a redaction plan next to every pb file of the plugin's `src/gen`, and that plan imports the SDK's `lib/redact`, which rc.24 is the first to have. The plugin's own code does not change.
- Nothing in your project changes: the same activation, the same env variables, no migration. Your project's own `go.mod` moves to rc.24 with the same w17ctl.

Needs w17 platform 1.11 (`requires_w17: ">=1.11"`): `public_limit` on the webhook endpoint.

### Every REST endpoint acts on the signed-in caller's own billing (breaking)

The `/billing` endpoints took whatever `user_id` the request named, and the reads took any id. A signed-in person could charge, subscribe or create a customer for another user, and read anyone's payment, subscription, balance or usage.

What changes:

- **`CreateCustomer`, `CreatePayment`, `Subscribe` and `TopUpCredit` act for the signed-in caller.** Through the gateway an empty `user_id` means the caller, and another id is refused with `PERMISSION_DENIED`. A call from the project's own code, which carries no signed-in caller, names the user as before.
- **New `GetMyPayment`, `GetMySubscription`, `GetMyCreditBalance` and `GetMyUsageMeter`** answer only with the caller's rows. Another person's payment or subscription reads as not found. The REST preset serves `GET /payments/{id}`, `/subscriptions/{id}`, `/credit/balance` and `/usage/{meter}/{period}` from them instead of from the storage reads. The project's own code still reads through `PaymentQuery`.
- **The caller is read from field 2 of the gateway's `x-w17-user` envelope.** w17 requires `string user_id = 2` on every auth method's response, and the auth plugin has it. An envelope that is present but empty, repeated or without a readable caller is refused (`UNAUTHENTICATED`), never treated as an internal call.
- **Project code that calls these methods while serving a signed-in person** acts as that person, because the envelope is relayed with the call (in process and over a dialled conn). Code that acts for someone else there (an admin action, an owner paying for a member) removes `x-w17-user` from its incoming metadata first; the README shows how.
- **Frontends:** drop `user_id` from the request bodies, or send the caller's own. The read paths are unchanged.

### The provider's text stays out of one more answer

When a top-up refund was refused and giving its credit back then failed, `RefundPayment` answered with the provider's error text and the store error in the message. It now answers with a fixed sentence, like every other provider failure, and logs both causes.

### Refunds are indexed by payment

`Refund.payment_id` gains an index. `SumRefundsForPayment` totals a payment's refunds on every refund, and it scanned the table. The migration adds one index.

### Spending credit works on a real database

`SpendCredit`, and taking back a refunded top-up's credit, were refused as "insufficient credit balance" whatever the balance. `ApplyCredit` wrote the balance with an upsert that inserted the delta, and the database checks `balance >= 0` on the row an INSERT proposes before it notices the conflict that would turn the insert into an update. For a debit, the proposed balance is negative. The in-memory store the tests used did not behave like that.

- **`ApplyCredit` makes the balance row at zero if it is missing, then applies the delta with an `UPDATE`**, all in one transaction. An overdraw, including a spend by someone who never had credit, still rolls everything back.
- **`GetMyCreditBalance` and `GetMyUsageMeter` answer zero** before the first grant or report, instead of `NOT_FOUND`.

### A payment's key belongs to the caller

`CreatePayment` and `TopUpCredit` stored the caller's idempotency key as it came and sent it to the provider the same way. Keys were one space for every user and both kinds of charge. When a second user chose a key someone had already used (`order-1` is an obvious choice), the provider refused the charge as a reuse with different parameters. A top-up under the key of an earlier payment was refused the same way.

- **The key is scoped by user and by kind of charge** before it is stored and sent: `v2:` and a hash, as the credit and usage keys already were. The same key from another user, or for the other kind of charge, is a separate charge.
- **`Payment.idempotency_key` holds the scoped key**, so the value a read returns is no longer the one the caller sent.
- **Payments stored by earlier versions keep their key.** A retry of one by the same user, for the same kind of charge, is still that payment.
- **New query `GetPaymentByIdempotencyKey`.**

### Webhook configuration is checked at boot

- **`webhook_signing_secret` is required while `stripe_webhooks` is on** (the default). A bundle without it used to boot and then refuse every delivery, leaving payments pending forever. It now fails `RegisterPlugin`.
- **`subscriptions` requires `stripe_webhooks`.** A subscription settles only when the provider's webhook confirms it.
- **`TopUpCredit` refuses to charge without `stripe_webhooks`** (`FAILED_PRECONDITION`). The credit is granted by the webhook, so before this change the charge went through and the credit never landed. The rest of the `prepaid` wallet (`GrantCredit`, `SpendCredit`, the balance) is local and needs no webhooks.
- **`POST /webhooks/stripe` is `public_limit: failed_only`.** A delivery answered 2xx (handled, a duplicate, or an event type that needs nothing) spends no per-address budget, so a burst of them from the provider is not answered 429. Every failed answer does spend it: a bad signature, and also a genuine delivery whose processing failed (its local row has not landed yet, a storage error). A storage outage longer than the burst can therefore have the provider's address answered 429 for a short while after it ends; the provider retries those too.

**Upgrading.** An activation that lists `features:` explicitly replaces the defaults, so one that lists `subscriptions` without `stripe_webhooks` is now refused at codegen (`feature "subscriptions" requires "stripe_webhooks"`). Add `stripe_webhooks` to the list, and set `webhook_signing_secret`: with the webhooks on, the bundle no longer boots without it. Point the provider's webhook at `POST /webhooks/stripe`.

### Provider error text stays in the log

A failed provider call used to reach the caller as `payment provider error: <the provider's text>`. That text carries the endpoint path, the provider's own diagnostics and, for a rejected key, a masked form of the key.

- **The caller gets the class** (`FAILED_PRECONDITION` for a decline, `INVALID_ARGUMENT` for a refused request, `UNAVAILABLE` otherwise) **and a fixed sentence.** The full cause is logged at WARN.
- **The exception is the caller's own input.** An amount the currency cannot represent is still explained, because that message names only the input (`backend.InputError`, which matches `backend.ErrInvalidRequest`).
- **The provider's reason code still reaches the caller**, as the `w17.ErrorDetail` code (upper-case): `INSUFFICIENT_FUNDS`, `EXPIRED_CARD`, `CHARGE_ALREADY_REFUNDED`. It is Stripe's `decline_code` (or else `code`), passed only when it is a plain identifier (`[a-z0-9_]`, at most 64 bytes), so a decline can be shown and acted on without the provider's prose.
- **A call the caller cancelled is `CANCELED`**, not `UNAVAILABLE`, and is not logged.

### A refunded top-up takes its credit back

Refunding a top-up payment returned the money and left the credit spendable, so the customer kept both.

- **`RefundPayment` on a top-up spends the refunded amount from the owner's credit** before the provider is asked. This is idempotent per refund key, so a retry does not take the credit twice — and a retry after a refusal that gave the credit back takes it again. Its ledger entries are out of reach of a caller's `SpendCredit` / `GrantCredit` key, and a refund key at the length limit works.
- **Credit already spent cannot be refunded as money.** Such a refund is refused with `FAILED_PRECONDITION`, and the provider is never called.
- **A top-up whose credit has not been granted yet cannot be refunded.** Otherwise the grant would land after the refund. Refund it once the payment has settled.
- **When the provider refuses the refund for good** (invalid or declined), the credit is given back. After a transient failure it stays taken for the retry. When giving it back fails, the refund answers `UNAVAILABLE`, so the retry gives it back.


### A retried refund or subscribe is recognised after the provider forgets its key

The provider remembers an idempotency key for about a day. After that a retried `RefundPayment` refunded a second time whenever the first attempt's local record had failed. A retried `Subscribe` started a second subscription even when the first had been recorded, because a subscription keeps no key locally.

- **The key now also rides in the refund's and the subscription's metadata** (`w17_refund`, `w17_subscribe`), where it does not expire.
- **Before making a refund or starting a subscription, the plugin asks the provider** whether one exists under that key, using the new `Backend.FindRefund` and `Backend.FindSubscription`. If one does, the plugin records it and makes no second one.
- **The found object must be the one the retry asks for.** A refund found under the key with another amount, or a subscription found under it on another plan, is `AlreadyExists` — as when the local record holds the key — and is not recorded.
- **A custom backend implements the two lookups (breaking for a custom `backend.Backend`).** A found refund reports its `Amount` and a found subscription its `ProviderPriceID`. A provider without metadata can return "not found", which keeps the old behaviour.
- A refund or subscription made before this version carries no key in its metadata and is not recognised this way.

### A payment's status follows refunds and cancellation

Nothing ever wrote `REFUNDED`, and `CANCELED` came only from the create response. A fully refunded payment read `SUCCEEDED` forever.

- **`REFUNDED` once the refunds reach the amount.** `RefundPayment` sets it when its refund completes the amount (new query `SumRefundsForPayment`, new mutation `MarkPaymentRefunded`, only from `SUCCEEDED`). The provider's `charge.refunded` webhook, for a charge that is fully refunded, settles it too. That covers partial refunds completing the amount concurrently, and refunds made outside the plugin. A `charge.refunded` that arrives before the payment's success has landed locally is not recorded, so its redelivery settles the status once it has; and a top-up refunded before its credit was granted is not granted by a redelivered success.
- **`CANCELED` from the provider's `payment_intent.canceled`** (`MarkPaymentCanceled`, never from `SUCCEEDED` or `REFUNDED`; from `FAILED` it is allowed, since a failed attempt leaves the PaymentIntent open and canceling it is how an abandoned payment ends).
- **New events `PaymentRefunded` and `PaymentCanceled`.**
- **Still open:** a refund the provider fails later (`refund.failed`) is not reflected locally yet. (Refunding a top-up through `RefundPayment` takes its credit back: see "A refunded top-up takes its credit back".)

### Run a project against Stripe's API mock

- **`provider_api_base`** (env): the root of a Stripe-compatible API to call instead of `https://api.stripe.com`. Empty means the real API. A value that is not an http(s) URL root (or carries credentials, a query or a fragment) is refused at startup, and so is a live key (`sk_live_…`, `rk_live_…`) together with it.
- **Sandbox `stripemock`:** Stripe's own API mock (`stripe/stripe-mock:v0.205.0`). With `provider_api_base = http://stripemock:12111` and any `sk_test_…` key, customers, payments and refunds answer with the shape the real API returns (canned values, no state), so a local stack or a test suite needs no Stripe account. Webhooks are not part of the mock; test them with a signed payload.

Nothing changes for a project that does not set the variable.

## 0.1.0-rc.4

Dependencies only: `golang.org/x/net` v0.60.0, which fixes GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610 and GO-2026-6603, together with `golang.org/x/crypto`, `x/sys` and `x/text`. Nothing in the plugin's behaviour changes. Take it with `w17ctl plugin update payment`.

## 0.1.0-rc.3

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
- A generated `go.mod` may keep a `replace` line for the old path beside the new one. It is harmless, and you may delete it.
- Hand-written code that imports the plugin's packages directly (a `lib/…` package, say) must change its import paths. It must also change any `replace` directive in its own `go.mod` that names the old module path.

**Upgrading** (migration, currencies, keys, rolling deploys): see the README section "Upgrading from 0.1.0-rc.2 or earlier". Read it before deploying.

### Fixes that move money
- **Every full refund failed.** The stored amount (`12.3400`) was refused for two-decimal currencies.
- **An amount that overflowed int64 minor units went out as 1 cent.** It is now refused.
- **A top-up's credit could be stranded for good** when its grant failed once.
- **A spend reusing a grant's key deducted nothing.** Credit and usage keys are now scoped by user and operation. Keys from earlier versions are still recognised.
- **Top-ups are charged in `default_currency` only.**
- **ISK and UGX are sent as whole units ×100**, as Stripe requires. UGX used to be charged at 1/100 of the amount.
- **Three-decimal currencies (BHD, JOD, KWD, OMR, TND) are refused.**
- **A refund retried after Stripe forgets its key (24h) no longer refunds again.** Refunds made by this version keep their key. A refund made before the upgrade gets its key stored when it is retried within 24h. See the README for the rest.
- **A refund key names one refund.** A different amount under the same key is AlreadyExists; reuse on another payment is InvalidArgument.

### Webhooks
- **A first charge, top-up or subscribe for a NEW user works.** Before, every lookup that found no row failed.
- **Every object the plugin creates is marked with `metadata[w17_payment]`** and its installation (`w17_install`). Events for objects that are not ours are acknowledged, not redelivered for days.
- **Terminal states are final.** CANCELED and REFUNDED payments stay so, and an older subscription event never overwrites a newer one.
- **Subscription status is the provider's.** New values: `INCOMPLETE`, `PAUSED`, `UNPAID`, `UNRECOGNIZED_STATUS`. `SubscriptionStarted` carries `status`. Grant entitlements only on TRIALING or ACTIVE.
- **Provider errors map by class.** A decline is FailedPrecondition and an invalid request is InvalidArgument. Both used to be Unavailable, which callers retry.

### Behaviour a caller will notice
- **A retried create returns the row it recorded.** This applies to CreatePayment, TopUpCredit, RefundPayment and Subscribe retried with the same idempotency key. If the key names someone else's object, the call returns AlreadyExists. Before, every retry returned InvalidArgument (UNIQUE_VIOLATION).
- **CreateCustomer is idempotent, and charges without a key no longer collide.**
- **CreatePlan for an existing slug with different terms returns AlreadyExists.** Before, it silently returned the old plan.
- **Stricter input checks**, each a new InvalidArgument refusal:
  - a 5th fractional digit;
  - more than 16 integer digits;
  - a currency that is not 3 letters;
  - an idempotency key over 255 bytes;
  - a negative partial refund;
  - amounts that are only whitespace.
- **A signed webhook event without an id is refused.**

### Storage (migration)
- **New nullable columns:** `Refund.idempotency_key` and `Subscription.provider_event_at`.
- **New `Subscription.Status` values.**
- **New queries and mutations:**
  - queries `GetPaymentByProviderId`, `GetRefundByProviderId`, `GetSubscriptionByProviderId`, `GetRefundByIdempotencyKey`, `GetCreditLedgerByKey` (prepaid) and `GetUsageRecordByKey` (usage);
  - mutation `SetRefundIdempotencyKey`.

### Configuration
- **`EnvConfig.ProviderAPIKey`** is the field the bundle sets. With the old name, no project activating payment could build.
