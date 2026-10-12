# payment — changelog

## 0.1.0-rc.5

Needs w17 platform 1.11 (`requires_w17: ">=1.11"`): `public_limit` on the webhook endpoint.

### Every REST endpoint acts on the signed-in caller's own billing (breaking)

The `/billing` endpoints took whatever `user_id` the request named, and the reads took any id. A signed-in person could charge, subscribe or create a customer for another user, and read anyone's payment, subscription, balance or usage.

What changes:

- **`CreateCustomer`, `CreatePayment`, `Subscribe` and `TopUpCredit` act for the signed-in caller.** Through the gateway an empty `user_id` means the caller, and another id is refused with `PERMISSION_DENIED`. A call from the project's own code, which carries no signed-in caller, names the user as before.
- **New `GetMyPayment`, `GetMySubscription`, `GetMyCreditBalance` and `GetMyUsageMeter`** answer only with the caller's rows. Another person's payment or subscription reads as not found. The REST preset serves `GET /payments/{id}`, `/subscriptions/{id}`, `/credit/balance` and `/usage/{meter}/{period}` from them instead of from the storage reads. The project's own code still reads through `PaymentQuery`.
- **The caller is read from field 2 of the gateway's `x-w17-user` envelope.** w17 requires `string user_id = 2` on every auth method's response, and the auth plugin has it. An envelope that is present but empty, repeated or without a readable caller is refused (`UNAUTHENTICATED`), never treated as an internal call.
- **Project code that calls these methods while serving a signed-in person** acts as that person, because the envelope is relayed with the call (in process and over a dialled conn). Code that acts for someone else there (an admin action, an owner paying for a member) removes `x-w17-user` from its incoming metadata first; the README shows how.
- **Frontends:** drop `user_id` from the request bodies, or send the caller's own. The read paths are unchanged.

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
