# payment — changelog

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
