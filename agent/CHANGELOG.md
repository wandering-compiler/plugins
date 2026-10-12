# agent — changelog

## Unreleased

### Spending limits hold

- **Every limit window is enforced.** `SetScopeLimit` accepted `DAY` and `TOTAL` limits and only `MONTH` was ever checked. Each window now counts its own spend: from the start of the UTC day, the start of the UTC month, or all time. The first window over its limit refuses.
- **Unpriced calls refuse under a limit.** Calls on a model with no price contributed nothing, so a capped scope on unpriced models was never refused. A scope with a limit and unpriced calls in a window is now refused with a reason that names the fix: price the model, or lift the limit. A scope with no limit is unaffected.
- **A scope or label too long to record is refused up front.** `usage_scope` over 128 characters, a label key over 64 or a label value over 256 is refused with `InvalidArgument` before the model is called, in every activation. Before, it was served, never capped, and lost at flush.
- **A missing limiter refuses the boot.** With `usage_persistence` on, a client set without `UsageQuery` or `UsageMutation` used to install the allow-all limiter silently. `RegisterPlugin` now fails, as it already did for a missing usage sink.
- The over-limit reason no longer says "for the current month", since any window can refuse.

## 0.1.0-rc.5

Dependencies only: `golang.org/x/net` v0.60.0, which fixes GO-2026-6617, GO-2026-6612, GO-2026-6611, GO-2026-6610 and GO-2026-6603, together with `golang.org/x/sync`, `x/crypto`, `x/sys` and `x/text`. Nothing in the plugin's behaviour changes. Take it with `w17ctl plugin update agent`.

## 0.1.0-rc.4

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
- A generated `go.mod` may keep a `replace` line for the old path beside the new one. It is harmless, and you may delete it.
- Hand-written code that imports the plugin's packages directly (a `lib/…` package, say) must change its import paths. It must also change any `replace` directive in its own `go.mod` that names the old module path.

### Billing and usage
- **A tool-calling run now bills every turn.** Before, it billed only its last turn, and a failed run billed nothing. A failed run now carries what it spent and is billed for it.
- **`measured` means every turn sent to the provider reported its usage.** A run that sent nothing is measured, at zero tokens.
- **A response the provider marks `failed` is a failure** (Unavailable, naming the provider's code), not an answer.
- **One bad usage event no longer drops the rest of its batch.** A row that landed with a missing label counts as written.

### Limits
- **A limit's currency is compared with the spend's currency.** A mismatch is refused, not compared blindly.
- **A transient database error no longer switches a scope's cap off.** Only "no limit" is cached.
- **A blank scope is uncapped.**
- **The limiter's caches are bounded.** They keep two generations, so hot keys survive.

### Streams and errors
- **`request_timeout_seconds` bounds the whole call**, not each SDK retry.
- **A caller hanging up or timing out is not reported as a model failure.**
- **A failure on our own side keeps its own status**: a message that is too large stays ResourceExhausted.
- **A provider transport error is returned as Unavailable.** Its URL is never shown to the caller, and it is logged.
- **A duplicated tool result can no longer block a run.**
- **A run cancelled during a tool wait ends.**
- **A half-close while a tool result is still owed is FailedPrecondition.**
- **The JSON_OBJECT response format applies without a ModelSpec.**
- **A malformed tool list is refused up front.**
