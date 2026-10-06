# agent — changelog

## 0.1.0-rc.4

### Module path

The Go module path changed from `github.com/wandering-compiler/platform/plugins/<name>` to `github.com/wandering-compiler/plugins/<name>`, matching the repository the plugin now lives in.

- Generated code needs nothing. `w17ctl plugin update` re-vendors the plugin, and codegen rewrites the imports from the manifest's `go_module`.
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
