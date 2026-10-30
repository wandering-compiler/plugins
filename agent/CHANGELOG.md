# agent — changelog

## 0.1.0-rc.7

### Usage counts clamp instead of wrapping, limits answer deterministically, logs keep the caller's text out

- `ModelUsage` token counts past 2^31 − 1 clamp at the bound instead of wrapping into a negative or small number. The persisted row keeps 64 bits.
- `GetScopeLimit` answers the limit set last when two share a scope, window and `valid_from`, instead of either one.
- The usage writer's failure log lines carry the counts and the kind of failure (the gRPC code), never the database error's text, which can quote a scope or label.

## 0.1.0-rc.6

### The final text can be cleaned

- **Two filters for the answer a caller keeps** — `CompleteResp.text` and `Finished.text`; the deltas stay the model's own, so a stream is as fast as before and a caller swaps the streamed text for the clean one at the end. Both are off unless the activation switches them on:
  - `final_text_scripts` drops letters of every Unicode script the activation does not allow: `<DOMAIN>_AGENT_ALLOWED_SCRIPTS`, comma-separated Go script names, default `Latin`. A Thai token a model leaked into a Czech sentence goes; diacritics, digits, punctuation and emoji stay. An unknown script name refuses the boot.
  - `final_text_invisible` drops control and invisible characters: zero-width spaces, the byte-order mark, bidi overrides, U+FFFD. The zero-width joiner (emoji) stays.
- **A call has its say** with `FinalText` on `CompleteReq` and `RunAgentReq.Start`: `allowed_scripts` for an answer in another language, `raw` for none. A name the filter cannot use is refused before the model is called.
- `Finished.text` is no longer always exactly the deltas: with a filter on it is the cleaned text. Without one nothing changes: the same activation, the same env variables, no migration.

### `src/gen` is generated, not shipped

- **Needs w17ctl v0.1.0-rc.75 or newer.** The release no longer carries `src/gen` (the pb, the `EnvConfig` / `ClientSet` / `HandlerRegistry` contract and the feature constants). A consumer's staging generates all of it for each activation from `plugin.yaml` and the protos, and w17ctl does that from rc.75 on. An older w17ctl expects the release to carry the contract; upgrade it before you take this release.
- Nothing in your project changes: the same activation, the same env variables, the same configuration, no migration.

### Built on SDK go/v0.1.0-rc.24

- **The plugin's module requires `github.com/wandering-compiler/sdk/go` v0.1.0-rc.24.** A w17ctl that knows the request data annotations (`gdpr`, `sensitive`) generates a redaction plan next to every pb file of the plugin's `src/gen`, and that plan imports the SDK's `lib/redact`, which rc.24 is the first to have. The plugin's own code does not change.
- Nothing in your project changes: the same activation, the same env variables, no migration. Your project's own `go.mod` moves to rc.24 with the same w17ctl.

### Your own final-text filters

- **The `text_filter` hook** runs business methods of your domain on the final text, after the built-in `final_text_*` filters, in the order the activation binds them: `hooks: [ { slot: "text_filter", methods: [ "filters.Filters.Clean" ] } ]`. A method takes `TextFilterReq` (the text, the plugin method, the model, the usage scope and labels) and returns `TextFilterResp` (the text that replaces it), as the activation stages them. The deltas are never filtered.
- **A filter that fails or does not answer in time is skipped and logged** (its gRPC code, never the text): the answer still reaches the caller. `<DOMAIN>_AGENT_TEXT_FILTER_TIMEOUT_SECONDS` (default 5) bounds each. `FinalText.raw` skips them too.
- **Needs platform 1.14** (`requires_w17: ">=1.14"`): a console that knows plugin hooks. An activation that binds no hook behaves exactly as before.

### Spending limits hold

- **Every limit window is enforced.** `SetScopeLimit` accepted `DAY` and `TOTAL` limits and only `MONTH` was ever checked. Each window now counts its own spend: from the start of the UTC day, the start of the UTC month, or all time. The first window over its limit refuses.
- **Unpriced calls refuse under a limit.** Calls on a model with no price contributed nothing, so a capped scope on unpriced models was never refused. A scope with a limit and unpriced calls that spent tokens in a window is now refused with a reason that names the fix: price the model from before those calls, or lift the limit. A price reaches only calls made after its `valid_from`, so a price added today does not lift the refusal for calls already made: the window has to end, or the price has to be backdated — and a `TOTAL` window never ends. A failed call that spent nothing (a model name the provider does not know) does not count. A scope with no limit is unaffected.
- **A scope or label too long to record is refused up front.** `usage_scope` over 128 characters, a label key over 64, a label value over 256, or any of them containing a NUL character (which PostgreSQL cannot store) is refused with `InvalidArgument` before the model is called, in every activation. Before, it was served, never capped, and lost at flush.
- **A missing limiter refuses the boot.** With `usage_persistence` on, a client set without `UsageQuery` or `UsageMutation` used to install the allow-all limiter silently. `RegisterPlugin` now fails, as it already did for a missing usage sink.
- The over-limit reason no longer says "for the current month", since any window can refuse.

### RunAgent keeps its contract

- **`Limits.tool_timeout_seconds` works.** It was ignored, so a caller that never answered a `ToolCall` held the run open. A tool past it now fails alone: the model reads that it did not answer in time, the activity ends as failed, and the run goes on. For a mutating tool the model is told the outcome is unknown, because the caller may still apply it. A late result is dropped. Zero (the default) means no per-tool bound.
- **`Activity` shows the declared `ToolSpec.activity`** (the tool's name when it has none). Its `activity_id` is the `call_id` of the `ToolCall` it brackets. A tool name the model invented gets no `Activity`; the model is still told there is no such tool.
- **`Finished.text` is every delta shown,** across all turns. It used to hold only the last turn's text, so text streamed beside tool calls was missing.
- **The last turn applies nothing.** It offers no tools. Calls a provider returns on it anyway are no longer run, and the run ends with the turn limit as before.
- **A `params_schema` that is not a JSON object is refused before the first turn.** It used to be replaced by `{"type":"object"}`, offering the tool with no argument contract.

### Usage, streams and the endpoint

- **`RunAgent` writes one usage row per turn it sent,** as the contract on `RunAgentReq.Start` always said. It wrote one row per run carrying the sum, so counting rows under-counted calls and the whole run was priced at the price in force when it started. Each row now carries its own turn's tokens, outcome and start time: a turn that finished is OK even if the run failed later. A run that sent nothing writes no row. `Finished.usage` is still the run's total.
- **`Complete` answers a caller that left with the caller's own code.** When the caller cancels or its deadline passes, the call ends `Canceled` or `DeadlineExceeded`, as `CompleteStream` and `RunAgent` already did. It used to answer `Unavailable` and log a model failure. What was spent is still recorded. A call whose context had already ended when it arrived, on `Complete` or `CompleteStream`, sends nothing and writes no usage row, as `RunAgent` does; it used to write a FAILED, unmeasured row for a call that cost nothing.
- **The stream output ceiling follows the token budget.** The streaming paths stopped any answer, or tool-call arguments, past 20 000 bytes, whatever `max_tokens` said, so an answer `Complete` returned in full failed half way on `CompleteStream`. The ceiling is now 8 bytes per budgeted token, never below 20 000 bytes. A call with no budget (`max_tokens < 0`) keeps 20 000 bytes. `ModelSpec.max_tokens` states it.
- **Spend is rounded once per group, not per row.** `GetScopeSpend` and `GetLabelSpend` rounded every usage row to whole minor units before summing, so a row worth under half a minor unit counted as nothing, toward the cap as well. With a row per turn that would let a run of many small turns price at zero. Each row is now priced exactly and the sum rounded once.
- **A plain-`http` endpoint is refused at boot** unless its host is loopback. Every request carries the API key, which plain http sends in clear text. An endpoint that is not an absolute URL is refused too.

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
