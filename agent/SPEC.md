# agent — behaviour specification

This document says what the `agent` plugin does, feature by feature, and what it
must never do: the security, consistency, performance and failure properties an
application built on it relies on. It is the reference the plugin's tests and
the example projects are measured against. A property listed here without a
proof is a gap, not a promise.

It covers plugin version 0.1.0-rc.5.

The plugin is an **engine**, not a chat product. It makes model calls and runs
a tool-calling loop. It has no conversation table, no history, no user and no
credential of its own toward the application: the calling service resolves who
is asking, loads the transcript, decides which tools exist, runs every tool
call under its own authorization, and stores what comes back. Several
properties one expects of an "LLM agent" (conversation ownership, per-user
isolation of history, tool authorization) are therefore the **caller's**
obligations. This specification states them as invariants about what the
engine must not do to weaken them, and lists them under the trust boundary in
[Cross-cutting invariants](#cross-cutting-invariants).

## How to read it

- Every **invariant** is one MUST or MUST NOT statement about observable
  behaviour, with a stable id (`<feature>/<name>`, `interaction/<a>-<b>-<name>`,
  `agent/<name>`). Ids do not change when the wording does, so tests and
  examples can cite them.
- **Categories:** Security · Consistency & concurrency · Performance · Failure &
  configuration.
- **Proof** names the unit tests in `agent/src/handlers`, `agent/src/lib/llm`,
  `agent/src/lib/usage` or the root package that demonstrate the invariant.
  Handler tests run against fake model clients, a local HTTP server that
  speaks the provider's wire format, and an in-memory gRPC fake of the
  generated usage storage clients. They prove sequencing, wire shape and error
  mapping, not what only the database can enforce (a unique index, an
  `UPSERT … RETURNING` under concurrency, the pricing join, a `CHECK`, a
  half-open time window). Such rows say **unit (mock) only** and name what a
  live test would have to show. `none` means nothing proves it yet.
- **Caller** always means the application service that calls `AgentService`.
  **End user** means the person on whose behalf that service acts. The plugin
  never sees an end user.
- **Gaps / suspected defects** after each feature are what the code does not
  enforce although the invariant requires it, found by reading the code. The
  ones re-checked against the code are collected under
  [Verified findings](#verified-findings).

## Features

| feature | default | requires | conflicts with |
|---|---|---|---|
| (base tier) | always | — | — |
| `usage_persistence` | off | — | — |

`go_files` of `usage_persistence`: `handlers/usage_enabled.go`,
`handlers/limits_enabled.go`. No `go_files_combined`. No REST, MCP or admin
preset, no sandbox, no events.

## Verified findings

Gaps confirmed by re-reading the handlers, the loop and the DQL. Each is a
defect to fix before an example may claim the invariant; the invariant id says
which.

| # | finding | invariants | where |
|---|---|---|---|
| 1 | The unary `Complete` path has no "caller left" branch. When the caller cancels or its own deadline passes, the error is recorded as a failed call, logged as `model call failed`, and answered `Unavailable` with "the model call failed". `CompleteStream` and `RunAgent` return the caller's own `Canceled` / `DeadlineExceeded` instead. An operator reading the log blames the provider, and a caller that retries on `Unavailable` retries its own timeout. | `base/caller-ending-is-not-a-model-failure` | `src/handlers/agent_service.go` (`Complete`) |
| 2 | **Fixed.** `Limits.tool_timeout_seconds` is ignored. `limitsFrom` copies only turns, tool calls and parallelism, `llm.Limits` has no timeout field, and `remoteTool.Call` waits for the result on the run's context alone. A caller that never answers a `ToolCall` holds the run open (and its turns already paid for) until the caller's own context ends. The wire contract promises that a slow tool "fails ALONE". | `base/run-tool-timeout` | `src/handlers/agent_run.go` (`limitsFrom`, `remoteTool.Call`), `src/lib/llm/tool.go` (`Limits`) |
| 3 | **Fixed.** `ToolSpec.activity` is never read. `Activity.text` is the tool **name** the model emitted, which for an undeclared tool is a model-invented string, although the contract says it is the declared, display-ready `activity`. `Activity.activity_id` is the provider's call id while `ToolCall.call_id` is a fresh UUID, so a watcher cannot correlate an activity with the tool call it brackets. A test pins the name behaviour. | `base/run-activity-display-safe` | `src/handlers/agent_run.go` (`sendRunEvent`) |
| 4 | `RunAgent` writes **one** usage row per run, carrying the sum of every turn. The published contract on `RunAgentReq.Start` says each turn "is recorded as its own row". Code and tests agree on one row; the contract text is wrong, or the code is. A consumer that counts rows as model calls under-counts, and a run is priced at the price in force when it **started**. | `interaction/base-usage_persistence-run-one-row` | `src/handlers/agent_run.go` (`RunAgent`, `recordUsageFor`), `proto/business/agent_service.proto` (`RunAgentReq.Start`) |
| 5 | **Fixed.** `RunAgent`'s `Finished.text` is the **last turn's** text only (`answer := *res`). Text the model streamed in an earlier turn, alongside its tool calls, reached the reader as deltas but is missing from `Finished.text`, which the contract defines as "every delta concatenated, and what the reader was actually shown". A consumer that persists only `Finished.text` stores less than the end user saw. | `base/run-finished-text-is-what-was-shown` | `src/lib/llm/loop.go` (`Run`) |
| 6 | **Fixed.** The last permitted turn offers no tools, but if the provider still returns function calls on it, `Run` dispatches them, including mutating ones, and then ends with `ErrTurnsExhausted`. The writes are applied and the model never reads their results, which is exactly what offering no tools was meant to prevent. | `base/run-last-turn-applies-nothing` | `src/lib/llm/loop.go` (`Run`) |
| 7 | Both streaming paths refuse any answer longer than 20 000 bytes of text (or of tool arguments) with `ResourceExhausted`, whatever `ModelSpec.max_tokens` says, including `< 0` ("no cap"). Unary `Complete` has no such limit. The same request therefore succeeds on `Complete` and fails on `CompleteStream`, and the wire contract mentions neither the limit nor the difference. | `base/stream-output-ceiling-stated` | `src/lib/llm/stream.go` (`maxStreamOutput`, `streamTurn`) |
| 8 | **Fixed.** A `ToolSpec.params_schema` that is not valid JSON (or not a JSON object) is silently replaced by `{"type":"object"}`. The tool is offered with no argument contract, so the model may send anything. Tool names are refused up front as preflight; schemas are not. | `base/run-tool-list-validated` | `src/handlers/agent_run.go` (`remoteTool.Params`), `src/lib/llm/loop.go` (`toolParams`) |
| 9 | **Fixed.** A `usage_scope` longer than the 128-character `Scope.external_id` column is accepted, served and never billed. No `Scope` row can hold it, so no limit can be set on it; the limiter's `InternScope` fails and the limiter fails open; at flush, the row cannot be written and the spend is lost (counted, and logged once per batch). Nothing validates the scope length at request time. A caller that derives scopes from long principal ids therefore runs unrecorded and uncappable. | `usage_persistence/scope-validated-at-request` | `src/handlers/limits_enabled.go` (`Allow`, `scopeID`), `src/handlers/usage_enabled.go` (`flushOne`) |
| 10 | **Fixed.** Only the `MONTH` window is enforced. `SetScopeLimit` accepts `DAY` and `TOTAL` limits, `GetScopeLimit` reads them, and `Allow` never asks for them: a daily or lifetime cap enforces nothing and nothing says so. | `usage_persistence/limit-windows-enforced-or-refused` | `src/handlers/limits_enabled.go` (`Allow`) |
| 11 | **Fixed.** Spend on a model with no price row contributes nothing to the cap (`totalSpend`: cost absent with `priced_calls = 0`). A capped scope that uses only unpriced models is never refused, however many tokens it spends. | `usage_persistence/cap-not-bypassable` | `src/handlers/limits_enabled.go` (`totalSpend`) |
| 12 | **Fixed.** The limiter has no boot guard. With `usage_persistence` on and either `UsageQuery` or `UsageMutation` missing from the client set, `newLimiter` silently installs the allow-all limiter. The usage sink has `VerifyUsageWiring` for exactly this drift; the limiter has nothing, so every cap is off with no error. | `usage_persistence/limiter-wiring-verified` | `src/handlers/limits_enabled.go` (`init`), `src/plugin.go` (`RegisterPlugin`) |
| 13 | `endpoint` is checked only for being non-empty. An `http://` endpoint is accepted, and every request then sends the provider API key in clear text. | `agent/api-key-only-over-tls` | `src/lib/llm/client.go` (`NewClient`) |

## Per feature

### (base tier)

- **Purpose.** One model call in, text and token usage out, in three shapes:
  `Complete` (unary), `CompleteStream` (server stream of text deltas then one
  `Finished`), and `RunAgent` (bidirectional tool-calling loop in which the
  engine asks the caller to run each tool). Always present.
- **Adds.** Business service `AgentService` with `Complete`,
  `CompleteStream`, `RunAgent`. Types `ModelSpec`, `Message`, `ModelUsage`,
  `Status`, `IncompleteReason`, `ResponseFormat`, `ToolSpec`, `Limits`,
  `ToolCall`, `Activity`, `Finished`. No tables, no storage RPCs, no REST,
  MCP or admin preset, no events. The request fields `usage_scope` and
  `usage_labels` are ungated: an activation without `usage_persistence`
  accepts and ignores them.
- **Env knobs.** `provider` (default `azure_openai`, the only accepted value;
  anything else fails `RegisterPlugin`), `endpoint` (required), `api_key`
  (secret, required), `api_version` (default set; blank fails boot),
  `default_model` (optional; empty means every request must name a model),
  `max_output_tokens` (default 4096, used when `ModelSpec.max_tokens = 0`; a
  default, **not** a ceiling; `<= 0` uses 4096), `request_timeout_seconds`
  (default 120; `<= 0` uses 120; bounds one provider call including the SDK's
  own retries).
- **Requires / conflicts / combined files.** None. Go files `handlers/*.go`
  (except the two gated ones), `lib/llm`, `lib/usage`.

#### Model call (all three entry points)

| id | invariant | category | proof |
|---|---|---|---|
| `base/model-required` | A request that names no model and finds no `default_model` MUST be refused as `InvalidArgument` before the provider is called, and MUST NOT be recorded as spend. | Failure & configuration | `TestRefusesAModelWithoutABudget`, `TestAPreflightRefusalIsNotRecordedAsACall`, `TestRunAgent_APreflightRefusalIsNotRecordedAsACall`, `TestRefusalsNeverReachTheProvider` |
| `base/token-budget-shape` | `max_tokens > 0` MUST be sent as that cap (plus bounded reasoning headroom on a reasoning family); `= 0` MUST use `max_output_tokens`; `< 0` MUST omit the cap. A reasoning family MUST NOT receive a temperature; a sampling family MUST NOT receive an effort. | Consistency & concurrency | `TestModelForMaxTokens`, `TestReasoningModelGetsHeadroomAndEffortButNoTemperature`, `TestReasoningHeadroomIsCapped`, `TestSamplingModelGetsTemperatureAndNoEffort`, `TestANegativeBudgetOmitsTheCapEntirely`, `TestModelSpecReachesTheWire`, `TestIsReasoningModel` |
| `base/no-hard-token-ceiling` | The deployment MUST be able to bound what one call may spend. Today a caller can always lift the cap with `max_tokens < 0` or any large value; `max_output_tokens` is only a default. | Security | none (gap 1) |
| `base/json-object-enforced` | `RESPONSE_FORMAT_JSON_OBJECT` MUST be sent to the provider as an enforced format, also when the request carries no `ModelSpec`. A request whose instructions and user turns never mention JSON MUST be refused as preflight (`InvalidArgument`, nothing recorded); an assistant turn mentioning it MUST NOT satisfy the check. | Failure & configuration | `TestJSONObjectIsEnforcedByTheProvider`, `TestNoFormatIsSentUnlessAsked`, `TestJSONObject_RefusedLocallyWhenThePromptNeverAsksForJSON`, `TestRun_SharesThePreflightOfThePlainPath` |
| `base/instructions-not-a-message` | The system prompt MUST travel as the provider's `instructions` field, never as a history entry, and the history MUST carry only user and assistant roles. | Security | `TestInstructionsAreAFieldNotAMessage`, `TestRolesSurviveTheTranslation` |
| `base/provider-stores-nothing` | Every provider request MUST set `store = false`, so prompts and answers are not retained provider-side by this plugin's request. | Security | `TestNothingIsStoredProviderSide` |
| `base/status-honest` | A response MUST reach the caller with the provider's status: `COMPLETED`, `INCOMPLETE` with its reason, or `UNSPECIFIED` for anything unrecognised. An unknown status MUST NOT be reported as completed. A truncated answer MUST stay distinguishable from a finished one. | Consistency & concurrency | `TestAnUnknownStatusIsNotReportedAsCompleted`, `TestStatusAndReasonReachTheCaller`, `TestStatusAndReasonMapping`, `TestTruncationIsVisibleToTheCaller` |
| `base/failed-response-is-a-failure` | A response the provider marks `failed` (including inside HTTP 200 or as a `response.failed` stream event) MUST be an error (`Unavailable`, naming the provider's code), never an answer, and MUST still carry the usage it reported. | Failure & configuration | `TestComplete_AFailedStatusIsAFailure`, `TestWire_AFailedResponseIsAnErrorThatStillCarriesItsSpend`, `TestWire_AFailedStreamIsAFailure`, `TestCompleteStream_OverTheWire_AFailedResponseIsAFailure`, `TestRunAgent_AFailedResponseNamesTheProvidersCode` |
| `base/empty-is-not-an-answer` | A nil response, a malformed body, and a stream that ends without a terminal event MUST be failures. They MUST NOT become an empty completed answer. | Failure & configuration | `TestNilResponseIsNotAnEmptyAnswer`, `TestWire_AMalformedBodyIsNotAnEmptyAnswer`, `TestAStreamWithoutATerminalEventIsNotAnAnswer`, `TestWire_AStreamThatBreaksIsNotAnAnswer`, `TestStream_ADecoderErrorIsReturned` |
| `base/unmeasured-is-not-free` | `ModelUsage.measured` MUST be false whenever a call that reached the provider reported no usage. A free call and an unreported one MUST NOT produce the same value. Token counts beside `measured = false` are a floor. | Consistency & concurrency | `TestUnreportedUsageIsNotMeasuredZero`, `TestWire_AnEmptyResponseIsUnmeasured`, `TestCompleteStream_OverTheWire_ADroppedStreamIsRecordedUnmeasured` |
| `base/provider-error-opaque` | A provider failure MUST reach the caller as `Unavailable` carrying only the provider's classification (HTTP status, error type, code, offending parameter). It MUST NOT carry the provider's message or body, the deployment URL, or the prompt. | Security | `TestProviderErrorTextDoesNotCrossTheWire`, `TestComplete_OverTheWire_ProviderFailures`, `TestWire_ProviderErrorKeepsTheClassificationAndDropsTheBody`, `TestModelCallFailure_NamesTheProvidersObjection`, `TestProviderFaultWithNothingToSay` |
| `base/caller-ending-is-not-a-model-failure` | When the caller hangs up or its own deadline passes, the call MUST end with the caller's `Canceled` / `DeadlineExceeded`, MUST NOT be logged as a model failure, and MUST still record what was spent. | Failure & configuration | `TestCompleteStream_AClientHangingUpIsNotAModelFailure`, `TestCompleteStream_TheCallersDeadlineIsNotAModelFailure`, `TestRunAgent_ACallerWhoLeftIsNotAModelFailure`. **Not met on `Complete`** (finding 1). |
| `base/request-timeout-whole-call` | `request_timeout_seconds` MUST bound one provider call end to end, including the SDK's automatic retries and, for a stream, the whole read of the stream. The caller's shorter deadline MUST win. | Failure & configuration | `TestWire_AHungProviderIsCutOffByTheTimeout`, `TestWire_TheTimeoutBoundsTheWholeCallNotEachRetry`, `TestWire_AStalledStreamIsCutOffByTheTimeout`, `TestWire_AStreamOutlivesItsOpeningUntilClosed`, `TestWire_TheCallersCancellationStopsTheCall` |

#### CompleteStream

| id | invariant | category | proof |
|---|---|---|---|
| `base/stream-shape` | A successful stream MUST be zero or more `delta` events followed by exactly one `finished`. Status and usage MUST appear only on `finished`. `Finished.text` MUST equal the concatenation of the deltas sent. | Consistency & concurrency | `TestStreamSendsDeltasThenExactlyOneFinished`, `TestStreamForwardsDeltasInOrder`, `TestWire_StreamDeliversDeltasThenUsage` |
| `base/stream-cancel-stops-spend` | A failed send to the caller (the client gone) MUST abort the provider stream at once, so no further output is paid for. | Security | `TestAClientGoingAwayStopsTheCall`, `TestADeltaSinkErrorAbortsTheCall`. **Unit (mock) only:** a live test would disconnect mid-answer and assert that the provider saw its connection closed. |
| `base/stream-own-side-failure` | A send that fails on the server's side (an oversized or unmarshalable event) MUST keep its own status (`ResourceExhausted` stays so, otherwise `Internal`), MUST be logged as a send failure and not as a model failure, and MUST be recorded once. | Failure & configuration | `TestCompleteStream_AServerSideSendFailureIsNotTheClientLeaving` |
| `base/stream-repetition-guard` | A stream whose tail turns periodic (more than 90 % self-match over the last 100 bytes, for a period of 4 to 33 bytes: a period is tried from 4 up to 50 only while it fits three times in the window) MUST be stopped. The text before the loop MUST be delivered in `Finished` with `stopped_repeating = true`, `status = UNSPECIFIED`, `measured = false`, and recorded as outcome UNKNOWN, never as a completed free call. A repeated price or short list MUST NOT trip it. | Consistency & concurrency | `TestRepeating`, `TestRepeatingToleratesDrift`, `TestTheGuardStopsTheStreamAndKeepsTheGoodPart`, `TestStoppedRepeatingIsReportedToTheConsumer`, `TestCompleteStream_GuardAndRunawayAreRecorded` |
| `base/stream-runaway-refused` | Accumulated text or tool-argument output over the runaway ceiling MUST end the call with `ResourceExhausted` and record the spend as failed. | Failure & configuration | `TestRunawayOutputIsRefused`, `TestRunawayOutputIsItsOwnCode`, `TestRun_RunawayToolArgumentsAreRefused` |
| `base/stream-output-ceiling-stated` | Any limit on answer size that differs from `max_tokens` MUST be part of the wire contract and MUST apply alike to unary and streaming calls. | Failure & configuration | none (finding 7) |
| `base/stream-no-client-is-unimplemented` | A deployment without a streaming client MUST answer `Unimplemented`, never panic. | Failure & configuration | `TestNoStreamClientIsUnimplementedNotAPanic`, `TestRunAgent_PlumbingRefusals` |

#### RunAgent (tool calling)

| id | invariant | category | proof |
|---|---|---|---|
| `base/run-start-first` | The first client message MUST be `Start`. Anything else MUST be refused with `InvalidArgument` before any model call. | Failure & configuration | `TestTheFirstMessageMustBeStart` |
| `base/run-no-authority-of-its-own` | The engine MUST NOT execute any tool itself. Every tool call MUST be a `ToolCall` sent to the caller on the same stream, and the only effect a tool can have is what the caller's handler does with its own authorization. Nothing the model emits, including text injected through a tool result, MUST widen what the engine can do. | Security | `TestRunAgentAsksTheCallerAndFinishes`, `TestLoopCallsAToolThenAnswers` |
| `base/run-undeclared-tool-not-forwarded` | A call to a tool name the caller did not declare MUST be answered to the model as "no such tool" and MUST NOT reach the caller as a `ToolCall`. | Security | `TestAnUnknownToolIsAnsweredNotFailed`, `TestRun_AnInventedToolIsToldSoUnderItsCallID` (loop level; no handler-level test asserts the absence of a `ToolCall` event) |
| `base/run-arguments-verbatim` | `ToolCall.arguments` MUST be the model's raw JSON, unvalidated and unmodified. The contract MUST state that it may be invalid or carry undeclared keys, so the caller validates it. | Security | `TestRunAgentAsksTheCallerAndFinishes` |
| `base/run-tool-list-validated` | A tool with no name, two tools with one name, and a `params_schema` that is not a JSON object MUST be refused as preflight (`InvalidArgument`, no provider call, no usage row). | Failure & configuration | `TestRun_AMalformedToolListIsPreflight`, `TestDuplicateToolNamesAreRefused`, `TestRunAgent_APreflightRefusalIsNotRecordedAsACall`. `TestRun_ABadParamsSchemaIsPreflight` (finding 8 fixed: a schema that is not a JSON object is preflight). |
| `base/run-results-bound-to-call` | A `ToolResult` MUST be delivered only to the call it names on the same stream, at most once. A duplicate, late or invented `call_id` MUST be dropped and MUST NOT block other calls or the reader. | Consistency & concurrency | `TestParallelCallsAreMatchedByCallID`, `TestPendingCalls_ADuplicateResultDoesNotBlockTheReader`, `TestRunAgent_DuplicateAndStrayResultsAreHarmless`, `TestPendingCalls_ACallAfterTheEndIsReleasedAtOnce` |
| `base/run-mutating-serial-first` | Within one round, mutating tools MUST run serially and before every read-only tool. Read-only tools MAY run in parallel, at most `max_parallel` at once. | Consistency & concurrency | `TestMutatingToolsRunBeforeReadsAndNotInParallel`, `TestRun_MaxParallelIsHonoured`, `TestRun_ReadOnlyCallsRunTogether` |
| `base/run-budget-reserved-per-round` | `max_tool_calls` MUST be reserved for a whole round before any tool of it runs. A round that would exceed it MUST apply no tool at all and end the run with `ResourceExhausted`. | Consistency & concurrency | `TestAnOverBudgetRoundAppliesNothing`, `TestBudgetExhaustionIsItsOwnCode`, `TestLimitDefaultsAndBudgetEdges` |
| `base/run-turn-limit` | A run MUST end after `max_turns` model turns (default 6) with `DeadlineExceeded`. A tool request MUST NOT be returned as an answer. | Failure & configuration | `TestRunningOutOfTurnsIsNotAnAnswer`, `TestRunErrorMapping`, `TestRunAgent_StartLimitsReachTheLoop` |
| `base/run-last-turn-applies-nothing` | The last permitted turn MUST be offered no tools, and any tool call returned on it MUST NOT be dispatched. | Consistency & concurrency | `TestTheLastTurnIsOfferedNoTools`, `TestRun_TheLastTurnAppliesNothing` (finding 6 fixed). |
| `base/run-tool-timeout` | A tool that does not answer within `tool_timeout_seconds` MUST fail alone: its timeout becomes the tool result and the run continues. | Failure & configuration | `TestRun_ASlowToolFailsAlone` (finding 2 fixed) |
| `base/run-tool-failure-is-a-result` | A `ToolResult` with `failed = true` MUST reach the model as the result text, MUST mark the activity failed, and MUST NOT end the run. | Failure & configuration | `TestAFailedToolResultDoesNotEndTheRun`, `TestAToolFailureBecomesAModelVisibleResult` |
| `base/run-caller-gone-ends-run` | The caller disconnecting, cancelling, or becoming unreachable while a tool result is owed MUST end the run without another model turn, and MUST release every waiter. No mutating tool MUST be started after the run's context ended. | Security | `TestACallerDisconnectingDoesNotHangTheRun`, `TestRunAgent_CancellationWhileWaitingForATool`, `TestRunAgent_ACallerThatCannotBeAskedEndsTheRun`, `TestAFatalToolErrorEndsTheRun`, `TestRun_ACancelledRunAppliesNoWrite`, `TestRun_ASinkFailureEndsTheRun` |
| `base/run-half-close-is-precondition` | A caller that half-closes its sending side while a tool result is owed MUST get `FailedPrecondition`, not `Unknown` and not a model failure. | Failure & configuration | `TestRunAgent_AHalfCloseWhileAResultIsOwed`, `TestRunAgent_AWrappedRecvEOFIsAHalfClose` |
| `base/run-own-side-stream-failure` | A send or receive that fails on the server's side (an oversized `ToolResult` or event) MUST keep its own status and MUST NOT be reported as the caller leaving or as the model failing. | Failure & configuration | `TestRunAgent_AServerSideSendFailureIsNotTheCallerLeaving`, `TestRunAgent_AServerSideRecvFailureIsNotTheCallerLeaving`, `TestCallerGone` |
| `base/run-provider-transport-error` | A provider transport error during a run (including an `EOF` on a reused connection) MUST be `Unavailable` with the classification only, and MUST be logged. | Failure & configuration | `TestRunAgent_AProviderTransportErrorIsAModelFailure` |
| `base/run-activity-display-safe` | `Activity.text` MUST be the declared `ToolSpec.activity`. `Activity.error` MUST be a fixed display-safe string and MUST NOT quote the caller's tool error or any model output. | Security | `TestRunAgent_AFailedToolsActivityDoesNotQuoteIt`, `TestRun_TheEventAndTheToolShareAnID`, `TestRun_AnInventedToolIsToldSoUnderItsCallID` (finding 3 fixed: the declared `activity`, nothing for an invented name, and `activity_id` = `call_id`). |
| `base/run-finished-text-is-what-was-shown` | `Finished.text` of a run MUST equal every delta sent during the run, across turns. | Consistency & concurrency | `TestRun_TheAnswerIsEverythingShown` (finding 5 fixed) |
| `base/run-spend-every-turn` | A run's usage MUST be the sum of every turn sent to the provider, on success and on every failure path. It MUST be measured only if every sent turn reported usage. A run that sent nothing MUST be measured at zero. | Consistency & concurrency | `TestRun_UsageIsTheSumOfEveryTurn`, `TestRun_AFailedRunStillCarriesWhatItSpent`, `TestRun_AContextEndedBeforeATurnIsNotAnUnreportedTurn`, `TestRun_AContextEndedBeforeTheFirstTurnIsMeasuredAtZero`, `TestWire_RunSendsToolResultsBackAndBillsEveryTurn`, `TestRunAgent_ARunThatSentNothingIsMeasuredAtZero` |
| `base/run-repetition-guard` | The repetition and runaway guards MUST apply to every turn of a run, with the same reporting as `CompleteStream`. | Consistency & concurrency | `TestRun_TheGuardStopsALoopingAnswer`, `TestRunAgent_TheGuardIsReported` |
| `base/run-bounded-by-time` | A run MUST have an overall bound on wall time. Today each provider call is bounded, and each tool wait only when `tool_timeout_seconds` is set; the number of turns the caller sets is not. | Failure & configuration | none (gap 3) |

**Gaps / suspected defects**

1. **No hard per-call ceiling.** `max_output_tokens` is a default, `max_tokens < 0` removes the cap, and `Limits` (`max_turns`, `max_tool_calls`, `max_parallel`) has no deployment-side maximum. A caller that forwards end-user parameters unchecked lets the end user choose the spend. The manifest says so; the plugin offers no knob to enforce it.
2. **Usage counts are narrowed to 32 bits on the wire.** `usageOf` converts the 64-bit totals to `int32`; a run whose summed tokens exceed 2^31 − 1 wraps. The persisted row keeps 64 bits.
3. **No run deadline.** Each provider call is bounded by `request_timeout_seconds`, but a run of many turns, plus tool waits when `tool_timeout_seconds` is zero (its default: no bound), is bounded only by the caller's context.
4. **The SDK's retries can be paid twice and recorded once.** The provider client retries a 5xx, a 429 or a dropped connection twice. An attempt the provider processed but whose answer was lost is billed by the provider and invisible here. The documented overrun of the deadline by a provider's `Retry-After` sleep (up to a minute) also remains.
5. **Tool-loop input grows without a size bound.** Every turn re-sends the whole accumulated input, including every tool result, and nothing caps a `ToolResult` below the transport's message limit.
6. **The reasoning-family table drifts.** A new reasoning family not in `reasoningModelPrefixes` is sent a temperature and is refused by the provider on first use (`400`), loudly but only then.

---

### usage_persistence

- **Purpose.** Record what every model call spent (tokens by kind, wall time,
  outcome) against an opaque scope the caller names, with the caller's labels,
  an append-only price list, and per-scope spending limits enforced before the
  call. Off by default: on, it adds seven tables, which is a migration.
- **Adds.** Tables `Scope` (`external_id` unique, max 128), `Model` (`name`
  unique, max 128), `Usage` (integers and timestamps only; `scope_id` and
  `model_id` indexed; `status` `CHECK`ed, no zero member), `ModelPrice`
  (unique `(model_id, valid_from)`; nullable per-kind rates in minor units per
  million tokens; `currency`), `ScopeLimit` (`scope_id` indexed; `window`
  DAY / MONTH / TOTAL; `limit_minor >= 0`; `currency`; `valid_from`), `Label`
  (unique `(key, value)`, 64 / 256), `UsageLabel` (`usage_id`, `label_id`
  indexed). Storage RPCs `UsageMutation.InternScope`, `InternModel`,
  `InternLabel` (UPSERT returning the id), `RecordUsage`, `AttachUsageLabel`,
  `RecordModelPrice`, `SetScopeLimit` (all append-only inserts), and
  `UsageQuery.GetScopeSpend`, `GetLabelSpend`, `ListModelPrices`,
  `GetScopeLimit`. Every message, RPC and table is gated on the feature. No
  business RPC, no REST, no events. Go files `handlers/usage_enabled.go`
  (installs the database sink) and `handlers/limits_enabled.go` (installs the
  database limiter).
- **Mechanics.** An asynchronous writer (`lib/usage`): queue 4096, batch 64,
  flush every 5 s or at 64 events, 30 s per flush, drained by a shutdown hook.
  Interning runs in the flush, cached in bounded two-generation caches. The
  limiter enforces a cap per scope in each window a limit is set in (UTC day,
  UTC month, all time), from a spend figure cached 30 s and a limit cached
  5 minutes, per scope and window, per process.
- **Requires / conflicts / combined files.** None.

| id | invariant | category | proof |
|---|---|---|---|
| `usage_persistence/every-call-recorded` | Every call that reached the provider, on all three entry points, success or failure, the caller leaving included, MUST hand exactly one event to the sink. | Consistency & concurrency | `TestAFailedCallIsStillRecorded`, `TestEveryEntryPointRecords` (source scan), `TestComplete_OverTheWire_RecordsWhatTheProviderBilled`, `TestRunAgent_RecordsTheSpendOfEveryTurn`, `TestRunAgent_FailuresAreCodedAndStillBilled` |
| `usage_persistence/refusals-record-nothing` | A call refused before the provider (limit, preflight, malformed tool list, empty request) MUST NOT produce a usage event. | Consistency & concurrency | `TestAnOverBudgetScopeNeverReachesTheProvider`, `TestRefusalsNeverReachTheProvider`, `TestAPreflightRefusalIsNotRecordedAsACall`, `TestRunAgent_APreflightRefusalIsNotRecordedAsACall` |
| `usage_persistence/no-content-recorded` | A usage row and every queued event MUST hold only integers, timestamps, the scope, the provider-named model and the caller's labels. No prompt, instruction, completion, tool argument or tool result MUST be recorded. | Security | none (by construction of `UsageEvent` and the schema; no test asserts it) |
| `usage_persistence/billed-model-is-what-answered` | The recorded model MUST be the one the provider says answered (a dated id or alias) when it named one, else the one requested. | Consistency & concurrency | `TestComplete_OverTheWire_RecordsWhatTheProviderBilled`, `TestRunAgent_RecordsTheSpendOfEveryTurn` |
| `usage_persistence/outcome-honest` | The row's status MUST be OK for an answer, FAILED for any error after the provider was reached, UNKNOWN when the guard stopped a stream. A failed call's reported tokens MUST be kept. | Consistency & concurrency | `TestRunOutcome`, `TestComplete_OverTheWire_ProviderFailures`, `TestCompleteStream_GuardAndRunawayAreRecorded` |
| `usage_persistence/blank-scope-attributed` | An empty or blank `usage_scope` MUST be recorded under the scope `unattributed`, never dropped and never allowed to fail its batch. An unkeyed label MUST be dropped and the rest of the event kept. | Consistency & concurrency | `TestRecordUsage_AnEmptyScopeIsStillRecorded`, `TestRecordUsage_AnUnkeyedLabelIsDroppedNotFatal` |
| `usage_persistence/scope-validated-at-request` | A `usage_scope` or label that cannot be stored (over its column length) MUST be refused with `InvalidArgument` before the provider is called. It MUST NOT be accepted and then lost at flush. | Failure & configuration | TestAdmitSpend_RefusesAScopeOrLabelLongerThanItsColumn (finding 9 fixed) |
| `usage_persistence/scope-isolation` | Every row MUST be filed under the scope its call named, and every spend and limit read MUST be filtered to exactly one scope. One scope's figures MUST NOT appear in another's answer. | Security | `TestUsageSink_RecordsEachTenantsCallsAgainstItsOwnScope`, `TestDBLimiter_TenantsAreIsolated`. **Unit (mock) only:** a live test would write rows for two scopes and assert `GetScopeSpend` / `GetLabelSpend` for one never includes the other's calls. |
| `usage_persistence/record-never-blocks` | Recording MUST NOT make a model call wait or fail. A full queue MUST drop and count the event. | Performance | `TestAFullQueueDropsRatherThanBlocks` |
| `usage_persistence/at-most-once-and-counted` | Each event MUST be written at most once: a failed flush MUST NOT be retried into a duplicate. Every event that is not written (queue full, closed writer, failed flush) MUST be counted and reported in a log line; a row written without all its labels MUST be counted as written, not lost. One bad event MUST NOT drop the rest of its batch. | Consistency & concurrency | `TestAFailedFlushIsCounted`, `TestRecordAfterCloseIsCountedNotLost`, `TestRecordRacingCloseLosesNothingUncounted`, `TestAPartialFlushCountsOnlyWhatFailed`, `TestAnImpossiblePartialCountFallsBackToTheWholeBatch`, `TestAnUnlabelledEventCountsAsWritten`, `TestFlush_OneBadEventDoesNotSinkTheBatch`, `TestFlush_TheWriterCountsAPartialBatchExactly`, `TestFlush_ABadLabelKeepsTheRowAndTheOtherLabels`, `TestFlush_TheWriterCountsABadLabelAsWrittenNotLost`, `TestCloseReportsLossInOneLine`, `TestCloseIsQuietWhenNothingWasLost` |
| `usage_persistence/drained-at-shutdown` | The plugin MUST register a shutdown hook that flushes everything accepted, bounded by the shutdown context. | Failure & configuration | `TestRegisterPlugin_RegistersAUsageDrain`, `TestCloseDrainsWhatWasAccepted`, `TestCloseIsBoundedByItsContext`, `TestAFlushHasADeadline`, `TestFlushesOnBatchSize`, `TestFlushesOnInterval`, `TestConfigDefaults` |
| `usage_persistence/interning-idempotent` | Interning a scope, model or label MUST return the same id for the same value, also when two flushes (or two replicas) intern a first-seen value concurrently. A failed intern MUST NOT be cached. | Consistency & concurrency | `TestFlush_ATransientInternFailureIsNotCached`. **Unit (mock) only:** a live test would race two `InternScope` calls for one new value and assert one `Scope` row and one id. |
| `usage_persistence/caches-bounded` | Every per-key cache (scope, model and label ids; spend; limits) MUST be bounded, and a key in use MUST survive a flood of new keys. | Performance | `TestFlush_TheInternCachesAreBounded`, `TestDBLimiter_TheScopeIDCacheIsBounded`, `TestSpendCacheIsBounded`, `TestCaches_AHotKeySurvivesAFlood`, `TestGenerations_AnUpdateIsNotResurrectedByPromotion`, `TestSpendCache_AnExpiredEntryIsNotPromoted` |
| `usage_persistence/cost-computed-not-stored` | Cost MUST be computed per usage row from the price whose `valid_from` is the newest not after the row's `started_at`, then summed. A price recorded later MUST NOT change a past call's cost unless its `valid_from` precedes the call. Cached input MUST be billed as (input − cached) at the input rate plus cached at the cached rate. | Consistency & concurrency | none. **Live only:** price change inside a period, a price starting after a call, and the cached-input arithmetic, on a real database. |
| `usage_persistence/unpriced-is-absent` | A line with no priced call MUST report no cost (absent, not zero). `priced_calls < calls` MUST mark a short cost. A rollup whose priced rows span more than one currency MUST report neither cost nor currency. | Consistency & concurrency | none. **Live only** (the DQL); `TestTotalSpend` covers the limiter's reading of such lines. |
| `usage_persistence/half-open-periods` | Spend periods MUST be half-open `[from, to)`: a call at a boundary belongs to exactly one period. | Consistency & concurrency | none (DQL; live only) |
| `usage_persistence/prices-append-only` | A price or limit MUST never be edited or deleted through the plugin's RPCs; a correction is a new row. `ListModelPrices` MUST return the history newest `valid_from` first with `recorded_at`, so a backdated row is visible. | Consistency & concurrency | none (DQL only) |
| `usage_persistence/limit-checked-before-call` | Every entry point MUST consult the limiter before the provider is called and refuse an over-cap scope with `ResourceExhausted`. | Security | `TestAnOverBudgetScopeNeverReachesTheProvider`, `TestRefusalsNeverReachTheProvider`, `TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints`, `TestDBLimiter_TheCapItself` |
| `usage_persistence/limit-refusal-reveals-nothing` | A limit refusal MUST NOT carry any amount, limit or spend figure. | Security | `TestDBLimiter_TheRefusalCarriesNoAmounts` |
| `usage_persistence/limit-month-utc` | The monthly window MUST be the current calendar month in UTC, from its first instant to now. The limit in force MUST be the newest `valid_from` not after now. | Consistency & concurrency | `TestDBLimiter_AsksForThisMonth` |
| `usage_persistence/limit-currency-safe` | A spend that cannot be totalled in one currency, or a limit in a different currency from the spend, MUST refuse (fail closed) with a reason that names the misconfiguration. | Consistency & concurrency | `TestTotalSpend`, `TestDBLimiter_MixedCurrencySpendFailsClosed`, `TestDBLimiter_ALimitInAnotherCurrencyIsNotComparedBlindly` |
| `usage_persistence/limit-fails-open-on-outage` | A database error while reading the limit or the spend MUST allow the call and MUST NOT be cached. Only the absence of a limit (`NotFound`) MAY be cached. | Failure & configuration | `TestDBLimiter_FailsOpenWhenTheDatabaseIsDown`, `TestDBLimiter_ATransientLimitErrorDoesNotSwitchTheCapOff`, `TestDBLimiter_NoLimitIsCachedAsAnAnswer` |
| `usage_persistence/limit-slack-bounded` | Overspend past a cap MUST be bounded and stated: at most what the scope can buy within (flush interval + spend TTL) per replica, plus what calls already admitted spend. A limit change MUST take effect within the limit TTL. | Consistency & concurrency | `TestDBLimiter_SpendIsReReadAfterItsTTL`, `TestSpendCacheExpires`, `TestDBLimiter_ConcurrentCallers` (correct answers under concurrency, not overspend). **Live only** for the bound itself. |
| `usage_persistence/limit-windows-enforced-or-refused` | Every limit window the schema accepts MUST be enforced, or `SetScopeLimit` MUST refuse it. | Security | TestDBLimiter_EveryWindowIsEnforced, TestDBLimiter_AsksForThisMonth (finding 10 fixed: every window is enforced) |
| `usage_persistence/cap-not-bypassable` | Nothing a caller chooses (the model, whether the model is priced) MUST let a capped scope spend without bound. | Security | TestDBLimiter_UnpricedSpendUnderACapFailsClosed, TestTotalSpend (finding 11 fixed: unpriced calls under a cap refuse) |
| `usage_persistence/blank-scope-uncapped` | A blank scope MUST be allowed without a database round trip and without interning a scope row. | Performance | `TestDBLimiter_ABlankScopeIsNotCapped` |
| `usage_persistence/limiter-steady-state-free` | In steady state, a call for a known scope MUST cost the limiter no database round trip. | Performance | `TestDBLimiter_TheSteadyStateAsksTheDatabaseNothing` |
| `usage_persistence/wiring-verified-at-boot` | With the feature on, a bundle in which the database sink was not installed MUST fail `RegisterPlugin`. | Failure & configuration | `TestVerifyUsageWiringAgreesWithTheActivation`, `TestUsageSink_WithoutTheClientStaysTheNoop`, `TestTheNoopSinkSwallowsEverything` |
| `usage_persistence/limiter-wiring-verified` | With the feature on, a bundle in which the database limiter was not installed MUST fail `RegisterPlugin`. | Failure & configuration | TestVerifyLimiterWiring, TestNewLimiter_NeedsBothClients (finding 12 fixed) |
| `usage_persistence/tables-declared` | The manifest's description MUST name every table the feature adds, so the migration it schedules is visible before activation. | Failure & configuration | `TestUsageManifestNamesEveryTable` |

**Gaps / suspected defects**

1. **Admission, not reservation.** The cap is read before a call and never reserves the call's cost. One admitted `RunAgent` (asked once at its start) or one call with `max_tokens < 0` can spend any amount past the cap. The slack also multiplies by the number of replicas, and a crash loses whatever is queued (up to 4096 events), which the cap then never sees.
2. **The first call for a new scope writes in front of the provider.** `scopeID` interns the scope (an UPSERT) on the request path when the id is not cached. The cache is bounded, so a caller cycling through many scopes makes this a write per call.
3. **No composite index for spend reads.** `GetScopeSpend` and `GetLabelSpend` filter `scope_id` and a `started_at` range, but `Usage` has only single-column indexes. The limiter re-reads each capped window's spend every 30 s per scope per replica, so the cost of that read grows with the scope's history inside the window — for a `TOTAL` limit, all of it — and, without a `(scope_id, started_at)` index, with all of it for every window.
4. **`ScopeLimit` has no uniqueness.** Two limits for one scope and window with the same `valid_from` are both accepted, and `GetScopeLimit` picks one of them arbitrarily.
5. **A row and its labels are not one unit of work.** `RecordUsage` and each `AttachUsageLabel` are separate statements; a failure or crash between them leaves a row with part of its attribution. It is counted, not prevented.
6. **The flush log line quotes the database error,** which can carry a scope or label value. Labels are the caller's free text.
7. **`unattributed` is a real scope name.** A caller that names its own scope `unattributed` shares it with every blank-scope call, and a cap set on it is never consulted for blank-scope calls (they skip the limiter).

---

## Across features

Every interaction goes through one of these mechanisms:

| Mechanism | Where | Rule |
|---|---|---|
| **Seam variable** (a single `var` replaced in `init()`) | `handlers/usage.go`: `newUsageSink`; `handlers/limits.go`: `newLimiter` | Only `usage_persistence` assigns them. The default (no-op sink, allow-all limiter) is the behaviour with the feature off. |
| **Feature constant** | `gen.FeatureUsagePersistence` | Read by `VerifyUsageWiring` at boot. |
| **Always-present call sites** | `recordUsage` / `recordUsageFor`, `Limits.Allow` | Every entry point records and asks unconditionally; whether anything happens is decided once, at wiring. |
| **Ungated wire fields** | `CompleteReq.usage_scope` / `usage_labels`, `RunAgentReq.Start.usage_scope` / `usage_labels` | The business contract is identical with the feature on or off. |
| **Message / RPC / table gates** | `(w17.contrib.plugin_feature)` on every usage message, `plugin_feature_svc` on both usage services | With the feature off, no usage table, message or RPC exists, and the proto files drop out whole. |

### Feature interaction matrix

Abbreviations: **b** base tier, **up** usage_persistence.

Cell codes: **H** one overrides the other's seam · **T** shared table · **Q**
shared RPC or helper · **O** ordering constraint inside one request · **·** no
interaction.

|    | b | up |
|----|----|----|
| **b** | — | H Q O |

### Interaction invariants

| ID | Features | Mechanism | MUST hold | Proof |
|---|---|---|---|---|
| `interaction/base-usage_persistence-wire-unchanged` | b up | Ungated fields | The business request and response shapes MUST be identical with the feature on or off. With it off, `usage_scope` and `usage_labels` MUST be accepted and ignored, no table MUST exist, and no write MUST be attempted. | `TestTheNoopSinkSwallowsEverything`, `TestTheAllowAllLimiterLetsEverythingThrough` (build of an activation without the feature: example-level only) |
| `interaction/base-usage_persistence-limit-then-preflight-then-record` | b up | O | On every entry point the order MUST be: limit check, then preflight, then the provider call, then exactly one usage event. A refusal at any step before the provider MUST leave no event. | `TestRefusalsNeverReachTheProvider`, `TestAnOverBudgetScopeNeverReachesTheProvider`, `TestAPreflightRefusalIsNotRecordedAsACall`, `TestRunAgent_APreflightRefusalIsNotRecordedAsACall`, `TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints` |
| `interaction/base-usage_persistence-run-one-row` | b up | Q: `recordUsageFor` | A run MUST be recorded as one row with the sum of every sent turn and the run's start time, and the contract MUST say so. **The published contract says one row per turn** (finding 4). | `TestRunAgent_RecordsTheSpendOfEveryTurn`, `TestRunAgent_FailuresAreCodedAndStillBilled` |
| `interaction/base-usage_persistence-caller-left-still-billed` | b up | O | A call or run that ends because the caller left MUST still record what its turns spent, exactly once, before the error is shaped. | `TestCompleteStream_AClientHangingUpIsNotAModelFailure`, `TestCompleteStream_TheCallersDeadlineIsNotAModelFailure`, `TestRunAgent_ACallerWhoLeftIsNotAModelFailure`, `TestCompleteStream_AServerSideSendFailureIsNotTheClientLeaving` |
| `interaction/base-usage_persistence-guard-is-unknown` | b up | Q | A stream or run stopped by the repetition guard MUST be recorded as UNKNOWN and unmeasured; a runaway MUST be recorded as FAILED. | `TestCompleteStream_GuardAndRunawayAreRecorded`, `TestRunAgent_TheGuardIsReported` |
| `interaction/base-usage_persistence-scope-mapping-agrees` | b up | Q: `attributableScope`, `Allow` | The limiter and the recorder MUST map a scope string to the same `Scope` row. Today they agree for every non-blank scope; a blank scope is recorded under `unattributed` and never capped (usage_persistence gap 7). | `TestDBLimiter_ABlankScopeIsNotCapped`, `TestRecordUsage_AnEmptyScopeIsStillRecorded` |
| `interaction/base-usage_persistence-run-cap-once` | b up | O | A run MUST be checked against the cap once, at its start, and MUST NOT be abandoned mid-run by the cap. Its spend past the cap is bounded only by `Limits` (usage_persistence gap 1). | `TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints` |

---

### Cross-cutting invariants

#### Trust boundary

The plugin authenticates nobody. `usage_scope` and `usage_labels` are taken
as the caller asserts them, and `AgentService` and the two usage services run
whatever they are asked by whoever can reach them.

| ID | MUST hold | Proof |
|---|---|---|
| `agent/not-a-public-surface` | `AgentService`, `UsageMutation` and `UsageQuery` MUST NOT be exposed on a client-facing transport. The manifest declares no REST, MCP or admin preset for any of them, and a project MUST NOT add one: anyone who could call them could spend on any scope, read any scope's spend, set prices and lift limits. | none (manifest only; live: assert the example's public gateway answers none of them) |
| `agent/caller-owns-identity` | The plugin MUST NOT read or rely on a principal. The calling service MUST derive `usage_scope` from its own authenticated principal, never from end-user input. | none (caller obligation) |
| `agent/caller-owns-conversations` | The plugin MUST NOT persist, cache or share a prompt, history or answer between requests. History arrives in each request and leaves with the response, so one end user's conversation cannot leak into another's call through the plugin. | none (by construction: no table, no cache of content) |
| `agent/caller-authorizes-every-tool-call` | Each `ToolCall` MUST be executed by the caller with the end user's permissions, never more. The engine carries no identity on a `ToolCall`, so the caller MUST bind the run to the end user on its own side, validate `arguments`, and treat an instruction injected through a tool result or the history as untrusted model output. A tool result is model-visible and MUST NOT contain what the end user may not see. | `TestRunAgentAsksTheCallerAndFinishes` (engine half only) |
| `agent/declared-tools-only` | The model MUST be offered only the tools the caller declared on `Start`, and only those MUST ever reach the caller. | `TestRemoteToolTranslation`, `TestRun_AnInventedToolIsToldSoUnderItsCallID` |

#### Secrets and content

| ID | MUST hold | Proof |
|---|---|---|
| `agent/api-key-never-emitted` | The provider API key MUST arrive as a secret value revealed once at wiring, MUST be sent only as the provider's authentication header, and MUST NOT appear in any log line, error, response, usage row or model input. Boot errors MUST name the setting, never its value. | `TestRegisterPlugin_TheRegisteredServiceCallsTheConfiguredProvider` (key reaches the header). No test scans logs or errors for the key. |
| `agent/api-key-only-over-tls` | A non-`https` endpoint MUST be refused at boot. | none (finding 13) |
| `agent/prompt-never-logged` | No log line MUST carry a prompt, instruction, history entry, answer, tool argument or tool result. A provider error MUST be logged only as its classification and request URL, never its body. | `TestNoHandlerLogsARawProviderError` (static gate), `TestProviderLogLineKeepsANonProviderError`, `TestComplete_OverTheWire_ProviderFailures` (canary prompt absent from the log) |
| `agent/error-messages-carry-no-content` | No error returned to the caller MUST carry the provider's body, the deployment URL, a tool's error text or any other scope's data. | `TestProviderErrorTextDoesNotCrossTheWire`, `TestComplete_OverTheWire_ProviderFailures`, `TestRunAgent_AFailedToolsActivityDoesNotQuoteIt`, `TestDBLimiter_TheRefusalCarriesNoAmounts` |

#### Events

| ID | MUST hold | Proof |
|---|---|---|
| `agent/no-events` | The plugin MUST emit no event. Usage reaches storage through the writer, not the bus, so no prompt, answer, scope or spend figure travels on an event channel. | none (manifest and protos declare none) |

#### Error codes

| Ending | Code |
|---|---|
| Empty request, first message not `Start`, preflight (no model, no budget, JSON format never asked for, bad tool list) | `InvalidArgument` |
| Scope over its cap, or cap not evaluable (mixed currency, currency mismatch) | `ResourceExhausted` |
| Tool-call budget spent; runaway output | `ResourceExhausted` |
| Turn limit reached | `DeadlineExceeded` |
| Caller half-closed while a result was owed | `FailedPrecondition` |
| Caller cancelled or its deadline passed (streams and runs) | caller's own `Canceled` / `DeadlineExceeded` |
| Server-side send or receive failure | its own status if `ResourceExhausted`, else `Internal` |
| Provider error, provider-marked failure, transport error, provider timeout | `Unavailable` with the classification |
| No streaming client | `Unimplemented` |

| ID | MUST hold | Proof |
|---|---|---|
| `agent/error-codes` | Each ending MUST map to the code in the table, on every entry point that can reach it. | `TestRunErrorMapping`, `TestRunAgent_PlumbingRefusals`, `TestEmptyRequestIsRefused`, `TestStreamRefusesAnEmptyRequest`, `TestBudgetExhaustionIsItsOwnCode`, `TestRunawayOutputIsItsOwnCode` (unary caller-cancel row: not met, finding 1) |

#### Configuration that must fail at boot

| ID | Condition | Enforced | Proof |
|---|---|---|---|
| `agent/boot-provider` | `provider` not `azure_openai` (case-insensitive; blank means the default) | `RegisterPlugin` → `NewClient` | `TestRegisterPlugin_RefusesABadConfigAndServesNothing`, `TestNewClient_RefusesAnIncompleteConfig` |
| `agent/boot-endpoint-key-version` | blank `endpoint`, `api_key` or `api_version` | `NewClient` | `TestRegisterPlugin_RefusesABadConfigAndServesNothing`, `TestNewClient_RefusesAnIncompleteConfig` |
| `agent/boot-serves-nothing-on-error` | any refused config registers neither the service nor the shutdown hook | `RegisterPlugin` | `TestRegisterPlugin_RefusesABadConfigAndServesNothing` |
| `agent/boot-defaults` | `max_output_tokens <= 0` → 4096; `request_timeout_seconds <= 0` → 120; `default_model` trimmed | `RegisterPlugin`, `NewClient` | `TestRegisterPlugin_AppliesTheDocumentedDefaults` |
| `agent/boot-usage-wiring` | feature on, no database sink | `VerifyUsageWiring` | `TestVerifyUsageWiringAgreesWithTheActivation` |
| **Not** boot-checked (gaps) | an `http://` or malformed `endpoint` (finding 13); feature on, no database limiter (finding 12); a negative `max_output_tokens` or `request_timeout_seconds` silently replaced by the default rather than refused; an `api_version` the provider does not know (fails per call) | — | none |

#### Transactions (one unit of work)

The plugin opens no transaction. Every storage RPC is one statement.

| Flow | Writes | Proof |
|---|---|---|
| Flush of one event | intern scope · intern model · `RecordUsage` · per label: intern label · `AttachUsageLabel`, each separate. A failure after `RecordUsage` leaves the row with part of its labels, counted as written-unlabelled. | `TestFlush_ABadLabelKeepsTheRowAndTheOtherLabels` |
| `RecordModelPrice`, `SetScopeLimit` | one insert each | none (live only) |

#### Performance

| ID | MUST hold | Proof |
|---|---|---|
| `agent/no-db-on-model-path` | A model call MUST NOT wait on a usage write. Interning MUST happen in the flush. The only database work on the request path MUST be the limiter's cached reads, plus one intern per scope not yet cached. | `TestAFullQueueDropsRatherThanBlocks`, `TestDBLimiter_TheSteadyStateAsksTheDatabaseNothing` |
| `agent/no-history-loads` | The plugin MUST NOT load history or transcripts from storage. Request size is bounded by the transport; the tool loop's input is bounded by `max_turns` × results (base gap 5). | none (by construction) |
| `agent/usage-reads-indexed` | `Usage` reads by scope and time, `Label` by `(key, value)`, `ModelPrice` by `(model_id, valid_from)`, `ScopeLimit` by scope MUST each be served by an index. `(scope_id, started_at)` has none today (usage_persistence gap 3). | none (schema; live: query plan) |
| `agent/interning-cached` | A steady stream of calls for known scopes, models and labels MUST cost one insert per call plus one per label, not three or more. | `TestUsageSink_RecordsEachTenantsCallsAgainstItsOwnScope` |

---

### How to prove it — live-only coverage

A unit test against fake clients cannot prove the invariants below. An example
project's end-to-end suite, run against a real database and the real gateway,
should cover them.

**The plugin has no LLM sandbox yet, and most of the list needs one.** A fake
provider for an example project would have to:

- speak the provider's Responses API at the path, query (`api-version`) and
  authentication header the plugin uses, for both a JSON response and an SSE
  stream;
- be scriptable per request without code in the bundle: a script selected by
  a marker in the instructions or the last user message, with a control
  endpoint to load scripts and read back what was received;
- emit text deltas, `function_call` output items (including several in one
  turn and a call on a turn that offered no tools), function-argument deltas,
  and each terminal event (`response.completed`, `response.incomplete` with
  `max_output_tokens` or `content_filter`, `response.failed` with a code), with
  usage including cached-input and reasoning tokens and a dated model id;
- inject failures: HTTP 400 naming a `param`, 401, 429 with `Retry-After`,
  500 (to exercise the SDK's retries), a body that echoes a canary prompt, a
  malformed body, a hang before headers, a stall mid-stream, a connection
  dropped before the terminal event, a periodic answer (repetition guard),
  and more than 20 000 bytes of text or tool arguments;
- record every request: count them (refusals must reach it zero times), keep
  the parsed body (`store`, `instructions`, `max_output_tokens`, `temperature`,
  `reasoning`, `text.format`, offered tools per turn, tool outputs fed back),
  and report when the client disconnected (cancellation must close the
  provider stream);
- never be reachable from outside the example's network, and accept only a
  fixed test key, so the suite can also scan logs for that key.

With such a sandbox, the suite should cover:

1. **Usage rows on a real database**: each entry point writes exactly one row
   with the right status, `measured`, tokens and provider-named model; a run
   writes one row summing its turns (`interaction/base-usage_persistence-run-one-row`);
   limit and preflight refusals write none; rows queued at shutdown are written
   by the drain hook (`usage_persistence/drained-at-shutdown`).
2. **Interning under concurrency**: two replicas, or parallel flushes, first
   seeing one scope, model or label produce one row and one id
   (`usage_persistence/interning-idempotent`).
3. **Pricing SQL**: a price change inside a period prices each call at its own
   `started_at`; a price starting after a call does not reach it; a backdated
   price does; cached-input arithmetic and rounding; `priced_calls`; absent
   cost for unpriced lines; absent cost and currency for a mixed-currency
   rollup; half-open boundaries; a call labelled with two values of one key
   counted under both (`usage_persistence/cost-computed-not-stored`,
   `unpriced-is-absent`, `half-open-periods`).
4. **Limits**: a `DAY`, `MONTH` and `TOTAL` cap each refuses the next call
   once the spend is flushed and the cache expires; the measured overspend
   stays within the stated bound (`usage_persistence/limit-slack-bounded`);
   currency mismatch fails closed; the database down fails open; the UTC day
   and month boundaries; a scope over 128 characters is refused (finding 9);
   a capped scope with unpriced calls that spent tokens is refused, and stays
   refused after a price that starts later, until the window ends or the
   price is backdated (finding 11); a bundle missing a usage client does not
   boot (finding 12).
5. **Streams over the real gateway**: SSE framing of `CompleteStream`; a client
   disconnect mid-answer closes the sandbox's stream and records one failed,
   unmeasured row (`base/stream-cancel-stops-spend`); the caller's deadline
   comes back as `DeadlineExceeded`. Expected red: the same on unary
   `Complete` (finding 1); a long answer on `CompleteStream` versus `Complete`
   (finding 7).
6. **Tool loop over the real transport**: a round trip of tool calls;
   read-only calls overlap and mutating ones do not; an over-budget round
   applies nothing; a half-close while a result is owed; an oversized
   `ToolResult` returns `ResourceExhausted`. Expected red: a caller that never
   answers a call (finding 2), text streamed before a tool call missing from
   `Finished.text` (finding 5), a function call on the last turn (finding 6),
   an invalid `params_schema` (finding 8).
7. **Trust boundary**: the example's public gateway answers none of
   `AgentService`, `UsageMutation`, `UsageQuery` (`agent/not-a-public-surface`).
   A prompt-injection scenario: the sandbox, on seeing a marker inside a tool
   result, emits a call for another end user's record and a call to an
   undeclared tool; the undeclared one never reaches the caller, and the
   caller's tool handler refuses the other user's record under the end user's
   own principal (`agent/caller-authorizes-every-tool-call`).
8. **Secrets and content**: across every failure script, the bundle's logs and
   every error the caller receives contain neither the API key nor the canary
   prompt (`agent/api-key-never-emitted`, `agent/prompt-never-logged`);
   every request the sandbox received has `store = false`. Expected red: an
   `http://` endpoint accepted at boot (finding 13).
9. **Feature-off build**: an activation without `usage_persistence` builds,
   has no usage tables, and accepts `usage_scope` and `usage_labels`
   (`interaction/base-usage_persistence-wire-unchanged`).
10. **Query plans**: with a realistic month of rows for one scope, the plan of
    `GetScopeSpend` and `GetLabelSpend` uses an index on scope and time
    (`agent/usage-reads-indexed`, expected red today).
