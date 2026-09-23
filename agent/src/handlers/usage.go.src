package handlers

import (
	"context"
	"strings"
	"time"

	"errors"

	gen "github.com/wandering-compiler/platform/plugins/agent/gen"
	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

// CallOutcome mirrors the proto CallStatus, and exists because this file is
// staged into EVERY activation while that enum lives in a gated proto: an
// activation without `usage_persistence` has no pb.CallStatus, so naming it
// here would break the build of a bundle that merely declined the feature.
// (It did, which is what the second activation in examples/plugin-surfaces is
// for.)
//
// The values are pinned against the proto's in handlers/usage_enabled.go,
// where the enum DOES exist — so a renumbering breaks that file's compile in
// the activation that has it, rather than silently recording the wrong
// outcome.
type CallOutcome int32

const (
	OutcomeUnspecified CallOutcome = 0
	OutcomeOK          CallOutcome = 1
	OutcomeFailed      CallOutcome = 2
	OutcomeUnknown     CallOutcome = 3
)

// UsageEvent is one model call as the usage layer sees it: integers, times,
// and the caller's own attribution. No prompt, no completion, no message
// bodies — this records what a call COST, and nothing it said.
type UsageEvent struct {
	// Scope is whoever pays, as the caller names them. Opaque here.
	Scope string
	// Model is what the PROVIDER says answered, which can differ from what was
	// asked for. Billing follows what answered.
	Model string
	// Labels is the caller's attribution, verbatim. A call that cannot be
	// attributed to one subject carries no label rather than a share of each:
	// aggregating later is always possible, splitting back never is.
	Labels map[string]string

	Measured          bool
	InputTokens       int64
	OutputTokens      int64
	CachedInputTokens int64
	ReasoningTokens   int64

	Status    CallOutcome
	StartedAt time.Time
	Duration  time.Duration
}

// UsageSink records what a call spent. Recording is best-effort by design —
// an implementation must never make a model call fail or wait — so Record
// takes no error: there is nothing a caller could usefully do with one, and
// returning it would invite exactly the coupling this avoids.
type UsageSink interface {
	Record(ev UsageEvent)
	// Close flushes what is queued. Best-effort, bounded by ctx.
	Close(ctx context.Context)
}

// noopUsageSink is what an activation without `usage_persistence` gets. It is
// not a fallback for an error — it is the honest answer when there are no
// tables to write to.
type noopUsageSink struct{}

func (noopUsageSink) Record(UsageEvent)     {}
func (noopUsageSink) Close(context.Context) {}

// newUsageSink is replaced by handlers/usage_enabled.go, which is staged ONLY
// when `usage_persistence` is active.
//
// A package variable rather than two files declaring the same function,
// because the plugin's own module holds BOTH files and would not compile if
// they collided. The gated file overrides this in init(); with the feature off
// it is not staged and the no-op stands.
//
// An init() with no caller to protect it is a thing this codebase has been
// bitten by — a move deletes it and nothing says so. That is what
// VerifyUsageWiring below is for.
var newUsageSink = func(gen.ClientSet) UsageSink { return noopUsageSink{} }

// NewUsageSink builds the sink for this activation.
func NewUsageSink(clients gen.ClientSet) UsageSink { return newUsageSink(clients) }

// VerifyUsageWiring refuses to boot when the activation says usage persistence
// is ON and no real sink got wired.
//
// The two halves come from different places — the constant is generated from
// the activation, the sink from a file that activation stages — so they can
// disagree, and the failure is silent in the worst possible way: every call
// succeeds and nothing is recorded, which looks exactly like a quiet month.
// Comparing them at boot turns that into a refusal with a name.
var errUsageWiring = errors.New(
	"agent: usage_persistence is active for this activation but no usage sink was wired — " +
		"handlers/usage_enabled.go should have installed one at init; nothing would be recorded " +
		"and every call would still succeed")

func VerifyUsageWiring(sink UsageSink) error {
	_, isNoop := sink.(noopUsageSink)
	if gen.FeatureUsagePersistence && isNoop {
		return errUsageWiring
	}
	return nil
}

// recordUsage hands one call to the sink.
//
// Never returns an error and never blocks: the sink's contract is
// best-effort, and a bill that could fail a completion would be a worse
// trade than a bill with a gap in it. The gap is COUNTED on the writer's
// side rather than hidden — "spend happened and was not recorded" has to stay
// distinguishable from "nothing was spent", which is the confusion this whole
// layer exists to remove.
func (h *AgentServiceHandler) recordUsage(req *pb.CompleteReq, model string, out *llm.Completion, outcome CallOutcome, startedAt time.Time) {
	h.recordUsageFor(req.GetUsageScope(), req.GetUsageLabels(), model, out, outcome, startedAt)
}

// recordUsageFor is the same, addressed by scope and labels rather than by a
// CompleteReq — RunAgent carries them on its Start message, and a run is many
// calls rather than one.
func (h *AgentServiceHandler) recordUsageFor(scope string, labels map[string]string, model string, out *llm.Completion, outcome CallOutcome, startedAt time.Time) {
	if h.Usage == nil {
		return
	}
	ev := UsageEvent{
		Scope:     attributableScope(scope),
		Model:     model,
		Labels:    keyedLabels(labels),
		Status:    outcome,
		StartedAt: startedAt,
		Duration:  time.Since(startedAt),
	}
	// A failed call may carry no completion at all. `measured` then stays
	// false, which is the row saying "this happened and we do not know what
	// it cost" — the state that used to be indistinguishable from "free".
	if out != nil {
		// The model the PROVIDER says answered wins over the one asked for: a
		// dated id or a deployment alias is what the price list has to key on.
		if out.Usage.Model != "" {
			ev.Model = out.Usage.Model
		}
		ev.Measured = out.Usage.Measured
		ev.InputTokens = out.Usage.InputTokens
		ev.OutputTokens = out.Usage.OutputTokens
		ev.CachedInputTokens = out.Usage.CachedInputTokens
		ev.ReasoningTokens = out.Usage.ReasoningTokens
	}
	h.Usage.Record(ev)
}

// runOutcome maps a run's ending onto the recorded status.
//
// A run that errored is FAILED; one that ended without a terminal status — the
// repetition guard cut it short — is UNKNOWN rather than OK, because what it
// spent is exactly what nobody can state.
func runOutcome(runErr error, out *llm.Completion) CallOutcome {
	switch {
	case runErr != nil:
		return OutcomeFailed
	case out == nil || out.Status == "":
		return OutcomeUnknown
	default:
		return OutcomeOK
	}
}

// ScopeUnattributed is the scope a call gets when the caller named none.
//
// `usage_scope` is OPTIONAL in the contract, and the layer's promise is that
// the caller cannot forget to record spend. An empty scope used to be queued
// as-is, fail the `external_id <> ”` check at insert, and take its whole
// batch down — so the one thing the caller was allowed to omit produced
// exactly the silent nothing this layer exists to remove. A consumer found it
// with 0 rows after hundreds of calls and no error anywhere.
//
// Written under a sentinel rather than refused, because spend that cannot be
// attributed is still spend, and because aggregating rows later is possible
// while splitting them back out never is.
const ScopeUnattributed = "unattributed"

// attributableScope maps an empty scope onto the sentinel.
func attributableScope(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return ScopeUnattributed
	}
	return scope
}

// keyedLabels drops label pairs with no key.
//
// The same constraint class as the scope (`agent_label` checks `key <> ”`),
// and the same failure: one unkeyed label would sink the batch that carried
// it. The answer is the opposite one, though — a sentinel is right for a scope
// because the spend is real and has to land somewhere, while a label with no
// key names nothing and could not be queried back. There is no value in
// inventing a name for it, so it goes and the rest of the event is kept.
func keyedLabels(labels map[string]string) map[string]string {
	for k := range labels {
		if strings.TrimSpace(k) != "" {
			continue
		}
		out := make(map[string]string, len(labels))
		for kk, vv := range labels {
			if strings.TrimSpace(kk) != "" {
				out[kk] = vv
			}
		}
		return out
	}
	return labels
}
