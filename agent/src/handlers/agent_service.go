// Package handlers is the agent plugin's gRPC surface.
//
// It is thin on purpose: it translates the wire contract into the `lib/llm`
// call and back, and holds nothing. Everything worth explaining about the model
// call itself lives in `lib/llm`, and everything about whose conversation this
// is lives in the caller.
package handlers

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

// AgentServiceHandler serves one model call per request.
type AgentServiceHandler struct {
	pb.UnimplementedAgentServiceServer

	// Client is the non-streaming model seam. Never nil after RegisterPlugin.
	Client llm.Completer

	// StreamClient is the streaming half. Separate field because the two are
	// separate interfaces — a deployment could satisfy one and not the other,
	// and CompleteStream says so rather than panicking.
	StreamClient llm.StreamCompleter

	// Usage records what each call spent. Never nil after RegisterPlugin —
	// an activation without `usage_persistence` gets a no-op, so the call
	// sites need no feature check of their own. That is the point of a sink
	// rather than an `if`: recording is unconditional here, and whether it
	// lands anywhere is settled once, at wiring time.
	Usage UsageSink

	// Limits refuses a call whose scope is over its cap. Never nil after
	// RegisterPlugin — an activation without `usage_persistence`, and a scope
	// with no limit set, both get an implementation that allows. Same reason
	// as Usage: the call site asks unconditionally.
	Limits Limiter

	// DefaultModel and DefaultMaxTokens fill in what a request leaves empty.
	// Both come from the deployment, so a project can standardise its model
	// without every caller repeating it.
	DefaultModel     string
	DefaultMaxTokens int64
}

// Complete runs one model call.
func (h *AgentServiceHandler) Complete(ctx context.Context, req *pb.CompleteReq) (*pb.CompleteResp, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "agent: empty request")
	}

	// Asked BEFORE the call, which is the entire difference between a limit
	// and a report: out of credit has to fail the first request, not show up
	// on the next invoice.
	if h.Limits != nil {
		if d := h.Limits.Allow(ctx, req.GetUsageScope()); !d.Allowed {
			return nil, status.Error(codes.ResourceExhausted, d.Reason)
		}
	}

	m := h.modelFor(req)

	startedAt := time.Now()
	out, err := llm.Complete(ctx, h.Client, m, req.GetInstructions(), messagesFrom(req.GetMessages()))
	if err != nil {
		// Recorded even though the call failed: a refused or timed-out
		// completion can still have spent tokens at the provider, and a bill
		// that drops them is wrong in the direction nobody checks. The token
		// counts are whatever the provider managed to report — usually
		// nothing, which is what `measured` is for.
		h.recordUsage(req, m.ID, out, OutcomeFailed, startedAt)
		// The provider's own text is NOT forwarded whole: it renders the
		// deployment URL and, on some failures, fragments of the prompt, and
		// neither belongs in an answer travelling back to whoever asked.
		//
		// But this used to forward NOTHING, while the comment here claimed the
		// detail was in the bundle's logs. Nothing logged it. A consumer
		// bisected a one-field regression with two PAID runs against a live
		// model, because `the model call failed` named neither the field nor
		// the status — the same shape as the `<DOMAIN>` placeholder they
		// reported earlier: the first line an operator sees, saying nothing.
		//
		// So: the whole error goes to the log, where the URL is acceptable,
		// and the provider's own CLASSIFICATION goes to the caller.
		log.Printf("agent: model call failed (model %q): %v", m.ID, err)
		return nil, status.Error(codes.Unavailable, modelCallFailure(err))
	}
	h.recordUsage(req, m.ID, out, OutcomeOK, startedAt)

	return &pb.CompleteResp{
		Text:             out.Text,
		Status:           statusOf(out.Status),
		IncompleteReason: reasonOf(out.IncompleteReason),
		Usage:            usageOf(out.Usage),
	}, nil
}

// modelFor resolves the model from the request, falling back to the
// deployment's defaults for whatever it leaves empty.
func (h *AgentServiceHandler) modelFor(req *pb.CompleteReq) llm.Model {
	m := llm.Model{ID: h.DefaultModel, MaxTokens: h.DefaultMaxTokens}
	spec := req.GetModel()
	if spec == nil {
		return m
	}
	if spec.GetId() != "" {
		m.ID = spec.GetId()
	}
	// Non-zero is the caller speaking, including a NEGATIVE value, which is how
	// "no cap" is said. Only zero falls through to the deployment default.
	if spec.GetMaxTokens() != 0 {
		m.MaxTokens = int64(spec.GetMaxTokens())
	}
	m.Effort = effortName(spec.GetEffort())
	m.JSONObject = req.GetResponseFormat() == pb.ResponseFormat_RESPONSE_FORMAT_JSON_OBJECT
	if spec.Temperature != nil {
		t := spec.GetTemperature()
		m.Temperature = &t
	}
	return m
}

func usageOf(u llm.Usage) *pb.ModelUsage {
	return &pb.ModelUsage{
		Model:             u.Model,
		Measured:          u.Measured,
		InputTokens:       int32(u.InputTokens),
		OutputTokens:      int32(u.OutputTokens),
		TotalTokens:       int32(u.TotalTokens),
		CachedInputTokens: int32(u.CachedInputTokens),
		ReasoningTokens:   int32(u.ReasoningTokens),
	}
}

func messagesFrom(in []*pb.Message) []llm.Message {
	out := make([]llm.Message, 0, len(in))
	for _, msg := range in {
		out = append(out, llm.Message{
			Assistant: msg.GetRole() == pb.Role_ROLE_ASSISTANT,
			Text:      msg.GetText(),
		})
	}
	return out
}

// effortName maps the enum onto the provider's vocabulary. UNSPECIFIED becomes
// the empty string rather than a guess: `lib/llm` then omits the field and the
// provider applies its own default, which is a decision nobody here has to own.
func effortName(e pb.Effort) string {
	switch e {
	case pb.Effort_EFFORT_NONE:
		return "none"
	case pb.Effort_EFFORT_LOW:
		return "low"
	case pb.Effort_EFFORT_MEDIUM:
		return "medium"
	case pb.Effort_EFFORT_HIGH:
		return "high"
	default:
		return ""
	}
}

// statusOf maps the provider's word onto the enum. An unrecognised status
// becomes UNSPECIFIED rather than COMPLETED: a value the provider invents must
// not arrive at the caller wearing the word "finished".
func statusOf(s string) pb.Status {
	switch s {
	case llm.StatusCompleted:
		return pb.Status_STATUS_COMPLETED
	case llm.StatusIncomplete:
		return pb.Status_STATUS_INCOMPLETE
	default:
		return pb.Status_STATUS_UNSPECIFIED
	}
}

func reasonOf(r string) pb.IncompleteReason {
	switch r {
	case llm.ReasonMaxOutputTokens:
		return pb.IncompleteReason_INCOMPLETE_REASON_MAX_OUTPUT_TOKENS
	case llm.ReasonContentFilter:
		return pb.IncompleteReason_INCOMPLETE_REASON_CONTENT_FILTER
	default:
		return pb.IncompleteReason_INCOMPLETE_REASON_UNSPECIFIED
	}
}

// modelCallFailure renders the gRPC message for a failed model call.
//
// Names the provider's status, error type and — the one that matters — the
// REQUEST FIELD it objected to, so a caller reads the cause instead of
// bisecting for it. Falls back to the bare sentence when the failure is not
// the provider's (a timeout, a dial error), where there is no classification
// to quote and the log is the whole story.
func modelCallFailure(err error) string {
	if summary, ok := llm.ProviderFault(err); ok {
		return "agent: the model call failed — the provider said: " + summary +
			" (full detail is in the bundle's log)"
	}
	return "agent: the model call failed (detail is in the bundle's log)"
}
