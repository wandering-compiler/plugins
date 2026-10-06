package handlers

import (
	"testing"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/llm"
)

// Every enum value the contract offers maps onto the provider's vocabulary, and
// UNSPECIFIED maps onto NOTHING — the provider's own default — rather than a
// guess somebody here would have to own.
func TestEffortMapping(t *testing.T) {
	for in, want := range map[pb.Effort]string{
		pb.Effort_EFFORT_UNSPECIFIED: "",
		pb.Effort_EFFORT_NONE:        "none",
		pb.Effort_EFFORT_LOW:         "low",
		pb.Effort_EFFORT_MEDIUM:      "medium",
		pb.Effort_EFFORT_HIGH:        "high",
		pb.Effort(99):                "",
	} {
		if got := effortName(in); got != want {
			t.Errorf("effortName(%v) = %q, want %q", in, got, want)
		}
	}
}

// The way back: only the two words the provider documents become a status; a
// truncation's reason survives; anything else is UNSPECIFIED, never COMPLETED.
func TestStatusAndReasonMapping(t *testing.T) {
	for in, want := range map[string]pb.Status{
		llm.StatusCompleted:  pb.Status_STATUS_COMPLETED,
		llm.StatusIncomplete: pb.Status_STATUS_INCOMPLETE,
		llm.StatusFailed:     pb.Status_STATUS_UNSPECIFIED,
		"":                   pb.Status_STATUS_UNSPECIFIED,
	} {
		if got := statusOf(in); got != want {
			t.Errorf("statusOf(%q) = %v, want %v", in, got, want)
		}
	}
	for in, want := range map[string]pb.IncompleteReason{
		llm.ReasonMaxOutputTokens: pb.IncompleteReason_INCOMPLETE_REASON_MAX_OUTPUT_TOKENS,
		llm.ReasonContentFilter:   pb.IncompleteReason_INCOMPLETE_REASON_CONTENT_FILTER,
		"something_new":           pb.IncompleteReason_INCOMPLETE_REASON_UNSPECIFIED,
	} {
		if got := reasonOf(in); got != want {
			t.Errorf("reasonOf(%q) = %v, want %v", in, got, want)
		}
	}
}

// Zero means "the deployment decides"; any other value — a negative one is how
// "no cap" is said — is the caller's.
func TestModelForMaxTokens(t *testing.T) {
	h := &AgentServiceHandler{DefaultModel: "gpt-4o", DefaultMaxTokens: 256}
	for in, want := range map[int32]int64{0: 256, 10: 10, -1: -1} {
		m := h.modelFor(&pb.CompleteReq{Model: &pb.ModelSpec{MaxTokens: in}})
		if m.MaxTokens != want || m.ID != "gpt-4o" {
			t.Errorf("max_tokens %d → %d / %q, want %d / gpt-4o", in, m.MaxTokens, m.ID, want)
		}
	}
	if m := h.modelFor(&pb.CompleteReq{Model: &pb.ModelSpec{}}); m.Temperature != nil {
		t.Error("an absent temperature became a value — reasoning models refuse any")
	}
	zero := 0.0
	if m := h.modelFor(&pb.CompleteReq{Model: &pb.ModelSpec{Temperature: &zero}}); m.Temperature == nil || *m.Temperature != 0 {
		t.Error("an explicit temperature of 0 was lost — it is not the same as unset")
	}
}

// The usage numbers the caller is shown are exactly the ones recorded.
func TestUsageOf(t *testing.T) {
	got := usageOf(llm.Usage{Model: "m", Measured: true, InputTokens: 1, OutputTokens: 2, TotalTokens: 3,
		CachedInputTokens: 4, ReasoningTokens: 5})
	if got.GetModel() != "m" || !got.GetMeasured() || got.GetInputTokens() != 1 || got.GetOutputTokens() != 2 ||
		got.GetTotalTokens() != 3 || got.GetCachedInputTokens() != 4 || got.GetReasoningTokens() != 5 {
		t.Errorf("usageOf = %v", got)
	}
}
