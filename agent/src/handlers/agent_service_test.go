package handlers

import (
	"context"
	"errors"
	"testing"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/responses"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

type fakeCompleter struct {
	got responses.ResponseNewParams
	res *responses.Response
	err error
}

func (f *fakeCompleter) New(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) (*responses.Response, error) {
	f.got = body
	return f.res, f.err
}

// The deployment's defaults fill in what a request omits, so a project can
// standardise its model without every caller repeating it.
func TestDeploymentDefaultsFillAnEmptyRequest(t *testing.T) {
	f := &fakeCompleter{res: &responses.Response{}}
	h := &AgentServiceHandler{Client: f, DefaultModel: "gpt-4o", DefaultMaxTokens: 256}

	if _, err := h.Complete(context.Background(), &pb.CompleteReq{}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if f.got.Model != "gpt-4o" {
		t.Errorf("model = %q, want the deployment default", f.got.Model)
	}
	if got := f.got.MaxOutputTokens.Value; got != 256 {
		t.Errorf("MaxOutputTokens = %d, want 256", got)
	}
}

// …and a request that states them wins, because the default is a default.
func TestRequestOverridesTheDefaults(t *testing.T) {
	f := &fakeCompleter{res: &responses.Response{}}
	h := &AgentServiceHandler{Client: f, DefaultModel: "gpt-4o", DefaultMaxTokens: 256}

	if _, err := h.Complete(context.Background(), &pb.CompleteReq{
		Model: &pb.ModelSpec{Id: "o3", MaxTokens: 1000, Effort: pb.Effort_EFFORT_HIGH},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if f.got.Model != "o3" {
		t.Errorf("model = %q, want the request's", f.got.Model)
	}
	if got := string(f.got.Reasoning.Effort); got != "high" {
		t.Errorf("effort = %q, want high", got)
	}
}

// A status the provider invents must NOT arrive wearing the word "finished".
// This is the mapping where a permissive default is a silent lie: the caller
// stores a truncated or filtered answer as a complete one.
func TestAnUnknownStatusIsNotReportedAsCompleted(t *testing.T) {
	f := &fakeCompleter{res: &responses.Response{Status: "something_new"}}
	h := &AgentServiceHandler{Client: f, DefaultModel: "gpt-4o", DefaultMaxTokens: 10}

	out, err := h.Complete(context.Background(), &pb.CompleteReq{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.GetStatus() == pb.Status_STATUS_COMPLETED {
		t.Error("an unrecognised provider status was reported as COMPLETED")
	}
	if out.GetStatus() != pb.Status_STATUS_UNSPECIFIED {
		t.Errorf("status = %v, want UNSPECIFIED", out.GetStatus())
	}
}

func TestStatusAndReasonReachTheCaller(t *testing.T) {
	res := &responses.Response{Status: llm.StatusIncomplete}
	res.IncompleteDetails.Reason = llm.ReasonContentFilter
	h := &AgentServiceHandler{Client: &fakeCompleter{res: res}, DefaultModel: "gpt-4o", DefaultMaxTokens: 10}

	out, err := h.Complete(context.Background(), &pb.CompleteReq{})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.GetStatus() != pb.Status_STATUS_INCOMPLETE {
		t.Errorf("status = %v", out.GetStatus())
	}
	if out.GetIncompleteReason() != pb.IncompleteReason_INCOMPLETE_REASON_CONTENT_FILTER {
		t.Errorf("reason = %v, want CONTENT_FILTER", out.GetIncompleteReason())
	}
}

// The provider's own error text renders the deployment URL and can quote the
// prompt. It must not cross the wire to a caller who may be a browser.
func TestProviderErrorTextDoesNotCrossTheWire(t *testing.T) {
	secretish := errors.New("401 from https://acme-prod.openai.azure.com/... key sk-abc123")
	h := &AgentServiceHandler{Client: &fakeCompleter{err: secretish}, DefaultModel: "gpt-4o", DefaultMaxTokens: 10}

	_, err := h.Complete(context.Background(), &pb.CompleteReq{})
	if err == nil {
		t.Fatal("no error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", st.Code())
	}
	for _, leak := range []string{"azure.com", "sk-abc123", "401"} {
		if contains(st.Message(), leak) {
			t.Errorf("the provider's detail %q reached the caller: %q", leak, st.Message())
		}
	}
}

// Roles map both ways. Getting this backwards makes the model read its own
// words as the user's, which changes the answer without failing anything.
func TestRolesSurviveTheTranslation(t *testing.T) {
	f := &fakeCompleter{res: &responses.Response{}}
	h := &AgentServiceHandler{Client: f, DefaultModel: "gpt-4o", DefaultMaxTokens: 10}

	if _, err := h.Complete(context.Background(), &pb.CompleteReq{
		Messages: []*pb.Message{
			{Role: pb.Role_ROLE_USER, Text: "q"},
			{Role: pb.Role_ROLE_ASSISTANT, Text: "a"},
		},
	}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if n := len(f.got.Input.OfInputItemList); n != 2 {
		t.Fatalf("input items = %d, want 2", n)
	}
}

func TestEmptyRequestIsRefused(t *testing.T) {
	h := &AgentServiceHandler{Client: &fakeCompleter{res: &responses.Response{}}}
	if _, err := h.Complete(context.Background(), nil); err == nil {
		t.Error("nil request accepted")
	}
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
