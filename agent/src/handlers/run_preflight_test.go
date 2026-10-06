package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
)

// a consumer — the third path.
//
// The rule, established on the unary path: a request the LLM layer refuses
// BEFORE the provider is not a failed call. Recording one invents spend, and `Unavailable` sends the
// caller to the provider's status page for what is an invalid argument. It was
// fixed on `Complete` and on the streaming path and missed on `RunAgent` — which
// is the one that makes the MOST model calls per invocation, because it loops.
//
// The same shape as TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints above,
// and found the same way: a consumer reading our source, not a test of ours.
func TestRunAgent_APreflightRefusalIsNotRecordedAsACall(t *testing.T) {
	sink := &capturingSink{}
	// No DefaultMaxTokens: the LLM layer refuses before the provider. The stream
	// client would answer if it were reached, so a usage event here could only
	// come from the call that did not happen.
	h := &AgentServiceHandler{
		StreamClient: &multiTurn{turns: [][]map[string]any{{completedEvent(1)}}},
		Usage:        sink,
		DefaultModel: "gpt-x",
	}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2)}
	b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_Start_{Start: &pb.RunAgentReq_Start{
		UsageScope: "tenant-7",
		Messages:   []*pb.Message{{Role: pb.Role_ROLE_USER, Text: "hi"}},
	}}}

	err := h.RunAgent(b)
	if err == nil {
		t.Fatal("a model with no token budget must be refused")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument — Unavailable reads as a provider outage", got)
	}
	if len(sink.events) != 0 {
		t.Fatalf("a run that never reached the provider recorded %d usage event(s): spend that did not happen",
			len(sink.events))
	}
}
