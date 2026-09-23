package handlers

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
)

// bidi fakes the gRPC stream: the test writes what the caller sends and reads
// what the handler emits.
type bidi struct {
	ctx      context.Context
	incoming chan *pb.RunAgentReq
	recvErr  error

	mu   sync.Mutex
	sent []*pb.RunAgentEvent
	// onSend lets a test answer a ToolCall the moment it appears, which is what
	// a real caller does.
	onSend func(*pb.RunAgentEvent)
	fail   error
}

func (b *bidi) Context() context.Context { return b.ctx }
func (b *bidi) Send(e *pb.RunAgentEvent) error {
	b.mu.Lock()
	if b.fail != nil {
		err := b.fail
		b.mu.Unlock()
		return err
	}
	b.sent = append(b.sent, e)
	f := b.onSend
	b.mu.Unlock()
	if f != nil {
		f(e)
	}
	return nil
}

func (b *bidi) Recv() (*pb.RunAgentReq, error) {
	msg, ok := <-b.incoming
	if !ok {
		if b.recvErr != nil {
			return nil, b.recvErr
		}
		return nil, io.EOF
	}
	return msg, nil
}

func (b *bidi) SetHeader(metadata.MD) error  { return nil }
func (b *bidi) SendHeader(metadata.MD) error { return nil }
func (b *bidi) SetTrailer(metadata.MD)       {}
func (b *bidi) SendMsg(any) error            { return nil }
func (b *bidi) RecvMsg(any) error            { return nil }

func (b *bidi) events() []*pb.RunAgentEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*pb.RunAgentEvent(nil), b.sent...)
}

// multiTurn replays one scripted response per model call.
type multiTurn struct {
	turns [][]map[string]any
	mu    sync.Mutex
	i     int
	// inputs records what each turn was given, which is the only place a test
	// can observe what the tool results actually said to the MODEL.
	inputs [][]responses.ResponseInputItemUnionParam
}

func (m *multiTurn) NewStreaming(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	m.mu.Lock()
	m.inputs = append(m.inputs, body.Input.OfInputItemList)
	idx := m.i
	if idx >= len(m.turns) {
		idx = len(m.turns) - 1
	}
	m.i++
	m.mu.Unlock()
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: m.turns[idx]}, nil)
}

func toolCallTurn(calls ...[3]string) map[string]any {
	var output []any
	for _, c := range calls {
		output = append(output, map[string]any{
			"type": "function_call", "call_id": c[0], "name": c[1], "arguments": c[2],
		})
	}
	return map[string]any{"type": "response.completed", "response": map[string]any{
		"status": "completed", "output": output,
		"usage": map[string]any{"total_tokens": 5},
	}}
}

func startMsg(tools ...*pb.ToolSpec) *pb.RunAgentReq {
	return &pb.RunAgentReq{Msg: &pb.RunAgentReq_Start_{Start: &pb.RunAgentReq_Start{
		Model:    &pb.ModelSpec{Id: "gpt-4o", MaxTokens: 100},
		Messages: []*pb.Message{{Role: pb.Role_ROLE_USER, Text: "q"}},
		Tools:    tools,
	}}}
}

// The whole round trip: the model asks, the plugin asks the caller, the caller
// answers, the model finishes.
func TestRunAgentAsksTheCallerAndFinishes(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"x", "search", `{"q":"byt"}`})},
		{delta("Nasel jsem tri."), completedEvent(9)},
	}}, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 4)}
	var gotArgs string
	b.onSend = func(e *pb.RunAgentEvent) {
		if tc := e.GetToolCall(); tc != nil {
			gotArgs = tc.GetArguments()
			b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_ToolResult_{
				ToolResult: &pb.RunAgentReq_ToolResult{CallId: tc.GetCallId(), Result: "three flats"},
			}}
		}
	}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search", Purpose: "find flats"})

	if err := h.RunAgent(b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	if gotArgs != `{"q":"byt"}` {
		t.Errorf("arguments = %q", gotArgs)
	}
	var finished *pb.Finished
	for _, e := range b.events() {
		if f := e.GetFinished(); f != nil {
			finished = f
		}
	}
	if finished == nil {
		t.Fatal("no Finished event")
	}
	if finished.GetText() != "Nasel jsem tri." {
		t.Errorf("text = %q", finished.GetText())
	}
}

// A caller who disconnects mid-run must not leave the loop waiting for a reply
// that cannot come. Without failAll this test hangs rather than fails — which
// is why it has a deadline of its own.
func TestACallerDisconnectingDoesNotHangTheRun(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"x", "search", `{}`})},
	}}, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2)}
	b.onSend = func(e *pb.RunAgentEvent) {
		if e.GetToolCall() != nil {
			// The caller goes away instead of answering.
			close(b.incoming)
		}
	}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

	done := make(chan error, 1)
	go func() { done <- h.RunAgent(b) }()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the run hung after the caller disconnected")
	}
}

// The first message has to be Start. Anything else is refused rather than
// tolerated: a ToolResult arriving first answers a call nobody made.
func TestTheFirstMessageMustBeStart(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{{completedEvent(1)}}}}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
	b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_ToolResult_{
		ToolResult: &pb.RunAgentReq_ToolResult{CallId: "x", Result: "y"},
	}}
	err := h.RunAgent(b)
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", st.Code())
	}
}

// A caller's failed tool is model-visible information, and the run continues.
func TestAFailedToolResultDoesNotEndTheRun(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"x", "search", `{}`})},
		{delta("Omlouvam se."), completedEvent(5)},
	}}, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 4)}
	b.onSend = func(e *pb.RunAgentEvent) {
		if tc := e.GetToolCall(); tc != nil {
			b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_ToolResult_{
				ToolResult: &pb.RunAgentReq_ToolResult{
					CallId: tc.GetCallId(), Result: "the database is down", Failed: true,
				},
			}}
		}
	}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

	if err := h.RunAgent(b); err != nil {
		t.Fatalf("RunAgent: %v — a failed tool must not end the run", err)
	}
}

// Several read-only calls are outstanding at once, and each answer must reach
// its own waiter. Matching by anything other than call_id crosses them.
func TestParallelCallsAreMatchedByCallID(t *testing.T) {
	st := &multiTurn{turns: [][]map[string]any{
		{toolCallTurn(
			[3]string{"a", "one", `{"n":1}`},
			[3]string{"b", "two", `{"n":2}`},
			[3]string{"c", "three", `{"n":3}`},
		)},
		{delta("hotovo"), completedEvent(5)},
	}}
	h := &AgentServiceHandler{StreamClient: st, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 8)}
	var mu sync.Mutex
	answered := map[string]string{}
	b.onSend = func(e *pb.RunAgentEvent) {
		tc := e.GetToolCall()
		if tc == nil {
			return
		}
		mu.Lock()
		answered[tc.GetCallId()] = tc.GetName()
		mu.Unlock()
		// Answer out of order on purpose.
		go func() {
			time.Sleep(time.Millisecond)
			b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_ToolResult_{
				ToolResult: &pb.RunAgentReq_ToolResult{
					CallId: tc.GetCallId(), Result: "result for " + tc.GetName(),
				},
			}}
		}()
	}
	b.incoming <- startMsg(
		&pb.ToolSpec{Name: "one"}, &pb.ToolSpec{Name: "two"}, &pb.ToolSpec{Name: "three"})

	done := make(chan error, 1)
	go func() { done <- h.RunAgent(b) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RunAgent: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parallel calls did not all get answered — results crossed or a waiter was lost")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(answered) != 3 {
		t.Errorf("asked for %d tools, want 3", len(answered))
	}

	// The count proves nothing about MATCHING. What does is the second turn's
	// input: each tool's answer must sit against the call_id that asked for it.
	// Assert on the channel the consumer reads — and the consumer here is the
	// model.
	st.mu.Lock()
	inputs := st.inputs
	st.mu.Unlock()
	if len(inputs) < 2 {
		t.Fatalf("turns = %d, want 2", len(inputs))
	}
	want := map[string]string{"a": "result for one", "b": "result for two", "c": "result for three"}
	seen := 0
	for _, item := range inputs[1] {
		out := item.OfFunctionCallOutput
		if out == nil {
			continue
		}
		seen++
		if want[out.CallID] != out.Output {
			t.Errorf("call %q got %q, want %q — results were crossed",
				out.CallID, out.Output, want[out.CallID])
		}
	}
	if seen != 3 {
		t.Errorf("the model was given %d tool results, want 3", seen)
	}
}

// A budget refusal gets its own code so the caller can tell "the model went
// wide" from "the provider is down".
func TestBudgetExhaustionIsItsOwnCode(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{toolCallTurn(
			[3]string{"a", "t", `{}`}, [3]string{"b", "t", `{}`}, [3]string{"c", "t", `{}`},
		)},
	}}, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 4)}
	start := startMsg(&pb.ToolSpec{Name: "t"})
	start.GetStart().Limits = &pb.Limits{MaxToolCalls: 2}
	b.incoming <- start

	err := h.RunAgent(b)
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", st.Code())
	}
}

// TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints — three entry points
// take `usage_scope`; two consulted the per-scope limit and RunAgent did not.
//
// It is the one that makes the MOST model calls per invocation, because it
// loops with tool calls, so the cap held on the two cheap paths and not on the
// expensive one. Nothing in the contract said so: one limit table, one scope
// field, and the gap visible only as a missing call. A review of a consumer's
// PR found it; they had never run RunAgent.
func TestRunAgent_AsksTheLimitLikeTheOtherTwoEntryPoints(t *testing.T) {
	denied := &stubLimiter{decision: LimitDecision{Allowed: false, Reason: "scope over its monthly cap"}}
	// A stream client it will never reach: the point is that the limit answers
	// FIRST. Without one the handler refuses with Unimplemented and this test
	// would pass without the limiter ever being consulted.
	h := &AgentServiceHandler{
		Limits:       denied,
		StreamClient: &multiTurn{turns: [][]map[string]any{{completedEvent(1)}}},
	}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2)}
	b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_Start_{Start: &pb.RunAgentReq_Start{
		Model:      &pb.ModelSpec{Id: "gpt-4o", MaxTokens: 100},
		Messages:   []*pb.Message{{Role: pb.Role_ROLE_USER, Text: "q"}},
		UsageScope: "tenant-42",
	}}}
	close(b.incoming)

	err := h.RunAgent(b)
	if err == nil {
		t.Fatal("a run over its scope limit was allowed to start — the cap holds on Complete and CompleteStream and would not hold here")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Errorf("code = %s, want ResourceExhausted (the same answer the other two give)", got)
	}
	if !denied.asked {
		t.Error("the limiter was never consulted")
	}
	if denied.scope != "tenant-42" {
		t.Errorf("asked about scope %q, want the one the Start message named", denied.scope)
	}
}

// stubLimiter records the question and gives a fixed answer.
type stubLimiter struct {
	decision LimitDecision
	asked    bool
	scope    string
}

func (s *stubLimiter) Allow(_ context.Context, scope string) LimitDecision {
	s.asked, s.scope = true, scope
	return s.decision
}
