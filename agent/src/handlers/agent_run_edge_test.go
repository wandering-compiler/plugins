package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

func toolResult(id, text string, failed bool) *pb.RunAgentReq {
	return &pb.RunAgentReq{Msg: &pb.RunAgentReq_ToolResult_{
		ToolResult: &pb.RunAgentReq_ToolResult{CallId: id, Result: text, Failed: failed},
	}}
}

// answerEvery replies to each ToolCall with `reply(call)`.
func answerEvery(b *bidi, reply func(*pb.ToolCall) []*pb.RunAgentReq) {
	b.onSend = func(e *pb.RunAgentEvent) {
		if tc := e.GetToolCall(); tc != nil {
			for _, r := range reply(tc) {
				b.incoming <- r
			}
		}
	}
}

func runWithin(t *testing.T, h *AgentServiceHandler, b *bidi) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- h.RunAgent(b) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("RunAgent hung")
		return nil
	}
}

func spendTurn(calls [][3]string, in, out int) map[string]any {
	var output []any
	for _, c := range calls {
		output = append(output, map[string]any{"type": "function_call", "call_id": c[0], "name": c[1], "arguments": c[2]})
	}
	return map[string]any{"type": "response.completed", "response": map[string]any{
		"status": "completed", "model": "gpt-4o-2024-08-06", "output": output,
		"usage": map[string]any{"input_tokens": in, "output_tokens": out, "total_tokens": in + out},
	}}
}

// A run is ONE usage row carrying the spend of EVERY turn, attributed to the
// scope and labels on its Start message.
//
// It carried the last turn's alone: the tool-calling turns — which re-send the
// whole conversation and are the expensive ones — were never billed.
func TestRunAgent_RecordsTheSpendOfEveryTurn(t *testing.T) {
	sink := &syncSink{}
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{spendTurn([][3]string{{"x", "search", `{}`}}, 100, 10)},
		{spendTurn([][3]string{{"y", "search", `{}`}}, 200, 20)},
		{delta("hotovo"), spendTurn(nil, 300, 30)},
	}}, Usage: sink}

	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 8)}
	answerEvery(b, func(tc *pb.ToolCall) []*pb.RunAgentReq {
		return []*pb.RunAgentReq{toolResult(tc.GetCallId(), "r", false)}
	})
	start := startMsg(&pb.ToolSpec{Name: "search"})
	start.GetStart().UsageScope = "tenant-a"
	start.GetStart().UsageLabels = map[string]string{"conversation": "c-1"}
	b.incoming <- start

	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	evs := sink.all()
	if len(evs) != 1 {
		t.Fatalf("recorded %d rows for one run, want 1", len(evs))
	}
	ev := evs[0]
	if ev.InputTokens != 600 || ev.OutputTokens != 60 || !ev.Measured || ev.Status != OutcomeOK {
		t.Errorf("row = %+v, want 600 in / 60 out over three turns", ev)
	}
	if ev.Scope != "tenant-a" || ev.Labels["conversation"] != "c-1" || ev.Model != "gpt-4o-2024-08-06" {
		t.Errorf("attribution = %q %v %q", ev.Scope, ev.Labels, ev.Model)
	}
	var finished *pb.Finished
	for _, e := range b.events() {
		if f := e.GetFinished(); f != nil {
			finished = f
		}
	}
	if finished.GetUsage().GetTotalTokens() != 660 {
		t.Errorf("the caller was told %d tokens, want 660", finished.GetUsage().GetTotalTokens())
	}
}

// A run that fails mid-way is recorded as FAILED with what its finished turns
// spent — and each failure has its own code.
func TestRunAgent_FailuresAreCodedAndStillBilled(t *testing.T) {
	var runaway []map[string]any
	for i := 0; i < 3000; i++ {
		runaway = append(runaway, delta(fmt.Sprintf("%012d", i*7919)))
	}
	for _, tc := range []struct {
		name   string
		turns  [][]map[string]any
		limits *pb.Limits
		code   codes.Code
		tokens int64
	}{
		{"out of turns", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}},
			&pb.Limits{MaxTurns: 2}, codes.DeadlineExceeded, 22},
		{"over the tool budget", [][]map[string]any{{spendTurn([][3]string{{"a", "search", `{}`}, {"b", "search", `{}`}}, 10, 1)}},
			&pb.Limits{MaxToolCalls: 1}, codes.ResourceExhausted, 11},
		{"runaway output on turn two", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}, runaway},
			nil, codes.ResourceExhausted, 11},
		{"the provider failing on turn two", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}, {delta("half")}},
			nil, codes.Unavailable, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syncSink{}
			h := &AgentServiceHandler{StreamClient: &multiTurn{turns: tc.turns}, Usage: sink}
			b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 8)}
			answerEvery(b, func(tc *pb.ToolCall) []*pb.RunAgentReq {
				return []*pb.RunAgentReq{toolResult(tc.GetCallId(), "r", false)}
			})
			start := startMsg(&pb.ToolSpec{Name: "search"})
			start.GetStart().Limits = tc.limits
			start.GetStart().UsageScope = "tenant-a"
			b.incoming <- start

			err := runWithin(t, h, b)
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v, want %v", err, tc.code)
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Status != OutcomeFailed {
				t.Fatalf("recorded %+v, want one FAILED row", evs)
			}
			if got := evs[0].InputTokens + evs[0].OutputTokens; got != tc.tokens || !evs[0].Measured {
				t.Errorf("billed %d tokens (measured %v), want %d — the turns that finished were paid for", got, evs[0].Measured, tc.tokens)
			}
			for _, e := range b.events() {
				if e.GetFinished() != nil {
					t.Error("a failed run sent Finished")
				}
			}
		})
	}
}

// A second ToolResult for the same call — a retried send, a duplicated
// message — must not wedge the run.
//
// The waiter's channel holds one reply and the call stayed registered until
// its waiter dropped it, so a second result arriving before the waiter woke
// blocked the single Recv reader for good: no further result was delivered and
// a disconnect was no longer noticed.
func TestPendingCalls_ADuplicateResultDoesNotBlockTheReader(t *testing.T) {
	p := newPendingCalls()
	wait := p.add("c1")
	done := make(chan struct{})
	go func() {
		p.deliver(&pb.RunAgentReq_ToolResult{CallId: "c1", Result: "first"})
		p.deliver(&pb.RunAgentReq_ToolResult{CallId: "c1", Result: "second"})
		p.deliver(&pb.RunAgentReq_ToolResult{CallId: "nobody", Result: "x"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deliver blocked on a duplicate result — the reader that serves every other call is stuck")
	}
	if r := <-wait; r.result != "first" {
		t.Errorf("waiter got %q, want the FIRST answer", r.result)
	}
	// A reader that survived still serves the next call.
	next := p.add("c2")
	p.deliver(&pb.RunAgentReq_ToolResult{CallId: "c2", Result: "ok"})
	if r := <-next; r.result != "ok" {
		t.Errorf("the next call got %q", r.result)
	}
}

// After failAll, a call added late is released at once rather than waiting.
func TestPendingCalls_ACallAfterTheEndIsReleasedAtOnce(t *testing.T) {
	p := newPendingCalls()
	early := p.add("a")
	p.failAll(io.EOF)
	p.failAll(errors.New("second end")) // the first reason is kept
	if r := <-early; !errors.Is(r.err, io.EOF) {
		t.Errorf("an outstanding call got %v", r.err)
	}
	select {
	case r := <-p.add("late"):
		if !errors.Is(r.err, io.EOF) {
			t.Errorf("a late call got %v, want the first ending", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("a call added after the end waits forever")
	}
}

// End to end: the caller answering every call TWICE, and once for a call id
// nobody asked, still finishes the run with the first answers.
func TestRunAgent_DuplicateAndStrayResultsAreHarmless(t *testing.T) {
	st := &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"a", "one", `{}`}, [3]string{"b", "two", `{}`})},
		{delta("ok"), completedEvent(5)},
	}}
	h := &AgentServiceHandler{StreamClient: st, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 16)}
	answerEvery(b, func(tc *pb.ToolCall) []*pb.RunAgentReq {
		return []*pb.RunAgentReq{
			toolResult(tc.GetCallId(), "first for "+tc.GetName(), false),
			toolResult(tc.GetCallId(), "second for "+tc.GetName(), false),
			toolResult("invented", "stray", false),
		}
	})
	b.incoming <- startMsg(&pb.ToolSpec{Name: "one"}, &pb.ToolSpec{Name: "two"})
	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, item := range st.inputs[1] {
		if out := item.OfFunctionCallOutput; out != nil && !strings.HasPrefix(out.Output, "first for ") {
			t.Errorf("call %s was answered with %q, want the first answer", out.CallID, out.Output)
		}
	}
}

// A caller whose stream breaks while a tool call is being SENT ends the run at
// once — the model is not asked again to retry a tool nobody can answer.
func TestRunAgent_ACallerThatCannotBeAskedEndsTheRun(t *testing.T) {
	st := &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"a", "search", `{}`})},
		{delta("never"), completedEvent(5)},
	}}
	sink := &syncSink{}
	h := &AgentServiceHandler{StreamClient: st, Usage: sink}
	gone := status.Error(codes.Unavailable, "transport is closing")
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2)}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})
	b.onSend = nil
	b.mu.Lock()
	b.fail = gone
	b.mu.Unlock()

	err := runWithin(t, h, b)
	if err == nil {
		t.Fatal("the run went on with nobody to ask")
	}
	st.mu.Lock()
	turns := len(st.inputs)
	st.mu.Unlock()
	if turns != 1 {
		t.Errorf("the model was called %d times — it was asked again for a tool that could not be run", turns)
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Status != OutcomeFailed {
		t.Errorf("recorded %+v, want one failed row", evs)
	}
}

// The caller cancelling while a tool is outstanding ends the run promptly.
func TestRunAgent_CancellationWhileWaitingForATool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st := &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"a", "search", `{}`})},
		{delta("ok"), completedEvent(5)},
	}}
	h := &AgentServiceHandler{StreamClient: st}
	defer func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		// The abandoned wait used to become a tool RESULT ("The tool failed:
		// context canceled"), and the model was asked another turn for a
		// caller who had left.
		if len(st.inputs) != 1 {
			t.Errorf("the model was called %d times after the caller cancelled, want 1", len(st.inputs))
		}
	}()
	b := &bidi{ctx: ctx, incoming: make(chan *pb.RunAgentReq, 2)}
	b.onSend = func(e *pb.RunAgentEvent) {
		if e.GetToolCall() != nil {
			cancel()
		}
	}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})
	if err := runWithin(t, h, b); err == nil {
		t.Error("a cancelled run reported success")
	}
}

// A failed tool's Activity says THAT it failed, never the caller's own error
// text — which may quote anything, and travels to whoever watches the run.
func TestRunAgent_AFailedToolsActivityDoesNotQuoteIt(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{toolCallTurn([3]string{"a", "lookup", `{}`})},
		{delta("sorry"), completedEvent(5)},
	}}}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 4)}
	answerEvery(b, func(tc *pb.ToolCall) []*pb.RunAgentReq {
		return []*pb.RunAgentReq{toolResult(tc.GetCallId(), "row 42 of tenant-b: secret", true)}
	})
	b.incoming <- startMsg(&pb.ToolSpec{Name: "lookup"})
	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	var started, finished int
	for _, e := range b.events() {
		a := e.GetActivity()
		if a == nil {
			continue
		}
		if a.GetText() != "lookup" {
			t.Errorf("activity text = %q, want the tool's name", a.GetText())
		}
		if !a.GetFinished() {
			started++
			continue
		}
		finished++
		if a.GetError() != "the tool failed" {
			t.Errorf("activity error = %q", a.GetError())
		}
		if strings.Contains(a.GetError(), "secret") {
			t.Error("the caller's error text was echoed into the activity")
		}
	}
	if started != 1 || finished != 1 {
		t.Errorf("activities: %d started, %d finished, want 1 and 1", started, finished)
	}
}

// What a ToolSpec turns into: the schema when it is JSON, nothing when it is
// not (rather than a request the provider refuses), and the Mutating flag that
// decides ordering.
func TestRemoteToolTranslation(t *testing.T) {
	for _, tc := range []struct {
		schema string
		want   string
	}{
		{`{"type":"object","properties":{"q":{"type":"string"}}}`, `{"type":"object","properties":{"q":{"type":"string"}}}`},
		{`{"type":`, ""},
		{"", ""},
	} {
		rt := &remoteTool{spec: &pb.ToolSpec{Name: "n", Purpose: "p", ParamsSchema: tc.schema, Mutating: true}}
		if got := string(rt.Params()); got != tc.want {
			t.Errorf("Params(%q) = %q, want %q", tc.schema, got, tc.want)
		}
		if rt.Name() != "n" || rt.Purpose() != "p" || !rt.Mutating() {
			t.Error("name/purpose/mutating lost in translation")
		}
	}

	// Through the loop: the declared schema and purpose reach the provider.
	st := &recordingStreamer{multiTurn: multiTurn{turns: [][]map[string]any{{delta("ok"), completedEvent(1)}}}}
	h := &AgentServiceHandler{StreamClient: st}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search", Purpose: "find flats", ParamsSchema: `{"type":"object","required":["q"]}`})
	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	if len(st.tools) != 1 || len(st.tools[0]) != 1 || st.tools[0][0].OfFunction == nil {
		t.Fatalf("tools offered = %v", st.tools)
	}
	fn := st.tools[0][0].OfFunction
	if fn.Name != "search" || fn.Description.Value != "find flats" {
		t.Errorf("declared %q / %q", fn.Name, fn.Description.Value)
	}
	if req, _ := fn.Parameters["required"].([]any); len(req) != 1 || req[0] != "q" {
		t.Errorf("the caller's schema did not reach the provider: %v", fn.Parameters)
	}
}

// Start.Limits reaches the loop: MaxTurns 1 means the only turn is the last
// one, which is offered no tools.
func TestRunAgent_StartLimitsReachTheLoop(t *testing.T) {
	st := &recordingStreamer{multiTurn: multiTurn{turns: [][]map[string]any{{delta("ok"), completedEvent(1)}}}}
	h := &AgentServiceHandler{StreamClient: st}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
	start := startMsg(&pb.ToolSpec{Name: "search"})
	start.GetStart().Limits = &pb.Limits{MaxTurns: 1, MaxToolCalls: 3, MaxParallel: 2}
	b.incoming <- start
	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	if len(st.toolCounts) != 1 || st.toolCounts[0] != 0 {
		t.Errorf("tools offered per turn = %v, want [0]", st.toolCounts)
	}
	if got := limitsFrom(start.GetStart().GetLimits()); got != (llm.Limits{MaxTurns: 1, MaxToolCalls: 3, MaxParallel: 2}) {
		t.Errorf("limitsFrom = %+v", got)
	}
	if got := limitsFrom(nil); got != (llm.Limits{}) {
		t.Errorf("limitsFrom(nil) = %+v", got)
	}
}

// The repetition guard on the tool path is reported as StoppedRepeating and
// recorded as UNKNOWN.
func TestRunAgent_TheGuardIsReported(t *testing.T) {
	looping := []map[string]any{delta("Cena je 5 900 000 Kč. ")}
	for i := 0; i < 30; i++ {
		looping = append(looping, delta("nevím, "))
	}
	sink := &syncSink{}
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{looping}}, Usage: sink}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
	b.incoming <- startMsg()
	if err := runWithin(t, h, b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	evs := b.events()
	f := evs[len(evs)-1].GetFinished()
	if f == nil || !f.GetStoppedRepeating() {
		t.Fatalf("last event = %v, want Finished with stopped_repeating", evs[len(evs)-1])
	}
	if rows := sink.all(); len(rows) != 1 || rows[0].Status != OutcomeUnknown {
		t.Errorf("recorded %+v, want one UNKNOWN row", rows)
	}
}

// The plumbing refusals: no streaming client, and a stream that fails before
// Start, whose own error comes back unchanged.
func TestRunAgent_PlumbingRefusals(t *testing.T) {
	if err := (&AgentServiceHandler{}).RunAgent(&bidi{ctx: context.Background()}); status.Code(err) != codes.Unimplemented {
		t.Errorf("no stream client: %v", err)
	}
	broken := errors.New("stream reset")
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq), recvErr: broken}
	close(b.incoming)
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{{completedEvent(1)}}}}
	if err := h.RunAgent(b); err != broken {
		t.Errorf("err = %v, want the stream's own", err)
	}
}

// runError: each loop ending has its own code, and a caller who LEFT gets the
// error unchanged — there is nobody to tell anything else.
func TestRunErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code codes.Code
	}{
		{llm.ErrBudgetExhausted, codes.ResourceExhausted},
		{fmt.Errorf("wrapped: %w", llm.ErrTurnsExhausted), codes.DeadlineExceeded},
		{llm.ErrRunawayOutput, codes.ResourceExhausted},
		{errors.New("provider down"), codes.Unavailable},
	} {
		if got := status.Code(runError(tc.err)); got != tc.code {
			t.Errorf("runError(%v) = %v, want %v", tc.err, got, tc.code)
		}
	}
	for _, left := range []error{io.EOF, context.Canceled} {
		if got := runError(left); got != left {
			t.Errorf("runError(%v) = %v, want it unchanged", left, got)
		}
	}
	if msg := status.Convert(runError(errors.New("https://acme.example.com secret"))).Message(); strings.Contains(msg, "secret") {
		t.Errorf("a run failure quoted the underlying error: %q", msg)
	}
}

// recordingStreamer notes what tools each turn was offered.
type recordingStreamer struct {
	multiTurn
	toolCounts []int
	tools      [][]responses.ToolUnionParam
}

func (r *recordingStreamer) NewStreaming(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	r.mu.Lock()
	r.toolCounts = append(r.toolCounts, len(body.Tools))
	r.tools = append(r.tools, body.Tools)
	r.mu.Unlock()
	return r.multiTurn.NewStreaming(ctx, body, opts...)
}
