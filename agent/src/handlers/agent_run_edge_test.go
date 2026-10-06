package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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
// spent — and each failure has its own code. The row is MEASURED only when
// every turn sent reported its usage: a turn cut off before its terminal event
// leaves the tokens as a floor with measured=false.
func TestRunAgent_FailuresAreCodedAndStillBilled(t *testing.T) {
	var runaway []map[string]any
	for i := 0; i < 3000; i++ {
		runaway = append(runaway, delta(fmt.Sprintf("%012d", i*7919)))
	}
	for _, tc := range []struct {
		name     string
		turns    [][]map[string]any
		limits   *pb.Limits
		code     codes.Code
		tokens   int64
		measured bool
	}{
		{"out of turns", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}},
			&pb.Limits{MaxTurns: 2}, codes.DeadlineExceeded, 22, true},
		{"over the tool budget", [][]map[string]any{{spendTurn([][3]string{{"a", "search", `{}`}, {"b", "search", `{}`}}, 10, 1)}},
			&pb.Limits{MaxToolCalls: 1}, codes.ResourceExhausted, 11, true},
		{"runaway output on turn two", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}, runaway},
			nil, codes.ResourceExhausted, 11, false},
		{"the provider failing on turn two", [][]map[string]any{{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)}, {delta("half")}},
			nil, codes.Unavailable, 11, false},
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
			if got := evs[0].InputTokens + evs[0].OutputTokens; got != tc.tokens || evs[0].Measured != tc.measured {
				t.Errorf("billed %d tokens (measured %v), want %d (measured %v) — the turns that finished were paid for, "+
					"and a turn that never reported makes the total a floor", got, evs[0].Measured, tc.tokens, tc.measured)
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

// runError: each loop ending has its own code. A caller who LEFT never reaches
// it — callerLeft answers that first — so an io.EOF or a context.Canceled here
// is somebody else's (the provider's transport) and is a model failure like
// any other.
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
	for _, notTheCaller := range []error{io.EOF, context.Canceled} {
		if got := status.Code(runError(notTheCaller)); got != codes.Unavailable {
			t.Errorf("runError(%v) = %v, want Unavailable — the caller-left case belongs to callerLeft", notTheCaller, got)
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

// A caller who goes away mid-run gets their own error back — never the
// `Unavailable` "the run failed" that blames the model — no model-failure log
// line is written, and what the run spent before they left is still billed.
//
// Three ways a caller leaves: their side of the stream refuses a Send (a
// hang-up the transport reports as a status), their own deadline passes while
// a tool call waits, and their side of the stream fails a Recv while a tool
// call waits.
func TestRunAgent_ACallerWhoLeftIsNotAModelFailure(t *testing.T) {
	hungUp := status.Error(codes.Canceled, "client hung up")
	recvGone := status.Error(codes.Canceled, "stream reset by the client")
	for _, tc := range []struct {
		name  string
		setup func(b *bidi) (context.CancelFunc, error)
		code  codes.Code
	}{
		{"a send refused", func(b *bidi) (context.CancelFunc, error) {
			b.fail = hungUp
			return func() {}, hungUp
		}, codes.Canceled},
		{"the caller's deadline", func(b *bidi) (context.CancelFunc, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			b.ctx = ctx
			return cancel, nil
		}, codes.DeadlineExceeded},
		{"a recv refused while a tool waits", func(b *bidi) (context.CancelFunc, error) {
			b.recvErr = recvGone
			b.onSend = func(e *pb.RunAgentEvent) {
				if e.GetToolCall() != nil {
					close(b.incoming)
				}
			}
			return func() {}, recvGone
		}, codes.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)
			sink := &syncSink{}
			h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
				{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)},
			}}, Usage: sink}
			b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 8)}
			b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})
			cancel, want := tc.setup(b)
			defer cancel()

			err := runWithin(t, h, b)
			if status.Code(err) != tc.code {
				t.Fatalf("err = %v (%v), want %v — the caller left, the model did not fail", err, status.Code(err), tc.code)
			}
			if want != nil && err != want {
				t.Errorf("err = %v, want the caller's own error as-is", err)
			}
			if strings.Contains(logs.String(), "model run failed") {
				t.Errorf("a caller leaving was logged as a model failure: %q", logs.String())
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Status != OutcomeFailed || evs[0].InputTokens+evs[0].OutputTokens != 11 {
				t.Fatalf("recorded %+v, want one FAILED row billing the 11 tokens spent before the caller left", evs)
			}
			// Measured: the one turn sent reported its usage, and the caller
			// leaving afterwards sent nothing more — so the 11 tokens are the
			// whole bill, not a floor.
			if !evs[0].Measured {
				t.Errorf("recorded %+v as unmeasured — every turn sent reported its usage", evs[0])
			}
		})
	}
}

// A response the provider marked FAILED keeps its code on the RunAgent path,
// as it does on Complete and CompleteStream. RunAgent used to answer it with
// the bare "agent: the run failed", so the one path that loops — and whose
// failures cost the most to reproduce — was the one that did not say why.
func TestRunAgent_AFailedResponseNamesTheProvidersCode(t *testing.T) {
	logs := captureLog(t)
	failed := map[string]any{"type": "response.failed", "response": map[string]any{
		"status": "failed", "model": "gpt-4o-2024-08-06",
		"error": map[string]any{"code": "server_error", "message": "the prompt said: secret"},
		"usage": map[string]any{"input_tokens": 7, "output_tokens": 0, "total_tokens": 7},
	}}
	sink := &syncSink{}
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)},
		{failed},
	}}, Usage: sink}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 8)}
	answerEvery(b, func(tc *pb.ToolCall) []*pb.RunAgentReq {
		return []*pb.RunAgentReq{toolResult(tc.GetCallId(), "r", false)}
	})
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

	err := runWithin(t, h, b)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable", err)
	}
	msg := status.Convert(err).Message()
	if !strings.Contains(msg, "code server_error") {
		t.Errorf("message = %q, want it to name the provider's failure code", msg)
	}
	if strings.Contains(msg, "secret") || strings.Contains(logs.String(), "secret") {
		t.Errorf("the provider's message travelled: %q / %q", msg, logs.String())
	}
	if !strings.Contains(logs.String(), "model run failed") {
		t.Errorf("log = %q, want the model failure logged", logs.String())
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Status != OutcomeFailed || evs[0].InputTokens != 17 || !evs[0].Measured {
		t.Errorf("recorded %+v, want one FAILED measured row of 17 input tokens", evs)
	}
}

// errStreamer fails every model call the way the SDK does when the request
// itself fails: the stream comes back already carrying the error.
type errStreamer struct{ err error }

func (e errStreamer) NewStreaming(context.Context, responses.ResponseNewParams, ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	return ssestream.NewStream[responses.ResponseStreamEventUnion](nil, e.err)
}

// An io.EOF or a context.Canceled from the PROVIDER's side, while the caller
// is still connected, is a model failure: Unavailable, the deployment URL kept
// out of the answer, and a log line.
//
// runError used to return both as-is under "the caller left". callerLeft had
// taken over every real caller-gone case, so that branch fired only for the
// provider — net/http's error for a reused keep-alive connection the provider
// closed is exactly the url.Error below — and the caller got codes.Unknown with
// the deployment URL in the text, and nothing was logged.
func TestRunAgent_AProviderTransportErrorIsAModelFailure(t *testing.T) {
	for name, providerErr := range map[string]error{
		"a keep-alive closed by the provider": &url.Error{
			Op:  "Post",
			URL: "https://acme-ai.example.com/openai/deployments/secret-deploy/responses",
			Err: io.EOF,
		},
		"a cancellation that is not the caller's": fmt.Errorf("provider client: %w", context.Canceled),
	} {
		t.Run(name, func(t *testing.T) {
			logs := captureLog(t)
			sink := &syncSink{}
			h := &AgentServiceHandler{StreamClient: errStreamer{err: providerErr}, Usage: sink}
			b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
			b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

			err := runWithin(t, h, b)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v (%v), want Unavailable — the caller is still here, the provider failed", err, status.Code(err))
			}
			if msg := status.Convert(err).Message(); strings.Contains(msg, "secret-deploy") {
				t.Errorf("the deployment URL reached the caller: %q", msg)
			}
			if !strings.Contains(logs.String(), "model run failed") {
				t.Errorf("log = %q, want the provider failure logged", logs.String())
			}
			if evs := sink.all(); len(evs) != 1 || evs[0].Status != OutcomeFailed {
				t.Errorf("recorded %+v, want one FAILED row", evs)
			}
		})
	}
}

// A caller that half-closes its sending side while a tool result is still owed
// gets FailedPrecondition saying so. It used to get codes.Unknown "EOF" — the
// bare io.EOF from Recv — which named neither the stream nor the tool call.
func TestRunAgent_AHalfCloseWhileAResultIsOwed(t *testing.T) {
	logs := captureLog(t)
	sink := &syncSink{}
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)},
	}}, Usage: sink}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2)}
	b.onSend = func(e *pb.RunAgentEvent) {
		if e.GetToolCall() != nil {
			// CloseSend instead of a ToolResult: Recv returns io.EOF.
			close(b.incoming)
		}
	}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

	err := runWithin(t, h, b)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v (%v), want FailedPrecondition", err, status.Code(err))
	}
	if msg := status.Convert(err).Message(); !strings.Contains(msg, "tool result") {
		t.Errorf("message = %q, want it to say a tool result was still owed", msg)
	}
	if strings.Contains(logs.String(), "model run failed") {
		t.Errorf("a caller's half-close was logged as a model failure: %q", logs.String())
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Status != OutcomeFailed || !evs[0].Measured {
		t.Errorf("recorded %+v, want one FAILED measured row for the turn that was paid for", evs)
	}
}

// A Send that fails on the SERVER's side — a message over the size limit, one
// that would not marshal — is not the caller leaving, and is not returned as if
// it were. callerLeft used to return any first Send error as-is, hiding a
// server-side failure behind a hang-up nobody made, with no log line.
func TestRunAgent_AServerSideSendFailureIsNotTheCallerLeaving(t *testing.T) {
	logs := captureLog(t)
	tooLarge := status.Error(codes.ResourceExhausted, "grpc: trying to send message larger than max (5000000 vs. 4194304)")
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{spendTurn([][3]string{{"x", "search", `{}`}}, 10, 1)},
	}}, Usage: &syncSink{}}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 2), fail: tooLarge}
	b.incoming <- startMsg(&pb.ToolSpec{Name: "search"})

	err := runWithin(t, h, b)
	if err == tooLarge {
		t.Fatalf("a server-side send failure came back as-is, as if the caller had left: %v", err)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("err = %v (%v), want the normal failure path (Unavailable)", err, status.Code(err))
	}
	if !strings.Contains(logs.String(), "model run failed") || !strings.Contains(logs.String(), "larger than max") {
		t.Errorf("log = %q, want the failure logged with its cause", logs.String())
	}
}

// sendGone: which Send failures are the caller leaving.
func TestSendGone(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{"the stream's context ended", done, errors.New("anything"), true},
		{"io.EOF", context.Background(), io.EOF, true},
		{"cancelled", context.Background(), status.Error(codes.Canceled, "x"), true},
		{"past the deadline", context.Background(), status.Error(codes.DeadlineExceeded, "x"), true},
		{"transport closing", context.Background(), status.Error(codes.Unavailable, "transport is closing"), true},
		{"message too large", context.Background(), status.Error(codes.ResourceExhausted, "larger than max"), false},
		{"marshal failure", context.Background(), status.Error(codes.Internal, "grpc: error while marshaling"), false},
		{"a plain error", context.Background(), errors.New("boom"), false},
	} {
		if got := sendGone(tc.ctx, tc.err); got != tc.want {
			t.Errorf("%s: sendGone = %v, want %v", tc.name, got, tc.want)
		}
	}
}
