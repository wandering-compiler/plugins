package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
)

// testTool is a tool whose behaviour a test dictates.
type testTool struct {
	name     string
	mutating bool
	fn       func(ctx context.Context, args string) (string, error)

	mu    sync.Mutex
	calls []string
}

func (t *testTool) Name() string            { return t.name }
func (t *testTool) Purpose() string         { return "purpose of " + t.name }
func (t *testTool) Params() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (t *testTool) Mutating() bool          { return t.mutating }
func (t *testTool) Call(ctx context.Context, args string) (string, error) {
	t.mu.Lock()
	t.calls = append(t.calls, args)
	t.mu.Unlock()
	if t.fn != nil {
		return t.fn(ctx, args)
	}
	return "ok from " + t.name, nil
}

func toolCallEvent(id, name, args string) map[string]any {
	return map[string]any{"type": "response.completed", "response": map[string]any{
		"status": "completed",
		"output": []any{map[string]any{
			"type": "function_call", "call_id": id, "name": name, "arguments": args,
		}},
		"usage": map[string]any{"total_tokens": 5},
	}}
}

// scriptedStreamer replays one scripted response per turn and records what each
// turn was offered.
type scriptedStreamer struct {
	turns [][]map[string]any
	i     int
	seen  []turnRecord
}

type turnRecord struct{ toolCount int }

func (s *scriptedStreamer) NewStreaming(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	s.seen = append(s.seen, turnRecord{toolCount: len(body.Tools)})
	idx := s.i
	if idx >= len(s.turns) {
		idx = len(s.turns) - 1
	}
	s.i++
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: s.turns[idx]}, nil)
}

// multiToolCall builds one response asking for several tools at once. Each
// entry is {call_id, name, arguments}.
func multiToolCall(calls ...[3]string) map[string]any {
	var output []any
	for _, c := range calls {
		output = append(output, map[string]any{
			"type": "function_call", "call_id": c[0], "name": c[1], "arguments": c[2],
		})
	}
	return map[string]any{"type": "response.completed", "response": map[string]any{
		"status": "completed",
		"output": output,
		"usage":  map[string]any{"total_tokens": 5},
	}}
}

func silent(RunEvent) error { return nil }

func runWith(t *testing.T, turns [][]map[string]any, tools []Tool, limits Limits, sink func(RunEvent) error) (*Completion, error) {
	t.Helper()
	if sink == nil {
		sink = silent
	}
	return Run(context.Background(), &scriptedStreamer{turns: turns},
		Model{ID: "gpt-4o", MaxTokens: 100}, "", []Message{{Text: "q"}}, tools, limits, sink)
}

// The loop: the model asks for a tool, the tool runs, the model answers.
func TestLoopCallsAToolThenAnswers(t *testing.T) {
	search := &testTool{name: "search"}
	out, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "search", `{"q":"byt"}`)},
		{delta("Nasel jsem tri."), completed(StatusCompleted, "", 20)},
	}, []Tool{search}, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Text != "Nasel jsem tri." {
		t.Errorf("text = %q", out.Text)
	}
	if len(search.calls) != 1 || search.calls[0] != `{"q":"byt"}` {
		t.Errorf("tool calls = %v", search.calls)
	}
}

// Mutating tools run SERIALLY and FIRST, so a read in the same round never
// observes a half-applied write. This is the ordering guarantee the Mutating
// flag exists for, and losing it is silent.
func TestMutatingToolsRunBeforeReadsAndNotInParallel(t *testing.T) {
	var order []string
	var mu sync.Mutex
	note := func(s string) {
		mu.Lock()
		order = append(order, s)
		mu.Unlock()
	}

	write := &testTool{name: "write", mutating: true, fn: func(context.Context, string) (string, error) {
		note("write:start")
		time.Sleep(20 * time.Millisecond)
		note("write:end")
		return "written", nil
	}}
	read := &testTool{name: "read", fn: func(context.Context, string) (string, error) {
		note("read")
		return "read", nil
	}}

	// The model asks for a read FIRST and a write second — the loop must still
	// run the write first, so declaration order cannot be what saves it.
	_, err := runWith(t, [][]map[string]any{
		{multiToolCall(
			[3]string{"c1", "read", `{}`},
			[3]string{"c2", "write", `{}`},
		)},
		{delta("hotovo"), completed(StatusCompleted, "", 5)},
	}, []Tool{write, read}, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(order) != 3 || order[0] != "write:start" || order[1] != "write:end" || order[2] != "read" {
		t.Errorf("order = %v, want the write to complete before the read starts", order)
	}
}

// The budget bounds the whole run, and it is reserved per ROUND: an over-budget
// round must apply NO writes rather than as many as the allowance covered.
func TestAnOverBudgetRoundAppliesNothing(t *testing.T) {
	write := &testTool{name: "write", mutating: true}
	_, err := runWith(t, [][]map[string]any{
		{multiToolCall(
			[3]string{"c1", "write", `{}`},
			[3]string{"c2", "write", `{}`},
			[3]string{"c3", "write", `{}`},
		)},
	}, []Tool{write}, Limits{MaxToolCalls: 2}, nil)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if len(write.calls) != 0 {
		t.Errorf("the tool ran %d times on an over-budget round — partial mutation", len(write.calls))
	}
}

// A failing tool is INFORMATION: its error goes back to the model as the result
// and the run continues. Failing the run instead would discard everything the
// model had got right.
func TestAToolFailureBecomesAModelVisibleResult(t *testing.T) {
	broken := &testTool{name: "broken", fn: func(context.Context, string) (string, error) {
		return "", errors.New("upstream is down")
	}}
	out, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "broken", `{}`)},
		{delta("Omlouvam se."), completed(StatusCompleted, "", 5)},
	}, []Tool{broken}, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v — a tool failure must not fail the run", err)
	}
	if out.Text != "Omlouvam se." {
		t.Errorf("text = %q", out.Text)
	}
}

// A tool the model invented is answered plainly rather than fatally: it usually
// corrects itself next turn.
func TestAnUnknownToolIsAnsweredNotFailed(t *testing.T) {
	out, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "teleport", `{}`)},
		{delta("To neumim."), completed(StatusCompleted, "", 5)},
	}, nil, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Text != "To neumim." {
		t.Errorf("text = %q", out.Text)
	}
}

// A fatal error from a tool ends the RUN. That is how a tool bridging to a
// caller who has gone away stops the loop buying tokens for nobody.
func TestAFatalToolErrorEndsTheRun(t *testing.T) {
	gone := errors.New("caller gone")
	dead := &testTool{name: "dead", fn: func(context.Context, string) (string, error) {
		return "", Fatal(gone)
	}}
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "dead", `{}`)},
		{delta("nikdy"), completed(StatusCompleted, "", 5)},
	}, []Tool{dead}, Limits{}, nil)
	if !errors.Is(err, gone) {
		t.Errorf("err = %v, want the fatal one", err)
	}
}

// The LAST permitted turn is offered no tools: dispatching on it would apply
// writes whose results the model never gets to read.
func TestTheLastTurnIsOfferedNoTools(t *testing.T) {
	s := &scriptedStreamer{turns: [][]map[string]any{
		{toolCallEvent("c1", "search", `{}`)},
		{delta("odpoved"), completed(StatusCompleted, "", 5)},
	}}
	_, err := Run(context.Background(), s, Model{ID: "gpt-4o", MaxTokens: 100}, "",
		[]Message{{Text: "q"}}, []Tool{&testTool{name: "search"}}, Limits{MaxTurns: 2}, silent)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(s.seen) != 2 {
		t.Fatalf("turns = %d, want 2", len(s.seen))
	}
	if s.seen[0].toolCount == 0 {
		t.Error("the first turn was offered no tools")
	}
	if s.seen[1].toolCount != 0 {
		t.Errorf("the last turn was offered %d tools — a write there is never read", s.seen[1].toolCount)
	}
}

// A model that never stops asking runs out of turns, and the partial state is
// NOT returned as an answer: it is a tool request, not a reply.
func TestRunningOutOfTurnsIsNotAnAnswer(t *testing.T) {
	out, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "search", `{}`)},
	}, []Tool{&testTool{name: "search"}}, Limits{MaxTurns: 3}, nil)
	if !errors.Is(err, ErrTurnsExhausted) {
		t.Errorf("err = %v, want ErrTurnsExhausted", err)
	}
	if out != nil {
		t.Error("a completion was returned alongside the error — a caller would show it")
	}
}

// Two tools under one name make the model's choice depend on map iteration.
func TestDuplicateToolNamesAreRefused(t *testing.T) {
	_, err := runWith(t, [][]map[string]any{{completed(StatusCompleted, "", 5)}},
		[]Tool{&testTool{name: "x"}, &testTool{name: "x"}}, Limits{}, nil)
	if err == nil || !strings.Contains(err.Error(), "two tools named") {
		t.Errorf("err = %v, want a refusal", err)
	}
}

// Events bracket every tool call, so a consumer can show what is happening.
func TestToolEventsBracketEachCall(t *testing.T) {
	var started, finished int
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "search", `{"q":"x"}`)},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{&testTool{name: "search"}}, Limits{}, func(e RunEvent) error {
		if e.ToolStarted != nil {
			started++
			if e.ToolStarted.Arguments != `{"q":"x"}` {
				t.Errorf("arguments = %q", e.ToolStarted.Arguments)
			}
		}
		if e.ToolFinished != nil {
			finished++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if started != 1 || finished != 1 {
		t.Errorf("started=%d finished=%d, want 1 and 1", started, finished)
	}
}
