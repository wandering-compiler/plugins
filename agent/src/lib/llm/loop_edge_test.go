package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
)

func usageTurn(calls [][3]string, in, out int64) map[string]any {
	var output []any
	for _, c := range calls {
		output = append(output, map[string]any{
			"type": "function_call", "call_id": c[0], "name": c[1], "arguments": c[2],
		})
	}
	return map[string]any{"type": eventCompleted, "response": map[string]any{
		"status": "completed", "model": "gpt-4o-2024-08-06", "output": output,
		"usage": map[string]any{"input_tokens": in, "output_tokens": out, "total_tokens": in + out},
	}}
}

// A run is billed for every turn it took, not the last one. The turns that ask
// for tools re-send the whole conversation and cost the most input.
func TestRun_UsageIsTheSumOfEveryTurn(t *testing.T) {
	out, err := runWith(t, [][]map[string]any{
		{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
		{usageTurn([][3]string{{"c2", "search", `{}`}}, 200, 6)},
		{delta("hotovo"), usageTurn(nil, 300, 7)},
	}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := Usage{Model: "gpt-4o-2024-08-06", Measured: true, InputTokens: 600, OutputTokens: 18, TotalTokens: 618}
	if out.Usage != want {
		t.Errorf("usage = %+v\n want %+v — a three-turn run billed as its last turn under-bills by two thirds", out.Usage, want)
	}
	if out.Text != "hotovo" || out.Status != StatusCompleted {
		t.Errorf("answer = %q / %q — the answer is still the LAST turn's", out.Text, out.Status)
	}
}

// A run that FAILS still paid for the turns before the failure. The spend rides
// on the error, and no completion is returned beside it.
func TestRun_AFailedRunStillCarriesWhatItSpent(t *testing.T) {
	t.Run("out of turns", func(t *testing.T) {
		out, err := runWith(t, [][]map[string]any{
			{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
		}, []Tool{&testTool{name: "search"}}, Limits{MaxTurns: 3}, nil)
		if !errors.Is(err, ErrTurnsExhausted) || out != nil {
			t.Fatalf("out = %+v, err = %v", out, err)
		}
		spent, ok := SpentBy(err)
		if !ok || spent.InputTokens != 300 || spent.TotalTokens != 315 {
			t.Errorf("SpentBy = %+v, %v — three paid turns, want 300 in / 315 total", spent, ok)
		}
	})
	t.Run("over budget after a paid turn", func(t *testing.T) {
		_, err := runWith(t, [][]map[string]any{
			{usageTurn([][3]string{{"a", "t", `{}`}, {"b", "t", `{}`}}, 40, 2)},
		}, []Tool{&testTool{name: "t"}}, Limits{MaxToolCalls: 1}, nil)
		if !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("err = %v", err)
		}
		if spent, ok := SpentBy(err); !ok || spent.TotalTokens != 42 {
			t.Errorf("SpentBy = %+v, %v — the turn that asked for too many tools was still paid for", spent, ok)
		}
	})
	t.Run("a provider failure on the second turn", func(t *testing.T) {
		failed := map[string]any{"type": eventFailed, "response": map[string]any{
			"status": "failed", "error": map[string]any{"code": "server_error", "message": "x"},
			"usage": map[string]any{"input_tokens": 7, "output_tokens": 0, "total_tokens": 7},
		}}
		_, err := runWith(t, [][]map[string]any{
			{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
			{failed},
		}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
		if !errors.Is(err, ErrResponseFailed) {
			t.Fatalf("err = %v, want ErrResponseFailed", err)
		}
		if spent, ok := SpentBy(err); !ok || spent.TotalTokens != 112 {
			t.Errorf("SpentBy = %+v, %v — want both turns: 105 + 7", spent, ok)
		}
	})
	// A turn that was SENT and never reported its usage makes the whole run
	// unmeasured. Measured used to mean "any turn was measured", so this run
	// was recorded measured=true with only the first turn's tokens — a floor
	// presented as the full bill. The first turn's tokens are still carried:
	// unmeasured-with-tokens is "at least this much".
	t.Run("a dropped stream on the second turn makes the run unmeasured", func(t *testing.T) {
		_, err := runWith(t, [][]map[string]any{
			{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
			{delta("half")},
		}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
		if !errors.Is(err, ErrNoTerminalEvent) {
			t.Fatalf("err = %v, want ErrNoTerminalEvent", err)
		}
		spent, ok := SpentBy(err)
		if !ok || spent.Measured || spent.TotalTokens != 105 || spent.Model != "gpt-4o-2024-08-06" {
			t.Errorf("SpentBy = %+v, %v — want measured=false with the first turn's 105 tokens as a floor", spent, ok)
		}
	})
	t.Run("every turn reported means measured", func(t *testing.T) {
		_, err := runWith(t, [][]map[string]any{
			{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
		}, []Tool{&testTool{name: "search"}}, Limits{MaxTurns: 2}, nil)
		if spent, ok := SpentBy(err); !ok || !spent.Measured || spent.TotalTokens != 210 {
			t.Errorf("SpentBy = %+v, %v — both turns reported, want measured with 210 tokens", spent, ok)
		}
	})
	t.Run("nothing finished means nothing is claimed", func(t *testing.T) {
		_, err := runWith(t, [][]map[string]any{{delta("half")}}, nil, Limits{}, nil)
		if !errors.Is(err, ErrNoTerminalEvent) {
			t.Fatalf("err = %v", err)
		}
		if spent, ok := SpentBy(err); ok {
			t.Errorf("SpentBy = %+v for a run with no finished turn — that is a measurement nobody made", spent)
		}
	})
}

// A tool list the loop refuses is refused BEFORE the provider, so it is a
// preflight refusal: the handler answers InvalidArgument and records nothing.
func TestRun_AMalformedToolListIsPreflight(t *testing.T) {
	for name, tools := range map[string][]Tool{
		"unnamed":   {&testTool{name: ""}},
		"nil":       {nil},
		"duplicate": {&testTool{name: "x"}, &testTool{name: "x"}},
	} {
		t.Run(name, func(t *testing.T) {
			s := &scriptedStreamer{turns: [][]map[string]any{{completed(StatusCompleted, "", 5)}}}
			_, err := Run(context.Background(), s, model(), "", []Message{{Text: "q"}}, tools, Limits{}, silent)
			if !IsPreflight(err) {
				t.Errorf("err = %v, want a preflight refusal — it is decided from the request alone", err)
			}
			if len(s.seen) != 0 {
				t.Errorf("the provider was called %d times for a request refused up front", len(s.seen))
			}
		})
	}
}

// The tool loop validates like the plain path: no model id, no budget, and a
// JSON request whose prompt never asks for JSON are all refused before a call.
func TestRun_SharesThePreflightOfThePlainPath(t *testing.T) {
	for name, m := range map[string]Model{
		"no model":  {MaxTokens: 10},
		"no budget": {ID: "gpt-4o"},
		"JSON never asked for, the assistant's mention not counting": {ID: "gpt-4o", MaxTokens: 10, JSONObject: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := &scriptedStreamer{turns: [][]map[string]any{{completed(StatusCompleted, "", 5)}}}
			_, err := Run(context.Background(), s, m, "", []Message{{Text: "q"}, {Assistant: true, Text: "here is JSON"}}, nil, Limits{}, silent)
			if !IsPreflight(err) {
				t.Errorf("err = %v, want preflight", err)
			}
			if len(s.seen) != 0 {
				t.Error("the provider was reached")
			}
		})
	}
	if _, err := Run(context.Background(), nil, model(), "", nil, nil, Limits{}, silent); err == nil {
		t.Error("a nil client was accepted")
	}
	if _, err := Run(context.Background(), &scriptedStreamer{}, model(), "", nil, nil, Limits{}, nil); err == nil {
		t.Error("a nil sink was accepted")
	}
}

// MaxParallel bounds how many read-only calls run at once — it is what keeps a
// fan-out from hitting the caller's database all at the same instant.
func TestRun_MaxParallelIsHonoured(t *testing.T) {
	var running, peak atomic.Int32
	slow := func(context.Context, string) (string, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		return "ok", nil
	}
	_, err := runWith(t, [][]map[string]any{
		{multiToolCall([3]string{"a", "r", `{}`}, [3]string{"b", "r", `{}`}, [3]string{"c", "r", `{}`}, [3]string{"d", "r", `{}`})},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{&testTool{name: "r", fn: slow}}, Limits{MaxParallel: 1}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if p := peak.Load(); p != 1 {
		t.Errorf("peak concurrency = %d with MaxParallel 1", p)
	}
}

// …and read-only calls DO run in parallel when allowed: four calls that each
// wait for all four to have started finish only if they ran together.
func TestRun_ReadOnlyCallsRunTogether(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(4)
	barrier := func(ctx context.Context, _ string) (string, error) {
		wg.Done()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
			return "ok", nil
		case <-time.After(5 * time.Second):
			return "", Fatal(errors.New("the calls were serialised"))
		}
	}
	_, err := runWith(t, [][]map[string]any{
		{multiToolCall([3]string{"a", "r", `{}`}, [3]string{"b", "r", `{}`}, [3]string{"c", "r", `{}`}, [3]string{"d", "r", `{}`})},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{&testTool{name: "r", fn: barrier}}, Limits{MaxParallel: 4}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// A sink that fails — the watcher is gone — ends the run, rather than letting
// it keep calling tools and buying tokens for nobody.
func TestRun_ASinkFailureEndsTheRun(t *testing.T) {
	gone := errors.New("watcher gone")
	tool := &testTool{name: "search"}
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "search", `{}`)},
		{delta("never"), completed(StatusCompleted, "", 5)},
	}, []Tool{tool}, Limits{}, func(e RunEvent) error {
		if e.ToolStarted != nil {
			return gone
		}
		return nil
	})
	if !errors.Is(err, gone) {
		t.Fatalf("err = %v, want the sink's", err)
	}
	if len(tool.calls) != 0 {
		t.Errorf("the tool ran %d times after its start could not be reported", len(tool.calls))
	}
}

// A cancelled run stops before applying a mutating call.
func TestRun_ACancelledRunAppliesNoWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	write := &testTool{name: "write", mutating: true}
	s := &cancellingStreamer{turn: toolCallEvent("c1", "write", `{}`), cancel: cancel}
	_, err := Run(ctx, s, model(), "", []Message{{Text: "q"}}, []Tool{write}, Limits{}, silent)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want Canceled", err)
	}
	if len(write.calls) != 0 {
		t.Error("a write was applied after the run was cancelled")
	}
}

// cancellingStreamer answers once and cancels the run as the answer is read —
// the caller leaving between the model's request and its dispatch.
type cancellingStreamer struct {
	turn   map[string]any
	cancel func()
}

func (c *cancellingStreamer) NewStreaming(_ context.Context, _ responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	c.cancel()
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: []map[string]any{c.turn}}, nil)
}

// A tool whose arguments never end is runaway output like any other: the cap
// covers arguments, or a model streaming endless JSON walks past it.
func TestRun_RunawayToolArgumentsAreRefused(t *testing.T) {
	chunk := strings.Repeat("x", 1000)
	var events []map[string]any
	for i := 0; i < 25; i++ {
		events = append(events, map[string]any{"type": eventFunctionArgsDelta, "delta": chunk})
	}
	events = append(events, toolCallEvent("c1", "search", `{}`))
	_, err := runWith(t, [][]map[string]any{events}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
	if !errors.Is(err, ErrRunawayOutput) {
		t.Errorf("err = %v, want ErrRunawayOutput", err)
	}
}

// The stuck-model guard on the tool path: the run ends with what was written
// and an EMPTY status, which is how the handler knows to say "stopped
// repeating" — and the run is still billed for the turns before. Billed as a
// FLOOR: the stopped turn never reported its usage, so the run is unmeasured
// while still carrying the first turn's tokens (it used to say measured=true,
// presenting the floor as the whole bill).
func TestRun_TheGuardStopsALoopingAnswer(t *testing.T) {
	looping := []map[string]any{delta("Cena je 5 900 000 Kč. ")}
	for i := 0; i < 30; i++ {
		looping = append(looping, delta("nevím, "))
	}
	out, err := runWith(t, [][]map[string]any{
		{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
		looping,
	}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Status != "" || !strings.HasPrefix(out.Text, "Cena je") {
		t.Errorf("status = %q text = %q", out.Status, head(out.Text, 40))
	}
	if out.Usage.Measured || out.Usage.TotalTokens != 105 {
		t.Errorf("usage = %+v — the first turn was paid for and must not vanish with the second, "+
			"and the unreported second turn makes the total unmeasured", out.Usage)
	}
}

// A model that asks for a tool nobody declared is told so; the run goes on.
// The answer goes back under the model's own call id.
func TestRun_AnInventedToolIsToldSoUnderItsCallID(t *testing.T) {
	var seen []string
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c9", "telepathy", `{}`)},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{&testTool{name: "search"}}, Limits{}, func(e RunEvent) error {
		if e.ToolFinished != nil {
			seen = append(seen, e.ToolFinished.CallID+"="+e.ToolFinished.Result)
			if e.ToolFinished.Err != nil {
				t.Error("an unknown tool was reported as a failed call — it is information, not a failure")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], `c9=There is no tool named "telepathy"`) {
		t.Errorf("results = %q", seen)
	}
}

// What the provider is told about each tool: its purpose as the description,
// and its schema — or an empty object schema when the declared one is not JSON,
// rather than a request the provider rejects outright.
func TestToolParams(t *testing.T) {
	good := &schemaTool{testTool: testTool{name: "good"}, schema: `{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}`}
	bad := &schemaTool{testTool: testTool{name: "bad"}, schema: `{"type":`}
	none := &schemaTool{testTool: testTool{name: "none"}}
	out := toolParams([]Tool{good, bad, none})
	if len(out) != 3 {
		t.Fatalf("declared %d tools", len(out))
	}
	for i, want := range []string{"properties", "", ""} {
		fn := out[i].OfFunction
		if fn == nil {
			t.Fatalf("tool %d is not a function", i)
		}
		if fn.Description.Value != "purpose of "+fn.Name {
			t.Errorf("%s: description = %q", fn.Name, fn.Description.Value)
		}
		params, _ := json.Marshal(fn.Parameters)
		if want != "" && !strings.Contains(string(params), want) {
			t.Errorf("%s: schema %s lost its %s", fn.Name, params, want)
		}
		if want == "" && string(params) != `{"type":"object"}` {
			t.Errorf("%s: schema = %s, want the empty object schema", fn.Name, params)
		}
	}
}

type schemaTool struct {
	testTool
	schema string
}

func (s *schemaTool) Params() json.RawMessage {
	if s.schema == "" {
		return nil
	}
	return json.RawMessage(s.schema)
}

// The defaults a zero Limits stands for, and the budget's edge cases.
func TestLimitDefaultsAndBudgetEdges(t *testing.T) {
	var l Limits
	if l.maxTurns() != defaultMaxTurns || l.maxParallel() != defaultMaxParallel || l.maxToolCalls() != defaultMaxToolCalls {
		t.Errorf("zero Limits = %d/%d/%d", l.maxTurns(), l.maxParallel(), l.maxToolCalls())
	}
	l = Limits{MaxTurns: 2, MaxParallel: 3, MaxToolCalls: 4}
	if l.maxTurns() != 2 || l.maxParallel() != 3 || l.maxToolCalls() != 4 {
		t.Error("stated limits were not used")
	}
	b := &budget{maxToolCalls: 2}
	if err := b.reserve(2); err != nil {
		t.Errorf("exactly the budget was refused: %v", err)
	}
	if err := b.reserve(0); err != nil {
		t.Errorf("an empty round was refused: %v", err)
	}
	if err := b.reserve(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("one over the budget = %v", err)
	}
	if err := (&budget{}).reserve(1000); err != nil {
		t.Errorf("an unbounded budget refused: %v", err)
	}
}

// A decoder error ends the stream with that error, not with a short answer.
func TestStream_ADecoderErrorIsReturned(t *testing.T) {
	broken := errors.New("connection reset")
	f := &fakeStreamer{events: []map[string]any{delta("a")}, err: broken}
	out, err := CompleteStream(context.Background(), f, model(), "", nil, func(string) error { return nil })
	if !errors.Is(err, broken) || out != nil {
		t.Errorf("out = %+v err = %v, want the decoder's error", out, err)
	}
	if _, err := CompleteStream(context.Background(), nil, model(), "", nil, func(string) error { return nil }); err == nil {
		t.Error("a nil client was accepted")
	}
}

// A failed response on the plain path, as a Go value: ErrResponseFailed with
// its spend, and a code-less failure still classified.
func TestComplete_AFailedStatusIsAFailure(t *testing.T) {
	res := &responses.Response{Status: "failed", Model: "gpt-4o"}
	res.Usage.TotalTokens = 9
	_, err := Complete(context.Background(), &fake{res: res}, model(), "", nil)
	if !errors.Is(err, ErrResponseFailed) {
		t.Fatalf("err = %v", err)
	}
	if summary, ok := ProviderFault(err); !ok || summary != "response failed" {
		t.Errorf("summary = %q, %v", summary, ok)
	}
	if spent, ok := SpentBy(err); !ok || spent.TotalTokens != 9 {
		t.Errorf("SpentBy = %+v, %v", spent, ok)
	}
}

// The classification helpers on errors that carry nothing to classify.
func TestProviderFaultWithNothingToSay(t *testing.T) {
	if s, ok := ProviderFault(&openai.Error{}); ok {
		t.Errorf("an empty provider error produced a summary %q", s)
	}
	if got := ProviderLogLine(&openai.Error{}); got != "provider error (no classification; body withheld)" {
		t.Errorf("log line = %q", got)
	}
	if _, ok := SpentBy(errors.New("plain")); ok {
		t.Error("a plain error claimed spend")
	}
	if withSpent(nil, Usage{Measured: true}) != nil {
		t.Error("withSpent invented an error")
	}
}

// Call ids are unique: two outstanding calls sharing one would cross results.
func TestNewCallIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewCallID()
		if id == "" || seen[id] {
			t.Fatalf("call id %q repeated or empty after %d", id, i)
		}
		seen[id] = true
	}
}

// ctxStreamer is scriptedStreamer with the one SDK behaviour this needs: a
// request whose context has already ended fails before anything is sent.
type ctxStreamer struct {
	scriptedStreamer
	calls int
}

func (c *ctxStreamer) NewStreaming(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	c.calls++
	if err := ctx.Err(); err != nil {
		return ssestream.NewStream[responses.ResponseStreamEventUnion](nil, err)
	}
	return c.scriptedStreamer.NewStreaming(ctx, body, opts...)
}

// A turn that never left is not an unreported turn. The run's context ending
// between turns — here, while a tool ran — means the next request is never
// sent; counting it as "sent, unreported" turned a complete bill into a floor
// (measured=false) for a run whose every SENT turn reported its usage.
func TestRun_AContextEndedBeforeATurnIsNotAnUnreportedTurn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &ctxStreamer{scriptedStreamer: scriptedStreamer{turns: [][]map[string]any{
		{usageTurn([][3]string{{"c1", "search", `{}`}}, 100, 5)},
		{delta("never"), usageTurn(nil, 1, 1)},
	}}}
	tool := &testTool{name: "search", fn: func(context.Context, string) (string, error) {
		cancel() // the caller leaves while the tool runs; the tool itself succeeds
		return "ok", nil
	}}
	_, err := Run(ctx, st, Model{ID: "gpt-4o", MaxTokens: 100}, "", []Message{{Text: "q"}},
		[]Tool{tool}, Limits{}, silent)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	spent, ok := SpentBy(err)
	if !ok || !spent.Measured || spent.TotalTokens != 105 {
		t.Errorf("SpentBy = %+v, %v — want measured=true with the one sent turn's 105 tokens: "+
			"the second turn never left, so nothing went unreported", spent, ok)
	}
	if st.calls != 1 {
		t.Errorf("the provider was asked %d times, want 1 — a request whose context had ended was attempted", st.calls)
	}
}

// A run whose context had ended before its FIRST turn sent nothing, so its
// cost is known: zero. It used to come back with no usage attached at all
// (Measured required at least one turn, and withSpent drops an unmeasured,
// model-less total), which the handler recorded as measured=false — "unknown
// cost" for a run that provably cost nothing.
func TestRun_AContextEndedBeforeTheFirstTurnIsMeasuredAtZero(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := &ctxStreamer{scriptedStreamer: scriptedStreamer{turns: [][]map[string]any{
		{delta("never"), usageTurn(nil, 1, 1)},
	}}}
	_, err := Run(ctx, st, Model{ID: "gpt-4o", MaxTokens: 100}, "", []Message{{Text: "q"}},
		nil, Limits{}, silent)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	spent, ok := SpentBy(err)
	if !ok || !spent.Measured || spent.TotalTokens != 0 || spent.InputTokens != 0 || spent.OutputTokens != 0 {
		t.Errorf("SpentBy = %+v, %v — want measured=true at zero tokens: no turn was sent", spent, ok)
	}
	if st.calls != 0 {
		t.Errorf("the provider was asked %d times, want 0", st.calls)
	}
}
