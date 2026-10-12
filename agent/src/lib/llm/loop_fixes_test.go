package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type badSchemaTool struct {
	testTool
	schema string
}

func (t *badSchemaTool) Params() json.RawMessage { return json.RawMessage(t.schema) }

type activityTool struct {
	testTool
	activity string
}

func (t *activityTool) Activity() string { return t.activity }

// A params schema that is not a JSON object is refused before the first
// turn; it used to be replaced by {"type":"object"}.
func TestRun_ABadParamsSchemaIsPreflight(t *testing.T) {
	for _, schema := range []string{`{"type":`, `[1]`, `"x"`, `null`} {
		_, err := runWith(t, [][]map[string]any{{delta("never")}},
			[]Tool{&badSchemaTool{testTool: testTool{name: "s"}, schema: schema}}, Limits{}, nil)
		if !IsPreflight(err) {
			t.Errorf("schema %q: err = %v, want preflight", schema, err)
		}
	}
}

// Calls returned on the last turn, which offered no tools, are not run.
func TestRun_TheLastTurnAppliesNothing(t *testing.T) {
	tool := &testTool{name: "write", mutating: true}
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "write", `{}`)},
		{toolCallEvent("c2", "write", `{}`)},
	}, []Tool{tool}, Limits{MaxTurns: 2}, nil)
	if !errors.Is(err, ErrTurnsExhausted) {
		t.Fatalf("err = %v, want turns exhausted", err)
	}
	if len(tool.calls) != 1 {
		t.Errorf("the tool ran %d times; the last turn's call must not run", len(tool.calls))
	}
}

// The answer's text is every delta shown, across turns.
func TestRun_TheAnswerIsEverythingShown(t *testing.T) {
	out, err := runWith(t, [][]map[string]any{
		{delta("Let me look. "), toolCallEvent("c1", "search", `{}`)},
		{delta("Found it."), completed(StatusCompleted, "", 5)},
	}, []Tool{&testTool{name: "search"}}, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "Let me look. Found it." {
		t.Errorf("text = %q, want both turns' deltas", out.Text)
	}
}

// A tool past ToolTimeout fails alone: the model reads it and the run ends
// normally.
func TestRun_ASlowToolFailsAlone(t *testing.T) {
	slow := &testTool{name: "slow", fn: func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", Fatal(ctx.Err()) // what a remote tool answers on its context ending
	}}
	var finished *ToolEvent
	out, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "slow", `{}`)},
		{delta("sorry"), completed(StatusCompleted, "", 5)},
	}, []Tool{slow}, Limits{ToolTimeout: 20 * time.Millisecond}, func(e RunEvent) error {
		if e.ToolFinished != nil {
			finished = e.ToolFinished
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v — a slow tool ended the run", err)
	}
	if out.Text != "sorry" || finished == nil || !errors.Is(finished.Err, ErrToolTimeout) ||
		!strings.Contains(finished.Result, "did not answer") {
		t.Errorf("out = %q, finished = %+v", out.Text, finished)
	}
}

// A mutating tool past its deadline is abandoned, not undone: the model is
// told its outcome is unknown, so it does not simply apply it a second time.
func TestRun_ASlowWriteIsNotSaidToHaveFailed(t *testing.T) {
	slow := &testTool{name: "write", mutating: true, fn: func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", Fatal(ctx.Err())
	}}
	var finished *ToolEvent
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "write", `{}`)},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{slow}, Limits{ToolTimeout: 20 * time.Millisecond}, func(e RunEvent) error {
		if e.ToolFinished != nil {
			finished = e.ToolFinished
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if finished == nil || !errors.Is(finished.Err, ErrToolTimeout) ||
		!strings.Contains(finished.Result, "may still have been applied") {
		t.Errorf("finished = %+v", finished)
	}
}

// A fatal error that is not the deadline stays fatal even when it arrives
// after the deadline: the caller closing its side must still end the run.
func TestRun_AFatalErrorAfterTheDeadlineStillEndsTheRun(t *testing.T) {
	gone := errors.New("caller closed its side")
	tool := &testTool{name: "slow", fn: func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", Fatal(gone)
	}}
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "slow", `{}`)},
		{delta("should not be asked"), completed(StatusCompleted, "", 5)},
	}, []Tool{tool}, Limits{ToolTimeout: 20 * time.Millisecond}, func(RunEvent) error { return nil })
	if !errors.Is(err, gone) {
		t.Fatalf("err = %v; want the fatal error, not a timeout the run survives", err)
	}
}

// The event's id is the one the tool sees, and the activity is the declared
// text.
func TestRun_TheEventAndTheToolShareAnID(t *testing.T) {
	var seenByTool string
	tool := &activityTool{testTool: testTool{name: "search", fn: func(ctx context.Context, _ string) (string, error) {
		seenByTool = CallID(ctx)
		return "ok", nil
	}}, activity: "Searching listings"}
	var started *ToolEvent
	_, err := runWith(t, [][]map[string]any{
		{toolCallEvent("c1", "search", `{}`)},
		{delta("ok"), completed(StatusCompleted, "", 5)},
	}, []Tool{tool}, Limits{}, func(e RunEvent) error {
		if e.ToolStarted != nil {
			started = e.ToolStarted
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if started == nil || started.CallID == "" || started.CallID != seenByTool || started.Activity != "Searching listings" || !started.Declared {
		t.Errorf("started = %+v, tool saw id %q", started, seenByTool)
	}
}
