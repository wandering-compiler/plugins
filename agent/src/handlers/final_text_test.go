package handlers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/openai/openai-go/v2/responses"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/textfilter"
)

// The answer a model gave, with a leaked Thai token glued to its last
// sentence and a zero-width space inside it — the leak this filter was written for.
const leaked = "Tu jsem v metodice\u200b nenašel.ข้อความ"

const cleaned = "Tu jsem v metodice nenašel."

func activationFilters(t *testing.T) FinalTextFilters {
	t.Helper()
	s, err := textfilter.NewScripts([]string{"Latin"})
	if err != nil {
		t.Fatal(err)
	}
	return FinalTextFilters{Scripts: s, Invisible: true}
}

func textResponse(t *testing.T, text string) *responses.Response {
	t.Helper()
	var r responses.Response
	body, _ := json.Marshal(map[string]any{"status": "completed", "output": []any{map[string]any{
		"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text}},
	}}})
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// Complete returns the cleaned text; a call can opt out (raw) or allow
// another script, and an activation without filters returns the model's text.
func TestFinalText_Complete(t *testing.T) {
	for _, c := range []struct {
		name    string
		filters FinalTextFilters
		opt     *pb.FinalText
		want    string
	}{
		{"the activation's filters", activationFilters(t), nil, cleaned},
		{"raw", activationFilters(t), &pb.FinalText{Raw: true}, leaked},
		{"the call allows Thai", activationFilters(t), &pb.FinalText{AllowedScripts: []string{"Latin", "Thai"}}, "Tu jsem v metodice nenašel.ข้อความ"},
		{"no filters", FinalTextFilters{}, nil, leaked},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := &AgentServiceHandler{Client: &fakeCompleter{res: textResponse(t, leaked)}, DefaultModel: "m", DefaultMaxTokens: 100, FinalText: c.filters}
			resp, err := h.Complete(context.Background(), &pb.CompleteReq{FinalText: c.opt})
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetText() != c.want {
				t.Errorf("text = %q, want %q", resp.GetText(), c.want)
			}
		})
	}
}

// The deltas are the model's, untouched; only Finished is cleaned.
func TestFinalText_StreamFiltersOnlyTheFinishedText(t *testing.T) {
	h := streamHandler([]map[string]any{delta("Tu jsem v metodice\u200b "), delta("nenašel.ข้อความ"), completedEvent(10)})
	h.FinalText = activationFilters(t)
	rec := &recorder{}
	if err := h.CompleteStream(&pb.CompleteReq{}, rec); err != nil {
		t.Fatal(err)
	}
	var deltas string
	var finished *pb.Finished
	for _, e := range rec.sent {
		deltas += e.GetDelta().GetText()
		if f := e.GetFinished(); f != nil {
			finished = f
		}
	}
	if deltas != leaked {
		t.Errorf("deltas = %q, want the model's own %q", deltas, leaked)
	}
	if finished.GetText() != cleaned {
		t.Errorf("finished = %q, want %q", finished.GetText(), cleaned)
	}
}

func TestFinalText_RunAgent(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &multiTurn{turns: [][]map[string]any{
		{delta(leaked), completedEvent(9)},
	}}, DefaultModel: "gpt-4o", DefaultMaxTokens: 100, FinalText: activationFilters(t)}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
	b.incoming <- startMsg()
	close(b.incoming)
	if err := h.RunAgent(b); err != nil {
		t.Fatal(err)
	}
	var finished *pb.Finished
	for _, e := range b.events() {
		if f := e.GetFinished(); f != nil {
			finished = f
		}
	}
	if finished.GetText() != cleaned {
		t.Errorf("finished = %q, want %q", finished.GetText(), cleaned)
	}
}

// A call's options the filters cannot honour are refused before the model is
// called, on every method: nothing is spent on an answer that would be
// refused.
func TestFinalText_RefusedBeforeTheModelIsCalled(t *testing.T) {
	for _, c := range []struct {
		name    string
		filters FinalTextFilters
		opt     *pb.FinalText
		code    codes.Code
	}{
		{"an unknown script", activationFilters(t), &pb.FinalText{AllowedScripts: []string{"Latn"}}, codes.InvalidArgument},
		{"scripts to an activation without the filter", FinalTextFilters{Invisible: true}, &pb.FinalText{AllowedScripts: []string{"Latin"}}, codes.FailedPrecondition},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeCompleter{res: textResponse(t, "x")}
			h := &AgentServiceHandler{Client: f, StreamClient: &fakeStreamer{}, DefaultModel: "m", DefaultMaxTokens: 100, FinalText: c.filters}
			if _, err := h.Complete(context.Background(), &pb.CompleteReq{FinalText: c.opt}); status.Code(err) != c.code {
				t.Errorf("Complete: %v, want %v", err, c.code)
			}
			if f.got.Model != "" {
				t.Error("Complete called the model")
			}
			if err := h.CompleteStream(&pb.CompleteReq{FinalText: c.opt}, &recorder{}); status.Code(err) != c.code {
				t.Errorf("CompleteStream: %v, want %v", err, c.code)
			}
			b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
			start := startMsg()
			start.GetStart().FinalText = c.opt
			b.incoming <- start
			close(b.incoming)
			if err := h.RunAgent(b); status.Code(err) != c.code {
				t.Errorf("RunAgent: %v, want %v", err, c.code)
			}
			if len(b.events()) != 0 {
				t.Errorf("RunAgent sent %d events before refusing", len(b.events()))
			}
		})
	}
}
