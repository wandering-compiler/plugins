package handlers

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
)

// byModel answers each request with the events scripted for the model it
// asks for, and records the order models were asked in.
type byModel struct {
	mu     sync.Mutex
	events map[string][]map[string]any
	asked  []string
}

func (b *byModel) NewStreaming(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	b.mu.Lock()
	b.asked = append(b.asked, string(body.Model))
	ev := b.events[string(body.Model)]
	b.mu.Unlock()
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: ev}, nil)
}

func serverError() map[string]any {
	return map[string]any{"type": "response.failed", "response": map[string]any{
		"status": "failed", "error": map[string]any{"code": "server_error", "message": "x"},
	}}
}

func invalidPrompt() map[string]any {
	return map[string]any{"type": "response.failed", "response": map[string]any{
		"status": "failed", "error": map[string]any{"code": "invalid_prompt", "message": "x"},
	}}
}

func withFallback(id string) *pb.ModelSpec {
	return &pb.ModelSpec{Id: "primary", Fallbacks: []*pb.ModelSpec{{Id: id}}}
}

// The primary fails at the provider half-way through its answer: the client
// is told the partial output is void (Restart), the fallback answers, and
// both calls are recorded under their own model.
func TestCompleteStream_FallsBackAfterAProviderFailure(t *testing.T) {
	sink := &syncSink{}
	client := &byModel{events: map[string][]map[string]any{
		"primary": {delta("half "), serverError()},
		"backup":  {delta("whole"), completedEvent(10)},
	}}
	h := &AgentServiceHandler{StreamClient: client, Usage: sink, DefaultMaxTokens: 100}
	rec := &recorder{}
	if err := h.CompleteStream(&pb.CompleteReq{Model: withFallback("backup")}, rec); err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	var kinds []string
	for _, e := range rec.sent {
		switch {
		case e.GetDelta() != nil:
			kinds = append(kinds, "delta:"+e.GetDelta().GetText())
		case e.GetRestart() != nil:
			r := e.GetRestart()
			kinds = append(kinds, "restart:"+r.GetModel())
			if r.GetAttempt() != 1 || !strings.Contains(r.GetReason(), "server_error") {
				t.Errorf("restart = %+v", r)
			}
		case e.GetFinished() != nil:
			kinds = append(kinds, "finished:"+e.GetFinished().GetText())
		}
	}
	if got := strings.Join(kinds, " | "); got != "delta:half  | restart:backup | delta:whole | finished:whole" {
		t.Errorf("events = %s", got)
	}
	rows := sink.all()
	if len(rows) != 2 || rows[0].Status != OutcomeFailed || rows[1].Status != OutcomeOK {
		t.Errorf("usage rows = %+v, want the failed primary and the fallback", rows)
	}
}

// A request the provider REFUSED is not retried elsewhere: the next model
// would refuse it too.
func TestCompleteStream_ARefusalDoesNotFallBack(t *testing.T) {
	client := &byModel{events: map[string][]map[string]any{
		"primary": {invalidPrompt()},
		"backup":  {delta("x"), completedEvent(10)},
	}}
	h := &AgentServiceHandler{StreamClient: client, DefaultMaxTokens: 100}
	if err := h.CompleteStream(&pb.CompleteReq{Model: withFallback("backup")}, &recorder{}); err == nil {
		t.Fatal("a refused request succeeded on the fallback")
	}
	if strings.Join(client.asked, ",") != "primary" {
		t.Errorf("asked %v, want the primary alone", client.asked)
	}
}

// A run falls back for the turn that failed and stays on the fallback: the
// turn's partial text is void, tools answered before are not asked again.
func TestRunAgent_FallsBackAndStaysOnTheFallback(t *testing.T) {
	sink := &syncSink{}
	client := &byModel{events: map[string][]map[string]any{
		"primary": {delta("wrong"), serverError()},
		"backup":  {delta("Done."), completedEvent(10)},
	}}
	h := &AgentServiceHandler{StreamClient: client, Usage: sink, DefaultMaxTokens: 100}
	b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 4)}
	start := startMsg(&pb.ToolSpec{Name: "t"})
	start.GetStart().Model = withFallback("backup")
	b.incoming <- start
	if err := h.RunAgent(b); err != nil {
		t.Fatalf("RunAgent: %v", err)
	}
	var restart *pb.Restart
	var fin *pb.Finished
	for _, e := range b.events() {
		if r := e.GetRestart(); r != nil {
			restart = r
		}
		if f := e.GetFinished(); f != nil {
			fin = f
		}
	}
	if restart == nil || restart.GetModel() != "backup" || restart.GetAttempt() != 1 {
		t.Errorf("restart = %+v", restart)
	}
	if fin == nil || fin.GetText() != "Done." {
		t.Errorf("finished = %+v — the void attempt's text must not be in the answer", fin)
	}
	rows := sink.all()
	if len(rows) != 2 || rows[0].Model != "primary" || rows[1].Model != "backup" {
		t.Errorf("usage rows %+v, want one per attempt under its own model", rows)
	}
}

// A fallback's own fallbacks are refused, not silently dropped.
func TestFallbacksAreOneLevel(t *testing.T) {
	h := &AgentServiceHandler{StreamClient: &byModel{}, DefaultMaxTokens: 100}
	spec := &pb.ModelSpec{Id: "a", Fallbacks: []*pb.ModelSpec{{Id: "b", Fallbacks: []*pb.ModelSpec{{Id: "c"}}}}}
	err := h.CompleteStream(&pb.CompleteReq{Model: spec}, &recorder{})
	if err == nil || !strings.Contains(err.Error(), "fallbacks of its own") {
		t.Fatalf("err = %v", err)
	}
}
