package llm

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
)

// fakeDecoder replays a fixed list of SSE events, so a streaming test needs no
// network and no provider.
type fakeDecoder struct {
	events []map[string]any
	i      int
	err    error
}

func (d *fakeDecoder) Next() bool {
	if d.err != nil {
		return false
	}
	d.i++
	return d.i <= len(d.events)
}

func (d *fakeDecoder) Event() ssestream.Event {
	body, _ := json.Marshal(d.events[d.i-1])
	return ssestream.Event{Type: "event", Data: body}
}

func (d *fakeDecoder) Close() error { return nil }
func (d *fakeDecoder) Err() error   { return d.err }

type fakeStreamer struct {
	events []map[string]any
	err    error
	got    responses.ResponseNewParams
}

func (f *fakeStreamer) NewStreaming(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	f.got = body
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: f.events, err: f.err}, nil)
}

func delta(text string) map[string]any {
	return map[string]any{"type": eventOutputTextDelta, "delta": text}
}

func completed(status, reason string, total int64) map[string]any {
	res := map[string]any{"status": status}
	if reason != "" {
		res["incomplete_details"] = map[string]any{"reason": reason}
	}
	if total != 0 {
		res["usage"] = map[string]any{"input_tokens": 10, "output_tokens": 20, "total_tokens": total}
	}
	return map[string]any{"type": eventCompleted, "response": res}
}

func model() Model { return Model{ID: "gpt-4o", MaxTokens: 100} }

// The happy path: fragments arrive in order and the whole answer comes back.
func TestStreamForwardsDeltasInOrder(t *testing.T) {
	f := &fakeStreamer{events: []map[string]any{
		delta("Ahoj"), delta(", "), delta("světe"), completed(StatusCompleted, "", 30),
	}}
	var seen []string
	out, err := CompleteStream(context.Background(), f, model(), "", nil, func(s string) error {
		seen = append(seen, s)
		return nil
	})
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if got := strings.Join(seen, "|"); got != "Ahoj|, |světe" {
		t.Errorf("deltas = %q", got)
	}
	if out.Text != "Ahoj, světe" {
		t.Errorf("text = %q", out.Text)
	}
	if !out.Usage.Measured || out.Usage.TotalTokens != 30 {
		t.Errorf("usage = %+v, want measured 30", out.Usage)
	}
}

// A send failure means the client is gone. The call must ABORT rather than keep
// paying the provider for tokens with nowhere to put them.
func TestADeltaSinkErrorAbortsTheCall(t *testing.T) {
	f := &fakeStreamer{events: []map[string]any{
		delta("a"), delta("b"), delta("c"), completed(StatusCompleted, "", 30),
	}}
	boom := errors.New("client gone")
	calls := 0
	_, err := CompleteStream(context.Background(), f, model(), "", nil, func(string) error {
		calls++
		return boom
	})
	if !errors.Is(err, boom) {
		t.Errorf("err = %v, want the sink's", err)
	}
	if calls != 1 {
		t.Errorf("sink called %d times — the call kept going after the client left", calls)
	}
}

// A stream that ends without a terminal event is NOT a finished answer. An
// empty status reads as "nothing to object to", and that licence belongs only
// to the stuck-model guard.
func TestAStreamWithoutATerminalEventIsNotAnAnswer(t *testing.T) {
	f := &fakeStreamer{events: []map[string]any{delta("half an answer")}}
	_, err := CompleteStream(context.Background(), f, model(), "", nil, func(string) error { return nil })
	if !errors.Is(err, ErrNoTerminalEvent) {
		t.Errorf("err = %v, want ErrNoTerminalEvent", err)
	}
}

// The stuck-model guard cuts the stream off and KEEPS what was written: a
// looping answer is usually right up until it starts looping.
func TestTheGuardStopsTheStreamAndKeepsTheGoodPart(t *testing.T) {
	events := []map[string]any{delta("Cena je 5 900 000 Kč. ")}
	for i := 0; i < 30; i++ {
		events = append(events, delta("nevím, "))
	}
	events = append(events, completed(StatusCompleted, "", 999))

	f := &fakeStreamer{events: events}
	out, err := CompleteStream(context.Background(), f, model(), "", nil, func(string) error { return nil })
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if !strings.HasPrefix(out.Text, "Cena je 5 900 000 Kč.") {
		t.Errorf("the good part was thrown away: %q", head(out.Text, 60))
	}
	// Empty status is how a caller tells the guard fired: no terminal event was
	// read, so there is no provider verdict and no usage either.
	if out.Status != "" {
		t.Errorf("status = %q, want empty — the guard returns before the terminal event", out.Status)
	}
	if out.Usage.Measured {
		t.Error("usage reported as measured for a stream that never reached its terminal event")
	}
	// It must stop EARLY. Reading to the end would mean paying for the loop.
	if len(out.Text) > 400 {
		t.Errorf("stopped after %d bytes — too late to be a guard", len(out.Text))
	}
}

// Runaway output is distinct from a truncated answer: the caller may keep a
// truncated one and must not keep this.
func TestRunawayOutputIsRefused(t *testing.T) {
	// Non-repeating chunks, so it is the size cap that fires and not the guard.
	var events []map[string]any
	for i := 0; i < 3000; i++ {
		events = append(events, delta(randomish(i)))
	}
	f := &fakeStreamer{events: events}
	_, err := CompleteStream(context.Background(), f, model(), "", nil, func(string) error { return nil })
	if !errors.Is(err, ErrRunawayOutput) {
		t.Errorf("err = %v, want ErrRunawayOutput", err)
	}
}

// Both call paths build their parameters the same way — a parameter added for
// one must not go missing from the other.
func TestStreamingSharesTheParameterShaping(t *testing.T) {
	f := &fakeStreamer{events: []map[string]any{completed(StatusCompleted, "", 5)}}
	temp := 0.4
	if _, err := CompleteStream(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 700, Temperature: &temp}, "be terse",
		[]Message{{Text: "q"}}, func(string) error { return nil }); err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if f.got.MaxOutputTokens.Value != 700 {
		t.Errorf("MaxOutputTokens = %d", f.got.MaxOutputTokens.Value)
	}
	if f.got.Temperature.Value != 0.4 {
		t.Errorf("Temperature = %v", f.got.Temperature.Value)
	}
	if f.got.Instructions.Value != "be terse" {
		t.Errorf("Instructions = %q", f.got.Instructions.Value)
	}
	if !f.got.Store.Valid() || f.got.Store.Value {
		t.Error("Store must be false on the streaming path too")
	}
}

func TestStreamRefusesWithoutASink(t *testing.T) {
	f := &fakeStreamer{events: []map[string]any{completed(StatusCompleted, "", 5)}}
	if _, err := CompleteStream(context.Background(), f, model(), "", nil, nil); err == nil {
		t.Error("accepted a nil sink")
	}
}

// 24 distinct 12-byte chunks, cycled — long enough that the repetition window
// never sees a short period.
func randomish(i int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, 12)
	for j := range out {
		out[j] = alphabet[(i*7+j*13+j*j)%len(alphabet)]
	}
	return string(out)
}
