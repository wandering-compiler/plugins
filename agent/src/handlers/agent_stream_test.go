package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
)

type fakeDecoder struct {
	events []map[string]any
	i      int
}

func (d *fakeDecoder) Next() bool   { d.i++; return d.i <= len(d.events) }
func (d *fakeDecoder) Close() error { return nil }
func (d *fakeDecoder) Err() error   { return nil }
func (d *fakeDecoder) Event() ssestream.Event {
	body, _ := json.Marshal(d.events[d.i-1])
	return ssestream.Event{Type: "event", Data: body}
}

type fakeStreamer struct{ events []map[string]any }

func (f *fakeStreamer) NewStreaming(_ context.Context, _ responses.ResponseNewParams, _ ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	return ssestream.NewStream[responses.ResponseStreamEventUnion](&fakeDecoder{events: f.events}, nil)
}

// recorder captures what the handler put on the wire.
type recorder struct {
	grpc.ServerStream
	sent     []*pb.CompleteEvent
	attempts int
	failAt   int
	sendErr  error
}

func (r *recorder) Context() context.Context { return context.Background() }
func (r *recorder) Send(e *pb.CompleteEvent) error {
	r.attempts++
	if r.failAt > 0 && len(r.sent) >= r.failAt {
		return r.sendErr
	}
	r.sent = append(r.sent, e)
	return nil
}

func streamHandler(events []map[string]any) *AgentServiceHandler {
	return &AgentServiceHandler{
		StreamClient:     &fakeStreamer{events: events},
		DefaultModel:     "gpt-4o",
		DefaultMaxTokens: 100,
	}
}

func delta(text string) map[string]any {
	return map[string]any{"type": "response.output_text.delta", "delta": text}
}

func completedEvent(total int64) map[string]any {
	return map[string]any{"type": "response.completed", "response": map[string]any{
		"status": "completed",
		"usage":  map[string]any{"input_tokens": 4, "output_tokens": 6, "total_tokens": total},
	}}
}

// A stream is deltas followed by exactly one finished event, and the finished
// one is the only place status and usage appear.
func TestStreamSendsDeltasThenExactlyOneFinished(t *testing.T) {
	h := streamHandler([]map[string]any{delta("Ahoj"), delta(" světe"), completedEvent(10)})
	rec := &recorder{}
	if err := h.CompleteStream(&pb.CompleteReq{}, rec); err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if len(rec.sent) != 3 {
		t.Fatalf("sent %d events, want 2 deltas + 1 finished", len(rec.sent))
	}
	var text []string
	finished := 0
	for _, e := range rec.sent {
		if d := e.GetDelta(); d != nil {
			text = append(text, d.GetText())
		}
		if f := e.GetFinished(); f != nil {
			finished++
			if f.GetText() != "Ahoj světe" {
				t.Errorf("finished text = %q, want the whole answer", f.GetText())
			}
			if f.GetStatus() != pb.Status_STATUS_COMPLETED {
				t.Errorf("status = %v", f.GetStatus())
			}
			if !f.GetUsage().GetMeasured() || f.GetUsage().GetTotalTokens() != 10 {
				t.Errorf("usage = %v", f.GetUsage())
			}
			if f.GetStoppedRepeating() {
				t.Error("stopped_repeating set on an ordinary answer")
			}
		}
	}
	if finished != 1 {
		t.Errorf("finished events = %d, want exactly 1", finished)
	}
	if got := strings.Join(text, ""); got != "Ahoj světe" {
		t.Errorf("deltas = %q", got)
	}
}

// The guard fired: the good part is delivered, and the event SAYS the stream
// was cut off. Without that flag a consumer reads an unmeasured row as a free
// call and a truncated answer as a finished one.
func TestStoppedRepeatingIsReportedToTheConsumer(t *testing.T) {
	events := []map[string]any{delta("Cena je 5 900 000 Kč. ")}
	for i := 0; i < 30; i++ {
		events = append(events, delta("nevím, "))
	}
	events = append(events, completedEvent(999))

	rec := &recorder{}
	if err := streamHandler(events).CompleteStream(&pb.CompleteReq{}, rec); err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	last := rec.sent[len(rec.sent)-1].GetFinished()
	if last == nil {
		t.Fatal("no finished event")
	}
	if !last.GetStoppedRepeating() {
		t.Error("the guard fired and the consumer was not told")
	}
	if last.GetUsage().GetMeasured() {
		t.Error("usage claimed measured for a stream that never reached its terminal event")
	}
	if !strings.HasPrefix(last.GetText(), "Cena je") {
		t.Errorf("the good part was lost: %q", last.GetText())
	}
}

// A client that goes away stops the call. The error is the transport's and is
// returned as-is: there is nobody left to tell anything else.
func TestAClientGoingAwayStopsTheCall(t *testing.T) {
	events := []map[string]any{delta("a"), delta("b"), delta("c"), completedEvent(3)}
	gone := errors.New("transport closed")
	rec := &recorder{failAt: 1, sendErr: gone}
	err := streamHandler(events).CompleteStream(&pb.CompleteReq{}, rec)
	if err == nil {
		t.Fatal("the call continued after the client left")
	}
	// ATTEMPTS, not successful sends. Counting the latter passes even when the
	// error is swallowed and the call runs to completion — every further send
	// fails too, so the count never moves and the final send supplies an error
	// that looks like the one being tested for. Attempts is the channel that
	// distinguishes "stopped" from "kept going and failed quietly".
	if rec.attempts != 2 {
		t.Errorf("Send attempted %d times, want 2 (the failing delta, then nothing more)", rec.attempts)
	}
}

// Runaway output is its own code: the caller can distinguish "the model would
// not stop" from "the provider is down", and they need different responses.
func TestRunawayOutputIsItsOwnCode(t *testing.T) {
	var events []map[string]any
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	for i := 0; i < 3000; i++ {
		out := make([]byte, 12)
		for j := range out {
			out[j] = alphabet[(i*7+j*13+j*j)%len(alphabet)]
		}
		events = append(events, delta(string(out)))
	}
	err := streamHandler(events).CompleteStream(&pb.CompleteReq{}, &recorder{})
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", st.Code())
	}
}

// A deployment with no streaming client says so rather than panicking.
func TestNoStreamClientIsUnimplementedNotAPanic(t *testing.T) {
	h := &AgentServiceHandler{DefaultModel: "gpt-4o", DefaultMaxTokens: 10}
	err := h.CompleteStream(&pb.CompleteReq{}, &recorder{})
	st, _ := status.FromError(err)
	if st.Code() != codes.Unimplemented {
		t.Errorf("code = %v, want Unimplemented", st.Code())
	}
}

func TestStreamRefusesAnEmptyRequest(t *testing.T) {
	if err := streamHandler(nil).CompleteStream(nil, &recorder{}); err == nil {
		t.Error("nil request accepted")
	}
}
