package handlers

// The handlers against an httptest server that speaks the provider's real wire
// format, through the client RegisterPlugin builds (llm.NewClient). What a
// caller gets back — code, message, Finished event — and what the usage sink
// records are asserted together, because they are two views of one call and a
// fake of the client interface can make them agree when the bytes would not.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"github.com/wandering-compiler/plugins/agent/lib/llm"
)

// syncSink is a capturing sink safe for the concurrent paths.
type syncSink struct {
	mu     sync.Mutex
	events []UsageEvent
}

func (s *syncSink) Record(ev UsageEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}
func (s *syncSink) Close(context.Context) {}
func (s *syncSink) all() []UsageEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]UsageEvent(nil), s.events...)
}

type provider struct {
	*httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	bodies []map[string]any
}

func newProvider(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, n int)) *provider {
	t.Helper()
	p := &provider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		p.mu.Lock()
		p.bodies = append(p.bodies, body)
		p.mu.Unlock()
		answer(w, r, int(p.hits.Add(1)))
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *provider) handler(t *testing.T, sink UsageSink, timeout time.Duration) *AgentServiceHandler {
	t.Helper()
	c, err := llm.NewClient(llm.Config{Endpoint: p.URL, APIKey: "k", APIVersion: "2025-04-01-preview", Timeout: timeout})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &AgentServiceHandler{Client: c, StreamClient: c, Usage: sink, DefaultModel: "gpt-4o", DefaultMaxTokens: 100}
}

func providerJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("x-should-retry", "false")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func providerSSE(w http.ResponseWriter, events ...map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, ev := range events {
		b, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev["type"], b)
	}
}

func wireResponse(text, st string) map[string]any {
	return map[string]any{
		"id": "resp_1", "object": "response", "status": st, "model": "gpt-4o-2024-08-06",
		"output": []any{map[string]any{
			"type": "message", "id": "m", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
		}},
		"usage": map[string]any{
			"input_tokens": 50, "output_tokens": 20, "total_tokens": 70,
			"input_tokens_details":  map[string]any{"cached_tokens": 30},
			"output_tokens_details": map[string]any{"reasoning_tokens": 4},
		},
	}
}

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

// The happy path end to end: the answer, and the usage row carrying the
// caller's attribution and what the PROVIDER billed — the dated model id and
// every token kind.
func TestComplete_OverTheWire_RecordsWhatTheProviderBilled(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		providerJSON(w, http.StatusOK, wireResponse("Ahoj", "completed"))
	})
	sink := &syncSink{}
	before := time.Now()
	out, err := p.handler(t, sink, 0).Complete(context.Background(), &pb.CompleteReq{
		UsageScope: "tenant-a", UsageLabels: map[string]string{"run": "r1"},
		Messages: []*pb.Message{{Role: pb.Role_ROLE_USER, Text: "q"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.GetText() != "Ahoj" || out.GetStatus() != pb.Status_STATUS_COMPLETED {
		t.Errorf("answer = %q / %v", out.GetText(), out.GetStatus())
	}
	u := out.GetUsage()
	if u.GetModel() != "gpt-4o-2024-08-06" || !u.GetMeasured() || u.GetTotalTokens() != 70 ||
		u.GetCachedInputTokens() != 30 || u.GetReasoningTokens() != 4 {
		t.Errorf("wire usage = %v", u)
	}
	evs := sink.all()
	if len(evs) != 1 {
		t.Fatalf("recorded %d events", len(evs))
	}
	ev := evs[0]
	if ev.Scope != "tenant-a" || ev.Labels["run"] != "r1" || ev.Status != OutcomeOK {
		t.Errorf("attribution = %+v", ev)
	}
	if ev.Model != "gpt-4o-2024-08-06" {
		t.Errorf("model = %q — the price list keys on what ANSWERED, not on what was asked", ev.Model)
	}
	if !ev.Measured || ev.InputTokens != 50 || ev.OutputTokens != 20 || ev.CachedInputTokens != 30 || ev.ReasoningTokens != 4 {
		t.Errorf("tokens = %+v", ev)
	}
	if ev.StartedAt.Before(before) || ev.Duration < 0 {
		t.Errorf("timing = %v / %v", ev.StartedAt, ev.Duration)
	}
}

// Every way the provider can fail maps to Unavailable, records ONE failed row,
// and tells the caller the provider's classification without its body. A
// timeout and a malformed answer are failures too — with nothing to classify.
func TestComplete_OverTheWire_ProviderFailures(t *testing.T) {
	const prompt = "TENANT-A-PRIVATE-PROMPT"
	errBody := func(code int, typ, param string) func(w http.ResponseWriter, _ *http.Request, _ int) {
		return func(w http.ResponseWriter, _ *http.Request, _ int) {
			providerJSON(w, code, map[string]any{"error": map[string]any{
				"message": "rejected: '" + prompt + "'", "type": typ, "param": param, "code": "x_code",
			}})
		}
	}
	for _, tc := range []struct {
		name     string
		answer   func(w http.ResponseWriter, r *http.Request, n int)
		timeout  time.Duration
		mustSay  []string
		measured bool
	}{
		{name: "400 naming a field", answer: errBody(400, "invalid_request_error", "temperature"),
			mustSay: []string{"HTTP 400", "invalid_request_error", "param temperature"}},
		{name: "401", answer: errBody(401, "authentication_error", ""), mustSay: []string{"HTTP 401"}},
		{name: "429", answer: errBody(429, "rate_limit_error", ""), mustSay: []string{"HTTP 429"}},
		{name: "500", answer: errBody(500, "server_error", ""), mustSay: []string{"HTTP 500"}},
		{name: "malformed body", answer: func(w http.ResponseWriter, _ *http.Request, _ int) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"completed","output":[ "`+prompt)
		}, mustSay: []string{"detail is in the bundle's log"}},
		{name: "timeout", timeout: 100 * time.Millisecond, answer: func(_ http.ResponseWriter, r *http.Request, _ int) {
			<-r.Context().Done()
		}, mustSay: []string{"detail is in the bundle's log"}},
		{name: "a response the provider marked failed", answer: func(w http.ResponseWriter, _ *http.Request, _ int) {
			res := wireResponse("half", "failed")
			res["error"] = map[string]any{"code": "server_error", "message": prompt}
			providerJSON(w, http.StatusOK, res)
		}, mustSay: []string{"response failed", "server_error"}, measured: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLog(t)
			p := newProvider(t, tc.answer)
			sink := &syncSink{}
			_, err := p.handler(t, sink, tc.timeout).Complete(context.Background(), &pb.CompleteReq{
				UsageScope: "tenant-a", Messages: []*pb.Message{{Role: pb.Role_ROLE_USER, Text: prompt}},
			})
			st, _ := status.FromError(err)
			if st.Code() != codes.Unavailable {
				t.Fatalf("code = %v (%v), want Unavailable", st.Code(), err)
			}
			for _, want := range tc.mustSay {
				if !strings.Contains(st.Message(), want) {
					t.Errorf("message %q does not say %q", st.Message(), want)
				}
			}
			for _, leak := range []string{prompt, p.URL, "127.0.0.1"} {
				if strings.Contains(st.Message(), leak) {
					t.Errorf("the caller was told %q: %q", leak, st.Message())
				}
			}
			if strings.Contains(logs.String(), prompt) {
				t.Errorf("the prompt reached the log:\n%s", logs.String())
			}
			if !strings.Contains(logs.String(), "model call failed") {
				t.Errorf("nothing was logged for the operator:\n%s", logs.String())
			}
			evs := sink.all()
			if len(evs) != 1 || evs[0].Status != OutcomeFailed || evs[0].Scope != "tenant-a" {
				t.Fatalf("recorded %+v, want one failed row for tenant-a", evs)
			}
			// A failed response still REPORTS what it spent, and that is what
			// the bill must say; the others reported nothing, and must say
			// that instead of zero.
			if evs[0].Measured != tc.measured {
				t.Errorf("measured = %v, want %v", evs[0].Measured, tc.measured)
			}
			if tc.measured && evs[0].InputTokens != 50 {
				t.Errorf("the failed response's tokens were not recorded: %+v", evs[0])
			}
		})
	}
}

// A request refused by the limit or by preflight never reaches the provider —
// on any of the three entry points — and records nothing.
func TestRefusalsNeverReachTheProvider(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		providerJSON(w, http.StatusOK, wireResponse("x", "completed"))
	})
	jsonNoMention := &pb.CompleteReq{
		ResponseFormat: pb.ResponseFormat_RESPONSE_FORMAT_JSON_OBJECT,
		Messages:       []*pb.Message{{Role: pb.Role_ROLE_USER, Text: "hi"}},
	}
	for _, tc := range []struct {
		name   string
		limits Limiter
		req    *pb.CompleteReq
		code   codes.Code
	}{
		{"over the limit", &denyingLimiter{}, &pb.CompleteReq{UsageScope: "broke"}, codes.ResourceExhausted},
		{"JSON never asked for", nil, jsonNoMention, codes.InvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syncSink{}
			h := p.handler(t, sink, 0)
			h.Limits = tc.limits

			_, err := h.Complete(context.Background(), tc.req)
			if status.Code(err) != tc.code {
				t.Errorf("Complete: %v, want %v", err, tc.code)
			}
			if err := h.CompleteStream(tc.req, &recorder{}); status.Code(err) != tc.code {
				t.Errorf("CompleteStream: %v, want %v", err, tc.code)
			}
			b := &bidi{ctx: context.Background(), incoming: make(chan *pb.RunAgentReq, 1)}
			b.incoming <- &pb.RunAgentReq{Msg: &pb.RunAgentReq_Start_{Start: &pb.RunAgentReq_Start{
				UsageScope: tc.req.GetUsageScope(), Messages: tc.req.GetMessages(),
				Model: &pb.ModelSpec{Id: "gpt-4o", MaxTokens: 100},
			}}}
			if tc.req.GetResponseFormat() == pb.ResponseFormat_RESPONSE_FORMAT_JSON_OBJECT {
				// RunAgent has no response_format; its preflight case is a
				// tool list that cannot be offered.
				b.incoming = make(chan *pb.RunAgentReq, 1)
				b.incoming <- startMsg(&pb.ToolSpec{Name: ""})
			}
			if err := h.RunAgent(b); status.Code(err) != tc.code {
				t.Errorf("RunAgent: %v, want %v", err, tc.code)
			}
			if n := p.hits.Load(); n != 0 {
				t.Errorf("the provider was called %d times for a refused request", n)
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Errorf("a refused request recorded %d usage events: spend that did not happen", len(evs))
			}
		})
	}
}

// A stream the provider ends with `response.failed` is a FAILURE: Unavailable
// naming the provider's code, after the deltas that did arrive — and a failed
// usage row with the tokens it reported. It used to end with a Finished event
// whose status was UNSPECIFIED and a usage row marked OK.
func TestCompleteStream_OverTheWire_AFailedResponseIsAFailure(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		failed := wireResponse("", "failed")
		failed["error"] = map[string]any{"code": "server_error", "message": "x"}
		providerSSE(w,
			map[string]any{"type": "response.output_text.delta", "delta": "Half an"},
			map[string]any{"type": "response.failed", "response": failed})
	})
	sink := &syncSink{}
	rec := &recorder{}
	err := p.handler(t, sink, 0).CompleteStream(&pb.CompleteReq{UsageScope: "tenant-a"}, rec)
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable || !strings.Contains(st.Message(), "server_error") {
		t.Fatalf("err = %v, want Unavailable naming server_error", err)
	}
	for _, e := range rec.sent {
		if e.GetFinished() != nil {
			t.Error("a Finished event was sent for a failed response — the caller would store it as an answer")
		}
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Status != OutcomeFailed || !evs[0].Measured || evs[0].InputTokens != 50 {
		t.Errorf("recorded %+v, want one FAILED row with the 50 input tokens the provider reported", evs)
	}
}

// A stream that dies without a verdict is Unavailable and recorded as failed
// and unmeasured — no tokens are claimed for a stream whose usage never came.
func TestCompleteStream_OverTheWire_ADroppedStreamIsRecordedUnmeasured(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		providerSSE(w, map[string]any{"type": "response.output_text.delta", "delta": "Half"})
	})
	sink := &syncSink{}
	err := p.handler(t, sink, 0).CompleteStream(&pb.CompleteReq{UsageScope: "tenant-a"}, &recorder{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v", err)
	}
	evs := sink.all()
	if len(evs) != 1 || evs[0].Status != OutcomeFailed || evs[0].Measured {
		t.Errorf("recorded %+v, want one failed, unmeasured row", evs)
	}
}

// The client hanging up mid-stream: the call stops, the transport's error comes
// back AS IS, the operator's log does not blame the model, and the call is still
// recorded — the provider was paid for what it produced.
func TestCompleteStream_AClientHangingUpIsNotAModelFailure(t *testing.T) {
	logs := captureLog(t)
	events := []map[string]any{delta("a"), delta("b"), delta("c"), completedEvent(3)}
	gone := status.Error(codes.Canceled, "client went away")
	sink := &syncSink{}
	h := streamHandler(events)
	h.Usage = sink
	err := h.CompleteStream(&pb.CompleteReq{UsageScope: "tenant-a"}, &recorder{failAt: 1, sendErr: gone})
	if err != gone {
		t.Errorf("err = %v, want the transport's own error unchanged", err)
	}
	if strings.Contains(logs.String(), "model stream failed") {
		t.Errorf("a client hanging up was logged as a model failure:\n%s", logs.String())
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Status != OutcomeFailed {
		t.Errorf("recorded %+v, want one failed row", evs)
	}
}

// The stuck-model guard's row is UNKNOWN and unmeasured; a runaway stream's row
// is FAILED. Both are recorded — neither is free.
func TestCompleteStream_GuardAndRunawayAreRecorded(t *testing.T) {
	looping := []map[string]any{delta("Cena je 5 900 000 Kč. ")}
	for i := 0; i < 30; i++ {
		looping = append(looping, delta("nevím, "))
	}
	var runaway []map[string]any
	for i := 0; i < 3000; i++ {
		runaway = append(runaway, delta(fmt.Sprintf("%012d", i*7919)))
	}
	for _, tc := range []struct {
		name    string
		events  []map[string]any
		outcome CallOutcome
	}{
		{"guard", looping, OutcomeUnknown},
		{"runaway", runaway, OutcomeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &syncSink{}
			h := streamHandler(tc.events)
			h.Usage = sink
			_ = h.CompleteStream(&pb.CompleteReq{UsageScope: "tenant-a"}, &recorder{})
			evs := sink.all()
			if len(evs) != 1 || evs[0].Status != tc.outcome || evs[0].Measured {
				t.Errorf("recorded %+v, want one unmeasured row with outcome %v", evs, tc.outcome)
			}
		})
	}
}

// The ModelSpec reaches the wire as the provider expects it, per family.
func TestModelSpecReachesTheWire(t *testing.T) {
	p := newProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		providerJSON(w, http.StatusOK, wireResponse("{}", "completed"))
	})
	h := p.handler(t, &syncSink{}, 0)
	temp := 0.3
	for _, req := range []*pb.CompleteReq{
		{Model: &pb.ModelSpec{Id: "gpt-4o", MaxTokens: 200, Temperature: &temp}, Instructions: "reply with JSON",
			ResponseFormat: pb.ResponseFormat_RESPONSE_FORMAT_JSON_OBJECT},
		{Model: &pb.ModelSpec{Id: "o3-mini", MaxTokens: 400, Effort: pb.Effort_EFFORT_LOW, Temperature: &temp}},
		{Model: &pb.ModelSpec{Id: "gpt-4o", MaxTokens: -1}},
		// No ModelSpec at all — the deployment's defaults — and JSON asked
		// for. The format was read only when a spec was present, so this
		// request went out as free text.
		{Instructions: "reply with a JSON object", ResponseFormat: pb.ResponseFormat_RESPONSE_FORMAT_JSON_OBJECT},
	} {
		if _, err := h.Complete(context.Background(), req); err != nil {
			t.Fatalf("Complete(%v): %v", req.GetModel(), err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sampling, reasoning, uncapped := p.bodies[0], p.bodies[1], p.bodies[2]
	if sampling["temperature"] != 0.3 || sampling["max_output_tokens"] != float64(200) {
		t.Errorf("sampling body = %v", sampling)
	}
	if f, _ := sampling["text"].(map[string]any)["format"].(map[string]any); f["type"] != "json_object" {
		t.Errorf("JSON_OBJECT did not reach the provider: %v", sampling["text"])
	}
	if _, has := reasoning["temperature"]; has {
		t.Errorf("a reasoning model was sent a temperature — that is a 400: %v", reasoning)
	}
	if r, _ := reasoning["reasoning"].(map[string]any); r["effort"] != "low" {
		t.Errorf("effort = %v", reasoning["reasoning"])
	}
	if reasoning["max_output_tokens"] != float64(400+100) {
		t.Errorf("reasoning budget = %v, want 400 plus a quarter of headroom", reasoning["max_output_tokens"])
	}
	if _, has := uncapped["max_output_tokens"]; has {
		t.Errorf("a negative budget still sent a cap: %v", uncapped["max_output_tokens"])
	}
	defaulted := p.bodies[3]
	if f, _ := defaulted["text"].(map[string]any)["format"].(map[string]any); f["type"] != "json_object" {
		t.Errorf("JSON_OBJECT on a request with no ModelSpec did not reach the provider: text = %v", defaulted["text"])
	}
	if defaulted["model"] != "gpt-4o" || defaulted["max_output_tokens"] != float64(100) {
		t.Errorf("the deployment defaults were not applied: %v / %v", defaulted["model"], defaulted["max_output_tokens"])
	}
}
