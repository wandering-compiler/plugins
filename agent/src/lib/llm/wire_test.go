package llm

// Tests against an httptest server speaking the provider's REAL wire format,
// through the client NewClient builds — not a fake of the Completer interface.
//
// A fake answers in Go values and so can never disagree with the SDK about what
// the bytes mean: what status a failed stream carries, where usage lives, how a
// 400 body becomes an *openai.Error, which header the key travels in. Those are
// the places a provider integration actually breaks, and only a server that
// sends the bytes can be wrong about them in the same way the provider can.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const wireKey = "test-key-acme-0001"

// wireRequest is one request as the provider saw it.
type wireRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   map[string]any
}

// fakeProvider is an httptest server that records every request and answers
// with whatever the test's handler writes.
type fakeProvider struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []wireRequest
}

func newFakeProvider(t *testing.T, answer func(w http.ResponseWriter, r *http.Request, n int)) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		p.mu.Lock()
		p.reqs = append(p.reqs, wireRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body,
		})
		n := len(p.reqs)
		p.mu.Unlock()
		answer(w, r, n)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *fakeProvider) requests() []wireRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]wireRequest(nil), p.reqs...)
}

func (p *fakeProvider) client(t *testing.T, timeout time.Duration) Client {
	t.Helper()
	c, err := NewClient(Config{
		Provider: "azure_openai", Endpoint: p.URL, APIKey: wireKey,
		APIVersion: "2025-04-01-preview", Timeout: timeout,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// The SDK retries 408/409/429/5xx on its own; a test that wants to see
	// ONE failure says so the way the provider would.
	w.Header().Set("x-should-retry", "false")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeSSE writes a stream of Responses API events, each as the provider
// frames it: an `event:` line naming the type, then `data:` with the JSON.
func writeSSE(w http.ResponseWriter, events ...map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, ev := range events {
		body, _ := json.Marshal(ev)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev["type"], body)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func answerResponse(text, status string) map[string]any {
	return map[string]any{
		"id": "resp_1", "object": "response", "status": status,
		"model": "gpt-4o-2024-08-06",
		"output": []any{map[string]any{
			"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
		}},
		"usage": map[string]any{
			"input_tokens": 50, "output_tokens": 20, "total_tokens": 70,
			"input_tokens_details":  map[string]any{"cached_tokens": 30},
			"output_tokens_details": map[string]any{"reasoning_tokens": 4},
		},
	}
}

// A misconfigured deployment fails at boot, naming the SETTING — never on the
// first user's request.
func TestNewClient_RefusesAnIncompleteConfig(t *testing.T) {
	ok := Config{Provider: "azure_openai", Endpoint: "https://acme.example.com", APIKey: "k", APIVersion: "v"}
	for _, tc := range []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"another provider", func(c *Config) { c.Provider = "acme-llm" }, "unsupported provider"},
		{"blank endpoint", func(c *Config) { c.Endpoint = "   " }, "no endpoint"},
		{"blank key", func(c *Config) { c.APIKey = " \t" }, "no api key"},
		{"blank api version", func(c *Config) { c.APIVersion = "" }, "no api version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ok
			tc.mut(&cfg)
			c, err := NewClient(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if c != nil {
				t.Error("a client was returned alongside the refusal")
			}
			// The message names the setting, never a `<DOMAIN>_…` placeholder
			// the plugin cannot fill in.
			if strings.Contains(err.Error(), "<") {
				t.Errorf("the refusal carries a placeholder: %q", err)
			}
		})
	}

	// The default provider and a differently-cased one are the same provider.
	for _, provider := range []string{"", " Azure_OpenAI "} {
		cfg := ok
		cfg.Provider = provider
		if _, err := NewClient(cfg); err != nil {
			t.Errorf("provider %q refused: %v", provider, err)
		}
	}
}

// The request the provider receives: the Azure Responses route, the version
// gate, the key in the header Azure reads, and the body the shaping promised.
func TestWire_CompleteSpeaksTheResponsesAPI(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusOK, answerResponse("Ahoj", "completed"))
	})
	temp := 0.25
	out, err := Complete(context.Background(), p.client(t, 0),
		Model{ID: "gpt-4o", MaxTokens: 300, Temperature: &temp}, "be terse",
		[]Message{{Text: "q1"}, {Assistant: true, Text: "a1"}, {Text: "q2"}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	reqs := p.requests()
	if len(reqs) != 1 {
		t.Fatalf("provider saw %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodPost || r.Path != "/openai/responses" {
		t.Errorf("request = %s %s, want POST /openai/responses", r.Method, r.Path)
	}
	if r.Query != "api-version=2025-04-01-preview" {
		t.Errorf("query = %q, want the configured api-version", r.Query)
	}
	if got := r.Header.Get("Api-Key"); got != wireKey {
		t.Errorf("Api-Key header = %q, want the configured key", got)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Errorf("the key also travelled as Authorization %q — Azure reads Api-Key, and a second copy is a second place to leak it", got)
	}
	if r.Body["model"] != "gpt-4o" || r.Body["instructions"] != "be terse" {
		t.Errorf("model/instructions = %v / %v", r.Body["model"], r.Body["instructions"])
	}
	if r.Body["store"] != false {
		t.Errorf("store = %v, want false — nothing is kept provider-side", r.Body["store"])
	}
	if r.Body["max_output_tokens"] != float64(300) || r.Body["temperature"] != 0.25 {
		t.Errorf("max_output_tokens/temperature = %v / %v", r.Body["max_output_tokens"], r.Body["temperature"])
	}
	input, _ := r.Body["input"].([]any)
	var roles []string
	for _, item := range input {
		m, _ := item.(map[string]any)
		roles = append(roles, fmt.Sprint(m["role"]))
	}
	if got := strings.Join(roles, ","); got != "user,assistant,user" {
		t.Errorf("roles on the wire = %s — the model would read its own words as the user's", got)
	}

	if out.Text != "Ahoj" || out.Status != StatusCompleted {
		t.Errorf("completion = %+v", out)
	}
	want := Usage{Model: "gpt-4o-2024-08-06", Measured: true, InputTokens: 50, OutputTokens: 20,
		TotalTokens: 70, CachedInputTokens: 30, ReasoningTokens: 4}
	if out.Usage != want {
		t.Errorf("usage = %+v\n want %+v — every kind is billed at its own rate, and the model is what ANSWERED", out.Usage, want)
	}
}

// A provider 400: the caller-safe summary names the field it objected to, and
// the log line names the URL — and neither carries the body, which here quotes
// the prompt, nor the key.
func TestWire_ProviderErrorKeepsTheClassificationAndDropsTheBody(t *testing.T) {
	const prompt = "MY-PRIVATE-PROMPT-TEXT"
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]any{
			"message": "Invalid value in prompt '" + prompt + "'",
			"type":    "invalid_request_error", "param": "text.format", "code": "unsupported_value",
		}})
	})
	_, err := Complete(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", []Message{{Text: prompt}})
	if err == nil {
		t.Fatal("a 400 came back as an answer")
	}
	if IsPreflight(err) {
		t.Error("a provider refusal was classified as preflight — it DID reach the provider")
	}
	summary, ok := ProviderFault(err)
	if !ok {
		t.Fatalf("no provider classification for a provider 400: %v", err)
	}
	for _, want := range []string{"HTTP 400", "invalid_request_error", "code unsupported_value", "param text.format"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q does not name %q", summary, want)
		}
	}
	logLine := ProviderLogLine(err)
	if !strings.Contains(logLine, p.URL) {
		t.Errorf("log line %q does not name the URL — the one thing an operator bisects with", logLine)
	}
	for _, leak := range []string{prompt, wireKey} {
		if strings.Contains(summary, leak) || strings.Contains(logLine, leak) {
			t.Errorf("%q leaked:\n  summary %q\n  log     %q", leak, summary, logLine)
		}
	}
	if n := len(p.requests()); n != 1 {
		t.Errorf("a non-retryable 400 was sent %d times", n)
	}
}

// A 200 whose body is not a response is a failure, not an empty answer.
func TestWire_AMalformedBodyIsNotAnEmptyAnswer(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status": "completed", "output": [ this is not json`)
	})
	out, err := Complete(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if err == nil {
		t.Fatalf("a malformed body became a completion: %+v", out)
	}
	if out != nil {
		t.Error("a completion was returned beside the error")
	}
}

// A 200 with an empty object is an answer with nothing in it — and it must say
// it was not measured, or a summed bill reads it as a free call.
func TestWire_AnEmptyResponseIsUnmeasured(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	out, err := Complete(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.Usage.Measured || out.Text != "" {
		t.Errorf("completion = %+v, want empty and unmeasured", out)
	}
}

// The provider marks a response FAILED inside a 200. That is not an answer, and
// what it reported spending is still spend.
func TestWire_AFailedResponseIsAnErrorThatStillCarriesItsSpend(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		res := answerResponse("half an ans", StatusFailed)
		res["error"] = map[string]any{"code": "server_error", "message": "the prompt 'SECRET' broke us"}
		writeJSON(w, http.StatusOK, res)
	})
	out, err := Complete(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if !errors.Is(err, ErrResponseFailed) {
		t.Fatalf("err = %v (completion %+v), want ErrResponseFailed", err, out)
	}
	if out != nil {
		t.Error("the failed response's text was returned as a completion")
	}
	spent, ok := SpentBy(err)
	if !ok || !spent.Measured || spent.TotalTokens != 70 {
		t.Errorf("SpentBy = %+v, %v — the provider reported 70 tokens for this failure", spent, ok)
	}
	summary, ok := ProviderFault(err)
	if !ok || !strings.Contains(summary, "server_error") {
		t.Errorf("summary = %q, %v — the provider's code is the classification", summary, ok)
	}
	if strings.Contains(err.Error(), "SECRET") || strings.Contains(summary, "SECRET") {
		t.Error("the provider's message (which can quote the prompt) was carried")
	}
}

// The deployment's timeout bounds a provider that never answers. A hung
// provider must not hold the call, its goroutine and the caller's connection.
func TestWire_AHungProviderIsCutOffByTheTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p := newFakeProvider(t, func(_ http.ResponseWriter, r *http.Request, _ int) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	started := time.Now()
	_, err := Complete(context.Background(), p.client(t, 150*time.Millisecond), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a deadline", err)
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Errorf("took %v — the timeout did not bound the call", took)
	}
}

// request_timeout_seconds is documented as a PER-CALL deadline. The SDK
// applies its request timeout per ATTEMPT and retries 5xx/429 twice, so a
// provider failing slowly held one call for three timeouts plus backoff — on
// the default, six minutes for a deadline that says two.
//
// Each attempt here takes 250ms and fails retryably; the deadline is 400ms. A
// per-call deadline ends the call during the second attempt. A per-attempt one
// lets all three run to their 500.
func TestWire_TheTimeoutBoundsTheWholeCallNotEachRetry(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		t.Run(fmt.Sprintf("streaming=%v", streaming), func(t *testing.T) {
			p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ int) {
				select {
				case <-time.After(250 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After-Ms", "10")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = io.WriteString(w, `{"error":{"message":"busy","type":"server_error"}}`)
			})
			c := p.client(t, 400*time.Millisecond)
			var err error
			if streaming {
				_, err = CompleteStream(context.Background(), c, Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
					func(string) error { return nil })
			} else {
				_, err = Complete(context.Background(), c, Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want the call's deadline", err)
			}
			if n := len(p.requests()); n > 2 {
				t.Errorf("the provider saw %d attempts — the deadline was applied per attempt, not per call", n)
			}
		})
	}
}

// A successful stream is not cut short by the per-call deadline's bookkeeping:
// the deadline is released when the stream is closed, not when it is opened.
func TestWire_AStreamOutlivesItsOpeningUntilClosed(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 3; i++ {
			b, _ := json.Marshal(map[string]any{"type": eventOutputTextDelta, "delta": fmt.Sprint(i)})
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventOutputTextDelta, b)
			w.(http.Flusher).Flush()
			time.Sleep(30 * time.Millisecond)
		}
		b, _ := json.Marshal(map[string]any{"type": eventCompleted, "response": answerResponse("012", StatusCompleted)})
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventCompleted, b)
	})
	out, err := CompleteStream(context.Background(), p.client(t, 5*time.Second), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
		func(string) error { return nil })
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if out.Text != "012" {
		t.Errorf("text = %q", out.Text)
	}
}

// The caller's own cancellation wins over the deployment's (longer) timeout.
func TestWire_TheCallersCancellationStopsTheCall(t *testing.T) {
	arrived := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p := newFakeProvider(t, func(_ http.ResponseWriter, r *http.Request, _ int) {
		close(arrived)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-arrived; cancel() }()
	_, err := Complete(ctx, p.client(t, time.Minute), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the caller's cancellation", err)
	}
}

// The streaming wire: deltas in order, then the terminal event's usage.
func TestWire_StreamDeliversDeltasThenUsage(t *testing.T) {
	final := answerResponse("Ahoj světe", StatusCompleted)
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeSSE(w,
			map[string]any{"type": "response.created", "response": map[string]any{"status": "in_progress"}},
			map[string]any{"type": eventOutputTextDelta, "delta": "Ahoj"},
			map[string]any{"type": eventOutputTextDelta, "delta": " světe"},
			map[string]any{"type": eventCompleted, "response": final},
		)
	})
	var got []string
	out, err := CompleteStream(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
		func(s string) error { got = append(got, s); return nil })
	if err != nil {
		t.Fatalf("CompleteStream: %v", err)
	}
	if strings.Join(got, "|") != "Ahoj| světe" || out.Text != "Ahoj světe" {
		t.Errorf("deltas = %q, text = %q", got, out.Text)
	}
	if !out.Usage.Measured || out.Usage.TotalTokens != 70 || out.Usage.Model != "gpt-4o-2024-08-06" {
		t.Errorf("usage = %+v", out.Usage)
	}
	if r := p.requests()[0]; r.Body["stream"] != true {
		t.Errorf("stream = %v — the provider would answer in one burst", r.Body["stream"])
	}
}

// `response.failed` ends the stream with a verdict, and the verdict is FAILED.
// It used to come back as an ordinary completion: no error, the handler wrote
// an OK usage row, and the caller got a Finished event whose status was
// UNSPECIFIED over the text that arrived before the failure.
func TestWire_AFailedStreamIsAFailure(t *testing.T) {
	failed := answerResponse("", StatusFailed)
	failed["error"] = map[string]any{"code": "server_error", "message": "boom"}
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeSSE(w,
			map[string]any{"type": eventOutputTextDelta, "delta": "Half an"},
			map[string]any{"type": eventFailed, "response": failed},
		)
	})
	out, err := CompleteStream(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
		func(string) error { return nil })
	if !errors.Is(err, ErrResponseFailed) {
		t.Fatalf("err = %v, completion = %+v — a failed response was read as an answer", err, out)
	}
	if spent, ok := SpentBy(err); !ok || spent.TotalTokens != 70 {
		t.Errorf("SpentBy = %+v, %v — the failed response's usage is still spend", spent, ok)
	}
}

// Every way a stream can end WITHOUT a verdict is an error, never a short
// answer: the connection dropping, an error event, an event that is not JSON.
func TestWire_AStreamThatBreaksIsNotAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(w http.ResponseWriter)
	}{
		{"connection drops mid-answer", func(w http.ResponseWriter) {
			writeSSE(w, map[string]any{"type": eventOutputTextDelta, "delta": "Half"})
		}},
		{"an error event", func(w http.ResponseWriter) {
			writeSSE(w,
				map[string]any{"type": eventOutputTextDelta, "delta": "Half"},
				map[string]any{"type": "error", "code": "server_error", "message": "boom"})
		}},
		{"an error object", func(w http.ResponseWriter) {
			writeSSE(w,
				map[string]any{"type": eventOutputTextDelta, "delta": "Half"},
				map[string]any{"type": "response.in_progress", "error": map[string]any{"message": "boom"}})
		}},
		{"an event that is not JSON", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "event: response.output_text.delta\ndata: {not json\n\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, _ int) { tc.write(w) })
			out, err := CompleteStream(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
				func(string) error { return nil })
			if err == nil {
				t.Fatalf("a broken stream came back as an answer: %+v", out)
			}
			if out != nil {
				t.Errorf("a completion was returned beside the error: %+v", out)
			}
		})
	}
}

// A stream that stalls after its first fragment is cut off by the timeout — the
// deadline covers reading the body, not only the response headers.
func TestWire_AStalledStreamIsCutOffByTheTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request, _ int) {
		writeSSE(w, map[string]any{"type": eventOutputTextDelta, "delta": "Ahoj"})
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	started := time.Now()
	_, err := CompleteStream(context.Background(), p.client(t, 200*time.Millisecond), Model{ID: "gpt-4o", MaxTokens: 10}, "", nil,
		func(string) error { return nil })
	if err == nil {
		t.Fatal("a stalled stream returned no error")
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Errorf("took %v — the stall was not bounded", took)
	}
}

// The tool loop over the wire: turn one asks for a tool, turn two is sent its
// result against the same call id and answers. The run is billed for BOTH turns.
func TestWire_RunSendsToolResultsBackAndBillsEveryTurn(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request, n int) {
		usage := map[string]any{"input_tokens": 100 * n, "output_tokens": 10 * n, "total_tokens": 110 * n}
		if n == 1 {
			writeSSE(w, map[string]any{"type": eventCompleted, "response": map[string]any{
				"status": "completed", "model": "gpt-4o-2024-08-06", "usage": usage,
				"output": []any{map[string]any{
					"type": "function_call", "id": "fc_1", "call_id": "call-7", "name": "lookup", "arguments": `{"q":"flat"}`,
				}},
			}})
			return
		}
		writeSSE(w,
			map[string]any{"type": eventOutputTextDelta, "delta": "Three flats."},
			map[string]any{"type": eventCompleted, "response": map[string]any{
				"status": "completed", "model": "gpt-4o-2024-08-06", "usage": usage,
			}})
	})
	lookup := &testTool{name: "lookup", fn: func(_ context.Context, args string) (string, error) {
		return "3 results for " + args, nil
	}}
	out, err := Run(context.Background(), p.client(t, 0), Model{ID: "gpt-4o", MaxTokens: 100}, "",
		[]Message{{Text: "find a flat"}}, []Tool{lookup}, Limits{}, silent)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Text != "Three flats." {
		t.Errorf("text = %q", out.Text)
	}
	// 110 + 220: the tool-calling turn re-sends the conversation and is paid
	// for like any other. Billing only the last turn under-bills every run.
	if out.Usage.TotalTokens != 330 || out.Usage.InputTokens != 300 || out.Usage.OutputTokens != 30 {
		t.Errorf("usage = %+v, want the sum of both turns (300 in, 30 out, 330 total)", out.Usage)
	}

	reqs := p.requests()
	if len(reqs) != 2 {
		t.Fatalf("provider saw %d requests, want 2", len(reqs))
	}
	tools, _ := reqs[0].Body["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("turn one declared %d tools, want 1", len(tools))
	}
	decl, _ := tools[0].(map[string]any)
	if decl["name"] != "lookup" || decl["description"] != "purpose of lookup" || decl["type"] != "function" {
		t.Errorf("tool declaration = %v", decl)
	}
	if reqs[0].Body["tool_choice"] != "auto" {
		t.Errorf("tool_choice = %v", reqs[0].Body["tool_choice"])
	}
	var gotOutput, gotCall bool
	for _, item := range reqs[1].Body["input"].([]any) {
		m, _ := item.(map[string]any)
		switch m["type"] {
		case "function_call":
			gotCall = m["call_id"] == "call-7" && m["name"] == "lookup"
		case "function_call_output":
			gotOutput = m["call_id"] == "call-7" && m["output"] == `3 results for {"q":"flat"}`
		}
	}
	if !gotCall || !gotOutput {
		t.Errorf("turn two's input lacks the call (%v) or its result under the same id (%v): %v",
			gotCall, gotOutput, reqs[1].Body["input"])
	}
}
