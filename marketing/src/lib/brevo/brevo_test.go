package brevo

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type call struct {
	method, path, query, key string
	body                     map[string]any
}

// stub answers each request with the next of answers (the last repeats) and
// records what it was sent.
type stub struct {
	*httptest.Server
	mu      sync.Mutex
	calls   []call
	answers []func(w http.ResponseWriter)
}

func newStub(t *testing.T, answers ...func(w http.ResponseWriter)) *stub {
	t.Helper()
	s := &stub{answers: answers}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		s.mu.Lock()
		s.calls = append(s.calls, call{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("api-key"), body})
		i := len(s.calls) - 1
		if i >= len(s.answers) {
			i = len(s.answers) - 1
		}
		answer := s.answers[i]
		s.mu.Unlock()
		answer(w)
	}))
	t.Cleanup(s.Close)
	return s
}

func status(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

func client(t *testing.T, s *stub) (*Client, *[]time.Duration) {
	t.Helper()
	c, err := New(s.URL, "k-1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	var slept []time.Duration
	c.sleep = func(ctx context.Context, d time.Duration) error {
		if d > 0 {
			slept = append(slept, d)
		}
		return ctx.Err()
	}
	return c, &slept
}

func TestSendEvents_PostsTheBatchWithTheKey(t *testing.T) {
	s := newStub(t, status(http.StatusNoContent, ""))
	c, _ := client(t, s)
	got, err := c.SendEvents(context.Background(), []Event{{
		EventName:       "TasksBusiness_CreateTask",
		EventDate:       "2026-10-19T09:00:00Z",
		Identifiers:     Identifiers{ExtID: "u-1"},
		EventProperties: map[string]any{"w17_status": 200},
	}})
	if err != nil || len(got.Failed) != 0 {
		t.Fatalf("SendEvents = %+v, %v", got, err)
	}
	if len(s.calls) != 1 {
		t.Fatalf("%d calls", len(s.calls))
	}
	c0 := s.calls[0]
	if c0.method != http.MethodPost || c0.path != "/events/batch" || c0.key != "k-1" {
		t.Errorf("call = %+v", c0)
	}
	ev := c0.body["events"].([]any)[0].(map[string]any)
	if ev["event_name"] != "TasksBusiness_CreateTask" || ev["identifiers"].(map[string]any)["ext_id"] != "u-1" {
		t.Errorf("event = %v", ev)
	}
}

// A 207 is a partial success: the call succeeds and names the refused ones.
func TestSendEvents_APartialBatchNamesTheRefusedEvents(t *testing.T) {
	s := newStub(t, status(http.StatusMultiStatus, `{"status":"partial","errors":[{"eventIndex":[1,2],"message":"invalid event_name"}]}`))
	c, _ := client(t, s)
	got, err := c.SendEvents(context.Background(), make([]Event, 3))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Failed) != 2 || got.Failed[1] != "invalid event_name" || got.Failed[2] == "" {
		t.Errorf("failed = %v", got.Failed)
	}
}

func TestSendEvents_RefusesWhatBrevoWould(t *testing.T) {
	s := newStub(t, status(http.StatusNoContent, ""))
	c, _ := client(t, s)
	if _, err := c.SendEvents(context.Background(), make([]Event, MaxBatchEvents+1)); err == nil {
		t.Error("a batch over 200 events was sent")
	}
	big := []Event{{EventName: "x", EventProperties: map[string]any{"p": strings.Repeat("a", MaxBatchBytes)}}}
	if _, err := c.SendEvents(context.Background(), big); err == nil {
		t.Error("a batch over 512 KB was sent")
	}
	if len(s.calls) != 0 {
		t.Errorf("%d calls reached Brevo", len(s.calls))
	}
}

// A 429 is waited out for as long as Brevo says, then the request goes again.
func TestDo_WaitsOutARateLimit(t *testing.T) {
	limited := func(w http.ResponseWriter) {
		w.Header().Set("x-sib-ratelimit-reset", "2")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	s := newStub(t, limited, status(http.StatusNoContent, ""))
	c, slept := client(t, s)
	if _, err := c.SendEvents(context.Background(), []Event{{EventName: "x"}}); err != nil {
		t.Fatal(err)
	}
	if len(s.calls) != 2 {
		t.Fatalf("%d calls, want the retry", len(s.calls))
	}
	waited := false
	for _, d := range *slept {
		if d >= 2*time.Second {
			waited = true
		}
	}
	if !waited {
		t.Errorf("slept %v, want at least the 2s Brevo asked for", *slept)
	}
}

// Past a few waits the 429 is the caller's to retry, and says it may be.
func TestDo_GivesUpOnARateLimitThatDoesNotLift(t *testing.T) {
	s := newStub(t, status(http.StatusTooManyRequests, `{"code":"too_many_requests","message":"slow down"}`))
	c, _ := client(t, s)
	_, err := c.SendEvents(context.Background(), []Event{{EventName: "x"}})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusTooManyRequests || !Retryable(err) {
		t.Fatalf("err = %v, want a retryable 429", err)
	}
	if len(s.calls) != maxRateLimitWaits+1 {
		t.Errorf("%d calls, want %d", len(s.calls), maxRateLimitWaits+1)
	}
}

func TestRetryable(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&Error{Status: 401}, false},
		{&Error{Status: 400}, false},
		{&Error{Status: 429}, true},
		{&Error{Status: 503}, true},
		{errors.New("connection reset"), true},
		{context.Canceled, false},
		{nil, false},
	} {
		if got := Retryable(c.err); got != c.want {
			t.Errorf("Retryable(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

func TestUpsertContact_ByTheUsersID(t *testing.T) {
	s := newStub(t, status(http.StatusCreated, `{"id":7}`))
	c, _ := client(t, s)
	if err := c.UpsertContact(context.Background(), "u-1", "a@example.com", map[string]any{"W17_MARKETING_CONSENT": true}); err != nil {
		t.Fatal(err)
	}
	b := s.calls[0].body
	if s.calls[0].path != "/contacts" || b["ext_id"] != "u-1" || b["email"] != "a@example.com" || b["updateEnabled"] != true ||
		b["attributes"].(map[string]any)["W17_MARKETING_CONSENT"] != true {
		t.Errorf("call = %+v", s.calls[0])
	}
	// No email, no attributes: neither key is sent, so Brevo keeps what it has.
	if err := c.UpsertContact(context.Background(), "u-1", "", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.calls[1].body["email"]; ok {
		t.Error("an empty email was sent")
	}
	if _, ok := s.calls[1].body["attributes"]; ok {
		t.Error("empty attributes were sent")
	}
}

func TestDeleteContact_AMissingContactIsDeleted(t *testing.T) {
	s := newStub(t, status(http.StatusNotFound, `{"code":"document_not_found","message":"Contact does not exist"}`))
	c, _ := client(t, s)
	if err := c.DeleteContact(context.Background(), "u/1"); err != nil {
		t.Fatalf("404 = %v, want done", err)
	}
	if s.calls[0].method != http.MethodDelete || s.calls[0].path != "/contacts/u/1" || s.calls[0].query != "identifierType=ext_id" {
		t.Errorf("call = %+v", s.calls[0])
	}
	s2 := newStub(t, status(http.StatusUnauthorized, `{"code":"unauthorized","message":"Key not found"}`))
	c2, _ := client(t, s2)
	if err := c2.DeleteContact(context.Background(), "u-1"); err == nil || Retryable(err) {
		t.Errorf("401 = %v, want a permanent failure", err)
	}
}

// Requests leave at the configured rate.
func TestPace_SpacesTheRequests(t *testing.T) {
	s := newStub(t, status(http.StatusNoContent, ""))
	c, slept := client(t, s)
	c.gap = 100 * time.Millisecond
	for i := 0; i < 3; i++ {
		if err := c.DeleteContact(context.Background(), "u"); err != nil {
			t.Fatal(err)
		}
	}
	if len(*slept) < 2 {
		t.Errorf("slept %v, want the second and third request held", *slept)
	}
}

func TestNew_RefusesAConfigurationThatCannotWork(t *testing.T) {
	for _, c := range []struct {
		base, key string
		rps       int
	}{
		{"https://api.brevo.com/v3", "", 8},
		{"api.brevo.com", "k", 8},
		{"https://api.brevo.com/v3", "k", 0},
	} {
		if _, err := New(c.base, c.key, c.rps); err == nil {
			t.Errorf("New(%q, %q, %d) accepted", c.base, c.key, c.rps)
		}
	}
}
