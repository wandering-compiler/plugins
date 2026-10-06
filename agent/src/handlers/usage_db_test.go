package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/usage"
)

// With the feature's clients present, NewUsageSink wires the database — and
// what a call recorded arrives as rows: each tenant's spend against ITS OWN
// scope id, every token kind, the outcome, the timing and the labels, after
// Close drains the queue.
func TestUsageSink_RecordsEachTenantsCallsAgainstItsOwnScope(t *testing.T) {
	store, clients := serveUsageStore(t)
	sink := NewUsageSink(clients)
	if _, ok := sink.(*dbUsageSink); !ok {
		t.Fatalf("sink = %T, want the database sink when the clients can write", sink)
	}
	if err := VerifyUsageWiring(sink); err != nil {
		t.Fatalf("VerifyUsageWiring refused a real sink: %v", err)
	}

	started := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)
	sink.Record(UsageEvent{Scope: "tenant-a", Model: "gpt-4o-2024-08-06", Labels: map[string]string{"run": "r1", "feature": "search"},
		Measured: true, InputTokens: 100, OutputTokens: 20, CachedInputTokens: 60, ReasoningTokens: 5,
		Status: OutcomeOK, StartedAt: started, Duration: 1500 * time.Millisecond})
	sink.Record(UsageEvent{Scope: "tenant-b", Model: "gpt-4o-2024-08-06",
		Status: OutcomeFailed, StartedAt: started, Duration: 30 * time.Millisecond})
	sink.Record(UsageEvent{Scope: "tenant-a", Model: "o3-mini", Labels: map[string]string{"run": "r1"},
		Measured: true, InputTokens: 1, OutputTokens: 1, Status: OutcomeUnknown, StartedAt: started})
	sink.Close(context.Background())

	rows := store.usageRows()
	if len(rows) != 3 {
		t.Fatalf("store holds %d rows, want 3", len(rows))
	}
	a, b := store.scopeIDOf("tenant-a"), store.scopeIDOf("tenant-b")
	if a == 0 || b == 0 || a == b {
		t.Fatalf("scope ids a=%d b=%d — two tenants must not share a scope", a, b)
	}
	first := rows[0].row
	if first.GetScopeId() != a || rows[1].row.GetScopeId() != b || rows[2].row.GetScopeId() != a {
		t.Errorf("rows were filed under the wrong scope: %d, %d, %d (a=%d b=%d)",
			first.GetScopeId(), rows[1].row.GetScopeId(), rows[2].row.GetScopeId(), a, b)
	}
	if !first.GetMeasured() || first.GetInputTokens() != 100 || first.GetOutputTokens() != 20 ||
		first.GetCachedInputTokens() != 60 || first.GetReasoningTokens() != 5 {
		t.Errorf("tokens = %+v", first)
	}
	if first.GetStatus() != pb.CallStatus_CALL_STATUS_OK || rows[1].row.GetStatus() != pb.CallStatus_CALL_STATUS_FAILED ||
		rows[2].row.GetStatus() != pb.CallStatus_CALL_STATUS_UNKNOWN {
		t.Errorf("statuses = %v %v %v", first.GetStatus(), rows[1].row.GetStatus(), rows[2].row.GetStatus())
	}
	if !first.GetStartedAt().AsTime().Equal(started) || first.GetDurationMs() != 1500 {
		t.Errorf("timing = %v / %dms", first.GetStartedAt().AsTime(), first.GetDurationMs())
	}
	if rows[1].row.GetMeasured() {
		t.Error("an unmeasured failure was stored as measured — it would read as a free call")
	}
	if got := rows[0].labels; got["run"] != "r1" || got["feature"] != "search" || len(got) != 2 {
		t.Errorf("first row's labels = %v", got)
	}
	if len(rows[1].labels) != 0 {
		t.Errorf("tenant-b's row carries labels it never had: %v", rows[1].labels)
	}
	if rows[0].row.GetModelId() == rows[2].row.GetModelId() {
		t.Error("two models were interned under one id — the price list keys on it")
	}

	// The cache keeps a steady stream down to one insert per call: each
	// scope, model and label pair is interned ONCE.
	if n := store.count("InternScope"); n != 2 {
		t.Errorf("InternScope ran %d times for 2 scopes", n)
	}
	if n := store.count("InternModel"); n != 2 {
		t.Errorf("InternModel ran %d times for 2 models", n)
	}
	if n := store.count("InternLabel"); n != 2 {
		t.Errorf("InternLabel ran %d times for 2 distinct pairs", n)
	}
}

// Without the mutation client — an activation whose ClientSet lacks it — the
// factory leaves the no-op in place, and it is VerifyUsageWiring's job to say
// so when the feature claims to be on.
func TestUsageSink_WithoutTheClientStaysTheNoop(t *testing.T) {
	for _, clients := range []any{nil, struct{}{}} {
		if s := NewUsageSink(clients); s != (noopUsageSink{}) {
			t.Errorf("NewUsageSink(%T) = %T, want the no-op", clients, s)
		}
	}
}

// One tenant's malformed row must not sink everybody else's.
//
// A batch is up to 64 calls from every tenant the process served. Flush used
// to return at the first failure, so a scope longer than its column — one
// caller's mistake — dropped every event queued behind it, and the writer then
// counted the rows that HAD landed as lost too.
func TestFlush_OneBadEventDoesNotSinkTheBatch(t *testing.T) {
	store, clients := serveUsageStore(t)
	f := &dbFlusher{mut: clients.UsageMutation()}

	err := f.Flush(context.Background(), []usage.Event{
		{Scope: "tenant-a", Model: "gpt-4o", Status: int32(OutcomeOK)},
		{Scope: strings.Repeat("x", 200), Model: "gpt-4o", Status: int32(OutcomeOK)},
		{Scope: "tenant-b", Model: "gpt-4o", Status: int32(OutcomeOK)},
	})
	var partial *usage.PartialFlushError
	if !errors.As(err, &partial) || partial.Failed != 1 {
		t.Fatalf("err = %v, want a partial failure of exactly 1 event", err)
	}
	if status.Code(errors.Unwrap(err)) != codes.InvalidArgument {
		t.Errorf("the cause was lost: %v", err)
	}
	rows := store.usageRows()
	if len(rows) != 2 {
		t.Fatalf("store holds %d rows, want tenant-a's and tenant-b's", len(rows))
	}
	if rows[1].row.GetScopeId() != store.scopeIDOf("tenant-b") {
		t.Error("tenant-b's call, queued after the bad one, was not recorded")
	}
}

// …and the writer's counters follow the partial count: two written, one lost.
func TestFlush_TheWriterCountsAPartialBatchExactly(t *testing.T) {
	_, clients := serveUsageStore(t)
	w := usage.New(usage.Config{BatchSize: 3, FlushInterval: time.Hour}, &dbFlusher{mut: clients.UsageMutation()})
	w.Record(usage.Event{Scope: "tenant-a", Model: "gpt-4o"})
	w.Record(usage.Event{Scope: "tenant-a", Model: strings.Repeat("m", 300)})
	w.Record(usage.Event{Scope: "tenant-b", Model: "gpt-4o"})
	w.Close(context.Background())
	if st := w.Stats(); st.Written != 2 || st.FailedEvents != 1 {
		t.Errorf("stats = %+v, want 2 written and 1 failed", st)
	}
}

// A label the table refuses costs that label, not the row or the other labels.
func TestFlush_ABadLabelKeepsTheRowAndTheOtherLabels(t *testing.T) {
	store, clients := serveUsageStore(t)
	f := &dbFlusher{mut: clients.UsageMutation()}
	err := f.Flush(context.Background(), []usage.Event{{
		Scope: "tenant-a", Model: "gpt-4o",
		Labels: map[string]string{"run": "r1", "note": strings.Repeat("v", 300)},
	}})
	var partial *usage.PartialFlushError
	if !errors.As(err, &partial) || partial.Failed != 1 {
		t.Errorf("err = %v — an event whose attribution did not fully land is reported", err)
	}
	rows := store.usageRows()
	if len(rows) != 1 {
		t.Fatalf("rows = %d — the spend itself must land", len(rows))
	}
	if rows[0].labels["run"] != "r1" {
		t.Errorf("labels = %v — the good label went down with the bad one", rows[0].labels)
	}
}

// A transient failure is not cached: the next flush interns again and lands.
// And an attach failure is reported like any other.
func TestFlush_ATransientFailureIsRetriedOnTheNextBatch(t *testing.T) {
	store, clients := serveUsageStore(t)
	f := &dbFlusher{mut: clients.UsageMutation()}
	ev := usage.Event{Scope: "tenant-a", Model: "gpt-4o", Labels: map[string]string{"run": "r1"}}

	for _, method := range []string{"InternScope", "InternModel", "RecordUsage", "InternLabel", "AttachUsageLabel"} {
		store.failWith(method, status.Error(codes.Unavailable, "db restarting"), 1)
		if err := f.Flush(context.Background(), []usage.Event{ev}); err == nil {
			t.Errorf("%s failed and Flush reported success", method)
		}
	}
	if err := f.Flush(context.Background(), []usage.Event{ev}); err != nil {
		t.Fatalf("Flush after recovery: %v", err)
	}
	rows := store.usageRows()
	last := rows[len(rows)-1]
	if last.row.GetScopeId() != store.scopeIDOf("tenant-a") || last.labels["run"] != "r1" {
		t.Errorf("the recovered flush wrote %+v / %v", last.row, last.labels)
	}
}

// The limiter factory needs BOTH halves; with either missing it allows, rather
// than half-working.
func TestNewLimiter_NeedsBothClients(t *testing.T) {
	_, clients := serveUsageStore(t)
	if l := NewLimiter(clients); l == nil {
		t.Fatal("nil limiter")
	} else if _, ok := l.(*dbLimiter); !ok {
		t.Errorf("NewLimiter(both) = %T, want the database limiter", l)
	}
	for _, c := range []any{nil, struct{}{}, mutationOnly{conn: clients.conn}} {
		if l := NewLimiter(c); l != (allowAllLimiter{}) {
			t.Errorf("NewLimiter(%T) = %T, want allow-all", c, l)
		}
	}
}
