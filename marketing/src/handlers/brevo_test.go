package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/eventlog"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// fakeBrevo records what the tool sends and answers as told.
type fakeBrevo struct {
	batches [][]brevo.Event
	failed  map[int]string
	sendErr error
	upserts []string // "<ext>|<email>|<attrs>"
	deletes []string
	callErr error
}

func (f *fakeBrevo) SendEvents(_ context.Context, events []brevo.Event) (brevo.BatchResult, error) {
	if f.sendErr != nil {
		return brevo.BatchResult{}, f.sendErr
	}
	f.batches = append(f.batches, append([]brevo.Event(nil), events...))
	return brevo.BatchResult{Failed: f.failed}, nil
}

func (f *fakeBrevo) UpsertContact(_ context.Context, ext, email string, attrs map[string]any) error {
	f.upserts = append(f.upserts, fmt.Sprintf("%s|%s|%v", ext, email, attrs))
	return f.callErr
}

func (f *fakeBrevo) DeleteContact(_ context.Context, ext string) error {
	f.deletes = append(f.deletes, ext)
	return f.callErr
}

// ledger fakes the SentEvent table.
type ledger struct {
	pb.MarketingQueryClient
	pb.MarketingMutationClient
	sent map[string]bool
}

func (l *ledger) ListSentEvents(_ context.Context, in *pb.ListSentEventsReq, _ ...grpc.CallOption) (*pb.ListSentEventsResp, error) {
	out := &pb.ListSentEventsResp{}
	for _, id := range in.GetIds() {
		if l.sent[id] {
			out.Ids = append(out.Ids, id)
		}
	}
	return out, nil
}

func (l *ledger) RecordSentEvent(_ context.Context, in *pb.RecordSentEventReq, _ ...grpc.CallOption) (*pb.RecordSentEventResp, error) {
	if l.sent[in.GetId()] {
		st, _ := status.New(codes.InvalidArgument, "duplicate").WithDetails(&w17pb.ErrorDetail{Code: "UNIQUE_VIOLATION"})
		return nil, st.Err()
	}
	l.sent[in.GetId()] = true
	return &pb.RecordSentEventResp{Id: in.GetId()}, nil
}

const (
	createTask = "/e2e.app.tasks.TasksBusiness/CreateTask"
	getTask    = "/e2e.app.tasks.TasksBusiness/GetTask"
)

func tool(t *testing.T, f *fakeBrevo, l *ledger, send, include, exclude string) *brevoTool {
	t.Helper()
	sel, err := newSelection(send, include, exclude, map[string]bool{createTask: false, getTask: true})
	if err != nil {
		t.Fatal(err)
	}
	return &brevoTool{client: f, sel: sel, consentAttr: "W17_MARKETING_CONSENT", query: l, mutation: l}
}

func record(id byte, method, user string) eventlog.ConsumedRecord {
	return eventlog.ConsumedRecord{Meta: &w17pb.RequestEventMeta{
		Id:     []byte{id},
		Method: method,
		UserId: user,
		Start:  timestamppb.New(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)),
	}}
}

func batch(recs ...eventlog.ConsumedRecord) *eventlog.ConsumedBatch {
	return &eventlog.ConsumedBatch{Records: recs}
}

// A record already sent is skipped; the rest are sent and then recorded.
func TestConsumeMarketing_SkipsWhatWasSentAndRecordsWhatIs(t *testing.T) {
	f, l := &fakeBrevo{}, &ledger{sent: map[string]bool{"01": true}}
	tl := tool(t, f, l, "all", "", "")
	if err := tl.ConsumeMarketing(context.Background(), batch(record(1, createTask, "u1"), record(2, createTask, "u2"))); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 1 || len(f.batches[0]) != 1 || f.batches[0][0].Identifiers.ExtID != "u2" {
		t.Fatalf("batches = %+v, want only the unsent record", f.batches)
	}
	if !l.sent["02"] {
		t.Error("the sent record was not recorded")
	}
}

// A transient failure fails the batch (the stream redelivers it) and records
// nothing, so the redelivery sends it.
func TestConsumeMarketing_ATransientFailureRecordsNothing(t *testing.T) {
	f, l := &fakeBrevo{sendErr: &brevo.Error{Status: 503}}, &ledger{sent: map[string]bool{}}
	if err := tool(t, f, l, "all", "", "").ConsumeMarketing(context.Background(), batch(record(1, createTask, "u1"))); err == nil {
		t.Fatal("a failed send returned nil — the stream would not redeliver it")
	}
	if len(l.sent) != 0 {
		t.Errorf("recorded %v after a failed send", l.sent)
	}
}

// An event Brevo refuses for its content is not retried: it is recorded too.
func TestConsumeMarketing_ARefusedEventIsNotRetried(t *testing.T) {
	f, l := &fakeBrevo{failed: map[int]string{0: "invalid event_name"}}, &ledger{sent: map[string]bool{}}
	if err := tool(t, f, l, "all", "", "").ConsumeMarketing(context.Background(), batch(record(1, createTask, "u1"))); err != nil {
		t.Fatal(err)
	}
	if !l.sent["01"] {
		t.Error("a refused event was left to be refused again on every redelivery")
	}
}

// A concurrent replica recording the same record first is not a failure.
func TestRecordSent_AnotherReplicaFirstIsTheSameOutcome(t *testing.T) {
	l := &ledger{sent: map[string]bool{"01": true}}
	if err := tool(t, &fakeBrevo{}, l, "all", "", "").recordSent(context.Background(), "01"); err != nil {
		t.Errorf("recordSent on a recorded id = %v", err)
	}
}

func TestConsumeMarketing_SendsWhatTheSelectionSays(t *testing.T) {
	for _, c := range []struct {
		send, include, exclude string
		want                   []string
	}{
		{"mutations", "", "", []string{"TasksBusiness_CreateTask"}},
		{"queries", "", "", []string{"TasksBusiness_GetTask"}},
		{"all", "", "", []string{"TasksBusiness_CreateTask", "TasksBusiness_GetTask"}},
		{"off", "", "", nil},
		{"mutations", getTask, "", []string{"TasksBusiness_CreateTask", "TasksBusiness_GetTask"}},
		{"all", "", createTask, []string{"TasksBusiness_GetTask"}},
		{"all", createTask, createTask, []string{"TasksBusiness_GetTask"}}, // exclude wins
	} {
		f := &fakeBrevo{}
		if err := tool(t, f, &ledger{sent: map[string]bool{}}, c.send, c.include, c.exclude).
			ConsumeMarketing(context.Background(), batch(record(1, createTask, "u"), record(2, getTask, "u"))); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, b := range f.batches {
			for _, e := range b {
				got = append(got, e.EventName)
			}
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("send=%s include=%s exclude=%s: sent %v, want %v", c.send, c.include, c.exclude, got, c.want)
		}
	}
}

// More than a batch's worth is split at Brevo's limit.
func TestConsumeMarketing_SplitsAtTheBatchLimit(t *testing.T) {
	var recs []eventlog.ConsumedRecord
	for i := 0; i < brevo.MaxBatchEvents+5; i++ {
		r := record(0, createTask, "u")
		r.Meta.Id = []byte{byte(i >> 8), byte(i)}
		recs = append(recs, r)
	}
	f := &fakeBrevo{}
	if err := tool(t, f, &ledger{sent: map[string]bool{}}, "all", "", "").ConsumeMarketing(context.Background(), batch(recs...)); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 2 || len(f.batches[0]) != brevo.MaxBatchEvents || len(f.batches[1]) != 5 {
		t.Errorf("batches of %d, want %d + 5", lens(f.batches), brevo.MaxBatchEvents)
	}
}

func lens(b [][]brevo.Event) []int {
	var out []int
	for _, x := range b {
		out = append(out, len(x))
	}
	return out
}

func TestNewSelection_RefusesWhatTheStreamDoesNotRecord(t *testing.T) {
	reads := map[string]bool{createTask: false}
	if _, err := newSelection("mutations", "/e2e.app.tasks.TasksBusiness/CreateTsk", "", reads); err == nil || !strings.Contains(err.Error(), "CreateTsk") {
		t.Errorf("a typo in include = %v, want it refused and named", err)
	}
	if _, err := newSelection("everything", "", "", reads); err == nil {
		t.Error("an unknown send mode was accepted")
	}
	if s, err := newSelection("", "", "", reads); err != nil || s.mode != "mutations" {
		t.Errorf("default = %+v, %v", s, err)
	}
}

// The event: the method as its name, the user as the contact, the record's
// own properties, the org and the consent on the contact. Nothing else.
func TestEventFor(t *testing.T) {
	consent := true
	meta := &w17pb.RequestEventMeta{
		Id: []byte{1}, Method: createTask, Route: "/api/v1/tasks", HttpStatus: 201,
		DurationMicros: 12500, Api: w17pb.RequestApi_REQUEST_API_REST,
		UserId: "u1", OrgId: "o1", MarketingConsent: proto.Bool(consent), Truncated: true,
		Start:  timestamppb.New(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)),
		Client: &w17pb.RequestClient{Ip: "10.0.0.1", UserAgent: "ua", Referrer: "https://x.example", Utm: map[string]string{"source": "news", "camp aign": "q4"}},
	}
	ev, ok := eventFor(meta, "W17_MARKETING_CONSENT")
	if !ok {
		t.Fatal("not sent")
	}
	if ev.EventName != "TasksBusiness_CreateTask" || ev.Identifiers.ExtID != "u1" || ev.EventDate != "2026-10-19T09:00:00Z" {
		t.Errorf("event = %+v", ev)
	}
	want := map[string]any{
		"w17_api": "rest", "w17_duration_ms": int64(12), "w17_status": int32(201), "w17_route": "/api/v1/tasks",
		"w17_truncated": true, "utm_source": "news", "utm_camp_aign": "q4", "referrer": "https://x.example",
	}
	if fmt.Sprint(ev.EventProperties) != fmt.Sprint(want) {
		t.Errorf("properties = %v\nwant         %v", ev.EventProperties, want)
	}
	for _, leaked := range []string{"10.0.0.1", "ua"} {
		if strings.Contains(fmt.Sprint(ev), leaked) {
			t.Errorf("the IP or user agent reached Brevo: %v", ev)
		}
	}
	if ev.ContactProperties["W17_ORG_ID"] != "o1" || ev.ContactProperties["W17_MARKETING_CONSENT"] != true {
		t.Errorf("contact = %v", ev.ContactProperties)
	}
	meta.MarketingConsent = nil
	ev, _ = eventFor(meta, "W17_MARKETING_CONSENT")
	if _, ok := ev.ContactProperties["W17_MARKETING_CONSENT"]; ok {
		t.Error("an unknown consent was written as false")
	}
	if _, ok := eventFor(&w17pb.RequestEventMeta{Method: createTask}, "X"); ok {
		t.Error("a record of nobody became an event")
	}
}

func TestEventName(t *testing.T) {
	for in, want := range map[string]string{
		createTask:                     "TasksBusiness_CreateTask",
		"/a.b.Svc/Do.It":               "Svc_Do_It",
		"/Svc/X":                       "Svc_X",
		"/" + strings.Repeat("a", 300): strings.Repeat("a", 255),
	} {
		if got := eventName(in); got != want {
			t.Errorf("eventName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestContacts_FollowTheAccounts(t *testing.T) {
	f := &fakeBrevo{}
	tl := tool(t, f, &ledger{}, "all", "", "")
	ctx := context.Background()
	_ = tl.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"})
	_ = tl.onUserUpdated(ctx, &pb.AuthUserUpdated{UserId: "u1", Email: "b@x.example"})
	_ = tl.onConsentChanged(ctx, &pb.AuthMarketingConsentChanged{UserId: "u1", Consent: false})
	_ = tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"})
	want := []string{"u1|a@x.example|map[]", "u1|b@x.example|map[]", "u1||map[W17_MARKETING_CONSENT:false]"}
	if strings.Join(f.upserts, ";") != strings.Join(want, ";") {
		t.Errorf("upserts = %v\nwant      %v", f.upserts, want)
	}
	if len(f.deletes) != 1 || f.deletes[0] != "u1" {
		t.Errorf("deletes = %v", f.deletes)
	}
}

// A transient failure is retried (an error back to the stream); a refusal
// is not (nil, logged).
func TestContacts_RetryOnlyWhatMaySucceed(t *testing.T) {
	ctx := context.Background()
	transient := tool(t, &fakeBrevo{callErr: &brevo.Error{Status: 503}}, &ledger{}, "all", "", "")
	if err := transient.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err == nil {
		t.Error("a transient failure to delete was swallowed — the erasure would be lost")
	}
	refused := tool(t, &fakeBrevo{callErr: &brevo.Error{Status: 400}}, &ledger{}, "all", "", "")
	if err := refused.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "bad"}); err != nil {
		t.Errorf("a refusal = %v, want nil (retrying it fails the same way)", err)
	}
}

func TestIsUniqueViolation(t *testing.T) {
	st, _ := status.New(codes.InvalidArgument, "dup").WithDetails(&w17pb.ErrorDetail{Code: "UNIQUE_VIOLATION"})
	if !isUniqueViolation(st.Err()) {
		t.Error("UNIQUE_VIOLATION not recognised")
	}
	if isUniqueViolation(status.Error(codes.InvalidArgument, "bad")) || isUniqueViolation(errors.New("x")) {
		t.Error("another error read as a duplicate")
	}
}
