package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	upserts []string // "<ext>|<email>|<attrs>|bl=<emailBlacklisted>"
	updates []string // "<ext>|<attrs>|bl=<emailBlacklisted>"
	known   map[string]bool
	mu      sync.Mutex // guards ensured and ensureFails (a goroutine's)
	ensured []string
	// ensureFails: how many more times each attribute's creation fails.
	ensureFails map[string]int
	// ensureBlocks: each attribute's creation waits for its context to end
	// (a Brevo that does not answer).
	ensureBlocks bool
	deletes      []string
	callErr      error
	// contacts is the account's listing (ListContacts), oldest first.
	contacts []brevo.Contact
	listErr  error
	listed   []int // the offsets asked for
	onList   func(calls int)
	// blacklisted is each contact's emailBlacklisted as Brevo holds it.
	blacklisted map[string]bool
	// onGet runs once, inside the next GetContact: another delivery landing
	// between the plugin's read of Brevo and its write.
	onGet func()
	// onCreate / onUpsert run once, inside the next CreateContact /
	// UpsertContact, before it writes.
	onCreate func()
	onUpsert func()
	// onSend / onUpdate run once, inside the next SendEvents / UpdateContact,
	// before it writes: another delivery (an erasure) landing in between.
	onSend   func()
	onUpdate func()
}

func (f *fakeBrevo) keep(ext string, blacklisted *bool) {
	if blacklisted == nil {
		return
	}
	if f.blacklisted == nil {
		f.blacklisted = map[string]bool{}
	}
	f.blacklisted[ext] = *blacklisted
}

func (f *fakeBrevo) CreateContact(ctx context.Context, ext, email string, attrs map[string]any, blacklisted *bool) error {
	if g := f.onCreate; g != nil {
		f.onCreate = nil
		g()
	}
	if f.callErr == nil && f.known[ext] {
		return &brevo.Error{Status: 400, Code: "duplicate_parameter", Message: "Contact already exist"}
	}
	hook := f.onUpsert
	f.onUpsert = nil
	defer func() { f.onUpsert = hook }()
	return f.UpsertContact(ctx, ext, email, attrs, blacklisted)
}

func (f *fakeBrevo) GetContact(_ context.Context, ext string) (brevo.Contact, error) {
	if g := f.onGet; g != nil {
		f.onGet = nil
		g()
	}
	if f.callErr != nil {
		return brevo.Contact{}, f.callErr
	}
	if !f.known[ext] {
		return brevo.Contact{}, &brevo.Error{Status: 404, Message: "Contact does not exist"}
	}
	return brevo.Contact{ExtID: ext, EmailBlacklisted: f.blacklisted[ext]}, nil
}

func bl(b *bool) string {
	if b == nil {
		return "bl=unset"
	}
	return fmt.Sprintf("bl=%v", *b)
}

// SendEvents records the batch and, as measured against an account, creates
// the contact of an ext_id Brevo does not know: no address, blacklisted.
func (f *fakeBrevo) SendEvents(_ context.Context, events []brevo.Event) (brevo.BatchResult, error) {
	if g := f.onSend; g != nil {
		f.onSend = nil
		g()
	}
	if f.sendErr != nil {
		return brevo.BatchResult{}, f.sendErr
	}
	f.batches = append(f.batches, append([]brevo.Event(nil), events...))
	for i, ev := range events {
		if _, refused := f.failed[i]; refused || ev.Identifiers.ExtID == "" || f.known[ev.Identifiers.ExtID] {
			continue
		}
		if f.known == nil {
			f.known = map[string]bool{}
		}
		f.known[ev.Identifiers.ExtID] = true
		yes := true
		f.keep(ev.Identifiers.ExtID, &yes)
	}
	return brevo.BatchResult{Failed: f.failed}, nil
}

func (f *fakeBrevo) UpsertContact(_ context.Context, ext, email string, attrs map[string]any, blacklisted *bool) error {
	if g := f.onUpsert; g != nil {
		f.onUpsert = nil
		g()
	}
	f.upserts = append(f.upserts, fmt.Sprintf("%s|%s|%v|%s", ext, email, attrs, bl(blacklisted)))
	if f.callErr == nil {
		if f.known == nil {
			f.known = map[string]bool{}
		}
		if !f.known[ext] && blacklisted == nil {
			f.keep(ext, new(bool)) // Brevo creates a contact subscribed
		}
		f.known[ext] = true
		f.keep(ext, blacklisted)
	}
	return f.callErr
}

func (f *fakeBrevo) UpdateContact(_ context.Context, ext string, attrs map[string]any, blacklisted *bool) error {
	if g := f.onUpdate; g != nil {
		f.onUpdate = nil
		g()
	}
	if f.callErr != nil {
		return f.callErr
	}
	if !f.known[ext] {
		return &brevo.Error{Status: 404, Message: "Contact does not exist"}
	}
	f.updates = append(f.updates, fmt.Sprintf("%s|%v|%s", ext, attrs, bl(blacklisted)))
	f.keep(ext, blacklisted)
	return nil
}

func (f *fakeBrevo) EnsureAttribute(ctx context.Context, name, typ string) error {
	f.mu.Lock()
	block := f.ensureBlocks
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return ctx.Err()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ensured = append(f.ensured, name+":"+typ)
	if f.ensureFails[name] > 0 {
		f.ensureFails[name]--
		return &brevo.Error{Status: 503}
	}
	return f.callErr
}

func (f *fakeBrevo) ensuredSoFar() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ensured...)
}

func (f *fakeBrevo) DeleteContact(_ context.Context, ext string) error {
	f.deletes = append(f.deletes, ext)
	if f.callErr == nil {
		delete(f.known, ext)
		delete(f.blacklisted, ext)
	}
	return f.callErr
}

func (f *fakeBrevo) ListContacts(_ context.Context, offset, limit int) ([]brevo.Contact, int, error) {
	f.listed = append(f.listed, offset)
	if f.onList != nil {
		f.onList(len(f.listed))
	}
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	if offset >= len(f.contacts) {
		return nil, len(f.contacts), nil
	}
	end := offset + limit
	if end > len(f.contacts) {
		end = len(f.contacts)
	}
	page := append([]brevo.Contact(nil), f.contacts[offset:end]...)
	for i := range page {
		if b, ok := f.blacklisted[page[i].ExtID]; ok && page[i].ExtID != "" {
			page[i].EmailBlacklisted = b
		}
	}
	return page, len(f.contacts), nil
}

// ledger fakes the plugin's tables: SentEvent, Contact, Reconciliation,
// Activity.
type ledger struct {
	activity map[string]map[string]time.Time // user → attribute → last_at
	// afterActivityRead runs once, after the next ListActivity has read: a
	// record on another replica moving a row while the contact is written.
	afterActivityRead func()
	pb.MarketingQueryClient
	pb.MarketingMutationClient
	sent     map[string]bool
	contacts map[string]*pb.ContactRow
	writeErr error  // every Contact write's
	badEmail string // an address ListContactsByEmail refuses as invalid
	recon    map[string]*reconRow
	now      time.Time // the database's NOW() for Reconciliation
	// beforeConsentWrite runs once, inside the next SetContactConsent, before
	// it writes: another delivery landing in between.
	beforeConsentWrite func()
	// recordFails: how many more times recording each sent id fails.
	recordFails map[string]int
	// byEmailErr: what ListContactsByEmail answers for an address.
	byEmailErr map[string]error
}

func (l *ledger) RecordActivity(_ context.Context, in *pb.ActivityReq, _ ...grpc.CallOption) (*pb.ActivityWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	if l.activity == nil {
		l.activity = map[string]map[string]time.Time{}
	}
	if l.activity[in.GetUserId()] == nil {
		l.activity[in.GetUserId()] = map[string]time.Time{}
	}
	if _, ok := l.activity[in.GetUserId()][in.GetAttribute()]; !ok {
		l.activity[in.GetUserId()][in.GetAttribute()] = in.GetLastAt().AsTime()
	}
	return &pb.ActivityWriteResp{}, nil
}

// BumpActivity is conditional, as its statement: only a later date.
func (l *ledger) BumpActivity(_ context.Context, in *pb.ActivityReq, _ ...grpc.CallOption) (*pb.ActivityMovedResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	at, ok := l.activity[in.GetUserId()][in.GetAttribute()]
	if !ok || !at.Before(in.GetLastAt().AsTime()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	l.activity[in.GetUserId()][in.GetAttribute()] = in.GetLastAt().AsTime()
	return &pb.ActivityMovedResp{UserId: in.GetUserId()}, nil
}

func (l *ledger) EraseActivity(_ context.Context, in *pb.EraseActivityReq, _ ...grpc.CallOption) (*pb.ActivityWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	delete(l.activity, in.GetUserId())
	return &pb.ActivityWriteResp{}, nil
}

func (l *ledger) ListActivity(_ context.Context, in *pb.ListActivityReq, _ ...grpc.CallOption) (*pb.ListActivityResp, error) {
	out := &pb.ListActivityResp{}
	for _, u := range in.GetUserIds() {
		for a, at := range l.activity[u] {
			out.Rows = append(out.Rows, &pb.ActivityRow{UserId: u, Attribute: a, LastAt: timestamppb.New(at)})
		}
	}
	if f := l.afterActivityRead; f != nil {
		l.afterActivityRead = nil
		f()
	}
	return out, nil
}

type reconRow struct {
	owner    string
	claimed  time.Time
	finished bool
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
	if l.recordFails[in.GetId()] > 0 {
		l.recordFails[in.GetId()]--
		return nil, status.Error(codes.Unavailable, "table hiccup")
	}
	if l.sent[in.GetId()] {
		st, _ := status.New(codes.InvalidArgument, "duplicate").WithDetails(&w17pb.ErrorDetail{Code: "UNIQUE_VIOLATION"})
		return nil, st.Err()
	}
	l.sent[in.GetId()] = true
	return &pb.RecordSentEventResp{Id: in.GetId()}, nil
}

func (l *ledger) contact(user string) *pb.ContactRow {
	if l.contacts == nil {
		l.contacts = map[string]*pb.ContactRow{}
	}
	c := l.contacts[user]
	if c == nil {
		c = &pb.ContactRow{UserId: user}
		l.contacts[user] = c
	}
	return c
}

func (l *ledger) ListContacts(_ context.Context, in *pb.ListContactsReq, _ ...grpc.CallOption) (*pb.ListContactsResp, error) {
	out := &pb.ListContactsResp{}
	for _, id := range in.GetUserIds() {
		if c := l.contacts[id]; c != nil {
			out.Contacts = append(out.Contacts, proto.Clone(c).(*pb.ContactRow))
		}
	}
	return out, nil
}

func (l *ledger) ListContactsByEmail(_ context.Context, in *pb.ListContactsByEmailReq, _ ...grpc.CallOption) (*pb.ListContactsResp, error) {
	if in.GetEmail() == l.badEmail {
		return nil, status.Error(codes.InvalidArgument, "email: not an address")
	}
	if err := l.byEmailErr[in.GetEmail()]; err != nil {
		return nil, err
	}
	out := &pb.ListContactsResp{}
	for _, c := range l.contacts {
		if c.GetEmail() == in.GetEmail() {
			out.Contacts = append(out.Contacts, proto.Clone(c).(*pb.ContactRow))
		}
	}
	return out, nil
}

// newContact is the row EnsureContact and SetContactEmail insert: it starts
// sent_blacklisted, as their statements write it.
func (l *ledger) newContact(user string) *pb.ContactRow {
	if c := l.contacts[user]; c != nil {
		return c
	}
	c := l.contact(user)
	c.SentBlacklisted = true
	return c
}

func (l *ledger) SetContactEmail(_ context.Context, in *pb.SetContactEmailReq, _ ...grpc.CallOption) (*pb.ContactWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	l.newContact(in.GetUserId()).Email = in.GetEmail()
	return &pb.ContactWriteResp{}, nil
}

func (l *ledger) EnsureContact(_ context.Context, in *pb.EnsureContactReq, _ ...grpc.CallOption) (*pb.ContactWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	l.newContact(in.GetUserId())
	return &pb.ContactWriteResp{}, nil
}

// SetContactConsent is conditional, as its statement: only a newer decision.
func (l *ledger) SetContactConsent(_ context.Context, in *pb.SetContactConsentReq, _ ...grpc.CallOption) (*pb.ContactUpdatedResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	if f := l.beforeConsentWrite; f != nil {
		l.beforeConsentWrite = nil
		f()
	}
	c := l.contacts[in.GetUserId()]
	if c == nil || (c.GetConsentAt() != nil && !c.GetConsentAt().AsTime().Before(in.GetConsentAt().AsTime())) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	c.Consent, c.ConsentAt = in.GetConsent(), in.GetConsentAt()
	return &pb.ContactUpdatedResp{UserId: in.GetUserId()}, nil
}

func (l *ledger) SetContactUnsubscribed(_ context.Context, in *pb.SetContactUnsubscribedReq, _ ...grpc.CallOption) (*pb.ContactUpdatedResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	c := l.contacts[in.GetUserId()]
	if c == nil || (c.GetUnsubscribedAt() != nil && !c.GetUnsubscribedAt().AsTime().Before(in.GetUnsubscribedAt().AsTime())) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	c.UnsubscribedAt = in.GetUnsubscribedAt()
	return &pb.ContactUpdatedResp{UserId: in.GetUserId()}, nil
}

func (l *ledger) SetContactSentBlacklisted(_ context.Context, in *pb.SetContactSentBlacklistedReq, _ ...grpc.CallOption) (*pb.ContactWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	l.contact(in.GetUserId()).SentBlacklisted = in.GetSentBlacklisted()
	return &pb.ContactWriteResp{}, nil
}

func (l *ledger) EraseContact(_ context.Context, in *pb.EraseContactReq, _ ...grpc.CallOption) (*pb.ContactWriteResp, error) {
	if l.writeErr != nil {
		return nil, l.writeErr
	}
	c := l.contact(in.GetUserId())
	c.Email, c.ErasedAt = "", timestamppb.Now()
	return &pb.ContactWriteResp{}, nil
}

func (l *ledger) reconNow() time.Time {
	if l.now.IsZero() {
		return time.Now()
	}
	return l.now
}

func (l *ledger) ClaimReconciliation(_ context.Context, in *pb.ClaimReconciliationReq, _ ...grpc.CallOption) (*pb.ReconciliationResp, error) {
	if l.recon == nil {
		l.recon = map[string]*reconRow{}
	}
	if l.recon[in.GetName()] != nil {
		st, _ := status.New(codes.InvalidArgument, "duplicate").WithDetails(&w17pb.ErrorDetail{Code: "UNIQUE_VIOLATION"})
		return nil, st.Err()
	}
	l.recon[in.GetName()] = &reconRow{owner: in.GetOwner(), claimed: l.reconNow()}
	return &pb.ReconciliationResp{Name: in.GetName()}, nil
}

func (l *ledger) TakeOverReconciliation(_ context.Context, in *pb.TakeOverReconciliationReq, _ ...grpc.CallOption) (*pb.ReconciliationResp, error) {
	r := l.recon[in.GetName()]
	if r == nil || r.finished || (r.owner != in.GetOwner() && !r.claimed.Before(in.GetStaleBefore().AsTime())) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.owner, r.claimed = in.GetOwner(), l.reconNow()
	return &pb.ReconciliationResp{Name: in.GetName()}, nil
}

func (l *ledger) RenewReconciliation(_ context.Context, in *pb.ReconciliationOwnerReq, _ ...grpc.CallOption) (*pb.ReconciliationResp, error) {
	r := l.recon[in.GetName()]
	if r == nil || r.finished || r.owner != in.GetOwner() {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.claimed = l.reconNow()
	return &pb.ReconciliationResp{Name: in.GetName()}, nil
}

func (l *ledger) FinishReconciliation(_ context.Context, in *pb.ReconciliationOwnerReq, _ ...grpc.CallOption) (*pb.ReconciliationResp, error) {
	r := l.recon[in.GetName()]
	if r == nil || r.finished || r.owner != in.GetOwner() {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.finished = true
	return &pb.ReconciliationResp{Name: in.GetName()}, nil
}

func (l *ledger) GetReconciliation(_ context.Context, in *pb.GetReconciliationReq, _ ...grpc.CallOption) (*pb.GetReconciliationResp, error) {
	r := l.recon[in.GetName()]
	if r == nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	out := &pb.GetReconciliationResp{Name: in.GetName(), ClaimedAt: timestamppb.New(r.claimed)}
	if r.finished {
		out.FinishedAt = timestamppb.Now()
	}
	return out, nil
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
	return &brevoTool{client: f, sel: sel, consentAttr: "W17_MARKETING_CONSENT", events: true, query: l, mutation: l}
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
// own properties with the org and the account type it acted in. Nothing on
// the contact: not the org (the request's, not the person's), and not the
// consent (the request's snapshot; the attribute comes from the Contact row).
func TestEventFor(t *testing.T) {
	consent := true
	meta := &w17pb.RequestEventMeta{
		Id: []byte{1}, Method: createTask, Route: "/api/v1/tasks", HttpStatus: 201,
		DurationMicros: 12500, Api: w17pb.RequestApi_REQUEST_API_REST,
		UserId: "u1", OrgId: "o1", MembershipKind: "client", MarketingConsent: proto.Bool(consent), Truncated: true,
		Start:  timestamppb.New(time.Date(2026, 10, 19, 9, 0, 0, 0, time.UTC)),
		Client: &w17pb.RequestClient{Ip: "10.0.0.1", UserAgent: "ua", Referrer: "https://x.example", Utm: map[string]string{"source": "news", "camp aign": "q4"}},
	}
	ev, ok := eventFor(meta)
	if !ok {
		t.Fatal("not sent")
	}
	if ev.EventName != "TasksBusiness_CreateTask" || ev.Identifiers.ExtID != "u1" || ev.EventDate != "2026-10-19T09:00:00Z" {
		t.Errorf("event = %+v", ev)
	}
	want := map[string]any{
		"w17_api": "rest", "w17_duration_ms": int64(12), "w17_status": int32(201), "w17_route": "/api/v1/tasks",
		"w17_truncated": true, "utm_source": "news", "utm_camp_aign": "q4", "referrer": "https://x.example",
		"w17_org_id": "o1", "w17_account_type": "client",
	}
	if fmt.Sprint(ev.EventProperties) != fmt.Sprint(want) {
		t.Errorf("properties = %v\nwant         %v", ev.EventProperties, want)
	}
	for _, leaked := range []string{"10.0.0.1", "ua"} {
		if strings.Contains(fmt.Sprint(ev), leaked) {
			t.Errorf("the IP or user agent reached Brevo: %v", ev)
		}
	}
	if len(ev.ContactProperties) != 0 {
		t.Errorf("contact = %v, want nothing written to the contact", ev.ContactProperties)
	}
	// A project without organizations or kinds: neither property, not empty
	// ones.
	bare := proto.Clone(meta).(*w17pb.RequestEventMeta)
	bare.OrgId, bare.MembershipKind = "", ""
	if ev, _ := eventFor(bare); ev.EventProperties["w17_org_id"] != nil || ev.EventProperties["w17_account_type"] != nil {
		t.Errorf("no org, no kind: properties = %v", ev.EventProperties)
	}
	if _, ok := eventFor(&w17pb.RequestEventMeta{Method: createTask}); ok {
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
	_ = tl.onConsentChanged(ctx, &pb.AuthMarketingConsentChanged{UserId: "u1", Consent: false, DecidedAt: timestamppb.Now()})
	_ = tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"})
	// Unknown at sign-up: created. Known: updated by its id, the address as
	// EMAIL — an upsert by POST cannot change an address (Brevo refuses the
	// ext_id as taken). Never consented: blacklisted throughout.
	if strings.Join(f.upserts, ";") != "u1|a@x.example|map[]|bl=true" {
		t.Errorf("upserts = %v", f.upserts)
	}
	// The consent attribute is dated by the decision.
	want := []string{"u1|map[EMAIL:b@x.example]|bl=true", "u1|map[W17_MARKETING_CONSENT:false W17_MARKETING_CONSENT_AT:" + brevoDate(time.Now()) + "]|bl=true"}
	if strings.Join(f.updates, ";") != strings.Join(want, ";") {
		t.Errorf("updates = %v\nwant      %v", f.updates, want)
	}
	if len(f.deletes) != 1 || f.deletes[0] != "u1" {
		t.Errorf("deletes = %v", f.deletes)
	}
}

// The consent for a user Brevo does not know yet creates the contact with it.
func TestContacts_ConsentBeforeTheContactCreatesIt(t *testing.T) {
	f := &fakeBrevo{}
	_ = tool(t, f, &ledger{}, "all", "", "").onConsentChanged(context.Background(), &pb.AuthMarketingConsentChanged{UserId: "u2", Consent: true, DecidedAt: timestamppb.Now()})
	if strings.Join(f.upserts, ";") != "u2||map[W17_MARKETING_CONSENT:true W17_MARKETING_CONSENT_AT:"+brevoDate(time.Now())+"]|bl=false" {
		t.Errorf("upserts = %v", f.upserts)
	}
}

// The attributes the plugin writes are created: Brevo drops an attribute the
// account has not created, silently. With brevo_attributes, also one date per
// method the selection sends, and the last activity's time.
func TestEnsureAttributes(t *testing.T) {
	for _, c := range []struct {
		name       string
		attributes bool
		send       string
		want       string
	}{
		{"brevo_events", false, "all", "W17_MARKETING_CONSENT:boolean,W17_MARKETING_CONSENT_AT:date,W17_SIGNED_UP_AT:date"},
		{"brevo_attributes, every method", true, "all", "W17_MARKETING_CONSENT:boolean,W17_MARKETING_CONSENT_AT:date,W17_SIGNED_UP_AT:date," +
			"W17_LAST_ACTIVITY_AT:text,W17_TASKSBUSINESS_CREATETASK:date,W17_TASKSBUSINESS_GETTASK:date"},
		{"brevo_attributes, mutations", true, "mutations", "W17_MARKETING_CONSENT:boolean,W17_MARKETING_CONSENT_AT:date,W17_SIGNED_UP_AT:date," +
			"W17_LAST_ACTIVITY_AT:text,W17_TASKSBUSINESS_CREATETASK:date"},
	} {
		f := &fakeBrevo{}
		tl := tool(t, f, &ledger{}, c.send, "", "")
		tl.attributes = c.attributes
		stop := tl.ensureAttributes(time.Millisecond)
		want := strings.Count(c.want, ",") + 1
		deadline := time.Now().Add(2 * time.Second)
		for len(f.ensuredSoFar()) < want && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		stop()
		if got := strings.Join(f.ensuredSoFar(), ","); got != c.want {
			t.Errorf("%s: ensured = %v\nwant %v", c.name, got, c.want)
		}
	}
}

// An attribute Brevo did not create is asked for again, and only it.
func TestEnsureAttributes_RetriesOnlyWhatFailed(t *testing.T) {
	f := &fakeBrevo{ensureFails: map[string]int{"W17_SIGNED_UP_AT": 2}}
	stop := tool(t, f, &ledger{}, "all", "", "").ensureAttributes(time.Millisecond)
	defer stop()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.ensuredSoFar()) < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // nothing more is asked once all exist
	want := "W17_MARKETING_CONSENT:boolean,W17_MARKETING_CONSENT_AT:date,W17_SIGNED_UP_AT:date,W17_SIGNED_UP_AT:date,W17_SIGNED_UP_AT:date"
	if got := strings.Join(f.ensuredSoFar(), ","); got != want {
		t.Errorf("ensured = %v\nwant %v", got, want)
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
	// A key or a server address the account does not accept is the
	// operator's to fix; what was sent meanwhile is kept for the replay.
	for _, st := range []int{401, 403} {
		denied := tool(t, &fakeBrevo{callErr: &brevo.Error{Status: st, Message: "We have detected you are using an unrecognised IP address"}}, &ledger{}, "all", "", "")
		if err := denied.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err == nil {
			t.Errorf("a %d was dropped — the contact would never reach Brevo once the account allows the server", st)
		}
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

// brevo/consent-from-the-row: an event writes nothing to the contact — the
// consent attribute in particular comes only from the Contact row, dated —
// so a record made before a withdrawal and delivered after it cannot move the
// attribute back.
func TestEventFor_WritesNothingToTheContact(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	tl := tool(t, f, l, "all", "", "")
	ctx := context.Background()
	if err := tl.onConsentChanged(ctx, consentEvent("u1", false, day2)); err != nil {
		t.Fatal(err)
	}
	r := record(1, createTask, "u1")
	r.Meta.MarketingConsent = proto.Bool(true) // authenticated before the withdrawal
	if err := tl.ConsumeMarketing(ctx, batch(r)); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 1 || len(f.batches[0]) != 1 {
		t.Fatalf("batches = %+v", f.batches)
	}
	if cp := f.batches[0][0].ContactProperties; len(cp) != 0 {
		t.Errorf("the event writes to the contact: %v (the kept decision is a no: %+v)", cp, l.contacts["u1"])
	}
}

// The attributes the auth events write exist before the plugin subscribes to
// them: prepareAttributes creates them before it returns (setupBrevo calls it
// before any registration), so a sign-up handled in the first moments of a
// fresh account does not write W17_SIGNED_UP_AT into the void, which Brevo
// drops silently and nothing writes again. The activity attributes, and a
// fixed one Brevo did not create, follow in the background.
func TestPrepareAttributes_TheFixedOnesBeforeItReturns(t *testing.T) {
	f := &fakeBrevo{ensureFails: map[string]int{"W17_MARKETING_CONSENT_AT": 1}}
	tl := tool(t, f, &ledger{}, "all", "", "")
	tl.attributes = true
	stop := tl.prepareAttributes(time.Second, time.Millisecond)
	defer stop()
	got := f.ensuredSoFar()
	want := []string{"W17_MARKETING_CONSENT:boolean", "W17_MARKETING_CONSENT_AT:date", "W17_SIGNED_UP_AT:date"}
	if len(got) < len(want) || strings.Join(got[:3], ",") != strings.Join(want, ",") {
		t.Fatalf("ensured when prepareAttributes returned = %v, want %v first", got, want)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !contains(f.ensuredSoFar(), "W17_TASKSBUSINESS_CREATETASK:date") || count(f.ensuredSoFar(), "W17_MARKETING_CONSENT_AT:date") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("the background did not create the rest: %v", f.ensuredSoFar())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A Brevo that does not answer holds the boot up for the bound at most; the
// attributes are then created in the background.
func TestPrepareAttributes_AnUnansweringBrevoHoldsTheBootForTheBoundOnly(t *testing.T) {
	f := &fakeBrevo{ensureBlocks: true}
	tl := tool(t, f, &ledger{}, "all", "", "")
	start := time.Now()
	stop := tl.prepareAttributes(50*time.Millisecond, time.Hour)
	stop()
	if d := time.Since(start); d > time.Second {
		t.Errorf("prepareAttributes took %v with a bound of 50ms", d)
	}
}

func contains(xs []string, x string) bool { return count(xs, x) > 0 }

func count(xs []string, x string) int {
	n := 0
	for _, v := range xs {
		if v == x {
			n++
		}
	}
	return n
}

// A contact write Brevo refuses for its content (400/422) is not retried —
// retrying fails the same way — but it is reported as a fault, not only
// logged: the contact then lacks its address and, for UserCreated, its
// sign-up date, which nothing writes again (SPEC gap 7).
func TestContacts_ARefusedContactWriteIsReported(t *testing.T) {
	var reported []error
	defer func(prev func(context.Context, error)) { reportFault = prev }(reportFault)
	reportFault = func(_ context.Context, err error) { reported = append(reported, err) }

	ctx := context.Background()
	refused := tool(t, &fakeBrevo{callErr: &brevo.Error{Status: 400, Message: "duplicate_parameter"}}, &ledger{}, "all", "", "")
	if err := refused.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err != nil {
		t.Fatalf("a refusal = %v, want nil", err)
	}
	if len(reported) != 1 || !strings.Contains(reported[0].Error(), "u1") || !brevo.Refused(reported[0]) {
		t.Errorf("reported = %v, want the one refusal, naming the user", reported)
	}
	reported = nil
	transient := tool(t, &fakeBrevo{callErr: &brevo.Error{Status: 503}}, &ledger{}, "all", "", "")
	if err := transient.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u2", Email: "b@x.example"}); err == nil {
		t.Fatal("a transient failure was swallowed")
	}
	if len(reported) != 0 {
		t.Errorf("a transient failure (redelivered) was reported as a lost write: %v", reported)
	}
}

// Recording one sent record failing does not resend the rest of its chunk:
// every record Brevo answered for is recorded, a failed record is tried
// again at once, and only one that still fails is left for the redelivery —
// which then sends it alone, not what came after it in the chunk.
func TestConsumeMarketing_AFailedRecordResendsOnlyItself(t *testing.T) {
	f, l := &fakeBrevo{}, &ledger{sent: map[string]bool{}, recordFails: map[string]int{"02": 1}}
	tl := tool(t, f, l, "all", "", "")
	b := batch(record(1, createTask, "u1"), record(2, createTask, "u1"), record(3, createTask, "u1"))
	if err := tl.ConsumeMarketing(context.Background(), b); err != nil {
		t.Fatalf("a record that failed once and then landed: %v", err)
	}
	if len(f.batches) != 1 || !l.sent["01"] || !l.sent["02"] || !l.sent["03"] {
		t.Fatalf("batches %d, sent %v; want one batch and all three recorded", len(f.batches), l.sent)
	}

	f, l = &fakeBrevo{}, &ledger{sent: map[string]bool{}, recordFails: map[string]int{"02": 1000}}
	tl = tool(t, f, l, "all", "", "")
	if err := tl.ConsumeMarketing(context.Background(), b); err == nil {
		t.Fatal("a record that cannot be recorded returned nil — it would be resent with no error")
	}
	if !l.sent["01"] || !l.sent["03"] || l.sent["02"] {
		t.Fatalf("sent = %v; want 01 and 03 recorded although 02 failed", l.sent)
	}
	l.recordFails = nil
	if err := tl.ConsumeMarketing(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 2 || len(f.batches[1]) != 1 {
		t.Errorf("the redelivery sent %d batches, the last of %d events; want the one unrecorded event alone", len(f.batches), len(f.batches[len(f.batches)-1]))
	}
}

// brevo/no-personal-extras: the referrer goes to Brevo as its origin and
// path only — a query string or fragment can carry an address, a token, a
// document's name — and a UTM value is bounded, so a personalised link does
// not ship its parameters into the marketing tool with every request.
func TestEventFor_TheReferrerWithoutItsQueryAndBoundedUTM(t *testing.T) {
	long := strings.Repeat("x", 600)
	ev, ok := eventFor(&w17pb.RequestEventMeta{
		UserId: "u1", Method: createTask,
		Client: &w17pb.RequestClient{
			Referrer: "https://mail.example/inbox/doc.pdf?to=a%40x.example&token=s3cret#p2",
			Utm:      map[string]string{"source": "news", "content": long, long: "v"},
		},
	})
	if !ok {
		t.Fatal("no event")
	}
	if got := ev.EventProperties["referrer"]; got != "https://mail.example/inbox/doc.pdf" {
		t.Errorf("referrer = %v, want its origin and path only", got)
	}
	if got, _ := ev.EventProperties["utm_content"].(string); len(got) != maxUTMValue {
		t.Errorf("utm_content has %d characters, want it cut at %d", len(got), maxUTMValue)
	}
	for k := range ev.EventProperties {
		if len(k) > 4+maxUTMValue {
			t.Errorf("a property name of %d characters", len(k))
		}
	}
	if ev.EventProperties["utm_source"] != "news" {
		t.Errorf("utm_source = %v", ev.EventProperties["utm_source"])
	}
	ev, _ = eventFor(&w17pb.RequestEventMeta{UserId: "u1", Method: createTask, Client: &w17pb.RequestClient{Referrer: "not a url\x7f"}})
	if r, ok := ev.EventProperties["referrer"]; ok {
		t.Errorf("an unparsable referrer was sent: %v", r)
	}
}

// A consent event without decided_at cannot be ordered against the decision
// kept: dated by its handling it would be the newest on every redelivery, and
// an older no (or yes) delivered again would overwrite a newer decision. It is
// acknowledged and changes nothing. (auth always dates the decision.)
func TestConsent_AnUndatedDecisionIsIgnored(t *testing.T) {
	f := &fakeBrevo{known: map[string]bool{"u1": true}}
	l := &ledger{contacts: map[string]*pb.ContactRow{"u1": {UserId: "u1", Consent: true, ConsentAt: timestamppb.New(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))}}}
	if err := tool(t, f, l, "all", "", "").onConsentChanged(context.Background(), &pb.AuthMarketingConsentChanged{UserId: "u1", Consent: false}); err != nil {
		t.Fatalf("an undated decision: %v, want it acknowledged", err)
	}
	if c := l.contacts["u1"]; !c.GetConsent() || !c.GetConsentAt().AsTime().Equal(time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("row = %+v, want the dated yes kept", c)
	}
	if len(f.updates)+len(f.upserts) != 0 {
		t.Errorf("an undated decision wrote to Brevo: %v %v", f.updates, f.upserts)
	}
}
