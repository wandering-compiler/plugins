package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wandering-compiler/sdk/go/lib/eventlog"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

// attrTool is the tool with brevo_attributes, and brevo_events as given.
func attrTool(t *testing.T, f *fakeBrevo, l *ledger, events bool) *brevoTool {
	t.Helper()
	tl := tool(t, f, l, "all", "", "")
	tl.events, tl.attributes = events, true
	return tl
}

func recordAt(id byte, method, user string, at time.Time) eventlog.ConsumedRecord {
	r := record(id, method, user)
	r.Meta.Start = timestamppb.New(at)
	return r
}

var (
	monday  = time.Date(2026, 11, 9, 14, 30, 5, 0, time.UTC)
	tuesday = time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
)

// brevo_attributes/date-per-method: with attributes only, a record moves its
// method's date attribute and the last activity's time, and sends no event;
// a contact Brevo lacks is created blacklisted.
func TestActivity_AttributesOnlyMoveTheDatesAndSendNoEvent(t *testing.T) {
	f, l := &fakeBrevo{}, &ledger{sent: map[string]bool{}}
	tl := attrTool(t, f, l, false)
	if err := tl.ConsumeMarketing(context.Background(), batch(
		recordAt(1, createTask, "u1", monday),
		recordAt(2, getTask, "u1", monday.Add(-time.Hour)),
	)); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 0 || len(l.sent) != 0 {
		t.Errorf("events sent: %v (recorded %v), want none", f.batches, l.sent)
	}
	want := "u1||map[W17_LAST_ACTIVITY_AT:2026-11-09T14:30:05Z W17_TASKSBUSINESS_CREATETASK:2026-11-09 W17_TASKSBUSINESS_GETTASK:2026-11-09]|bl=true"
	if got := strings.Join(f.upserts, ";"); got != want {
		t.Errorf("upserts = %s\nwant      %s", got, want)
	}
}

// brevo_attributes/both: with both, the batch is written as attributes and
// sent as events.
func TestActivity_BothWriteTheAttributesAndSendTheEvents(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	if err := attrTool(t, f, l, true).ConsumeMarketing(context.Background(), batch(recordAt(1, createTask, "u1", monday))); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 1 || len(f.batches[0]) != 1 || f.batches[0][0].EventName != "TasksBusiness_CreateTask" {
		t.Errorf("events = %v, want the one event", f.batches)
	}
	if want := "u1|map[W17_LAST_ACTIVITY_AT:2026-11-09T14:30:05Z W17_TASKSBUSINESS_CREATETASK:2026-11-09]|bl=unset"; last(f.updates) != want {
		t.Errorf("update = %s\nwant     %s", last(f.updates), want)
	}
}

// brevo_attributes/never-back: a record older than the date kept — a
// redelivery overtaken by a newer batch — leaves the newer date in Brevo.
func TestActivity_AnOlderRecordDoesNotMoveADateBack(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	tl := attrTool(t, f, l, false)
	ctx := context.Background()
	if err := tl.ConsumeMarketing(ctx, batch(recordAt(2, createTask, "u1", tuesday))); err != nil {
		t.Fatal(err)
	}
	if err := tl.ConsumeMarketing(ctx, batch(recordAt(1, createTask, "u1", monday))); err != nil {
		t.Fatal(err)
	}
	if want := "u1|map[W17_LAST_ACTIVITY_AT:2026-11-10T08:00:00Z W17_TASKSBUSINESS_CREATETASK:2026-11-10]|bl=unset"; last(f.updates) != want {
		t.Errorf("Brevo holds %s\nwant           %s", last(f.updates), want)
	}
	if got := l.activity["u1"][activityAttr(createTask)]; !got.Equal(tuesday) {
		t.Errorf("kept %v, want tuesday", got)
	}
}

// brevo_attributes/never-back: a row another replica moves while this one
// writes the contact is written again, so Brevo ends on the newer date.
func TestActivity_ARowMovedDuringTheWriteIsWrittenAgain(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	l.afterActivityRead = func() { l.activity["u1"][activityAttr(createTask)] = tuesday }
	if err := attrTool(t, f, l, false).ConsumeMarketing(context.Background(), batch(recordAt(1, createTask, "u1", monday))); err != nil {
		t.Fatal(err)
	}
	if len(f.updates) != 2 {
		t.Fatalf("updates = %v, want the monday write and the tuesday one after it", f.updates)
	}
	if want := "u1|map[W17_LAST_ACTIVITY_AT:2026-11-10T08:00:00Z W17_TASKSBUSINESS_CREATETASK:2026-11-10]|bl=unset"; last(f.updates) != want {
		t.Errorf("Brevo ends on %s\nwant          %s", last(f.updates), want)
	}
}

// brevo_attributes/erasure: an erased user's late record writes nothing, and
// UserDeleted forgets what the user did.
func TestActivity_AnErasedUserIsNotWrittenAndForgotten(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	tl := attrTool(t, f, l, false)
	ctx := context.Background()
	if err := tl.ConsumeMarketing(ctx, batch(recordAt(1, createTask, "u1", monday))); err != nil {
		t.Fatal(err)
	}
	if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
		t.Fatal(err)
	}
	if _, kept := l.activity["u1"]; kept {
		t.Errorf("activity of the erased user kept: %v", l.activity["u1"])
	}
	writes := len(f.updates) + len(f.upserts)
	if err := tl.ConsumeMarketing(ctx, batch(recordAt(2, createTask, "u1", tuesday))); err != nil {
		t.Fatal(err)
	}
	if len(f.updates)+len(f.upserts) != writes || l.activity["u1"] != nil {
		t.Errorf("a late record of the erased user was written: %v %v", f.updates, l.activity["u1"])
	}
}

// brevo_attributes/transient-is-redelivered: a failure writing the attributes
// fails the batch before any event is sent, so its redelivery sends each once.
func TestActivity_AFailureSendsNoEventAndIsRedelivered(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}, callErr: &brevo.Error{Status: 503}}, &ledger{sent: map[string]bool{}}
	err := attrTool(t, f, l, true).ConsumeMarketing(context.Background(), batch(recordAt(1, createTask, "u1", monday)))
	var be *brevo.Error
	if !errors.As(err, &be) || be.Status != 503 {
		t.Fatalf("err = %v, want the 503 returned for a redelivery", err)
	}
	if len(f.batches) != 0 || len(l.sent) != 0 {
		t.Errorf("events sent before the attributes were written: %v", f.batches)
	}
}

// brevo_attributes/transient-is-redelivered: a failure of the Activity table
// fails the batch before anything reaches Brevo, and records nothing as sent.
func TestActivity_ATableFailureWritesNothing(t *testing.T) {
	f := &fakeBrevo{known: map[string]bool{"u1": true}}
	l := &ledger{sent: map[string]bool{}, writeErr: errors.New("db down")}
	err := attrTool(t, f, l, true).ConsumeMarketing(context.Background(), batch(recordAt(1, createTask, "u1", monday)))
	if err == nil {
		t.Fatal("a table failure was swallowed")
	}
	if len(f.batches)+len(f.updates)+len(f.upserts) != 0 || len(l.sent) != 0 {
		t.Errorf("Brevo was written on a table failure: batches=%v updates=%v upserts=%v", f.batches, f.updates, f.upserts)
	}
}

// brevo_attributes/selection: only what send / include / exclude let through
// moves an attribute.
func TestActivity_FollowsTheSelection(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{sent: map[string]bool{}}
	tl := tool(t, f, l, "mutations", "", "")
	tl.events, tl.attributes = false, true
	if err := tl.ConsumeMarketing(context.Background(), batch(recordAt(1, getTask, "u1", monday))); err != nil {
		t.Fatal(err)
	}
	if len(f.updates)+len(f.upserts) != 0 || len(l.activity) != 0 {
		t.Errorf("a query under send=mutations moved an attribute: %v %v", f.updates, l.activity)
	}
}

func TestActivityAttr(t *testing.T) {
	for in, want := range map[string]string{
		createTask:                         "W17_TASKSBUSINESS_CREATETASK",
		"/a.b.My-Svc/Do.It":                "W17_MY_SVC_DO_IT",
		"/e2e.app.auth.AuthService/SignUp": "W17_AUTHSERVICE_SIGNUP",
	} {
		if got := activityAttr(in); got != want {
			t.Errorf("activityAttr(%q) = %q, want %q", in, got, want)
		}
	}
}

// brevo/dated-contact: the contact carries the day the account was created.
func TestContacts_CarryTheSignUpDate(t *testing.T) {
	f := &fakeBrevo{}
	ev := &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example", CreatedAt: timestamppb.New(monday)}
	if err := tool(t, f, &ledger{}, "all", "", "").onUserCreated(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	if want := "u1|a@x.example|map[W17_SIGNED_UP_AT:2026-11-09]|bl=true"; strings.Join(f.upserts, ";") != want {
		t.Errorf("upserts = %v, want %s", f.upserts, want)
	}
}

// brevo/events-by-default: brevo_events and brevo_attributes choose; naming
// neither keeps the events brevo always sent, and only brevo_attributes
// without brevo_events turns them off.
func TestSendsEvents(t *testing.T) {
	for _, c := range []struct{ events, attributes, want bool }{
		{false, false, true}, // brevo alone, as before the choice existed
		{true, false, true},
		{false, true, false}, // attributes only
		{true, true, true},
	} {
		if got := sendsEvents(c.events, c.attributes); got != c.want {
			t.Errorf("brevo_events=%v brevo_attributes=%v: events %v, want %v", c.events, c.attributes, got, c.want)
		}
	}
}
