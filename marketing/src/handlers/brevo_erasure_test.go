package handlers

import (
	"context"
	"testing"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
)

// brevo/erasure on every path that writes to Brevo: the request records
// (events, attributes) and the auth events (contacts). A late or replayed
// write of an erased user must not bring their contact back — an event alone
// creates it (measured), and an update of a deleted contact falls back to
// creating it.

func erasedFixture(t *testing.T, tl *brevoTool) {
	t.Helper()
	ctx := context.Background()
	if err := tl.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err != nil {
		t.Fatal(err)
	}
	if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
		t.Fatal(err)
	}
}

// A record of an erased user — late in the stream, redelivered, or replayed
// from the dead-letter stream — sends no event, with events alone and with
// both features.
func TestConsumeMarketing_AnErasedUsersRecordSendsNoEvent(t *testing.T) {
	for _, both := range []bool{false, true} {
		f, l := &fakeBrevo{}, &ledger{sent: map[string]bool{}}
		tl := tool(t, f, l, "all", "", "")
		if both {
			tl = attrTool(t, f, l, true)
		}
		erasedFixture(t, tl)
		if err := tl.ConsumeMarketing(context.Background(), batch(recordAt(1, createTask, "u1", monday), recordAt(2, createTask, "u2", monday))); err != nil {
			t.Fatal(err)
		}
		for _, b := range f.batches {
			for _, ev := range b {
				if ev.Identifiers.ExtID == "u1" {
					t.Errorf("both=%v: a record of the erased user was sent: %+v", both, ev)
				}
			}
		}
		if f.known["u1"] {
			t.Errorf("both=%v: the erased user's contact exists in Brevo again", both)
		}
		if !f.known["u2"] {
			t.Errorf("both=%v: the other user's record was not sent", both)
		}
	}
}

// An erasure that lands while a batch is being sent (after the batch read
// the rows, before Brevo took the events) is not undone by it: the contact
// the events created again is deleted.
func TestConsumeMarketing_AnErasureDuringTheSendIsNotUndone(t *testing.T) {
	for _, both := range []bool{false, true} {
		f, l := &fakeBrevo{}, &ledger{sent: map[string]bool{}}
		tl := tool(t, f, l, "all", "", "")
		if both {
			tl = attrTool(t, f, l, true)
		}
		ctx := context.Background()
		if err := tl.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err != nil {
			t.Fatal(err)
		}
		erase := func() {
			if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
				t.Fatal(err)
			}
		}
		if both {
			f.onUpdate = erase // the attributes are written first
		} else {
			f.onSend = erase
		}
		if err := tl.ConsumeMarketing(ctx, batch(recordAt(1, createTask, "u1", monday))); err != nil {
			t.Fatal(err)
		}
		if f.known["u1"] {
			t.Errorf("both=%v: the erased user's contact exists in Brevo after the batch", both)
		}
		if both && l.activity["u1"] != nil {
			t.Errorf("the erased user's activity was kept: %v", l.activity["u1"])
		}
	}
}

// The same for the auth events: an erasure landing while an address or a
// consent is being written to Brevo is not undone by that write.
func TestContacts_AnErasureDuringTheWriteIsNotUndone(t *testing.T) {
	ctx := context.Background()
	t.Run("address", func(t *testing.T) {
		f, l := &fakeBrevo{}, &ledger{}
		tl := tool(t, f, l, "all", "", "")
		f.onUpdate = func() {
			if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tl.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err != nil {
			t.Fatal(err)
		}
		if f.known["u1"] {
			t.Error("the erased user's contact exists in Brevo after UserCreated")
		}
	})
	t.Run("consent", func(t *testing.T) {
		f, l := &fakeBrevo{}, &ledger{}
		tl := tool(t, f, l, "all", "", "")
		f.onGet = func() {
			if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tl.onConsentChanged(ctx, consentEvent("u1", true, day1)); err != nil {
			t.Fatal(err)
		}
		if f.known["u1"] {
			t.Error("the erased user's contact exists in Brevo after the consent")
		}
	})
}
