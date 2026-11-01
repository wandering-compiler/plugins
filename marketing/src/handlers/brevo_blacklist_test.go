package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/marketing/gen/pb"
	"github.com/wandering-compiler/plugins/marketing/lib/brevo"
)

var (
	day1 = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	day2 = day1.Add(24 * time.Hour)
	day3 = day2.Add(24 * time.Hour)
)

func consentEvent(user string, consent bool, at time.Time) *pb.AuthMarketingConsentChanged {
	return &pb.AuthMarketingConsentChanged{UserId: user, Consent: consent, DecidedAt: timestamppb.New(at)}
}

func last(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

// brevo/blacklisted-without-consent: a new account's contact is created
// blacklisted — its consent is unknown, which is no consent — and without a
// consent attribute, since an unknown consent is not a false one.
func TestContacts_ANewAccountIsBlacklisted(t *testing.T) {
	f, l := &fakeBrevo{}, &ledger{}
	if err := tool(t, f, l, "all", "", "").onUserCreated(context.Background(), &pb.AuthUserCreated{UserId: "u1", Email: "A@X.example"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.upserts, ";") != "u1|A@X.example|map[]|bl=true" {
		t.Errorf("upserts = %v, want the contact created blacklisted, no consent attribute", f.upserts)
	}
	if l.contacts["u1"].GetEmail() != "a@x.example" {
		t.Errorf("kept address = %q, want it lower-cased", l.contacts["u1"].GetEmail())
	}
}

// brevo/blacklisted-without-consent: the consent sets the attribute and
// emailBlacklisted = !consent, together, in one write.
func TestConsent_SetsEmailBlacklistedWithTheAttribute(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{}
	tl := tool(t, f, l, "all", "", "")
	ctx := context.Background()
	if err := tl.onConsentChanged(ctx, consentEvent("u1", true, day1)); err != nil {
		t.Fatal(err)
	}
	if got := last(f.updates); got != "u1|map[W17_MARKETING_CONSENT:true]|bl=false" {
		t.Errorf("consent given: %s", got)
	}
	if err := tl.onConsentChanged(ctx, consentEvent("u1", false, day2)); err != nil {
		t.Fatal(err)
	}
	if got := last(f.updates); got != "u1|map[W17_MARKETING_CONSENT:false]|bl=true" {
		t.Errorf("consent withdrawn: %s", got)
	}
}

// brevo/address-change-keeps-subscription: an address change carries the
// blacklist status the user's known consent gives — never subscribed without
// a consent, subscribed with one, and not again after an unsubscribe in
// Brevo the consent predates.
func TestContacts_AnAddressChangeNeverSubscribes(t *testing.T) {
	for _, c := range []struct {
		name  string
		state *pb.ContactRow
		want  string
	}{
		{"no state (an account from before the plugin kept any)", nil, "bl=true"},
		{"consent unknown", &pb.ContactRow{UserId: "u1", Email: "a@x.example"}, "bl=true"},
		{"consent refused", &pb.ContactRow{UserId: "u1", Consent: false, ConsentAt: timestamppb.New(day1)}, "bl=true"},
		{"consent given", &pb.ContactRow{UserId: "u1", Consent: true, ConsentAt: timestamppb.New(day1)}, "bl=false"},
		{"unsubscribed in Brevo after consenting", &pb.ContactRow{UserId: "u1", Consent: true, ConsentAt: timestamppb.New(day1), UnsubscribedAt: timestamppb.New(day2)}, "bl=true"},
		{"consented again after unsubscribing", &pb.ContactRow{UserId: "u1", Consent: true, ConsentAt: timestamppb.New(day3), UnsubscribedAt: timestamppb.New(day2)}, "bl=false"},
	} {
		f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{}
		if c.state != nil {
			l.contacts = map[string]*pb.ContactRow{"u1": c.state}
		}
		if err := tool(t, f, l, "all", "", "").onUserUpdated(context.Background(), &pb.AuthUserUpdated{UserId: "u1", Email: "new@x.example"}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if want := "u1|map[EMAIL:new@x.example]|" + c.want; last(f.updates) != want {
			t.Errorf("%s: %s, want %s", c.name, last(f.updates), want)
		}
		if l.contacts["u1"].GetEmail() != "new@x.example" {
			t.Errorf("%s: the new address was not kept", c.name)
		}
	}
}

// brevo/address-change-keeps-subscription: a decision older than the one on
// record (a redelivery overtaken by a newer event) leaves the newer standing.
func TestConsent_AnOlderDecisionDoesNotOverwriteANewerOne(t *testing.T) {
	f := &fakeBrevo{known: map[string]bool{"u1": true}}
	l := &ledger{contacts: map[string]*pb.ContactRow{"u1": {UserId: "u1", Consent: false, ConsentAt: timestamppb.New(day2)}}}
	if err := tool(t, f, l, "all", "", "").onConsentChanged(context.Background(), consentEvent("u1", true, day1)); err != nil {
		t.Fatal(err)
	}
	if c := l.contacts["u1"]; c.GetConsent() || !c.GetConsentAt().AsTime().Equal(day2) {
		t.Errorf("state = %+v, want the newer withdrawal kept", c)
	}
	if got := last(f.updates); got != "u1|map[W17_MARKETING_CONSENT:false]|bl=true" {
		t.Errorf("Brevo got %s, want the newer withdrawal", got)
	}
}

// brevo/erasure: the plugin's row loses the address on UserDeleted, and a
// late event of the erased user writes nothing to Brevo.
func TestContacts_AnErasedUserIsNotWrittenAgain(t *testing.T) {
	f, l := &fakeBrevo{known: map[string]bool{"u1": true}}, &ledger{}
	tl := tool(t, f, l, "all", "", "")
	ctx := context.Background()
	_ = tl.onUserCreated(ctx, &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"})
	if err := tl.onUserDeleted(ctx, &pb.AuthUserDeleted{UserId: "u1"}); err != nil {
		t.Fatal(err)
	}
	if c := l.contacts["u1"]; c.GetEmail() != "" || c.GetErasedAt() == nil {
		t.Errorf("state after erasure = %+v, want no address and erased_at", c)
	}
	n := len(f.updates) + len(f.upserts)
	_ = tl.onUserUpdated(ctx, &pb.AuthUserUpdated{UserId: "u1", Email: "b@x.example"})
	_ = tl.onConsentChanged(ctx, consentEvent("u1", true, day3))
	if len(f.updates)+len(f.upserts) != n {
		t.Errorf("an erased user's late events reached Brevo: %v %v", f.upserts, f.updates)
	}
}

// A failure of the plugin's own table is retried (an error to the stream),
// and Brevo is not written without it: the blacklist status would be a guess.
func TestContacts_AStateFailureIsRetried(t *testing.T) {
	f, l := &fakeBrevo{}, &ledger{writeErr: errors.New("db down")}
	tl := tool(t, f, l, "all", "", "")
	if err := tl.onUserCreated(context.Background(), &pb.AuthUserCreated{UserId: "u1", Email: "a@x.example"}); err == nil {
		t.Error("a failed state write was swallowed")
	}
	if err := tl.onConsentChanged(context.Background(), consentEvent("u1", true, day1)); err == nil {
		t.Error("a failed consent write was swallowed")
	}
	if len(f.upserts)+len(f.updates) != 0 {
		t.Errorf("Brevo was written without the state: %v %v", f.upserts, f.updates)
	}
}

// ── brevo_webhook ───────────────────────────────────────────────────────

type hookCalls struct {
	got []string
	err error
}

func (h *hookCalls) fn(_ context.Context, req *pb.ConsentWithdrawnReq) (*pb.ConsentWithdrawnResp, error) {
	h.got = append(h.got, req.GetUserId()+"@"+req.GetWithdrawnAt().AsTime().Format(time.RFC3339))
	return &pb.ConsentWithdrawnResp{}, h.err
}

func webhook(t *testing.T, l *ledger, token string, h *hookCalls) *brevoWebhook {
	t.Helper()
	w := &brevoWebhook{token: token, tool: tool(t, &fakeBrevo{}, l, "all", "", "")}
	if h != nil {
		w.hooks = append(w.hooks, h.fn)
	}
	return w
}

func withToken(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(brevoWebhookTokenKey, token))
}

const unsubscribe = `{"id":1,"camp_id":7,"email":"A@X.example","event":"unsubscribe","date_event":"2026-10-02 09:00:00","ts_event":1791018000}`

// brevo_webhook/authenticated: a call without the token, with another, or
// while none is configured is refused, and nothing is recorded.
func TestIngestBrevo_RefusesWithoutTheToken(t *testing.T) {
	for _, c := range []struct {
		name, configured string
		ctx              context.Context
	}{
		{"no token", "s3cret", context.Background()},
		{"wrong token", "s3cret", withToken("guess")},
		{"empty token", "s3cret", withToken("")},
		{"none configured", "", withToken("")},
		{"none configured, any token", "", withToken("anything")},
	} {
		l := &ledger{contacts: map[string]*pb.ContactRow{"u1": {UserId: "u1", Email: "a@x.example"}}}
		h := &hookCalls{}
		_, err := webhook(t, l, c.configured, h).IngestBrevo(c.ctx, &pb.IngestBrevoReq{RawPayload: []byte(unsubscribe)})
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s: %v, want Unauthenticated", c.name, err)
		}
		if len(h.got) != 0 || l.contacts["u1"].GetUnsubscribedAt() != nil {
			t.Errorf("%s: an unauthenticated call recorded something", c.name)
		}
	}
}

// brevo_webhook/unsubscribe-writes-back: an unsubscribe is kept on the
// contact and handed to the project's hook for the user of that address,
// at the time Brevo says it happened.
func TestIngestBrevo_AnUnsubscribeIsWrittenBack(t *testing.T) {
	l := &ledger{contacts: map[string]*pb.ContactRow{
		"u1": {UserId: "u1", Email: "a@x.example", Consent: true, ConsentAt: timestamppb.New(day1)},
		"u2": {UserId: "u2", Email: "b@x.example"},
	}}
	h := &hookCalls{}
	resp, err := webhook(t, l, "s3cret", h).IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte(unsubscribe)})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1791018000, 0).UTC()
	if resp.GetUnsubscribed() != 1 || strings.Join(h.got, ";") != "u1@"+at.Format(time.RFC3339) {
		t.Errorf("unsubscribed %d, hook calls %v", resp.GetUnsubscribed(), h.got)
	}
	if got := l.contacts["u1"].GetUnsubscribedAt(); got == nil || !got.AsTime().Equal(at) {
		t.Errorf("unsubscribed_at = %v", got)
	}
	if !stateOf(l.contacts["u1"]).blacklisted() {
		t.Error("an unsubscribed contact would be subscribed by its next write")
	}
	if l.contacts["u2"].GetUnsubscribedAt() != nil {
		t.Error("another address was unsubscribed")
	}
}

// A batched delivery, other events, an address nobody has: only the
// unsubscribes of known users are written back; the rest is acknowledged.
func TestIngestBrevo_ABatchAndWhatItIgnores(t *testing.T) {
	l := &ledger{contacts: map[string]*pb.ContactRow{
		"u1": {UserId: "u1", Email: "a@x.example"},
		"u3": {UserId: "u3", ErasedAt: timestamppb.New(day1), Email: "c@x.example"},
	}}
	h := &hookCalls{}
	body := `[` + unsubscribe + `,{"event":"opened","email":"a@x.example"},{"event":"unsubscribe","email":"nobody@x.example"},{"event":"unsubscribe","email":"c@x.example"}]`
	resp, err := webhook(t, l, "s3cret", h).IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetUnsubscribed() != 1 || len(h.got) != 1 || !strings.HasPrefix(h.got[0], "u1@") {
		t.Errorf("unsubscribed %d, hook calls %v, want u1 alone", resp.GetUnsubscribed(), h.got)
	}
	l.badEmail = "c@x.example"
	if _, err := webhook(t, l, "s3cret", h).IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte(`{"event":"unsubscribe","email":"c@x.example"}`)}); err != nil {
		t.Errorf("an address the table refuses = %v, want it acknowledged (redelivering it fails the same way)", err)
	}
	if _, err := webhook(t, l, "s3cret", h).IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte("{not json")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a malformed body = %v, want InvalidArgument", err)
	}
}

// A hook that fails fails the delivery (Unavailable, which Brevo sends
// again); the unsubscribe is kept on the contact meanwhile, and the
// redelivery writes back the same again.
func TestIngestBrevo_AFailedWriteBackIsRedelivered(t *testing.T) {
	l := &ledger{contacts: map[string]*pb.ContactRow{"u1": {UserId: "u1", Email: "a@x.example"}}}
	h := &hookCalls{err: errors.New("business tier unreachable")}
	w := webhook(t, l, "s3cret", h)
	if _, err := w.IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte(unsubscribe)}); status.Code(err) != codes.Unavailable {
		t.Fatalf("a failed hook = %v, want Unavailable", err)
	}
	if l.contacts["u1"].GetUnsubscribedAt() == nil {
		t.Error("the unsubscribe was not kept while the write-back failed")
	}
	h.err = nil
	if _, err := w.IngestBrevo(withToken("s3cret"), &pb.IngestBrevoReq{RawPayload: []byte(unsubscribe)}); err != nil {
		t.Fatal(err)
	}
	if len(h.got) != 2 {
		t.Errorf("hook calls %v, want the redelivery written back", h.got)
	}
}

// ── the one-time reconciliation ─────────────────────────────────────────

const (
	uA = "0199a000-0000-7000-8000-00000000000a"
	uB = "0199a000-0000-7000-8000-00000000000b"
	uC = "0199a000-0000-7000-8000-00000000000c"
	uD = "0199a000-0000-7000-8000-00000000000d"
	uE = "0199a000-0000-7000-8000-00000000000e"
)

func reconcileFixture() (*fakeBrevo, *ledger) {
	f := &fakeBrevo{known: map[string]bool{uA: true, uB: true, uC: true, uD: true, uE: true}, contacts: []brevo.Contact{
		{ID: 1, ExtID: uA, Attributes: map[string]any{"W17_MARKETING_CONSENT": true}},  // consented: stays
		{ID: 2, ExtID: uB, Attributes: map[string]any{"W17_MARKETING_CONSENT": false}}, // refused: blacklisted
		{ID: 3, ExtID: uC},                         // never asked: blacklisted
		{ID: 4, ExtID: uD, EmailBlacklisted: true}, // already: untouched
		{ID: 5, Attributes: map[string]any{}},      // not the plugin's (a form): untouched
		{ID: 6, ExtID: "crm-42"},                   // not the plugin's: untouched
		{ID: 7, ExtID: uE, Attributes: map[string]any{"W17_MARKETING_CONSENT": true}}, // the plugin knows better
	}}
	l := &ledger{contacts: map[string]*pb.ContactRow{
		// Consented, then unsubscribed in Brevo: the plugin's state wins.
		uE: {UserId: uE, Consent: true, ConsentAt: timestamppb.New(day1), UnsubscribedAt: timestamppb.New(day2)},
	}}
	return f, l
}

// brevo/reconcile-once: the pass blacklists the plugin's subscribed contacts
// whose user has not consented, only those, and never subscribes anyone.
func TestReconcile_BlacklistsThePluginsContactsWithoutConsent(t *testing.T) {
	f, l := reconcileFixture()
	tl := tool(t, f, l, "all", "", "")
	done, err := tl.reconcileBlacklist(context.Background(), "replica-1")
	if err != nil || !done {
		t.Fatalf("done %v, err %v", done, err)
	}
	want := []string{uB + "|map[]|bl=true", uC + "|map[]|bl=true", uE + "|map[]|bl=true"}
	if strings.Join(f.updates, ";") != strings.Join(want, ";") {
		t.Errorf("updates = %v\nwant      %v", f.updates, want)
	}
	if len(f.upserts) != 0 {
		t.Errorf("the pass created contacts: %v", f.upserts)
	}
	if !l.recon[reconcileBlacklistName].finished {
		t.Error("the pass was not recorded as done")
	}
}

// brevo/reconcile-once: done once, it does not run again — on a restart or
// another replica.
func TestReconcile_RunsOncePerDeployment(t *testing.T) {
	f, l := reconcileFixture()
	if done, err := tool(t, f, l, "all", "", "").reconcileBlacklist(context.Background(), "replica-1"); !done || err != nil {
		t.Fatalf("first run: %v %v", done, err)
	}
	f.updates, f.listed = nil, nil
	for _, owner := range []string{"replica-1", "replica-2"} {
		done, err := tool(t, f, l, "all", "", "").reconcileBlacklist(context.Background(), owner)
		if !done || err != nil {
			t.Errorf("%s after the pass: done %v, err %v, want done", owner, done, err)
		}
	}
	if len(f.listed) != 0 || len(f.updates) != 0 {
		t.Errorf("the pass ran again: listed %v, updated %v", f.listed, f.updates)
	}
}

// brevo/reconcile-once: while another replica holds a live claim the pass is
// not run twice; a claim left unrenewed past the lease is taken over; a
// replica whose run failed takes its own claim back at once.
func TestReconcile_SafeUnderSeveralReplicas(t *testing.T) {
	f, l := reconcileFixture()
	l.recon = map[string]*reconRow{reconcileBlacklistName: {owner: "replica-1", claimed: time.Now()}}
	done, err := tool(t, f, l, "all", "", "").reconcileBlacklist(context.Background(), "replica-2")
	if done || !errors.Is(err, errReconcileElsewhere) || len(f.listed) != 0 {
		t.Fatalf("a live claim elsewhere: done %v, err %v, listed %v — want it left alone", done, err, f.listed)
	}
	l.recon[reconcileBlacklistName].claimed = time.Now().Add(-2 * reconcileLease)
	done, err = tool(t, f, l, "all", "", "").reconcileBlacklist(context.Background(), "replica-2")
	if !done || err != nil || l.recon[reconcileBlacklistName].owner != "replica-2" {
		t.Errorf("a stale claim: done %v, err %v, owner %s — want it taken over and finished", done, err, l.recon[reconcileBlacklistName].owner)
	}

	f, l = reconcileFixture()
	f.listErr = &brevo.Error{Status: 503}
	tl := tool(t, f, l, "all", "", "")
	if done, err := tl.reconcileBlacklist(context.Background(), "replica-1"); done || err == nil {
		t.Fatalf("Brevo down: done %v, err %v, want a retry", done, err)
	}
	f.listErr = nil
	if done, err := tl.reconcileBlacklist(context.Background(), "replica-1"); !done || err != nil {
		t.Errorf("the retry by the claim's owner: done %v, err %v", done, err)
	}
}

// brevo/reconcile-once: it runs in the background — the boot does not wait
// on Brevo — and retries until it is done.
func TestReconcile_InTheBackgroundUntilDone(t *testing.T) {
	f, l := reconcileFixture()
	f.listErr = &brevo.Error{Status: 503}
	lists := make(chan int, 16)
	f.onList = func(n int) {
		if n == 2 {
			f.listErr = nil // Brevo is back for the retry
		}
		select {
		case lists <- n:
		default:
		}
	}
	start := time.Now()
	stop := tool(t, f, l, "all", "", "").reconcileInBackground(time.Millisecond)
	defer stop()
	if time.Since(start) > 100*time.Millisecond {
		t.Error("starting the pass waited on Brevo")
	}
	timeout := time.After(2 * time.Second)
	for {
		select {
		case n := <-lists:
			if n >= 2 {
				return // retried after the failure
			}
		case <-timeout:
			t.Fatal("the pass was not retried after Brevo failed")
		}
	}
}
