package handlers

import (
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/wandering-compiler/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// Stripe sends events for objects this plugin never made: a subscription's
// invoice payments, a dashboard charge, another app on the same account.
// They have no local row and never will. Failing them (as a missing row of
// the plugin's OWN is failed) had each redelivered for days.
func TestFlow_AForeignPaymentIsAcknowledgedOnce(t *testing.T) {
	r := newRig(t)
	for _, typ := range []string{"payment_intent.succeeded", "payment_intent.payment_failed"} {
		id := "evt_foreign_" + typ
		resp, err := r.deliver(eventJSON(id, typ, "pi_not_ours", nil))
		if err != nil {
			t.Fatalf("%s for a payment the plugin never created must be acknowledged, got %v", typ, err)
		}
		if !resp.GetHandled() || !r.store.isProcessed(id) {
			t.Errorf("%s: not recorded (handled=%v)", typ, resp.GetHandled())
		}
	}
}

// The plugin marks what it creates, and Stripe echoes the mark on every
// event about the object.
func TestFlow_CreatedObjectsCarryTheOriginMark(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k1")
	tp := r.topUp("user-a", "5", "k2")
	if got := r.stripe.origins[p.GetProviderPaymentId()]; got != "charge" {
		t.Errorf("a charge's intent carries origin %q, want charge", got)
	}
	if got := r.stripe.origins[tp.GetProviderPaymentId()]; got != "topup" {
		t.Errorf("a top-up's intent carries origin %q, want topup", got)
	}
}

// With prepaid on, an ORDINARY payment's success must not wait for a
// top-up row that will never exist (every delivery used to fail).
func TestFlow_PrepaidOn_AnOrdinaryPaymentSucceeds(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k1")
	if _, err := r.deliver(r.stripe.objectEvent("evt_ok", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatalf("an ordinary payment's success failed: %v", err)
	}
	if !r.store.isProcessed("evt_ok") {
		t.Error("not recorded")
	}
}

// The success can arrive between the Payment INSERT and the CreditTopup
// INSERT. Acknowledging it then ("not a top-up") stranded the credit for
// good; the origin mark says it IS one, so it fails until the row lands.
func TestFlow_TopUpSuccessBeforeItsTopupRow_IsRetriedNotLost(t *testing.T) {
	r := newRig(t)
	tp := r.topUp("user-a", "5", "k1")
	pid := tp.GetProviderPaymentId()
	saved := r.store.topups[pid]
	delete(r.store.topups, pid) // as if its INSERT had not landed yet

	body := r.stripe.objectEvent("evt_early", "payment_intent.succeeded", pid, nil)
	_, err := r.deliver(body)
	wantCode(t, err, codes.NotFound, "a top-up whose row has not landed")
	if r.store.isProcessed("evt_early") {
		t.Fatal("recorded before the credit was granted")
	}

	r.store.topups[pid] = saved
	if _, err := r.deliver(body); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	bal, err := r.h.currentBalance(bg, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	if bal.GetBalance() != "5.0000" {
		t.Errorf("balance = %q, want 5.0000", bal.GetBalance())
	}
}

// A grant that committed under an earlier version's key and then failed to
// stamp is retried by redelivery after an upgrade. It must find that key —
// any other key grants the credit a second time.
func TestFlow_TopUpGrantKeepsTheKeyEarlierVersionsWrote(t *testing.T) {
	r := newRig(t)
	tp := r.topUp("user-a", "5", "k1")
	pid := tp.GetProviderPaymentId()
	if got := ledgerKey(creditTopup, "user-a", pid); got != "topup:"+pid {
		t.Fatalf("top-up ledger key = %q, want topup:%s", got, pid)
	}
	// The earlier version's committed grant, unstamped.
	if _, err := r.store.ApplyCredit(bg, &pb.ApplyCreditReq{UserId: "user-a", Delta: "5", Reason: "topup", Ref: pid, IdempotencyKey: "topup:" + pid}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(r.stripe.objectEvent("evt_after_upgrade", "payment_intent.succeeded", pid, nil)); err != nil {
		t.Fatal(err)
	}
	bal, err := r.h.currentBalance(bg, "user-a")
	if err != nil {
		t.Fatal(err)
	}
	if bal.GetBalance() != "5.0000" {
		t.Errorf("balance = %q — the redelivery granted the top-up twice", bal.GetBalance())
	}
}

// Two installations share one provider account (staging and production on
// the same test-mode account). Each installation's endpoint receives every
// event of the account, so each saw the OTHER's origin-marked objects, found
// no local row and failed the event — redelivered for days. The mark names
// the installation; an object another installation made is acknowledged.
func TestFlow_AnotherInstallationsObject_IsAcknowledged(t *testing.T) {
	r := newRig(t)
	other := map[string]string{"w17_payment": "charge", "w17_install": backend.InstallID("whsec_other_installation")}
	unnamed := map[string]string{"w17_payment": "topup"} // origin mark, no install id
	for _, c := range []struct {
		id, typ, obj string
		md           map[string]string
	}{
		{"evt_other_ok", "payment_intent.succeeded", "pi_other_1", other},
		{"evt_other_fail", "payment_intent.payment_failed", "pi_other_2", other},
		{"evt_other_sub", "customer.subscription.updated", "sub_other", map[string]string{"w17_payment": "subscription", "w17_install": "0000000000000000"}},
		{"evt_unnamed", "payment_intent.succeeded", "pi_unnamed", unnamed},
	} {
		extra := map[string]any{"metadata": c.md}
		if c.typ == "customer.subscription.updated" {
			extra["status"] = "active"
		}
		resp, err := r.deliver(eventJSON(c.id, c.typ, c.obj, extra))
		if err != nil {
			t.Errorf("%s: an object another installation made must be acknowledged, got %v", c.id, err)
			continue
		}
		if !resp.GetHandled() || !r.store.isProcessed(c.id) {
			t.Errorf("%s: not recorded (handled=%v)", c.id, resp.GetHandled())
		}
	}
}

// The other half: this installation's own object without a row yet still
// fails unrecorded, so the provider redelivers until the row lands.
func TestFlow_OwnInstallationsObjectWithoutRow_IsRetried(t *testing.T) {
	r := newRig(t)
	for _, c := range []struct{ id, typ, obj, origin string }{
		{"evt_own_ok", "payment_intent.succeeded", "pi_own_1", "charge"},
		{"evt_own_topup", "payment_intent.succeeded", "pi_own_2", "topup"},
		{"evt_own_fail", "payment_intent.payment_failed", "pi_own_3", "charge"},
		{"evt_own_sub", "customer.subscription.updated", "sub_own", "subscription"},
	} {
		extra := map[string]any{"metadata": ownMark(c.origin)}
		if c.typ == "customer.subscription.updated" {
			extra["status"] = "active"
		}
		_, err := r.deliver(eventJSON(c.id, c.typ, c.obj, extra))
		wantCode(t, err, codes.NotFound, c.id+": own object, row not landed")
		if r.store.isProcessed(c.id) {
			t.Errorf("%s: recorded although nothing was reconciled", c.id)
		}
	}
	// And what the plugin creates carries this installation's id.
	p := r.charge("user-a", "10", "k-own")
	if got := r.stripe.installs[p.GetProviderPaymentId()]; got == "" || got != backend.InstallID(testWebhookSecret) {
		t.Errorf("a charge's intent carries install %q, want %q", got, backend.InstallID(testWebhookSecret))
	}
}

// The top-up hook reads the same discriminator: a top-up success with no
// CreditTopup row is retried only when this installation made the intent.
func TestTopupHook_MissingRow_RetriedOnlyForThisInstallation(t *testing.T) {
	r := newRig(t)
	ev := stripeEvent("payment_intent.succeeded", "pi_topup_x")
	ev.Origin = backend.OriginTopup
	ev.Install = backend.InstallID("whsec_other_installation")
	if err := grantTopupOnPaymentSuccess(bg, r.h, ev); err != nil {
		t.Errorf("another installation's top-up: %v, want acknowledged", err)
	}
	ev.Install = backend.InstallID(testWebhookSecret)
	if err := grantTopupOnPaymentSuccess(bg, r.h, ev); err != errNoLocalRecord {
		t.Errorf("this installation's top-up without its row: %v, want errNoLocalRecord", err)
	}
}
