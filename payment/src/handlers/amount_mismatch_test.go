package handlers

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"
)

// An intent changed at the provider, by something other than this plugin,
// succeeds for another amount or currency than its local row holds. The
// success is not trusted: the payment is held at AMOUNT_MISMATCH, nothing
// announces it succeeded, and a top-up grants no credit.

func succeededEvent(id, pi string, received int64, cur string) []byte {
	return eventJSON(id, "payment_intent.succeeded", pi, map[string]any{"amount_received": received, "currency": cur})
}

func wantHeld(t *testing.T, r *rig, p *pb.Payment, amount, cur string) {
	t.Helper()
	r.store.mu.Lock()
	row := clone(r.store.payments[p.GetId()])
	r.store.mu.Unlock()
	if row.GetStatus() != pb.Payment_AMOUNT_MISMATCH || row.GetReceivedAmount() != amount || row.GetReceivedCurrency() != cur {
		t.Errorf("payment = %v received %s %s, want AMOUNT_MISMATCH received %s %s",
			row.GetStatus(), row.GetReceivedAmount(), row.GetReceivedCurrency(), amount, cur)
	}
}

func TestMismatch_ATopUpPaidLessIsHeldAndGrantsNothing(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "1000.00", "top-1")
	body := succeededEvent("evt_s", p.GetProviderPaymentId(), 1000, "usd") // 10.00 of 1000.00
	for i := 0; i < 2; i++ {
		deliverOK(t, r, body)
	}
	wantHeld(t, r, p, "10.0000", "usd")
	wantBalance(t, r, "0.0000")
	wantEvents(t, r, map[string]int{"PaymentAmountMismatch": 1, "PaymentSucceeded": 0, "CreditApplied": 0})
}

func TestMismatch_PaidMoreOrInAnotherCurrencyIsHeldToo(t *testing.T) {
	for _, c := range []struct {
		name       string
		received   int64
		cur, want  string
		wantAmount string
	}{
		{"more", 2000, "usd", "usd", "20.0000"},
		{"another currency", 1000, "eur", "eur", "10.0000"},
	} {
		r := newRig(t)
		p := r.charge("user-a", "10.00", "k")
		deliverOK(t, r, succeededEvent("evt_"+c.name, p.GetProviderPaymentId(), c.received, c.cur))
		wantHeld(t, r, p, c.wantAmount, c.want)
		wantEvents(t, r, map[string]int{"PaymentAmountMismatch": 1, "PaymentSucceeded": 0})
	}
}

// What was asked, received, is a success as before — the amount written in
// another scale or case included.
func TestMismatch_TheAskedAmountSucceeds(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 1000, "USD"))
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_SUCCEEDED {
		t.Errorf("status = %v, want SUCCEEDED", st)
	}
	wantEvents(t, r, map[string]int{"PaymentAmountMismatch": 0, "PaymentSucceeded": 1})
	if n := r.stripe.count("GET /v1/payment_intents/{id}"); n != 0 {
		t.Errorf("provider reads = %d; the event said what was received", n)
	}
}

// The signed event decides when it says what was received; the provider is
// read only for an event that does not.
func TestMismatch_TheEventDecides_TheProviderOnlyWhenItIsSilent(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	r.stripe.changeIntent(p.GetProviderPaymentId(), 1000, "")                      // the provider agrees with the asked amount…
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 500, "usd")) // …the event does not
	wantHeld(t, r, p, "5.0000", "usd")

	q := r.charge("user-a", "10.00", "k2")
	r.stripe.changeIntent(q.GetProviderPaymentId(), 300, "")
	deliverOK(t, r, eventJSON("evt_q", "payment_intent.succeeded", q.GetProviderPaymentId(), nil)) // silent
	wantHeld(t, r, q, "3.0000", "usd")
	if n := r.stripe.count("GET /v1/payment_intents/{id}"); n != 1 {
		t.Errorf("provider reads = %d, want 1 (only for the silent event)", n)
	}
}

// When neither the event nor the provider says what was received, nothing
// is decided: the delivery fails and is redelivered.
func TestMismatch_AnUncheckableSuccessIsNotTrusted(t *testing.T) {
	be := &fakeBackend{getPaymentErr: errors.New("connection reset")}
	q := &fakeQuery{paymentByProvider: &pb.Payment{Id: "pay-1", ProviderPaymentId: "pi_1", Amount: "10", Currency: "usd", Status: pb.Payment_REQUIRES_ACTION}}
	m := &fakeMutation{}
	h := newHandler(q, m, be)
	held, err := h.holdAmountMismatch(bg, stripeSucceeded("pi_1"))
	if err == nil || held {
		t.Fatalf("a failed provider read: held=%v err=%v, want an error", held, err)
	}
	be.getPaymentErr = nil // the provider answers, but with no received amount
	held, err = h.holdAmountMismatch(bg, stripeSucceeded("pi_1"))
	wantCode(t, err, codes.FailedPrecondition, "a success nobody can check")
	if held {
		t.Error("held without knowing what was received")
	}
	be.received = backend.Money{Amount: "10.00", Currency: "usd"}
	if held, err = h.holdAmountMismatch(bg, stripeSucceeded("pi_1")); err != nil || held {
		t.Errorf("the provider reports the asked amount: held=%v err=%v", held, err)
	}
}

// A held payment is the operator's: no later event moves it.
func TestMismatch_NoLaterEventMovesAHeldPayment(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	pi := p.GetProviderPaymentId()
	deliverOK(t, r, succeededEvent("evt_s", pi, 1, "usd"))
	deliverOK(t, r, eventJSON("evt_f", "payment_intent.payment_failed", pi, nil))
	deliverOK(t, r, eventJSON("evt_c", "payment_intent.canceled", pi, nil))
	deliverOK(t, r, succeededEvent("evt_s2", pi, 1000, "usd")) // even one that now matches
	wantHeld(t, r, p, "0.0100", "usd")
	wantEvents(t, r, map[string]int{"PaymentAmountMismatch": 1, "PaymentSucceeded": 0, "PaymentFailed": 0, "PaymentCanceled": 0})
}

// The provider reconciliation checks what it finds the same way.
func TestMismatch_TheReconciliationHoldsToo(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	r.stripe.changeIntent(p.GetProviderPaymentId(), 700, "")
	r.reconcileAll()
	wantHeld(t, r, p, "7.0000", "usd")
	if n := r.stripe.count("GET /v1/payment_intents/{id}"); n != 0 {
		t.Errorf("provider reads = %d; the listing already said what was received", n)
	}
	wantEvents(t, r, map[string]int{"PaymentAmountMismatch": 1, "PaymentSucceeded": 0})
}

// A held payment refunds what it took, in the currency it took, and no more.
func TestMismatch_AHeldPaymentRefundsWhatItTook(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	r.stripe.changeIntent(p.GetProviderPaymentId(), 300, "")
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 300, "usd"))
	_, err := refund(r, p.GetId(), "3.01", "r-over")
	wantCode(t, err, codes.InvalidArgument, "a refund past what the held payment took")
	got, err := refund(r, p.GetId(), "", "r-full")
	if err != nil {
		t.Fatalf("full refund of a held payment: %v", err)
	}
	if got.GetRefund().GetAmount() != "3.0000" || got.GetRefund().GetCurrency() != "usd" {
		t.Errorf("full refund = %s %s, want what it took (3.0000 usd)", got.GetRefund().GetAmount(), got.GetRefund().GetCurrency())
	}
	if n := r.stripe.intent(p.GetProviderPaymentId()).refunded; n != 300 {
		t.Errorf("provider refunded %d minor units, want 300", n)
	}
	// The provider's charge.refunded for it is settled, not redelivered for
	// ever: a held payment never reads REFUNDED.
	deliverOK(t, r, refundEvent("evt_cr", "charge.refunded", p.GetProviderPaymentId(), p.GetProviderPaymentId()))
	wantHeld(t, r, p, "3.0000", "usd")
	wantNoLocksLeft(t, r)
}

// A held top-up was never credited: its refund returns the money and takes
// back no credit (the ungranted-top-up refusal is for a success on its way).
func TestMismatch_AHeldTopUpRefundsWithoutTakingCredit(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "5", IdempotencyKey: "g"}); err != nil {
		t.Fatal(err)
	}
	p := r.topUp("user-a", "100.00", "top-1")
	r.stripe.changeIntent(p.GetProviderPaymentId(), 1000, "")
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 1000, "usd"))
	if _, err := refund(r, p.GetId(), "", "r"); err != nil {
		t.Fatalf("refund of a held top-up: %v", err)
	}
	wantBalance(t, r, "5.0000")
}

// Before its webhook arrives, a payment the provider reports took another
// amount is not refunded on the asked amount.
func TestMismatch_ARefundBeforeTheHoldIsRefused(t *testing.T) {
	r := erringRig(t)
	p := r.charge("user-a", "10.00", "k")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	r.stripe.changeIntent(p.GetProviderPaymentId(), 100, "")
	_, err := refund(r, p.GetId(), "", "r")
	wantCode(t, err, codes.FailedPrecondition, "a full refund of the asked amount of a payment that took 1.00")
	if n := r.stripe.count("/v1/refunds"); n != 0 {
		t.Errorf("refunded at the provider (%d calls)", n)
	}
}

// A charge retried under its key is answered with the held payment, not a new
// intent.
func TestMismatch_AChargeRetryIsAnsweredWithTheHeldPayment(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 1, "usd"))
	r.stripe.forgetKeys()
	before := r.stripe.count("/v1/payment_intents")
	again := r.charge("user-a", "10.00", "k")
	if again.GetId() != p.GetId() || again.GetStatus() != pb.Payment_AMOUNT_MISMATCH {
		t.Errorf("retry answered %v (%v), want the held payment", again.GetId(), again.GetStatus())
	}
	if n := r.stripe.count("/v1/payment_intents"); n != before {
		t.Error("the retry made a new intent")
	}
}

// stripeSucceeded is a parsed success event that says nothing of what was
// received.
func stripeSucceeded(pi string) stripe.Event {
	return stripe.Event{Type: "payment_intent.succeeded", ObjectID: pi, PaymentIntentID: pi}
}

// A held payment that took MORE than was asked, refunded in full: its
// refunds reach the asked amount, the REFUNDED write is refused (it is
// held), and the provider's charge.refunded must still be settled — not
// failed for a redelivery that would wait for ever.
func TestMismatch_AnOverpaidHeldPaymentRefundedInFullIsSettled(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "k")
	r.stripe.changeIntent(p.GetProviderPaymentId(), 2000, "")
	deliverOK(t, r, succeededEvent("evt_s", p.GetProviderPaymentId(), 2000, "usd"))
	if _, err := refund(r, p.GetId(), "", "r"); err != nil {
		t.Fatalf("full refund: %v", err)
	}
	if n := r.stripe.intent(p.GetProviderPaymentId()).refunded; n != 2000 {
		t.Errorf("provider refunded %d minor units, want 2000 (what it took)", n)
	}
	deliverOK(t, r, refundEvent("evt_cr", "charge.refunded", p.GetProviderPaymentId(), p.GetProviderPaymentId()))
	wantHeld(t, r, p, "20.0000", "usd")
}
