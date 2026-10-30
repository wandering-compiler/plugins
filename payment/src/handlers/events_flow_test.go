package handlers

import (
	"testing"
	"time"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// The events of a payment's life, counted at the store: what is emitted, how
// often, and by which write (TestEvents_EachIsEmittedByTheWriteThatRecordsIt
// pins the declarations these model).

func wantEvents(t *testing.T, r *rig, want map[string]int) {
	t.Helper()
	for name, n := range want {
		if got := r.store.events(name); got != n {
			t.Errorf("%s emitted %d time(s), want %d (all: %v)", name, got, n, r.store.emitted)
		}
	}
}

// One PaymentCreated per payment: a retried charge answered with the
// recorded payment, or replayed by the provider, emits nothing more.
func TestEvents_PaymentCreatedOncePerPayment(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "order-1")
	if p.GetStatus() != pb.Payment_REQUIRES_ACTION {
		t.Fatalf("a new charge is %v", p.GetStatus())
	}
	r.charge("user-a", "10", "order-1") // the provider replays it
	wantEvents(t, r, map[string]int{"PaymentCreated": 1})
	r.charge("user-a", "10", "order-2")
	wantEvents(t, r, map[string]int{"PaymentCreated": 2, "PaymentSucceeded": 0})
}

// A partial refund announces itself — PaymentRefunded only comes with the
// whole amount — and a retry of it announces nothing more.
func TestEvents_APartialRefundIsAnnounced(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	for i := 0; i < 2; i++ {
		if _, err := refund(r, p.GetId(), "3", "r1"); err != nil {
			t.Fatal(err)
		}
	}
	wantEvents(t, r, map[string]int{"RefundCreated": 1, "ProviderRefundRecorded": 0, "PaymentRefunded": 0})
	if _, err := refund(r, p.GetId(), "7", "r2"); err != nil {
		t.Fatal(err)
	}
	wantEvents(t, r, map[string]int{"RefundCreated": 2, "PaymentRefunded": 1})
}

// A refund made at the provider directly is announced as the provider's when
// its webhook records it; one this plugin made, whose webhook outran its own
// insert, is still the plugin's.
func TestEvents_ARefundMadeAtTheProviderIsAnnouncedAsTheProviders(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	re := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
	deliverOK(t, r, refundEvent("evt_r1", "refund.created", re, p.GetProviderPaymentId()))
	deliverOK(t, r, refundEvent("evt_r1b", "refund.updated", re, p.GetProviderPaymentId())) // nothing new
	wantEvents(t, r, map[string]int{"ProviderRefundRecorded": 1, "RefundCreated": 0})

	// The plugin's own refund, recorded by its webhook first (the insert
	// failed after the provider refunded).
	r.store.injectBefore("CreateRefund", errTransient)
	if _, err := refund(r, p.GetId(), "2", "r-own"); err == nil {
		t.Fatal("want the record failure surfaced")
	}
	deliverOK(t, r, refundEvent("evt_r2", "charge.refunded", p.GetProviderPaymentId(), p.GetProviderPaymentId()))
	wantEvents(t, r, map[string]int{"ProviderRefundRecorded": 1, "RefundCreated": 1})
}

// A pending refund's outcome is announced once: the success, or the failure
// that leaves the money where it was.
func TestEvents_ARefundsOutcomeIsAnnouncedOnce(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	r.stripe.refundStatus = "pending"
	ok, err := refund(r, p.GetId(), "3", "r-ok")
	if err != nil {
		t.Fatal(err)
	}
	bad, err := refund(r, p.GetId(), "3", "r-bad")
	if err != nil {
		t.Fatal(err)
	}
	r.stripe.setRefundStatus(ok.GetRefund().GetProviderRefundId(), "succeeded")
	r.stripe.setRefundStatus(bad.GetRefund().GetProviderRefundId(), "failed")
	for _, evt := range []string{"evt_u1", "evt_u2"} { // a redelivery changes nothing
		deliverOK(t, r, refundEvent(evt, "refund.updated", ok.GetRefund().GetProviderRefundId(), p.GetProviderPaymentId()))
		deliverOK(t, r, refundEvent(evt+"f", "refund.failed", bad.GetRefund().GetProviderRefundId(), p.GetProviderPaymentId()))
	}
	wantEvents(t, r, map[string]int{"RefundStatusChanged:SUCCEEDED": 1, "RefundStatusChanged:FAILED": 1, "RefundCreated": 2})
}

// A dispute is announced when it opens and once when it closes; the open
// states in between, and redeliveries, announce nothing.
func TestEvents_ADisputeOpensAndClosesOnce(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	pi := p.GetProviderPaymentId()
	now := time.Now().Unix()
	deliverOK(t, r, disputeEvent(t, "evt_d1", "charge.dispute.created", "dp_1", pi, "needs_response", 1000, now))
	deliverOK(t, r, disputeEvent(t, "evt_d2", "charge.dispute.updated", "dp_1", pi, "under_review", 1000, now+1))
	wantEvents(t, r, map[string]int{"DisputeOpened:NEEDS_RESPONSE": 1, "DisputeClosed:LOST": 0, "DisputeClosed:WON": 0})
	for _, evt := range []string{"evt_d3", "evt_d3-again"} {
		deliverOK(t, r, disputeEvent(t, evt, "charge.dispute.closed", "dp_1", pi, "lost", 1000, now+2))
	}
	// An older event arriving late reopens nothing and announces nothing.
	deliverOK(t, r, disputeEvent(t, "evt_d0", "charge.dispute.updated", "dp_1", pi, "under_review", 1000, now-5))
	wantEvents(t, r, map[string]int{"DisputeOpened:NEEDS_RESPONSE": 1, "DisputeClosed:LOST": 1})
}

// The first event the plugin sees may already be the closing one: the
// dispute is announced opened, then closed — both, once.
func TestEvents_ADisputeFirstSeenClosed_IsOpenedThenClosed(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	for _, evt := range []string{"evt_w", "evt_w2"} {
		deliverOK(t, r, disputeEvent(t, evt, "charge.dispute.closed", "dp_w", p.GetProviderPaymentId(), "won", 1000, time.Now().Unix()))
	}
	wantEvents(t, r, map[string]int{"DisputeOpened:WON": 1, "DisputeClosed:WON": 1})
	opened, closed := -1, -1
	for i, e := range r.store.emitted {
		switch e {
		case "DisputeOpened:WON":
			opened = i
		case "DisputeClosed:WON":
			closed = i
		}
	}
	if opened > closed {
		t.Errorf("DisputeClosed came before DisputeOpened: %v", r.store.emitted)
	}
}

// An announcement that fails is not lost: the delivery fails, the provider
// redelivers, the status write changes nothing and the announcement runs.
func TestEvents_AFailedCloseAnnouncementIsRetriedByTheRedelivery(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	body := disputeEvent(t, "evt_l", "charge.dispute.closed", "dp_l", p.GetProviderPaymentId(), "lost", 1000, time.Now().Unix())
	r.store.injectBefore("MarkDisputeClosed", errTransient)
	if _, err := r.deliver(body); err == nil {
		t.Fatal("want the failed announcement surfaced, so the provider redelivers")
	}
	wantEvents(t, r, map[string]int{"DisputeClosed:LOST": 0})
	deliverOK(t, r, body)
	wantEvents(t, r, map[string]int{"DisputeOpened:LOST": 1, "DisputeClosed:LOST": 1})
}

// An inquiry that closes without becoming a dispute withdrew nothing: it is
// not announced as a closed dispute.
func TestEvents_AClosedInquiryIsNotADisputeClosed(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	now := time.Now().Unix()
	deliverOK(t, r, disputeEvent(t, "evt_i1", "charge.dispute.created", "dp_i", p.GetProviderPaymentId(), "warning_needs_response", 1000, now))
	deliverOK(t, r, disputeEvent(t, "evt_i2", "charge.dispute.closed", "dp_i", p.GetProviderPaymentId(), "warning_closed", 1000, now+1))
	wantEvents(t, r, map[string]int{"DisputeOpened:INQUIRY": 1, "DisputeClosed:INQUIRY_CLOSED": 0})
}
