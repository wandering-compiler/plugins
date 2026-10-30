package handlers

import (
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// totalCalls is every store call so far.
func (s *memStore) totalCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		n += c
	}
	return n
}

// A copy of a processed event — the provider's redelivery, or a signed
// request replayed inside the 300 s window — is answered from the ledger:
// one read, no reconciliation, no provider call.
func TestIngestStripe_ACopyOfAProcessedEventDoesNoWork(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", "10", "k")
	if _, err := refund(r, p.GetId(), "4", "r1"); err != nil {
		t.Fatal(err)
	}
	// A refund event: its processing reads the payment's refunds from the
	// provider.
	body := refundEvent("evt_r", "charge.refunded", p.GetProviderPaymentId(), p.GetProviderPaymentId())
	first, err := r.deliver(body)
	if err != nil || !first.GetHandled() {
		t.Fatalf("first delivery: %v %v", first, err)
	}
	storeBefore, providerBefore := r.store.totalCalls(), r.stripe.count("GET /v1/refunds")+r.stripe.count("/v1/refunds")
	for i := 0; i < 5; i++ {
		resp, err := r.deliver(body)
		if err != nil || resp.GetHandled() {
			t.Fatalf("copy %d: handled=%v err=%v, want acknowledged as already handled", i, resp.GetHandled(), err)
		}
	}
	if n := r.store.totalCalls() - storeBefore; n != 5 {
		t.Errorf("five copies made %d store calls, want 5 (one ledger read each)", n)
	}
	if n := r.stripe.count("GET /v1/refunds") + r.stripe.count("/v1/refunds") - providerBefore; n != 0 {
		t.Errorf("five copies made %d provider calls, want none", n)
	}
}

// A delivery whose processing failed wrote no ledger row: its redelivery is
// not short-circuited, and runs in full.
func TestIngestStripe_AFailedDeliveryIsNotShortCircuited(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	body := eventJSON("evt_s", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)
	r.store.injectBefore("MarkPaymentSucceeded", errTransient)
	if _, err := r.deliver(body); err == nil {
		t.Fatal("want the failure surfaced")
	}
	resp, err := r.deliver(body)
	if err != nil || !resp.GetHandled() {
		t.Fatalf("redelivery: handled=%v err=%v, want processed", resp.GetHandled(), err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_SUCCEEDED {
		t.Errorf("status = %v, want SUCCEEDED", st)
	}
}

// A ledger read that fails decides nothing: the delivery fails, to be
// redelivered, and nothing runs or is recorded.
func TestIngestStripe_ALedgerReadFailureRunsNothing(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	body := eventJSON("evt_s", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)
	r.store.injectBefore("GetProcessedWebhookEvent", errTransient)
	_, err := r.deliver(body)
	wantCode(t, err, codes.Unavailable, "a failed ledger read")
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_REQUIRES_ACTION {
		t.Errorf("status = %v, want REQUIRES_ACTION untouched", st)
	}
	if r.store.isProcessed("evt_s") {
		t.Error("the event was recorded")
	}
}
