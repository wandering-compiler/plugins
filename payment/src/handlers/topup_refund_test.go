package handlers

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// grantedTopUp tops up and settles it, so the credit is on the balance.
func grantedTopUp(t *testing.T, r *rig, amount string) *pb.Payment {
	t.Helper()
	p := r.topUp("user-a", amount, "top-"+amount)
	if _, err := r.deliver(eventJSON("evt_top_"+amount, "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatalf("settle top-up: %v", err)
	}
	return p
}

// Refunding a top-up takes its credit back, once however often the refund
// is retried.
func TestFlow_RefundedTopUpTakesItsCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	for i := 0; i < 2; i++ {
		if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"}); err != nil {
			t.Fatalf("refund attempt %d: %v", i, err)
		}
	}
	if got := r.store.balance(t, "user-a"); got != "6.0000" {
		t.Errorf("balance = %s, want 6.0000 (10 granted, 4 refunded)", got)
	}
}

// Credit already spent cannot be refunded as money: the refund is refused
// and the provider is never asked.
func TestFlow_RefundOfSpentTopUpCreditIsRefused(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "8", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	before := r.stripe.count("/v1/refunds")
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "10", IdempotencyKey: "rt"})
	wantCode(t, err, codes.FailedPrecondition, "refund of spent credit")
	if r.stripe.count("/v1/refunds") != before {
		t.Error("the provider was asked to refund spent credit")
	}
	if got := r.store.balance(t, "user-a"); got != "2.0000" {
		t.Errorf("balance = %s, want 2.0000 untouched", got)
	}
}

// A top-up whose credit has not been granted yet cannot be refunded: the
// grant would land after the refund and keep the credit.
func TestFlow_RefundOfAnUngrantedTopUpIsRefused(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-x")
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "10", IdempotencyKey: "rt"})
	wantCode(t, err, codes.FailedPrecondition, "refund before the grant")
}

// A refusal the provider will repeat gives the credit back.
func TestFlow_RefusedTopUpRefundGivesTheCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.stripe.failNext(400)
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"})
	wantCode(t, err, codes.InvalidArgument, "refund the provider refused")
	if got := r.store.balance(t, "user-a"); got != "10.0000" {
		t.Errorf("balance = %s, want 10.0000 after the refusal", got)
	}
}

// A retry after a refusal that gave the credit back takes it again: the
// earlier take-back is undone, so finding it must not skip this one.
func TestFlow_RetryAfterARefusedTopUpRefundTakesTheCreditAgain(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.stripe.failNext(400)
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"})
	wantCode(t, err, codes.InvalidArgument, "refund the provider refused")
	for i := 0; i < 2; i++ {
		if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"}); err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
	if got := r.store.balance(t, "user-a"); got != "6.0000" {
		t.Errorf("balance = %s, want 6.0000 (the refund paid out, its credit taken once)", got)
	}
}

// A refund key at the length limit refunds a top-up too: the take-back's
// ledger key is derived from it, never longer than the limit.
func TestFlow_TopUpRefundUnderALongKey(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	key := strings.Repeat("k", maxIdempotencyKeyLen)
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: key}); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if got := r.store.balance(t, "user-a"); got != "6.0000" {
		t.Errorf("balance = %s, want 6.0000", got)
	}
}

// A caller's spend under a key shaped like the take-back's cannot stand in
// for it: the refund still takes its credit.
func TestFlow_CallerSpendKeyCannotNameTheTakeBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "topup-refund:rt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"}); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if got := r.store.balance(t, "user-a"); got != "5.0000" {
		t.Errorf("balance = %s, want 5.0000 (1 spent, 4 refunded)", got)
	}
}

// A refused top-up refund whose credit cannot be given back yet answers
// Unavailable, so the caller retries, and like every provider failure it
// does not hand the caller the provider's text.
func TestFlow_RefusedTopUpRefundWithAFailedUndo_KeepsTheProviderTextInside(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.stripe.failNext(400)
	// Let the take-back apply, then fail the undo that follows the refusal.
	r.store.onceBefore("ApplyCredit", func() {
		r.store.onceBefore("ApplyCredit", func() { r.store.injectBefore("ApplyCredit", errTransient) })
	})
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"})
	wantCode(t, err, codes.Unavailable, "refused refund with a failed undo")
	for _, leak := range []string{"injected", "/v1/", "stripe", "connection reset"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the answer carries %q: %v", leak, err)
		}
	}
}
