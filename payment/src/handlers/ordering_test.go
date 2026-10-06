package handlers

import (
	"testing"
	"time"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// The provider forgets an idempotency key after a day. A refund retried
// after that used to reach the provider as a NEW refund, and the local
// replay lookup (by the provider's new refund id) found nothing: the money
// went back twice. The key is kept and looked up first.
func TestFlow_RefundRetriedAfterTheProviderForgotTheKey_RefundsOnce(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	first, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	r.stripe.forgetKeys() // a day later
	before := r.stripe.count("/v1/refunds")
	again, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if again.GetRefund().GetId() != first.GetRefund().GetId() {
		t.Errorf("the retry recorded a second refund %s (first %s)", again.GetRefund().GetId(), first.GetRefund().GetId())
	}
	if n := r.stripe.count("/v1/refunds"); n != before {
		t.Errorf("the retry reached the provider again (%d → %d requests) — a second refund", before, n)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 400 {
		t.Errorf("provider refunded %d minor units, want 400", got)
	}
	// The same caller key on ANOTHER payment is a different refund.
	q := r.charge("user-a", "10", "k2")
	other, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: q.GetId(), Amount: "4", IdempotencyKey: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if other.GetRefund().GetPaymentId() != q.GetId() {
		t.Errorf("key r1 on the second payment answered with payment %s's refund", other.GetRefund().GetPaymentId())
	}
}

// Events arrive out of order. An older update must not overwrite the status
// a newer one set.
func TestFlow_AnOlderSubscriptionEventDoesNotOverwriteANewerOne(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	sub, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	sid := sub.GetSubscription().GetProviderSubscriptionId()
	newer := time.Now().Unix()
	event := func(id, st string, created int64) []byte {
		b := r.stripe.objectEvent(id, "customer.subscription.updated", sid, map[string]any{"status": st})
		return withCreated(t, b, created)
	}
	if _, err := r.deliver(event("evt_new", "past_due", newer)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(event("evt_old", "active", newer-60)); err != nil {
		t.Fatalf("a stale event must be acknowledged, got %v", err)
	}
	got, err := r.store.GetSubscriptionByProviderId(bg, &pb.GetSubscriptionByProviderIdReq{ProviderSubscriptionId: sid})
	if err != nil {
		t.Fatal(err)
	}
	if got.GetSubscription().GetStatus() != pb.Subscription_PAST_DUE {
		t.Errorf("status = %v — the older event overwrote the newer PAST_DUE", got.GetSubscription().GetStatus())
	}
	if !r.store.isProcessed("evt_old") {
		t.Error("the stale event was not recorded")
	}
}

// CANCELED is terminal: a late success must not resurrect the payment.
func TestFlow_ALateSuccessDoesNotResurrectACanceledPayment(t *testing.T) {
	for _, terminal := range []pb.Payment_Status{pb.Payment_CANCELED, pb.Payment_REFUNDED} {
		r := newRig(t)
		p := r.charge("user-a", "10", "k")
		r.store.mu.Lock()
		for _, sp := range r.store.payments {
			if sp.GetId() == p.GetId() {
				sp.Status = terminal
			}
		}
		r.store.mu.Unlock()
		for _, typ := range []string{"payment_intent.succeeded", "payment_intent.payment_failed"} {
			if _, err := r.deliver(r.stripe.objectEvent("evt_"+typ, typ, p.GetProviderPaymentId(), nil)); err != nil {
				t.Fatalf("%v / %s: %v", terminal, typ, err)
			}
			if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != terminal {
				t.Errorf("%v / %s: status became %v", terminal, typ, st)
			}
		}
	}
}
