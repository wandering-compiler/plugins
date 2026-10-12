package handlers

import (
	"testing"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// succeededPayment charges and confirms a payment through the webhook.
func succeededPayment(t *testing.T, r *rig, amount string) *pb.Payment {
	t.Helper()
	p := r.charge("user-a", amount, "k-"+amount)
	if _, err := r.deliver(eventJSON("evt_s_"+p.GetId(), "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatalf("succeeded: %v", err)
	}
	return p
}

// A payment refunded in full reads REFUNDED; a partial refund leaves it
// SUCCEEDED until the refunds reach the amount.
func TestFlow_RefundsMoveThePaymentToRefundedWhenComplete(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "r1"}); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_SUCCEEDED {
		t.Errorf("after a partial refund: %v, want SUCCEEDED", st)
	}
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "6", IdempotencyKey: "r2"}); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_REFUNDED {
		t.Errorf("after refunds reaching the amount: %v, want REFUNDED", st)
	}
	if r.store.events("PaymentRefunded") != 1 {
		t.Errorf("PaymentRefunded emitted %d times, want 1", r.store.events("PaymentRefunded"))
	}
}

// The provider's charge.refunded settles a fully refunded charge, whoever
// refunded it; a charge only partly refunded changes nothing.
func TestWebhook_ChargeRefundedSettlesTheStatus(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	if _, err := r.deliver(eventJSON("evt_partial", "charge.refunded", "ch_1",
		map[string]any{"payment_intent": p.GetProviderPaymentId(), "refunded": false})); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_SUCCEEDED {
		t.Errorf("partly refunded charge: %v, want SUCCEEDED", st)
	}
	if _, err := r.deliver(eventJSON("evt_full", "charge.refunded", "ch_1",
		map[string]any{"payment_intent": p.GetProviderPaymentId(), "refunded": true})); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_REFUNDED {
		t.Errorf("fully refunded charge: %v, want REFUNDED", st)
	}
	// Redelivery, and a charge of a payment this plugin never made, are
	// acknowledged.
	if _, err := r.deliver(eventJSON("evt_full2", "charge.refunded", "ch_1",
		map[string]any{"payment_intent": p.GetProviderPaymentId(), "refunded": true})); err != nil {
		t.Errorf("redelivery: %v", err)
	}
	if _, err := r.deliver(eventJSON("evt_foreign", "charge.refunded", "ch_9",
		map[string]any{"payment_intent": "pi_foreign", "refunded": true})); err != nil {
		t.Errorf("foreign charge: %v", err)
	}
}

// payment_intent.canceled moves a payment that never completed to CANCELED,
// and never a succeeded one.
func TestWebhook_PaymentIntentCanceled(t *testing.T) {
	r := newRig(t)
	open := r.charge("user-a", "5", "k-open")
	if _, err := r.deliver(eventJSON("evt_c", "payment_intent.canceled", open.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, open.GetProviderPaymentId()); st != pb.Payment_CANCELED {
		t.Errorf("canceled: %v, want CANCELED", st)
	}
	done := succeededPayment(t, r, "7")
	if _, err := r.deliver(eventJSON("evt_c2", "payment_intent.canceled", done.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, done.GetProviderPaymentId()); st != pb.Payment_SUCCEEDED {
		t.Errorf("a succeeded payment was canceled: %v", st)
	}
}

// A failed attempt leaves the provider's PaymentIntent open, so the cancel
// that ends an abandoned payment moves FAILED to CANCELED.
func TestWebhook_PaymentIntentCanceledAfterAFailure(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "5", "k-failed")
	if _, err := r.deliver(eventJSON("evt_f", "payment_intent.payment_failed", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(eventJSON("evt_c", "payment_intent.canceled", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_CANCELED {
		t.Errorf("failed then canceled: %v, want CANCELED", st)
	}
	if r.store.events("PaymentCanceled") != 1 {
		t.Errorf("PaymentCanceled emitted %d times, want 1", r.store.events("PaymentCanceled"))
	}
}

// Stripe does not order charge.refunded against payment_intent.succeeded: a
// refund seen while the payment is not SUCCEEDED locally is not recorded,
// and its redelivery settles REFUNDED once the success has landed.
func TestWebhook_ChargeRefundedBeforeTheSuccess(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k-early")
	refunded := eventJSON("evt_early_refund", "charge.refunded", "ch_e",
		map[string]any{"payment_intent": p.GetProviderPaymentId(), "refunded": true})
	if _, err := r.deliver(refunded); err == nil {
		t.Fatal("charge.refunded before the success was acknowledged; the REFUNDED would be lost")
	}
	if r.store.isProcessed("evt_early_refund") {
		t.Fatal("early charge.refunded recorded in the ledger")
	}
	if _, err := r.deliver(eventJSON("evt_s", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(refunded); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_REFUNDED {
		t.Errorf("after the redelivery: %v, want REFUNDED", st)
	}
}

// A top-up whose grant failed and which was then refunded in full gets no
// credit from the redelivered success.
func TestFlow_RefundedTopUpIsNotGrantedOnRedelivery(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "20.00", "top-refunded")
	body := eventJSON("evt_top", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)
	r.store.injectBefore("ApplyCredit", errTransient)
	if _, err := r.deliver(body); err == nil {
		t.Fatal("want the grant failure to surface")
	}
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), IdempotencyKey: "rf"}); err != nil {
		t.Fatal(err)
	}
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != pb.Payment_REFUNDED {
		t.Fatalf("after the full refund: %v, want REFUNDED", st)
	}
	if _, err := r.deliver(body); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if got := r.store.balance(t, "user-a"); got != "0.0000" {
		t.Errorf("balance = %s for a refunded top-up, want 0.0000", got)
	}
}
