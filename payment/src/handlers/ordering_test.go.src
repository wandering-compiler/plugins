package handlers

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
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
}

// A retry under a refund's key that asks for a DIFFERENT amount is not that
// refund. The key lookup used to answer before comparing anything: a refund
// of 4 under r1, then 6 under r1, returned the refund of 4 with no error, and
// the caller believed 6 had gone back.
func TestFlow_RefundKeyReusedForADifferentAmount_IsRefused(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "r1"}); err != nil {
		t.Fatal(err)
	}
	for _, when := range []string{"within the provider's day", "after the provider forgot the key"} {
		if when != "within the provider's day" {
			r.stripe.forgetKeys()
		}
		_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "6", IdempotencyKey: "r1"})
		if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "different refund") {
			t.Errorf("%s: 6 under the key of a refund of 4 = %v, want AlreadyExists", when, err)
		}
		// The same amount written another way IS the same refund.
		again, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4.00", IdempotencyKey: "r1"})
		if err != nil || again.GetRefund().GetAmount() != "4.0000" {
			t.Errorf("%s: a retry of the refund of 4 as 4.00 = %v / %v", when, again, err)
		}
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 400 {
		t.Errorf("provider refunded %d minor units, want 400", got)
	}
	if n := r.store.count("refunds"); n != 1 {
		t.Errorf("refund rows = %d, want 1", n)
	}
}

// A refund key names ONE refund across all payments — the scope the provider
// gives the key, which it is sent verbatim. The handler used to store it
// scoped by payment and document that one key could name a refund on each of
// several payments; at the provider the second use was an idempotency error
// for a day (the old test passed only by making the provider forget first),
// and after the day it was a second refund. Now it is refused, the same way,
// whenever it happens.
func TestFlow_RefundKeyReusedOnAnotherPayment_IsRefused(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	q := r.charge("user-a", "10", "k2")
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "r1"}); err != nil {
		t.Fatal(err)
	}
	for _, when := range []string{"within the provider's day", "after the provider forgot the key"} {
		if when != "within the provider's day" {
			r.stripe.forgetKeys()
		}
		_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: q.GetId(), Amount: "4", IdempotencyKey: "r1"})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "another payment") {
			t.Errorf("%s: key r1 reused on another payment = %v, want InvalidArgument naming the other payment", when, err)
		}
	}
	if got := r.stripe.intent(q.GetProviderPaymentId()).refunded; got != 0 {
		t.Errorf("the second payment was refunded %d minor units under a reused key", got)
	}
	// The provider is sent the caller's key verbatim (see RefundPayment for
	// why not a payment-scoped one): a refund made by an earlier version and
	// retried after the upgrade must stay a provider replay.
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: q.GetId(), Amount: "4", IdempotencyKey: "r2"}); err != nil {
		t.Fatal(err)
	}
}

// A refund an earlier version made (no stored key) and the caller retries
// after the upgrade, within the provider's day: the provider replays it for
// the same raw key, and the existing row is the answer — never a second
// refund.
func TestFlow_RefundMadeBeforeTheUpgrade_RetriedAfterIt_RefundsOnce(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	// What the earlier version did: the provider refund under the raw key,
	// then the local row WITHOUT a stored key.
	res, err := r.h.Backend.RefundPayment(bg, p.GetProviderPaymentId(), backend.Money{Amount: "4", Currency: "usd"}, "legacy-r1")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := r.store.CreateRefund(bg, &pb.CreateRefundReq{PaymentId: p.GetId(), ProviderRefundId: res.ProviderRefundID, Amount: "4", Currency: "usd"})
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "legacy-r1"})
	if err != nil {
		t.Fatalf("retry across the upgrade: %v", err)
	}
	if again.GetRefund().GetId() != legacy.GetRefund().GetId() {
		t.Errorf("the retry answered refund %s, want the pre-upgrade %s", again.GetRefund().GetId(), legacy.GetRefund().GetId())
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 400 {
		t.Errorf("provider refunded %d minor units, want 400 — the retry refunded again", got)
	}

	// The replay stamped the kept key on the pre-upgrade row, so a retry
	// after the provider forgets the key is still found locally. Unstamped,
	// it reached the provider as a NEW refund and the money went back twice.
	r.stripe.forgetKeys() // a day later
	before := r.stripe.count("/v1/refunds")
	late, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "legacy-r1"})
	if err != nil {
		t.Fatalf("retry after the provider forgot the key: %v", err)
	}
	if late.GetRefund().GetId() != legacy.GetRefund().GetId() {
		t.Errorf("the late retry answered refund %s, want the pre-upgrade %s", late.GetRefund().GetId(), legacy.GetRefund().GetId())
	}
	if n := r.stripe.count("/v1/refunds"); n != before {
		t.Errorf("the late retry reached the provider again (%d → %d requests) — a second refund", before, n)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 400 {
		t.Errorf("provider refunded %d minor units, want 400 — the late retry refunded again", got)
	}
	if n := r.store.count("refunds"); n != 1 {
		t.Errorf("refund rows = %d, want 1", n)
	}
}

// Stamping the kept key on a pre-upgrade refund: a guard refusal (the row
// already holds a key) is nothing to do; a key another row holds is a
// different refund (AlreadyExists); any other failure surfaces.
func TestFlow_RefundMadeBeforeTheUpgrade_StampOutcomes(t *testing.T) {
	legacyRetry := func(t *testing.T, r *rig, key string) (*pb.Refund, error) {
		t.Helper()
		p := r.charge("user-a", "10", "k-"+key)
		res, err := r.h.Backend.RefundPayment(bg, p.GetProviderPaymentId(), backend.Money{Amount: "4", Currency: "usd"}, key)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := r.store.CreateRefund(bg, &pb.CreateRefundReq{PaymentId: p.GetId(), ProviderRefundId: res.ProviderRefundID, Amount: "4", Currency: "usd"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: key})
		if err == nil && got.GetRefund().GetId() != legacy.GetRefund().GetId() {
			t.Errorf("answered refund %s, want the pre-upgrade %s", got.GetRefund().GetId(), legacy.GetRefund().GetId())
		}
		return got.GetRefund(), err
	}

	t.Run("guard refused", func(t *testing.T) {
		r := newRig(t)
		r.store.injectBefore("SetRefundIdempotencyKey", noRows("SetRefundIdempotencyKey"))
		if _, err := legacyRetry(t, r, "legacy-g"); err != nil {
			t.Errorf("a guard refusal failed the replay: %v", err)
		}
	})
	t.Run("key held by another row", func(t *testing.T) {
		r := newRig(t)
		r.store.injectBefore("SetRefundIdempotencyKey", uniqueErr("idempotency_key"))
		_, err := legacyRetry(t, r, "legacy-u")
		wantCode(t, err, codes.AlreadyExists, "stamp hit the unique key")
	})
	t.Run("transient", func(t *testing.T) {
		r := newRig(t)
		r.store.injectBefore("SetRefundIdempotencyKey", errTransient)
		_, err := legacyRetry(t, r, "legacy-t")
		wantCode(t, err, codes.Unavailable, "stamp failed")
	})
}

// A concurrent request under the same key recorded its refund first: that
// refund answers this one only when it is the same refund.
func TestFlow_RefundKeyRace_ComparesTheRecordedRefund(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "k")
	r.store.onceBefore("CreateRefund", func() {
		_, _ = r.store.CreateRefund(bg, &pb.CreateRefundReq{PaymentId: p.GetId(), ProviderRefundId: "re_concurrent", Amount: "3", Currency: "usd", IdempotencyKey: refundKey("race")})
	})
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "race"})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("a concurrent refund of 3 under the key answered a request for 4: %v, want AlreadyExists", err)
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
