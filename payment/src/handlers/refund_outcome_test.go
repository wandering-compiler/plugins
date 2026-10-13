package handlers

import (
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// refundNow refunds amount of p through RefundPayment under key.
func refundNow(t *testing.T, r *rig, p *pb.Payment, amount, key string) *pb.Refund {
	t.Helper()
	resp, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: amount, IdempotencyKey: key})
	if err != nil {
		t.Fatalf("refund %s under %q: %v", amount, key, err)
	}
	return resp.GetRefund()
}

// deliverOK delivers an event and fails the test on an error.
func deliverOK(t *testing.T, r *rig, body []byte) {
	t.Helper()
	if _, err := r.deliver(body); err != nil {
		t.Fatalf("delivery: %v", err)
	}
}

func wantRefundStatus(t *testing.T, r *rig, providerRefundID string, want pb.Refund_Status) *pb.Refund {
	t.Helper()
	row := r.store.refundByProvider(t, providerRefundID)
	if row == nil {
		t.Fatalf("no local refund %s", providerRefundID)
	}
	if row.GetStatus() != want {
		t.Errorf("refund %s: %v, want %v", providerRefundID, row.GetStatus(), want)
	}
	return row
}

func wantPaymentStatus(t *testing.T, r *rig, p *pb.Payment, want pb.Payment_Status) {
	t.Helper()
	if st := r.store.paymentStatus(t, p.GetProviderPaymentId()); st != want {
		t.Errorf("payment: %v, want %v", st, want)
	}
}

func wantBalance(t *testing.T, r *rig, want string) {
	t.Helper()
	if got := r.store.balance(t, "user-a"); got != want {
		t.Errorf("balance = %s, want %s", got, want)
	}
}

// ── the refund's own outcome (finding 6) ─────────────────────────────

// RefundPayment records what the provider answered. A pending refund counts
// toward REFUNDED (the provider holds the money for it), and settling to
// succeeded later changes the row, not the payment.
func TestFlow_RefundRecordsTheProviderOutcome(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	r.stripe.refundStatus = "pending"
	ref := refundNow(t, r, p, "10", "r1")
	if ref.GetStatus() != pb.Refund_PENDING {
		t.Errorf("answered refund: %v, want PENDING", ref.GetStatus())
	}
	wantRefundStatus(t, r, ref.GetProviderRefundId(), pb.Refund_PENDING)
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)

	r.stripe.setRefundStatus(ref.GetProviderRefundId(), "succeeded")
	deliverOK(t, r, refundEvent("evt_ru", "refund.updated", ref.GetProviderRefundId(), p.GetProviderPaymentId()))
	wantRefundStatus(t, r, ref.GetProviderRefundId(), pb.Refund_SUCCEEDED)
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)
	if n := r.store.events("PaymentRefunded"); n != 1 {
		t.Errorf("PaymentRefunded emitted %d times, want 1", n)
	}
}

// A refund the provider fails after it completed the amount stops counting:
// the payment goes back to SUCCEEDED with PaymentRefundReversed, once, however
// often (and through whichever event) the failure is delivered.
func TestWebhook_FailedRefundReversesRefunded(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	ref := refundNow(t, r, p, "10", "r1")
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)

	r.stripe.setRefundStatus(ref.GetProviderRefundId(), "failed")
	failed := refundEvent("evt_rf", "refund.failed", ref.GetProviderRefundId(), p.GetProviderPaymentId())
	deliverOK(t, r, failed)
	wantRefundStatus(t, r, ref.GetProviderRefundId(), pb.Refund_FAILED)
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
	deliverOK(t, r, failed) // duplicate delivery
	deliverOK(t, r, refundEvent("evt_cr", "charge.refund.updated", ref.GetProviderRefundId(), p.GetProviderPaymentId()))
	if n := r.store.events("PaymentRefundReversed"); n != 1 {
		t.Errorf("PaymentRefundReversed emitted %d times, want 1", n)
	}
	sum, err := r.store.SumRefundsForPayment(bg, &pb.SumRefundsForPaymentReq{PaymentId: p.GetId()})
	if err != nil || sum.GetTotal() != "0.0000" {
		t.Errorf("SumRefundsForPayment = %v, %v; a failed refund counts nothing", sum.GetTotal(), err)
	}
	// The amount can be refunded again, under a new key.
	refundNow(t, r, p, "10", "r2")
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)
}

// Events arrive in any order: a stale view that still says succeeded, read or
// delivered after the failure, never revives a failed refund nor the
// payment's REFUNDED.
func TestWebhook_RefundFailureIsNeverUndoneByAnOlderView(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	ref := refundNow(t, r, p, "10", "r1")
	r.stripe.setRefundStatus(ref.GetProviderRefundId(), "failed")
	deliverOK(t, r, refundEvent("evt_rf", "refund.failed", ref.GetProviderRefundId(), p.GetProviderPaymentId()))

	// A lagging read of the provider: the refund still reads succeeded.
	r.stripe.setRefundStatus(ref.GetProviderRefundId(), "succeeded")
	deliverOK(t, r, refundEvent("evt_old", "charge.refunded", "ch_1", p.GetProviderPaymentId()))
	wantRefundStatus(t, r, ref.GetProviderRefundId(), pb.Refund_FAILED)
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
	if n := r.store.events("PaymentRefunded"); n != 1 {
		t.Errorf("PaymentRefunded emitted %d times, want 1 (no revival)", n)
	}
}

// A refund the provider answers failed at once is recorded FAILED, does not
// count, and a top-up's credit it took is given back at once.
func TestFlow_RefundAnsweredFailedAtCreation(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.stripe.refundStatus = "failed"
	ref := refundNow(t, r, p, "4", "rt")
	if ref.GetStatus() != pb.Refund_FAILED {
		t.Errorf("refund: %v, want FAILED", ref.GetStatus())
	}
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
	wantBalance(t, r, "10.0000")
	// A retry under the key is the same failed refund; nothing is taken again.
	refundNow(t, r, p, "4", "rt")
	wantBalance(t, r, "10.0000")
}

// A top-up refund made through RefundPayment that the provider fails later
// gives the credit back, once.
func TestWebhook_FailedTopUpRefundGivesTheCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	ref := refundNow(t, r, p, "4", "rt")
	wantBalance(t, r, "6.0000")

	r.stripe.setRefundStatus(ref.GetProviderRefundId(), "failed")
	failed := refundEvent("evt_rf", "refund.failed", ref.GetProviderRefundId(), p.GetProviderPaymentId())
	deliverOK(t, r, failed)
	wantBalance(t, r, "10.0000")
	deliverOK(t, r, failed)
	deliverOK(t, r, refundEvent("evt_ru", "refund.updated", ref.GetProviderRefundId(), p.GetProviderPaymentId()))
	// The caller's retry is the failed refund; it neither takes nor gives again.
	refundNow(t, r, p, "4", "rt")
	wantBalance(t, r, "10.0000")
}

// The refund's event can outrun RefundPayment's own insert (or that insert
// can fail). The webhook records the refund under the caller's key and takes
// no credit (RefundPayment took it), so the caller's retry is that refund.
func TestWebhook_RefundEventBeforeRefundPaymentRecordedIt(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.store.injectBefore("CreateRefund", errTransient)
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"}); err == nil {
		t.Fatal("want the local insert failure to surface")
	}
	id := r.stripe.lastRefundID()
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId()))
	row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED)
	if row.GetIdempotencyKey() != refundKey("rt") {
		t.Errorf("recorded without the caller's key: %q", row.GetIdempotencyKey())
	}
	wantBalance(t, r, "6.0000")
	again := refundNow(t, r, p, "4", "rt")
	if again.GetProviderRefundId() != id {
		t.Errorf("retry answered %s, want the recorded %s", again.GetProviderRefundId(), id)
	}
	wantBalance(t, r, "6.0000")
	if r.store.count("refunds") != 1 {
		t.Errorf("%d refund rows, want 1", r.store.count("refunds"))
	}
}

// ── refunds made at the provider directly (finding 5) ────────────────

// A refund this plugin does not know is recorded from the provider's list,
// once, without a key.
func TestWebhook_UnknownRefundIsRecorded(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 300)
	body := refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId())
	deliverOK(t, r, body)
	deliverOK(t, r, body)
	deliverOK(t, r, refundEvent("evt_cr", "charge.refunded", "ch_1", p.GetProviderPaymentId()))
	row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED)
	if row.GetAmount() != "3.0000" || row.GetCurrency() != "usd" || row.GetIdempotencyKey() != "" || row.GetPaymentId() != p.GetId() {
		t.Errorf("recorded %+v", row)
	}
	if r.store.count("refunds") != 1 {
		t.Errorf("%d refund rows, want 1", r.store.count("refunds"))
	}
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
	// It counts: refunding the rest through RefundPayment completes the amount.
	refundNow(t, r, p, "7", "r-rest")
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)
}

// A refund made at the provider of a top-up takes its credit back, once.
func TestWebhook_RefundAtTheProviderTakesTheTopUpCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
	body := refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId())
	deliverOK(t, r, body)
	deliverOK(t, r, body)
	deliverOK(t, r, refundEvent("evt_cr", "charge.refunded", "ch_1", p.GetProviderPaymentId()))
	wantBalance(t, r, "6.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "0.0000" {
		t.Errorf("shortfall %q, want 0.0000", row.GetCreditShortfall())
	}
}

// Credit already spent cannot be refused by a webhook — the money is gone. The
// balance is taken to zero, never below, and the rest is recorded as owed.
func TestWebhook_RefundAtTheProviderOfSpentCredit_RecordsTheShortfall(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "8", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 1000)
	body := refundEvent("evt_cr", "charge.refunded", "ch_1", p.GetProviderPaymentId())
	deliverOK(t, r, body)
	deliverOK(t, r, body)
	wantBalance(t, r, "0.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "8.0000" {
		t.Errorf("shortfall %q, want 8.0000", row.GetCreditShortfall())
	}
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)
}

// A spend that lands between the balance read and the take-back makes the
// CHECK refuse the take; the balance is read again and what is left taken.
func TestWebhook_RefundAtTheProvider_ASpendRacingTheTakeBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 1000)
	r.store.onceBefore("ApplyCredit", func() {
		if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "3", IdempotencyKey: "race"}); err != nil {
			t.Errorf("racing spend: %v", err)
		}
	})
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId()))
	wantBalance(t, r, "0.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "3.0000" {
		t.Errorf("shortfall %q, want 3.0000", row.GetCreditShortfall())
	}
}

// A refund made at the provider that later fails gives back what it took.
func TestWebhook_FailedRefundAtTheProviderGivesItsCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId()))
	wantBalance(t, r, "6.0000")
	r.stripe.setRefundStatus(id, "failed")
	failed := refundEvent("evt_rf", "refund.failed", id, p.GetProviderPaymentId())
	deliverOK(t, r, failed)
	deliverOK(t, r, failed)
	wantBalance(t, r, "10.0000")
	wantRefundStatus(t, r, id, pb.Refund_FAILED)
}

// A refund first seen already failed was never counted and takes nothing.
func TestWebhook_UnknownRefundFirstSeenFailed_TakesNothing(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
	r.stripe.setRefundStatus(id, "failed")
	deliverOK(t, r, refundEvent("evt_rf", "refund.failed", id, p.GetProviderPaymentId()))
	wantBalance(t, r, "10.0000")
	wantRefundStatus(t, r, id, pb.Refund_FAILED)
}

// A partial refund at the provider of a top-up whose grant has not landed is
// acknowledged with nothing taken (there is nothing to take, and waiting would
// hold up every other refund of the payment); the grant leaves the refunded
// part out.
func TestWebhook_RefundAtTheProviderOfAnUngrantedTopUp_IsLeftOutOfTheGrant(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-x")
	success := eventJSON("evt_top", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)
	r.store.injectBefore("ApplyCredit", errTransient)
	if _, err := r.deliver(success); err == nil {
		t.Fatal("want the grant failure to surface")
	}
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId()))
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "0.0000" {
		t.Errorf("shortfall %q, want 0.0000 (the grant leaves it out)", row.GetCreditShortfall())
	}
	// The payment is SUCCEEDED and its grant due: the refund's delivery
	// grants what is left, and the success's redelivery grants nothing more.
	wantBalance(t, r, "6.0000")
	deliverOK(t, r, success)
	wantBalance(t, r, "6.0000")
}

// A top-up refunded in full at the provider before its grant reads REFUNDED,
// and its grant is refused. When that refund fails, the payment is SUCCEEDED
// again and the credit — paid for, and kept — is granted. Later reversals of
// the payment are reconciled, never held up.
func TestWebhook_FailedFullRefundOfAnUngrantedTopUp_GrantsTheCredit(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-x")
	pi := p.GetProviderPaymentId()
	success := eventJSON("evt_top", "payment_intent.succeeded", pi, nil)
	r.store.injectBefore("ApplyCredit", errTransient)
	if _, err := r.deliver(success); err == nil {
		t.Fatal("want the grant failure to surface")
	}
	id := r.stripe.refundAtProvider(pi, 1000)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, pi))
	wantPaymentStatus(t, r, p, pb.Payment_REFUNDED)
	deliverOK(t, r, success)
	wantBalance(t, r, "0.0000")

	r.stripe.setRefundStatus(id, "failed")
	failed := refundEvent("evt_rf", "refund.failed", id, pi)
	deliverOK(t, r, failed)
	deliverOK(t, r, failed)
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
	wantBalance(t, r, "10.0000")
	deliverOK(t, r, success)
	wantBalance(t, r, "10.0000")

	again := r.stripe.refundAtProvider(pi, 400)
	deliverOK(t, r, refundEvent("evt_rc2", "refund.created", again, pi))
	wantBalance(t, r, "6.0000")
}

// A lost dispute on a top-up whose grant has not landed takes nothing (there
// is nothing to take) and is acknowledged; the grant will hand the credit
// over, so its amount is recorded as owed.
func TestWebhook_LostDisputeOnAnUngrantedTopUp_IsOwed(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-x")
	r.store.injectBefore("ApplyCredit", errTransient)
	if _, err := r.deliver(eventJSON("evt_top", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err == nil {
		t.Fatal("want the grant failure to surface")
	}
	deliverOK(t, r, disputeEvent(t, "evt_d", "charge.dispute.closed", "dp_u", p.GetProviderPaymentId(), "lost", 1000, time.Now().Unix()))
	if d := r.store.dispute(t, "dp_u"); d == nil || d.GetStatus() != pb.Dispute_LOST || d.GetCreditShortfall() != "10.0000" {
		t.Errorf("dispute %+v, want LOST owing 10.0000", d)
	}
}

// Two deliveries of one provider refund: A takes what the balance holds; B
// checked the ledger before A committed, then finds the balance emptied by A.
// Both answer the shortfall from the one ledger row, so B — recording the
// refund first — records what A could not take, not the whole amount.
func TestWebhook_ConcurrentReversalDeliveries_RecordOneShortfall(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "6", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	pi := p.GetProviderPaymentId()
	id := r.stripe.refundAtProvider(pi, 1000)
	atInsert, release, aDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	r.store.onceBefore("RecordProviderRefund", func() { close(atInsert); <-release })
	r.store.onceBefore("GetCreditBalance", func() {
		go func() {
			_, err := r.deliver(refundEvent("evt_a", "refund.created", id, pi))
			aDone <- err
		}()
		<-atInsert // A has taken the 4 and waits to record the refund
	})
	_, errB := r.deliver(refundEvent("evt_b", "charge.refunded", "ch_1", pi))
	close(release)
	if errA := <-aDone; errA != nil || errB != nil {
		t.Fatalf("deliveries: A %v, B %v", errA, errB)
	}
	wantBalance(t, r, "0.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "6.0000" {
		t.Errorf("shortfall %q, want 6.0000 (10 refunded, 4 taken)", row.GetCreditShortfall())
	}
}

// The same, as a free-for-all: eight deliveries at once, every run.
func TestWebhook_ConcurrentReversalDeliveries_Stress(t *testing.T) {
	for run := 0; run < 15; run++ {
		r := newRig(t)
		p := grantedTopUp(t, r, "10.00")
		if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "6", IdempotencyKey: "s1"}); err != nil {
			t.Fatal(err)
		}
		pi := p.GetProviderPaymentId()
		id := r.stripe.refundAtProvider(pi, 1000)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if _, err := r.deliver(refundEvent(fmt.Sprintf("evt_%d", i), "refund.created", id, pi)); err != nil {
					t.Errorf("delivery %d: %v", i, err)
				}
			}(i)
		}
		wg.Wait()
		wantBalance(t, r, "0.0000")
		if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "6.0000" {
			t.Fatalf("run %d: shortfall %q, want 6.0000", run, row.GetCreditShortfall())
		}
	}
}

// A delivery that read the refund as succeeded is about to mark the payment
// REFUNDED; meanwhile the refund fails and a second delivery records that,
// finding nothing to reverse yet. The first one's REFUNDED must not stand.
func TestWebhook_StaleRefundListCannotLeaveThePaymentRefunded(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	pi := p.GetProviderPaymentId()
	id := r.stripe.refundAtProvider(pi, 1000)
	r.store.onceBefore("MarkPaymentRefunded", func() {
		r.stripe.setRefundStatus(id, "failed")
		deliverOK(t, r, refundEvent("evt_b", "refund.failed", id, pi))
	})
	deliverOK(t, r, refundEvent("evt_a", "refund.created", id, pi))
	wantRefundStatus(t, r, id, pb.Refund_FAILED)
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
}

// A refund made at the provider over spent credit records what is owed; when
// it fails, what it took comes back and nothing is owed any more.
func TestWebhook_FailedRefundClearsItsShortfall(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "8", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	id := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 1000)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, p.GetProviderPaymentId()))
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "8.0000" {
		t.Fatalf("shortfall %q, want 8.0000", row.GetCreditShortfall())
	}
	r.stripe.setRefundStatus(id, "failed")
	deliverOK(t, r, refundEvent("evt_rf", "refund.failed", id, p.GetProviderPaymentId()))
	wantBalance(t, r, "2.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_FAILED); row.GetCreditShortfall() != "0.0000" {
		t.Errorf("a failed refund still owes %q", row.GetCreditShortfall())
	}
}

// A payment this installation never made is acknowledged without a provider
// call or a row.
func TestWebhook_RefundOfAForeignPaymentIsAcknowledged(t *testing.T) {
	r := newRig(t)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", "re_foreign", "pi_foreign"))
	if r.stripe.count("GET /v1/refunds") != 0 || r.store.count("refunds") != 0 {
		t.Error("a foreign refund reached the provider or the store")
	}
}

// ── disputes (finding 5) ─────────────────────────────────────────────

// An open dispute is recorded and takes nothing; a lost one takes a top-up's
// credit back, once, and an older event delivered after it does not reopen it.
func TestWebhook_LostDisputeTakesTheTopUpCreditBack(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	pi := p.GetProviderPaymentId()
	t0 := time.Now().Unix()
	deliverOK(t, r, disputeEvent(t, "evt_d1", "charge.dispute.created", "dp_1", pi, "needs_response", 1000, t0))
	if d := r.store.dispute(t, "dp_1"); d == nil || d.GetStatus() != pb.Dispute_NEEDS_RESPONSE || d.GetPaymentId() != p.GetId() || d.GetAmount() != "10.0000" {
		t.Fatalf("open dispute recorded as %+v", d)
	}
	wantBalance(t, r, "10.0000")

	lost := disputeEvent(t, "evt_d2", "charge.dispute.closed", "dp_1", pi, "lost", 1000, t0+10)
	deliverOK(t, r, lost)
	deliverOK(t, r, lost)
	wantBalance(t, r, "0.0000")
	// The opening event redelivered late.
	deliverOK(t, r, disputeEvent(t, "evt_d1b", "charge.dispute.updated", "dp_1", pi, "under_review", 1000, t0+5))
	if d := r.store.dispute(t, "dp_1"); d.GetStatus() != pb.Dispute_LOST || d.GetCreditShortfall() != "0.0000" {
		t.Errorf("dispute: %v shortfall %s, want LOST 0.0000", d.GetStatus(), d.GetCreditShortfall())
	}
	wantBalance(t, r, "0.0000")
}

// A lost dispute over spent credit records what is owed on the dispute.
func TestWebhook_LostDisputeOverSpentCredit_RecordsTheShortfall(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "7.5", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	// The first event this installation sees is the closing one.
	deliverOK(t, r, disputeEvent(t, "evt_d", "charge.dispute.closed", "dp_2", p.GetProviderPaymentId(), "lost", 1000, time.Now().Unix()))
	wantBalance(t, r, "0.0000")
	if d := r.store.dispute(t, "dp_2"); d == nil || d.GetStatus() != pb.Dispute_LOST || d.GetCreditShortfall() != "7.5000" {
		t.Errorf("dispute %+v, want LOST with shortfall 7.5000", d)
	}
}

// A won dispute, an inquiry, and an open dispute take nothing; between the
// open states the provider's order decides.
func TestWebhook_DisputeStatesThatTakeNothing(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	pi := p.GetProviderPaymentId()
	t0 := time.Now().Unix()
	deliverOK(t, r, disputeEvent(t, "evt_i", "charge.dispute.created", "dp_i", pi, "warning_needs_response", 1000, t0))
	deliverOK(t, r, disputeEvent(t, "evt_d2", "charge.dispute.updated", "dp_w", pi, "under_review", 1000, t0+5))
	deliverOK(t, r, disputeEvent(t, "evt_d1", "charge.dispute.created", "dp_w", pi, "needs_response", 1000, t0))
	if d := r.store.dispute(t, "dp_w"); d.GetStatus() != pb.Dispute_UNDER_REVIEW {
		t.Errorf("an older event overwrote a newer status: %v", d.GetStatus())
	}
	deliverOK(t, r, disputeEvent(t, "evt_d3", "charge.dispute.closed", "dp_w", pi, "won", 1000, t0+10))
	if d := r.store.dispute(t, "dp_w"); d.GetStatus() != pb.Dispute_WON {
		t.Errorf("dispute: %v, want WON", d.GetStatus())
	}
	if d := r.store.dispute(t, "dp_i"); d.GetStatus() != pb.Dispute_INQUIRY {
		t.Errorf("inquiry: %v, want INQUIRY", d.GetStatus())
	}
	wantBalance(t, r, "10.0000")
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
}

// A dispute on a payment this installation never made is acknowledged and
// not recorded.
func TestWebhook_DisputeOfAForeignPaymentIsAcknowledged(t *testing.T) {
	r := newRig(t)
	deliverOK(t, r, disputeEvent(t, "evt_d", "charge.dispute.closed", "dp_x", "pi_foreign", "lost", 1000, time.Now().Unix()))
	if r.store.dispute(t, "dp_x") != nil {
		t.Error("a foreign dispute was recorded")
	}
}

// A lost dispute on a non-top-up payment is recorded and takes no credit.
func TestWebhook_LostDisputeOnAPayment_TakesNoCredit(t *testing.T) {
	r := newRig(t)
	grantedTopUp(t, r, "10.00")
	p := succeededPayment(t, r, "5")
	deliverOK(t, r, disputeEvent(t, "evt_d", "charge.dispute.closed", "dp_p", p.GetProviderPaymentId(), "lost", 500, time.Now().Unix()))
	if d := r.store.dispute(t, "dp_p"); d == nil || d.GetStatus() != pb.Dispute_LOST || d.GetCreditShortfall() != "0.0000" {
		t.Errorf("dispute %+v", d)
	}
	wantBalance(t, r, "10.0000")
}

// A refund answered failed whose credit could not be given back at once (a
// store failure) is recorded; the caller's retry under the key gives the
// credit back.
func TestFlow_FailedRefundsCreditIsGivenBackOnRetry(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	r.stripe.refundStatus = "failed"
	// Let the take-back apply, then fail the give-back that follows the answer.
	r.store.onceBefore("ApplyCredit", func() {
		r.store.onceBefore("ApplyCredit", func() { r.store.injectBefore("ApplyCredit", errTransient) })
	})
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "4", IdempotencyKey: "rt"}); err == nil {
		t.Fatal("want the give-back failure to surface")
	}
	wantBalance(t, r, "6.0000")
	ref := refundNow(t, r, p, "4", "rt")
	if ref.GetStatus() != pb.Refund_FAILED {
		t.Errorf("retry answered %v, want the FAILED refund", ref.GetStatus())
	}
	wantBalance(t, r, "10.0000")
}

// A refund made at the provider when the whole credit was already spent takes
// nothing (its take-back row holds zero) and owes all of it; when it fails,
// there is nothing to give back and nothing owed.
func TestWebhook_FailedRefundThatTookNothing(t *testing.T) {
	r := newRig(t)
	p := grantedTopUp(t, r, "10.00")
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "10", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	pi := p.GetProviderPaymentId()
	id := r.stripe.refundAtProvider(pi, 1000)
	deliverOK(t, r, refundEvent("evt_rc", "refund.created", id, pi))
	if row := wantRefundStatus(t, r, id, pb.Refund_SUCCEEDED); row.GetCreditShortfall() != "10.0000" {
		t.Fatalf("shortfall %q, want 10.0000", row.GetCreditShortfall())
	}
	r.stripe.setRefundStatus(id, "failed")
	deliverOK(t, r, refundEvent("evt_rf", "refund.failed", id, pi))
	wantBalance(t, r, "0.0000")
	if row := wantRefundStatus(t, r, id, pb.Refund_FAILED); row.GetCreditShortfall() != "0.0000" {
		t.Errorf("a failed refund still owes %q", row.GetCreditShortfall())
	}
}

// RefundPayment marking REFUNDED races the webhook recording that refund's
// failure (which found nothing to reverse yet): RefundPayment reads the rows
// again after its write, so the payment does not stay REFUNDED.
func TestFlow_RefundPaymentRacingTheRefundsFailure_DoesNotStayRefunded(t *testing.T) {
	r := newRig(t)
	p := succeededPayment(t, r, "10")
	pi := p.GetProviderPaymentId()
	r.store.onceBefore("MarkPaymentRefunded", func() {
		id := r.stripe.lastRefundID()
		r.stripe.setRefundStatus(id, "failed")
		deliverOK(t, r, refundEvent("evt_rf", "refund.failed", id, pi))
	})
	refundNow(t, r, p, "10", "r1")
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
}
