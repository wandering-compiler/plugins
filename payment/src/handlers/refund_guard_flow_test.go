package handlers

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/lib/backend"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
)

// The refund guard (base/refund-within-captured, base/refund-only-succeeded)
// is the plugin's own: it holds against a gateway that errs. Every flow here
// runs against stripeFake.erring, which refunds past what is left on the
// intent the way a broken gateway would.

func (l *rowLocks) waitCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waits
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func erringRig(t *testing.T) *rig {
	r := newRig(t)
	r.stripe.erring = true
	return r
}

// refund is bounded: a lock never released fails the test instead of hanging it.
func refund(r *rig, id string, amount int64, key string) (*pb.RefundPaymentResp, error) {
	ctx, cancel := context.WithTimeout(bg, 10*time.Second)
	defer cancel()
	return r.h.RefundPayment(ctx, &pb.RefundPaymentReq{PaymentId: id, Amount: amount, IdempotencyKey: key})
}

// wantNoLocksLeft: every refund ends its transaction, whatever the outcome.
func wantNoLocksLeft(t *testing.T, r *rig) {
	t.Helper()
	if n := r.store.locks.open(); n != 0 {
		t.Errorf("%d payment row locks still held after the refunds returned", n)
	}
}

func TestFlow_RefundPastWhatRemains_IsRefusedBeforeTheProvider(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	if _, err := refund(r, p.GetId(), 60000, "r1"); err != nil {
		t.Fatal(err)
	}
	before := r.stripe.count("/v1/refunds")
	_, err := refund(r, p.GetId(), 60000, "r2")
	wantCode(t, err, codes.InvalidArgument, "6 more of a payment of 10 with 6 refunded")
	if !strings.Contains(err.Error(), "4.0000 of 10.0000 usd") {
		t.Errorf("the refusal does not say what remains: %v", err)
	}
	if n := r.stripe.count("/v1/refunds"); n != before {
		t.Errorf("a refused refund reached the provider (%d → %d)", before, n)
	}
	if n := r.store.count("refunds"); n != 1 {
		t.Errorf("refund rows = %d, want 1 (a refused refund records nothing)", n)
	}
	// Exactly what remains goes through, written in another scale too.
	if _, err := refund(r, p.GetId(), 40000, "r4"); err != nil {
		t.Fatalf("refund of exactly what remains: %v", err)
	}
	_, err = refund(r, p.GetId(), 100, "r5")
	wantCode(t, err, codes.InvalidArgument, "a cent more than a payment refunded in full")
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 1000 {
		t.Errorf("provider refunded %d minor units, want 1000", got)
	}
	wantNoLocksLeft(t, r)
}

// A pending refund counts: the provider counts it against the refundable
// amount, and it may still succeed. A failed or canceled one does not.
func TestFlow_PendingRefundsCount_FailedOnesDoNot(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	r.stripe.refundStatus = "pending"
	first, err := refund(r, p.GetId(), 100000, "r1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = refund(r, p.GetId(), 10000, "r2")
	wantCode(t, err, codes.InvalidArgument, "a refund beside a pending refund of the whole payment")

	r.store.mu.Lock()
	r.store.refunds[first.GetRefund().GetId()].Status = pb.Refund_FAILED
	r.store.mu.Unlock()
	r.stripe.refundStatus = ""
	if _, err := refund(r, p.GetId(), 100000, "r3"); err != nil {
		t.Fatalf("after the first refund failed, the payment is refundable again: %v", err)
	}
	wantNoLocksLeft(t, r)
}

// Two refunds of one payment under different keys at once: the second waits
// for the first's lock, then counts it. Without the lock both read "nothing
// refunded yet" and the gateway, erring, refunds 12 of 10.
func TestFlow_ConcurrentRefunds_TheSecondWaitsAndCountsTheFirst(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	second := make(chan error, 1)
	r.store.onceBefore("CreateRefund", func() {
		// The first refund is made at the provider and holds the lock; the
		// second starts now.
		go func() {
			_, err := refund(r, p.GetId(), 60000, "r2")
			second <- err
		}()
		eventually(t, "the second refund to wait for the payment's lock", func() bool { return r.store.locks.waitCount() > 0 })
	})
	if _, err := refund(r, p.GetId(), 60000, "r1"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, <-second, codes.InvalidArgument, "the second of two concurrent refunds of 6 of 10")
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 600 {
		t.Errorf("provider refunded %d minor units, want 600", got)
	}
	if n := r.stripe.count("/v1/refunds"); n != 1 {
		t.Errorf("provider refund calls = %d, want 1", n)
	}
	wantNoLocksLeft(t, r)
}

// Many at once: exactly as many as fit go through.
func TestFlow_ManyConcurrentRefunds_NeverExceedThePayment(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	var wg sync.WaitGroup
	errs := make([]error, 12)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = refund(r, p.GetId(), 30000, "r"+string(rune('a'+i)))
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch status.Code(err) {
		case codes.OK:
			ok++
		case codes.InvalidArgument:
		default:
			t.Errorf("unexpected answer: %v", err)
		}
	}
	if ok != 3 {
		t.Errorf("%d refunds of 3 went through on a payment of 10, want 3", ok)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 900 {
		t.Errorf("provider refunded %d minor units, want 900", got)
	}
	wantNoLocksLeft(t, r)
}

// A payment that did not succeed is refused before any provider call.
func TestFlow_RefundOfAFailedOrCanceledPayment_IsRefused(t *testing.T) {
	for _, st := range []pb.Payment_Status{pb.Payment_FAILED, pb.Payment_CANCELED} {
		r := erringRig(t)
		p := r.paid("user-a", 100000, "k")
		r.store.mu.Lock()
		r.store.payments[p.GetId()].Status = st
		r.store.mu.Unlock()
		_, err := refund(r, p.GetId(), 0, "r1")
		wantCode(t, err, codes.FailedPrecondition, "a refund of a "+st.String()+" payment")
		if n := r.stripe.count("/v1/refunds") + r.stripe.count("GET /v1/payment_intents/{id}"); n != 0 {
			t.Errorf("%s: the provider was asked (%d calls)", st, n)
		}
		wantNoLocksLeft(t, r)
	}
}

// A payment whose webhook has not arrived yet: the provider is asked, and its
// answer decides. Succeeded there is refundable; anything else is not yet.
func TestFlow_RefundBeforeTheSuccessWebhook_AsksTheProvider(t *testing.T) {
	r := erringRig(t)
	p := r.charge("user-a", 100000, "k") // locally REQUIRES_ACTION
	_, err := refund(r, p.GetId(), 0, "r1")
	wantCode(t, err, codes.FailedPrecondition, "a refund of a payment the provider has not seen succeed")
	if n := r.stripe.count("/v1/refunds"); n != 0 {
		t.Errorf("an unpaid payment was refunded at the provider (%d calls)", n)
	}
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "processing", false)
	_, err = refund(r, p.GetId(), 0, "r1")
	wantCode(t, err, codes.FailedPrecondition, "a refund of a payment still processing at the provider")

	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false) // paid; webhook in flight
	if _, err := refund(r, p.GetId(), 0, "r1"); err != nil {
		t.Fatalf("a payment the provider reports succeeded is refundable before its webhook: %v", err)
	}
	if n := r.stripe.count("GET /v1/payment_intents/{id}"); n != 3 {
		t.Errorf("provider reads = %d, want one per refund attempt (3)", n)
	}
	wantNoLocksLeft(t, r)
}

// Locally SUCCEEDED needs no provider read.
func TestFlow_RefundOfASucceededPayment_ReadsNothingFromTheProvider(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	if _, err := refund(r, p.GetId(), 40000, "r1"); err != nil {
		t.Fatal(err)
	}
	if n := r.stripe.count("GET /v1/payment_intents/{id}"); n != 0 {
		t.Errorf("provider reads = %d for a payment known to have succeeded", n)
	}
}

// A retry of a recorded refund is answered from its row, even once nothing
// remains: the guard is for NEW refunds.
func TestFlow_RetryOfARecordedRefund_IsAnsweredAfterThePaymentIsFullyRefunded(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	first, err := refund(r, p.GetId(), 0, "r1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := refund(r, p.GetId(), 0, "r1")
	if err != nil {
		t.Fatalf("retry of the full refund: %v", err)
	}
	if again.GetRefund().GetId() != first.GetRefund().GetId() {
		t.Errorf("the retry answered refund %s, want %s", again.GetRefund().GetId(), first.GetRefund().GetId())
	}
}

// Every way a refund ends releases the payment's lock: a refusal, a provider
// failure, a failed record, and success. A held lock would stop every later
// refund of the payment until the transaction timed out.
func TestFlow_TheRefundLockIsReleasedOnEveryPath(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	dt := r.h.DistTx.(*fakeDistTx)

	_, _ = refund(r, p.GetId(), 110000, "r-over") // refused
	r.stripe.failNext(503)
	_, _ = refund(r, p.GetId(), 10000, "r-503") // provider failure
	r.store.injectBefore("CreateRefund", errTransient)
	_, _ = refund(r, p.GetId(), 10000, "r-rec") // recorded at the provider, not locally
	if _, err := refund(r, p.GetId(), 10000, "r-ok"); err != nil {
		t.Fatal(err)
	}
	wantNoLocksLeft(t, r)
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if dt.begun != 4 || len(dt.ended) != 4 {
		t.Errorf("transactions begun %d, ended %d — want every one ended", dt.begun, len(dt.ended))
	}
	commits := 0
	for _, how := range dt.ended {
		if how == "commit" {
			commits++
		}
	}
	if commits != 1 {
		t.Errorf("%d transactions committed, want only the successful refund's (refusals roll back)", commits)
	}
}

// A provider read that fails is the provider's failure, and nothing is
// refunded on a guess.
func TestRefundPayment_AProviderReadFailureRefundsNothing(t *testing.T) {
	be := &fakeBackend{getPaymentErr: errors.New("connection reset"), refundRes: backend.RefundResult{ProviderRefundID: "re_1", Status: "succeeded"}}
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-1", ProviderPaymentId: "pi_1", Amount: 100000, Currency: "usd", Status: pb.Payment_PROCESSING}}
	h := newHandler(q, &fakeMutation{}, be)
	_, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-1", IdempotencyKey: "r"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("got %v, want the provider failure as Unavailable", err)
	}
	if be.refundCalls != 0 {
		t.Errorf("refunded %d times after a failed read", be.refundCalls)
	}
}

// A REFUNDED payment is judged by what remains, not refused outright: a
// refund that failed after it was settled leaves the rest refundable.
func TestRefundPayment_ARefundedPaymentIsJudgedByWhatRemains(t *testing.T) {
	for _, c := range []struct {
		refunded int64
		want     codes.Code
	}{{0, codes.OK}, {100000, codes.InvalidArgument}} {
		be := &fakeBackend{refundRes: backend.RefundResult{ProviderRefundID: "re_1", Status: "succeeded"}}
		q := &fakeQuery{payment: &pb.Payment{Id: "pay-1", ProviderPaymentId: "pi_1", Amount: 100000, Currency: "usd", Status: pb.Payment_REFUNDED}, refundedTotal: c.refunded}
		h := newHandler(q, &fakeMutation{}, be)
		_, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-1", IdempotencyKey: "r"})
		if status.Code(err) != c.want {
			t.Errorf("REFUNDED with %d refunded: %v, want %v", c.refunded, err, c.want)
		}
		if len(be.gotPayment) != 0 {
			t.Error("a payment known to have succeeded was read from the provider")
		}
	}
}

// Without a transaction client a refund is refused, never made unguarded.
func TestRefundPayment_WithoutATransactionClientRefundsNothing(t *testing.T) {
	be := &fakeBackend{refundRes: backend.RefundResult{ProviderRefundID: "re_1", Status: "succeeded"}}
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-1", ProviderPaymentId: "pi_1", Amount: 100000, Currency: "usd", Status: pb.Payment_SUCCEEDED}}
	h := newHandler(q, &fakeMutation{}, be)
	h.DistTx = nil
	_, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-1", IdempotencyKey: "r"})
	if status.Code(err) != codes.Internal {
		t.Fatalf("got %v, want Internal", err)
	}
	if be.refundCalls != 0 {
		t.Errorf("refunded %d times without the guard", be.refundCalls)
	}
	if err := ValidateConfig(&PaymentServiceHandler{Query: q, Mutation: &fakeMutation{}, Backend: be, WebhookSecret: "whsec_x"}); err == nil {
		t.Error("a handler without a transaction client passed ValidateConfig")
	}
}

// prepaid gap 4: two refunds of one top-up at once run one after the other
// under the payment's lock, so the second one's credit check counts the
// credit the first took back: refused, and never sent to the provider.
func TestFlow_ConcurrentTopUpRefunds_TheSecondSeesTheFirstsTakeBack(t *testing.T) {
	r := erringRig(t)
	p := grantedTopUp(t, r, 100000)
	if _, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: 40000, IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	r.store.onceBefore("CreateRefund", func() {
		go func() {
			_, err := refund(r, p.GetId(), 50000, "r2")
			second <- err
		}()
		eventually(t, "the second refund to wait for the payment's lock", func() bool { return r.store.locks.waitCount() > 0 })
	})
	if _, err := refund(r, p.GetId(), 50000, "r1"); err != nil {
		t.Fatal(err)
	}
	wantCode(t, <-second, codes.FailedPrecondition, "a second refund of 5 when 1 credit is left")
	if n := r.stripe.count("/v1/refunds"); n != 1 {
		t.Errorf("provider refund calls = %d, want 1", n)
	}
	if got := r.store.balance(t, "user-a"); got != 10000 {
		t.Errorf("balance = %d, want 1.0000 (10 granted, 4 spent, 5 refunded)", got)
	}
	wantNoLocksLeft(t, r)
}

// The guards under a row lock read what the previous holder committed AFTER
// the lock is granted (the refunded sum, the open subscription). That holds
// only under READ COMMITTED: under REPEATABLE READ the snapshot is taken by
// the lock statement before it waits, and the sum misses the refund the
// previous holder recorded. A connection's default isolation is the
// project's setting, so every transaction the plugin opens asks for READ
// COMMITTED itself.
func TestInLockedTx_AsksForReadCommitted(t *testing.T) {
	r := subRig(t)
	p := r.paid("user-a", 100000, "k")
	if _, err := refund(r, p.GetId(), 10000, "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := subscribe(r, "pro", "s1"); err != nil {
		t.Fatal(err)
	}
	d := r.h.DistTx.(*fakeDistTx)
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.isolations) < 2 {
		t.Fatalf("%d transactions begun, want one per refund and per subscribe", len(d.isolations))
	}
	for i, iso := range d.isolations {
		if iso != distxpb.Isolation_READ_COMMITTED {
			t.Errorf("transaction %d asked for %v, want READ_COMMITTED", i, iso)
		}
	}
}

// amount = 0 refunds what remains, as the provider's own refund without an
// amount does: after a partial refund it is the rest, not the whole payment
// (which used to be refused as exceeding what remains). Resolved under the
// payment's lock; a retry under its key is answered with that refund; once
// nothing remains it is refused before the provider.
func TestFlow_AFullRefundAfterAPartialOneRefundsTheRest(t *testing.T) {
	r := erringRig(t)
	p := r.paid("user-a", 100000, "k")
	if _, err := refund(r, p.GetId(), 30000, "r1"); err != nil {
		t.Fatal(err)
	}
	rest, err := refund(r, p.GetId(), 0, "r2")
	if err != nil {
		t.Fatalf("refund of the rest after a partial one: %v", err)
	}
	if got := rest.GetRefund().GetAmount(); got != 70000 {
		t.Errorf("the rest refunded %d, want 70000", got)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 1000 {
		t.Errorf("provider refunded %d minor units, want 1000", got)
	}
	again, err := refund(r, p.GetId(), 0, "r2")
	if err != nil || again.GetRefund().GetId() != rest.GetRefund().GetId() {
		t.Errorf("a retry of the rest under its key = %v, %v; want the same refund", again, err)
	}
	// Under a key that names a partial refund, "what remains" is that refund
	// only once, with it, nothing remains (the request's goal holds); while
	// something remains it names another refund.
	q := r.paid("user-b", 100000, "k2")
	if _, err := refund(r, q.GetId(), 30000, "q1"); err != nil {
		t.Fatal(err)
	}
	if _, err := refund(r, q.GetId(), 0, "q1"); status.Code(err) != codes.AlreadyExists {
		t.Errorf("\"the rest\" under the key of a partial refund, 70 remaining: err = %v, want AlreadyExists", err)
	}
	if got, err := refund(r, p.GetId(), 0, "r1"); err != nil || got.GetRefund().GetAmount() != 30000 {
		t.Errorf("\"the rest\" under the key of a partial refund, nothing remaining = %v, %v; want that refund", got, err)
	}
	before := r.stripe.count("/v1/refunds")
	_, err = refund(r, p.GetId(), 0, "r3")
	wantCode(t, err, codes.InvalidArgument, "a refund of the rest when nothing remains")
	if n := r.stripe.count("/v1/refunds"); n != before {
		t.Errorf("a refund of nothing reached the provider (%d → %d)", before, n)
	}
	if n := r.store.count("refunds"); n != 3 {
		t.Errorf("refund rows = %d, want 3", n)
	}
	wantNoLocksLeft(t, r)
}
