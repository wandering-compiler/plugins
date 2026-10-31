package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// The provider reconciliation (ReconcileProvider), against the stateful store
// and the wire-format provider fake: what the webhooks never brought in is
// recorded through their own paths, once.

// fromTheStart covers every object the fake makes.
var fromTheStart = timestamppb.New(time.Unix(fakeEpoch, 0))

func (r *rig) reconcileAll() *pb.ReconcileProviderResp {
	r.t.Helper()
	resp, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
	if err != nil {
		r.t.Fatalf("ReconcileProvider: %v", err)
	}
	if resp.GetNextCursor() != "" {
		r.t.Fatalf("a walk within the default limit left a cursor: %q", resp.GetNextCursor())
	}
	return resp
}

// counts renders one kind's counts as created/updated/in_sync/foreign/superseded/failed.
func counts(c *pb.ReconcileCounts) string {
	return fmt.Sprintf("c%d u%d s%d f%d x%d F%d", c.GetCreated(), c.GetUpdated(), c.GetInSync(), c.GetForeign(), c.GetSuperseded(), c.GetFailed())
}

func wantCounts(t *testing.T, what string, c *pb.ReconcileCounts, want string) {
	t.Helper()
	if got := counts(c); got != want {
		t.Errorf("%s: %s, want %s", what, got, want)
	}
}

// A charge whose local row never landed (the insert failed and the caller
// never retried) and which the customer then paid: the run records it, at the
// provider's status, through the webhook's transition — PaymentSucceeded is
// emitted once. The caller's late retry with its key (the provider replays the
// intent) gets that row, not AlreadyExists.
func TestReconcile_OrphanPayment_RecordedWithItsStatus(t *testing.T) {
	r := newRig(t)
	r.charge("user-a", "1.00", "warm-up") // the customer's row
	r.store.injectBefore("CreatePayment", errTransient)
	_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "19.99", Currency: "usd", IdempotencyKey: "order-1"})
	wantCode(t, err, codes.Unavailable, "the charge whose row failed")
	orphan := r.stripe.order[len(r.stripe.order)-1]
	r.stripe.setIntentStatus(orphan, "succeeded", false)

	resp := r.reconcileAll()
	wantCounts(t, "payments", resp.GetPayments(), "c1 u0 s1 f0 x0 F0")
	wantCounts(t, "customers", resp.GetCustomers(), "c0 u0 s1 f0 x0 F0")
	row := r.store.paymentByProvider(orphan)
	if row == nil {
		t.Fatal("no row recorded for the orphan intent")
	}
	if row.GetStatus() != pb.Payment_SUCCEEDED || row.GetAmount() != "19.9900" || row.GetCurrency() != "usd" {
		t.Errorf("recorded row = %+v", row)
	}
	if row.GetIdempotencyKey() != reconciledChargeKey(orphan) {
		t.Errorf("key = %q, want the reconciled stand-in", row.GetIdempotencyKey())
	}
	if n := r.store.events("PaymentSucceeded"); n != 1 {
		t.Errorf("PaymentSucceeded emitted %d times, want 1", n)
	}

	retry, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "19.99", Currency: "usd", IdempotencyKey: "order-1"})
	if err != nil {
		t.Fatalf("the caller's retry after the reconciliation: %v", err)
	}
	if retry.GetPayment().GetId() != row.GetId() {
		t.Errorf("the retry answered another payment: %+v", retry.GetPayment())
	}
}

// A payment attempt that failed reads requires_payment_method with an error:
// FAILED, the webhook's payment_failed. One nobody tried to pay stays open.
func TestReconcile_FailedAndOpenIntents(t *testing.T) {
	r := newRig(t)
	failed := r.charge("user-a", "5.00", "f-1")
	open := r.charge("user-a", "6.00", "o-1")
	r.stripe.setIntentStatus(failed.GetProviderPaymentId(), "requires_payment_method", true)

	resp := r.reconcileAll()
	wantCounts(t, "payments", resp.GetPayments(), "c0 u1 s1 f0 x0 F0")
	wantPaymentStatus(t, r, failed, pb.Payment_FAILED)
	wantPaymentStatus(t, r, open, pb.Payment_REQUIRES_ACTION)
	if n := r.store.events("PaymentFailed"); n != 1 {
		t.Errorf("PaymentFailed emitted %d times, want 1", n)
	}
}

// A webhook endpoint that was down past the provider's redelivery: the run
// brings the lagging status in, a second run changes nothing.
func TestReconcile_LaggingStatus_UpdatedThenInSync(t *testing.T) {
	r := newRig(t)
	paid := r.charge("user-a", "5.00", "k-1")
	canceled := r.charge("user-a", "7.00", "k-2")
	r.stripe.setIntentStatus(paid.GetProviderPaymentId(), "succeeded", false)
	r.stripe.setIntentStatus(canceled.GetProviderPaymentId(), "canceled", false)

	wantCounts(t, "first run", r.reconcileAll().GetPayments(), "c0 u2 s0 f0 x0 F0")
	wantPaymentStatus(t, r, paid, pb.Payment_SUCCEEDED)
	wantPaymentStatus(t, r, canceled, pb.Payment_CANCELED)

	before := r.store.callsSince(nil)
	wantCounts(t, "second run", r.reconcileAll().GetPayments(), "c0 u0 s2 f0 x0 F0")
	if r.store.events("PaymentSucceeded") != 1 || r.store.events("PaymentCanceled") != 1 {
		t.Errorf("events: succeeded=%d canceled=%d, want 1 each", r.store.events("PaymentSucceeded"), r.store.events("PaymentCanceled"))
	}
	for m, n := range r.store.callsSince(before) {
		if m == "CreatePayment" || m == "CreateCustomer" {
			t.Errorf("the rerun wrote: %s x%d", m, n)
		}
	}
}

// A top-up whose CreditTopup row never landed (TopUpCredit writes the Payment
// first) and whose payment then succeeded: the run records the top-up and
// grants its credit — once, however often it runs.
func TestReconcile_TopupWithoutItsRecord_GrantedOnce(t *testing.T) {
	r := newRig(t)
	r.store.injectBefore("CreateCreditTopup", errTransient)
	_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "10.00", IdempotencyKey: "top-1"})
	wantCode(t, err, codes.Unavailable, "the top-up whose record failed")
	pid := r.stripe.order[len(r.stripe.order)-1]
	r.stripe.setIntentStatus(pid, "succeeded", false)

	wantCounts(t, "first run", r.reconcileAll().GetPayments(), "c0 u1 s0 f0 x0 F0")
	wantBalance(t, r, "10.0000")
	wantCounts(t, "second run", r.reconcileAll().GetPayments(), "c0 u0 s1 f0 x0 F0")
	wantBalance(t, r, "10.0000")
	if n := r.store.events("CreditApplied"); n != 1 {
		t.Errorf("CreditApplied emitted %d times, want 1", n)
	}
}

// A refund made in the provider's dashboard on a granted top-up, whose webhook
// never arrived: the run records it and takes the credit back once; the late
// webhook then finds nothing to do.
func TestReconcile_OrphanRefundOnTopup_TakesTheCreditOnce(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "10.00", "top-1")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	deliverOK(t, r, r.stripe.objectEvent("evt_ok", "payment_intent.succeeded", p.GetProviderPaymentId(), nil))
	wantBalance(t, r, "10.0000")
	re := r.stripe.refundAtProvider(p.GetProviderPaymentId(), 400)

	wantCounts(t, "first run", r.reconcileAll().GetRefunds(), "c1 u0 s0 f0 x0 F0")
	wantRefundStatus(t, r, re, pb.Refund_SUCCEEDED)
	wantBalance(t, r, "6.0000")
	wantCounts(t, "second run", r.reconcileAll().GetRefunds(), "c0 u0 s1 f0 x0 F0")
	deliverOK(t, r, refundEvent("evt_re", "refund.created", re, p.GetProviderPaymentId()))
	wantBalance(t, r, "6.0000")

	// The refund then fails at the provider, and that webhook is lost too:
	// the next run records the failure and gives the credit back.
	r.stripe.setRefundStatus(re, "failed")
	wantCounts(t, "after the failure", r.reconcileAll().GetRefunds(), "c0 u1 s0 f0 x0 F0")
	wantBalance(t, r, "10.0000")
}

// A subscription whose local row never landed: recorded in the provider's
// status (SubscriptionStarted once); a later status change is brought in; a
// webhook event older than the run's read cannot put the older status back.
func TestReconcile_OrphanSubscription(t *testing.T) {
	r := newRig(t)
	r.stripe.subStatus = "active" // its first payment made by the time the run reads it
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	r.store.injectBefore("CreateSubscription", errTransient)
	_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s-1"})
	wantCode(t, err, codes.Unavailable, "the subscribe whose row failed")
	sid := r.stripe.subs[0].id

	resp := r.reconcileAll()
	wantCounts(t, "subscriptions", resp.GetSubscriptions(), "c1 u0 s0 f0 x0 F0")
	if r.store.count("subs") != 1 || r.store.events("SubscriptionStarted") != 1 {
		t.Fatalf("subs=%d started=%d, want 1 each", r.store.count("subs"), r.store.events("SubscriptionStarted"))
	}
	wantSub := func(what string, want pb.Subscription_Status) {
		t.Helper()
		for _, s := range r.store.subs {
			if s.GetStatus() != want {
				t.Errorf("%s: %v, want %v", what, s.GetStatus(), want)
			}
		}
	}
	wantSub("recorded", pb.Subscription_ACTIVE)
	// The creation event, created before the run read the provider and
	// redelivered only now, says incomplete: older than the row.
	stale := time.Now().Add(-time.Hour).Unix()
	deliverOK(t, r, withCreated(t, r.stripe.objectEvent("evt_created", "customer.subscription.created", sid, map[string]any{"status": "incomplete"}), stale))
	wantSub("after a stale event", pb.Subscription_ACTIVE)

	r.stripe.setSubStatus(sid, "past_due")
	wantCounts(t, "after a change", r.reconcileAll().GetSubscriptions(), "c0 u1 s0 f0 x0 F0")
	wantCounts(t, "rerun", r.reconcileAll().GetSubscriptions(), "c0 u0 s1 f0 x0 F0")
	deliverOK(t, r, withCreated(t, r.stripe.objectEvent("evt_old", "customer.subscription.updated", sid, map[string]any{"status": "active"}), stale))
	wantSub("after a stale event", pb.Subscription_PAST_DUE)
	// An event created after the run's read applies.
	deliverOK(t, r, withCreated(t, r.stripe.objectEvent("evt_new", "customer.subscription.updated", sid, map[string]any{"status": "unpaid"}), time.Now().Add(time.Minute).Unix()))
	wantSub("after a newer event", pb.Subscription_UNPAID)
	// Subscribe's own retry finds the recorded row.
	sv, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s-1"})
	if err != nil || sv.GetSubscription().GetProviderSubscriptionId() != sid {
		t.Errorf("Subscribe retry: %+v, %v", sv, err)
	}
}

// Objects this installation did not make — unmarked, marked by another
// installation sharing the account, a refund of a payment that is not local —
// are counted foreign and left alone.
func TestReconcile_ForeignObjectsAreLeftAlone(t *testing.T) {
	r := newRig(t)
	other := map[string]string{"w17_payment": "charge", "w17_install": backend.InstallID("whsec_another_installation")}
	cus := r.stripe.foreignCustomer(map[string]string{"user_id": "user-x"})
	r.stripe.foreignCustomer(map[string]string{"user_id": "user-y", "w17_payment": "customer", "w17_install": other["w17_install"]})
	pi := r.stripe.foreignIntent(cus, 500, nil)
	r.stripe.foreignIntent(cus, 700, other)
	r.stripe.refundAtProvider(pi, 100)
	r.stripe.foreignSub(cus, "price_x")
	r.stripe.setIntentStatus(pi, "succeeded", false)

	resp := r.reconcileAll()
	wantCounts(t, "customers", resp.GetCustomers(), "c0 u0 s0 f2 x0 F0")
	wantCounts(t, "payments", resp.GetPayments(), "c0 u0 s0 f2 x0 F0")
	wantCounts(t, "refunds", resp.GetRefunds(), "c0 u0 s0 f1 x0 F0")
	wantCounts(t, "subscriptions", resp.GetSubscriptions(), "c0 u0 s0 f1 x0 F0")
	for _, table := range []string{"customers", "payments", "refunds", "subs"} {
		if n := r.store.count(table); n != 0 {
			t.Errorf("%s: %d rows written for foreign objects", table, n)
		}
	}
}

// A customer whose link never landed gets it; one whose principal is linked
// to another customer (the loser of two first charges) is superseded and the
// link stays. A customer made before customers were marked is foreign.
func TestReconcile_Customers(t *testing.T) {
	r := newRig(t)
	r.store.injectBefore("CreateCustomer", errTransient)
	_, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a", Email: "a@example.com"})
	wantCode(t, err, codes.Unavailable, "the customer whose row failed")
	orphan := r.stripe.customers[0].id

	// The retry carries another address, so it is another create: a retry
	// of the SAME create gets the first customer back under its idempotency
	// key (TestFlow_CustomerAndPlanCreatesCarryAnIdempotencyKey) and leaves
	// nothing to supersede.
	r.store.injectBefore("CreateCustomer", errTransient)
	_, err = r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-b"})
	wantCode(t, err, codes.Unavailable, "user-b's first customer")
	if _, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-b", Email: "b@example.com"}); err != nil {
		t.Fatal(err)
	}
	r.stripe.foreignCustomer(map[string]string{"user_id": "user-c"}) // an earlier version's

	wantCounts(t, "customers", r.reconcileAll().GetCustomers(), "c1 u0 s1 f1 x1 F0")
	got, err := r.h.Query.GetCustomerByUserId(bg, &pb.GetCustomerByUserIdReq{UserId: "user-a"})
	if err != nil || got.GetCustomer().GetProviderCustomerId() != orphan || got.GetCustomer().GetEmail() != "a@example.com" {
		t.Errorf("user-a's link = %+v, %v", got.GetCustomer(), err)
	}
	if r.store.count("customers") != 2 {
		t.Errorf("customers = %d, want 2", r.store.count("customers"))
	}
	wantCounts(t, "rerun", r.reconcileAll().GetCustomers(), "c0 u0 s2 f1 x1 F0")
}

// A run beside the webhook deliveries of the same success, and beside other
// runs: the payment succeeds once and the top-up's credit is granted once.
func TestReconcile_ConcurrentWithWebhooksAndItself_GrantsOnce(t *testing.T) {
	r := newRig(t)
	p := r.topUp("user-a", "20.00", "top-c")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	body := r.stripe.objectEvent("evt_c", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := r.deliver(body); err != nil {
				errs <- fmt.Errorf("delivery: %w", err)
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
			if err != nil {
				errs <- fmt.Errorf("run: %w", err)
				return
			}
			if resp.GetPayments().GetFailed() != 0 {
				errs <- fmt.Errorf("run: payments %s", counts(resp.GetPayments()))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	wantBalance(t, r, "20.0000")
	if r.store.events("PaymentSucceeded") != 1 || r.store.events("CreditApplied") != 1 {
		t.Errorf("events: succeeded=%d credit=%d, want 1 each", r.store.events("PaymentSucceeded"), r.store.events("CreditApplied"))
	}
}

// limit bounds the objects one call examines; the cursor continues the walk
// across pages and kinds, and the calls together count every object once.
// since leaves older objects out.
func TestReconcile_PagingLimitAndCursor(t *testing.T) {
	r := newRig(t)
	r.charge("user-old", "1.00", "old") // before since
	since := timestamppb.New(time.Unix(fakeEpoch+int64(r.stripe.seq)+1, 0))
	for i := 0; i < 3; i++ {
		r.charge(fmt.Sprintf("user-%d", i), "2.00", "k") // a customer and an intent each
	}
	for _, id := range r.stripe.order {
		if len(id) > 3 && id[:3] == "pi_" {
			r.stripe.setIntentStatus(id, "succeeded", false)
		}
	}

	total := map[string]*pb.ReconcileCounts{"customers": {}, "payments": {}}
	add := func(dst, src *pb.ReconcileCounts) {
		dst.Created += src.GetCreated()
		dst.Updated += src.GetUpdated()
		dst.InSync += src.GetInSync()
		dst.Foreign += src.GetForeign()
	}
	req := &pb.ReconcileProviderReq{Since: since, Limit: 2}
	calls := 0
	for {
		resp, err := r.h.ReconcileProvider(bg, req)
		if err != nil {
			t.Fatalf("call %d: %v", calls, err)
		}
		calls++
		seen := 0
		for _, c := range []*pb.ReconcileCounts{resp.GetCustomers(), resp.GetPayments(), resp.GetRefunds(), resp.GetSubscriptions()} {
			seen += int(c.GetCreated() + c.GetUpdated() + c.GetInSync() + c.GetForeign() + c.GetSuperseded() + c.GetFailed())
		}
		if seen > 2 {
			t.Errorf("call %d examined %d objects, limit 2", calls, seen)
		}
		add(total["customers"], resp.GetCustomers())
		add(total["payments"], resp.GetPayments())
		if resp.GetNextCursor() == "" {
			break
		}
		if calls > 10 {
			t.Fatal("the walk does not end")
		}
		req = &pb.ReconcileProviderReq{Cursor: resp.GetNextCursor(), Limit: 2}
	}
	if calls != 4 {
		t.Errorf("calls = %d, want 4 (6 objects by 2, then the empty kinds)", calls)
	}
	wantCounts(t, "customers over the walk", total["customers"], "c0 u0 s3 f0 x0 F0")
	wantCounts(t, "payments over the walk", total["payments"], "c0 u3 s0 f0 x0 F0")
	if st := r.store.paymentStatus(t, r.stripe.order[1]); st != pb.Payment_REQUIRES_ACTION {
		t.Errorf("the payment before since was walked: %v", st)
	}
}

// Refusals: no since, a limit out of range, a cursor this call did not
// return, a since beside a cursor that differs from it, no installation id.
func TestReconcile_Refusals(t *testing.T) {
	r := newRig(t)
	for name, req := range map[string]*pb.ReconcileProviderReq{
		"no since":            {},
		"negative limit":      {Since: fromTheStart, Limit: -1},
		"limit above the cap": {Since: fromTheStart, Limit: reconcileMaxLimit + 1},
		"malformed cursor":    {Cursor: "nonsense"},
		"old cursor shape":    {Cursor: "1700000000:payments:x"},
		"unknown kind":        {Cursor: "1700000000:invoices:0:x"},
		"negative since":      {Cursor: "-1:payments:0:x"},
		"bad created":         {Cursor: "1700000000:payments:y:x"},
		"since beside cursor": {Since: fromTheStart, Cursor: "1:payments:0:"},
	} {
		_, err := r.h.ReconcileProvider(bg, req)
		wantCode(t, err, codes.InvalidArgument, name)
	}
	if _, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart, Cursor: fmt.Sprintf("%d:refunds:0:", fakeEpoch)}); err != nil {
		t.Errorf("a cursor with its own since alongside: %v", err)
	}

	noSecret := &PaymentServiceHandler{Query: r.store, Mutation: r.store, Backend: r.stripe.backend()}
	_, err := noSecret.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
	wantCode(t, err, codes.FailedPrecondition, "no installation id")
}

// One object that cannot be recorded is counted failed and the walk goes on.
func TestReconcile_OneFailureDoesNotStopTheWalk(t *testing.T) {
	r := newRig(t)
	a := r.charge("user-a", "1.00", "a")
	b := r.charge("user-b", "2.00", "b")
	r.stripe.setIntentStatus(a.GetProviderPaymentId(), "succeeded", false)
	r.stripe.setIntentStatus(b.GetProviderPaymentId(), "succeeded", false)
	r.store.injectBefore("MarkPaymentSucceeded", errTransient)

	wantCounts(t, "payments", r.reconcileAll().GetPayments(), "c0 u1 s0 f0 x0 F1")
	wantCounts(t, "the next run", r.reconcileAll().GetPayments(), "c0 u1 s1 f0 x0 F0")
}

// fastRetries makes the list retries instant for the test.
func fastRetries(t *testing.T) {
	t.Helper()
	saved := reconcileBackoff
	reconcileBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { reconcileBackoff = saved })
}

// A list the provider refuses ends the call with what it did so far, a
// cursor at the page that failed and the reason — not an error that throws
// the walk away. The next call resumes there.
func TestReconcile_AFailedListKeepsTheProgressAndTheCursor(t *testing.T) {
	r := newRig(t)
	fastRetries(t)
	for i := 0; i < 3; i++ {
		p := r.charge(fmt.Sprintf("user-%d", i), "2.00", "k")
		r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	}
	r.stripe.failNextList("/v1/refunds", http.StatusBadRequest)

	resp, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
	if err != nil {
		t.Fatalf("a failed list answered an error, losing the progress: %v", err)
	}
	wantCounts(t, "payments before the failure", resp.GetPayments(), "c0 u3 s0 f0 x0 F0")
	if resp.GetStopped() == "" || resp.GetNextCursor() != fmt.Sprintf("%d:refunds:0:", fakeEpoch) {
		t.Fatalf("stopped=%q cursor=%q", resp.GetStopped(), resp.GetNextCursor())
	}
	if n := r.stripe.count("GET /v1/refunds"); n != 1 {
		t.Errorf("a refused list was asked %d times, want once (it fails the same way every time)", n)
	}
	resp, err = r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Cursor: resp.GetNextCursor()})
	if err != nil || resp.GetStopped() != "" || resp.GetNextCursor() != "" {
		t.Fatalf("resumed: %+v, %v", resp, err)
	}
	wantCounts(t, "payments on resume", resp.GetPayments(), "c0 u0 s0 f0 x0 F0")
}

// A transient list failure (a rate limit, a 5xx) is retried with backoff; one
// that outlasts the retries stops the walk with a cursor.
func TestReconcile_TransientListFailuresAreRetried(t *testing.T) {
	r := newRig(t)
	fastRetries(t)
	p := r.charge("user-a", "2.00", "k")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)

	r.stripe.failNextList("/v1/payment_intents", http.StatusTooManyRequests, http.StatusServiceUnavailable)
	resp, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
	if err != nil || resp.GetStopped() != "" {
		t.Fatalf("two transient failures were not retried: %+v, %v", resp, err)
	}
	wantCounts(t, "payments", resp.GetPayments(), "c0 u1 s0 f0 x0 F0")
	if n := r.stripe.count("GET /v1/payment_intents"); n != 3 {
		t.Errorf("payment list asked %d times, want 3", n)
	}

	r.stripe.failNextList("/v1/payment_intents", 503, 503, 503, 503)
	resp, err = r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart})
	if err != nil || resp.GetStopped() == "" || resp.GetNextCursor() != fmt.Sprintf("%d:payments:0:", fakeEpoch) {
		t.Fatalf("a failure past the retries: %+v, %v", resp, err)
	}
	if n := r.stripe.count("GET /v1/payment_intents"); n != 3+4 {
		t.Errorf("payment list asked %d times, want 4 more (1 + 3 retries)", n-3)
	}
}

// A retry never waits past the caller's deadline: the walk stops at once
// with its cursor instead.
func TestReconcile_RetriesHonourTheDeadline(t *testing.T) {
	r := newRig(t)
	saved := reconcileBackoff
	reconcileBackoff = []time.Duration{time.Hour}
	t.Cleanup(func() { reconcileBackoff = saved })
	r.stripe.failNextList("/v1/customers", 503)

	ctx, cancel := context.WithTimeout(bg, 30*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := r.h.ReconcileProvider(ctx, &pb.ReconcileProviderReq{Since: fromTheStart})
	if err != nil || resp.GetStopped() == "" || resp.GetNextCursor() == "" {
		t.Fatalf("got %+v, %v", resp, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the call waited %v for a retry past its deadline", time.Since(start))
	}
}

// The object a cursor continues after was deleted at the provider, which then
// refuses to page after it: the walk continues from its creation time and
// covers the rest of the list.
func TestReconcile_ACursorAtADeletedObjectRecovers(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 5; i++ {
		if _, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: fmt.Sprintf("user-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Since: fromTheStart, Limit: 2})
	if err != nil || resp.GetNextCursor() == "" {
		t.Fatalf("first call: %+v, %v", resp, err)
	}
	wantCounts(t, "first call", resp.GetCustomers(), "c0 u0 s2 f0 x0 F0")
	r.stripe.deleteObject(r.stripe.customers[3].id) // the second newest: where the cursor stopped

	resp, err = r.h.ReconcileProvider(bg, &pb.ReconcileProviderReq{Cursor: resp.GetNextCursor()})
	if err != nil || resp.GetStopped() != "" || resp.GetNextCursor() != "" {
		t.Fatalf("resumed after a deleted object: %+v, %v", resp, err)
	}
	wantCounts(t, "the rest", resp.GetCustomers(), "c0 u0 s3 f0 x0 F0")
}

// The time a subscription's reconciliation is ordered by is the provider's
// (its answer's Date), not the local clock: with the local clock an hour
// ahead, a webhook event the provider created after the read still applies.
func TestReconcile_SubscriptionOrderedByTheProvidersClock(t *testing.T) {
	r := newRig(t)
	r.stripe.dateOffset = -time.Hour // the provider's clock: an hour behind ours
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	r.store.injectBefore("CreateSubscription", errTransient)
	_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s-1"})
	wantCode(t, err, codes.Unavailable, "the subscribe whose row failed")
	sid := r.stripe.subs[0].id
	wantCounts(t, "subscriptions", r.reconcileAll().GetSubscriptions(), "c1 u0 s0 f0 x0 F0")

	providerNow := time.Now().Add(-time.Hour)
	for _, s := range r.store.subs {
		if d := s.GetProviderEventAt().AsTime().Sub(providerNow); d < -5*time.Second || d > 5*time.Second {
			t.Errorf("provider_event_at = %v, want the provider's time %v", s.GetProviderEventAt().AsTime(), providerNow)
		}
	}
	deliverOK(t, r, withCreated(t, r.stripe.objectEvent("evt_next", "customer.subscription.updated", sid, map[string]any{"status": "past_due"}), providerNow.Add(time.Minute).Unix()))
	for _, s := range r.store.subs {
		if s.GetStatus() != pb.Subscription_PAST_DUE {
			t.Errorf("a newer event was refused: %v", s.GetStatus())
		}
	}
}

// Rotating the signing secret changes the installation mark: the objects made
// before it read as foreign — until the old mark is listed in
// previous_install_marks.
func TestReconcile_ARotatedSecretKeepsItsObjectsThroughPreviousMarks(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "5.00", "k")
	r.stripe.setIntentStatus(p.GetProviderPaymentId(), "succeeded", false)
	r.h.WebhookSecret = "whsec_rotated"

	resp := r.reconcileAll()
	wantCounts(t, "after the rotation", resp.GetPayments(), "c0 u0 s0 f1 x0 F0")
	wantPaymentStatus(t, r, p, pb.Payment_REQUIRES_ACTION)

	r.h.PreviousInstallMarks = []string{backend.InstallID(testWebhookSecret)}
	resp = r.reconcileAll()
	wantCounts(t, "with the previous mark", resp.GetPayments(), "c0 u1 s0 f0 x0 F0")
	wantCounts(t, "customers with the previous mark", resp.GetCustomers(), "c0 u0 s1 f0 x0 F0")
	wantPaymentStatus(t, r, p, pb.Payment_SUCCEEDED)
}
