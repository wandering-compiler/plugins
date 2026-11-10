package handlers

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// The record of what a call did under a row lock (a Refund, a Subscription)
// is made in the transaction holding the lock and commits with it; the live
// half of the proof is live_pg_test.go. memStore models the foreign-key
// check (rowLocks.keyShare), so a record made on another connection fails
// here as a lock timeout.

func (d *fakeDistTx) outcomes() (commits, rollbacks int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, how := range d.ended {
		if how == "commit" {
			commits++
		} else {
			rollbacks++
		}
	}
	return commits, rollbacks
}

func TestFlow_ARefundIsRecordedInItsLocksTransaction(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", 100000, "k")
	start := time.Now()
	if _, err := refund(r, p.GetId(), 40000, "r1"); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > fkLockTimeout/2 {
		t.Errorf("the refund took %v: its record waited on its own lock", took)
	}
	if c, rb := r.h.DistTx.(*fakeDistTx).outcomes(); c != 1 || rb != 0 {
		t.Errorf("transactions committed %d, rolled back %d; want the refund's one committed", c, rb)
	}
	wantNoLocksLeft(t, r)
}

func TestFlow_ASubscribeIsRecordedInItsLocksTransaction(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: 290000, Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s1"}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > fkLockTimeout/2 {
		t.Errorf("the subscribe took %v: its record waited on its own lock", took)
	}
	if c, rb := r.h.DistTx.(*fakeDistTx).outcomes(); c != 1 || rb != 0 {
		t.Errorf("transactions committed %d, rolled back %d; want the subscribe's one committed", c, rb)
	}
	wantNoLocksLeft(t, r)
}

// A record that does not commit is the caller's failure to retry, not a
// success with a warning: the provider acted, and the retry under the same
// key finds it there and records it.
func TestFlow_ARecordThatDoesNotCommitIsReported(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", 100000, "k")
	r.h.DistTx.(*fakeDistTx).commitErr = status.Error(codes.NotFound, "the transaction exceeded its tx_timeout_ms and was rolled back")
	_, err := refund(r, p.GetId(), 40000, "r1")
	wantCode(t, err, codes.Unavailable, "a refund whose record did not commit")

	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: 290000, Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	r.h.DistTx.(*fakeDistTx).commitErr = status.Error(codes.Unavailable, "connection reset")
	_, err = r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-b", PlanSlug: "pro", IdempotencyKey: "s1"})
	wantCode(t, err, codes.Unavailable, "a subscribe whose record did not commit")
}

// A refund answered by another writer's row (a unique violation on the key)
// wrote nothing of its own: its transaction is rolled back, not committed —
// in PostgreSQL the refused insert has aborted it.
func TestFlow_ARefundAnsweredByAnotherRowCommitsNothing(t *testing.T) {
	r := newRig(t)
	p := r.paid("user-a", 100000, "k")
	r.store.onceBefore("acquire:LockPaymentForRefund", func() {
		_, _ = r.store.CreateRefund(bg, &pb.CreateRefundReq{PaymentId: p.GetId(), ProviderRefundId: "re_other", Amount: 40000, Currency: "usd", IdempotencyKey: refundKey("race"), Status: int32(pb.Refund_SUCCEEDED)})
	})
	if _, err := refund(r, p.GetId(), 40000, "race"); err != nil {
		t.Fatal(err)
	}
	if c, rb := r.h.DistTx.(*fakeDistTx).outcomes(); c != 0 || rb != 1 {
		t.Errorf("transactions committed %d, rolled back %d; want one rolled back", c, rb)
	}
}

// blockingRefunds is a provider whose refund call never answers on its own.
type blockingRefunds struct{ backend.Backend }

func (b blockingRefunds) RefundPayment(ctx context.Context, _ string, _ backend.Money, _ string) (backend.RefundResult, error) {
	<-ctx.Done()
	return backend.RefundResult{}, ctx.Err()
}

// The work under a row lock is cut off before the transaction's timeout, so
// the handler ends the transaction itself: the coordinator never frees the
// lock under a provider call still in flight (a second refund would then
// pass the guard while the first is unrecorded).
func TestFlow_TheWorkUnderARowLockEndsBeforeItsTransactionTimesOut(t *testing.T) {
	timeout, margin := refundLockTimeout, lockedWorkMargin
	refundLockTimeout, lockedWorkMargin = 600*time.Millisecond, 450*time.Millisecond
	t.Cleanup(func() { refundLockTimeout, lockedWorkMargin = timeout, margin })

	r := newRig(t)
	p := r.paid("user-a", 100000, "k")
	r.h.Backend = blockingRefunds{r.h.Backend}
	start := time.Now()
	_, err := refund(r, p.GetId(), 40000, "r1")
	took := time.Since(start)
	if err == nil {
		t.Fatal("a refund the provider never answered succeeded")
	}
	if took >= refundLockTimeout {
		t.Errorf("the work under the lock ran %v, past the transaction's timeout %v", took, refundLockTimeout)
	}
	if c, rb := r.h.DistTx.(*fakeDistTx).outcomes(); c != 0 || rb != 1 {
		t.Errorf("transactions committed %d, rolled back %d; want the handler's rollback", c, rb)
	}
	wantNoLocksLeft(t, r)
}
