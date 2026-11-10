package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
)

// rowLocks models SELECT … FOR UPDATE on Payment rows: a lock taken inside a
// transaction (a ctx carrying w17-tx-id) is held until that transaction ends,
// and a second transaction locking the same row waits for it.
type rowLocks struct {
	mu    sync.Mutex
	held  map[string]chan struct{} // payment id → released when its holder ends
	owner map[string]string        // payment id → tx id
	byTx  map[string][]string      // tx id → payment ids it holds
	waits int                      // lock acquisitions that had to wait
}

func (l *rowLocks) acquire(ctx context.Context, tx, id string) error {
	for {
		l.mu.Lock()
		if l.held == nil {
			l.held, l.owner, l.byTx = map[string]chan struct{}{}, map[string]string{}, map[string][]string{}
		}
		ch, busy := l.held[id]
		if !busy || l.owner[id] == tx {
			if !busy {
				l.held[id] = make(chan struct{})
				l.owner[id] = tx
				l.byTx[tx] = append(l.byTx[tx], id)
			}
			l.mu.Unlock()
			return nil
		}
		l.waits++
		l.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// fkLockTimeout is how long keyShare waits before it gives up, the way a
// database's lock_timeout ends the wait. Short: the waits it models end in
// milliseconds when the holder is another call, and never when the holder is
// the inserting call itself.
const fkLockTimeout = 2 * time.Second

// keyShare models the foreign-key check of an INSERT naming parent id
// (Refund.payment_id, Subscription.customer_id, Payment.customer_id,
// Dispute.payment_id): the database takes FOR KEY SHARE on the parent row,
// which conflicts with the FOR UPDATE a row lock holds. An insert made inside
// the transaction that holds the lock (a ctx carrying its w17-tx-id) passes;
// one made on another connection waits until the holder ends — or, past
// fkLockTimeout, fails as a lock timeout. A handler that holds a row lock and
// inserts a child of that row on its own ctx waits on itself.
func (l *rowLocks) keyShare(ctx context.Context, id string) error {
	tx := txOf(ctx)
	timeout := time.NewTimer(fkLockTimeout)
	defer timeout.Stop()
	for {
		l.mu.Lock()
		ch, busy := l.held[id]
		if !busy || l.owner[id] == tx {
			l.mu.Unlock()
			return nil
		}
		holder := l.owner[id]
		l.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return status.Errorf(codes.Unavailable, "lock timeout: the foreign-key check on %s waits for the row lock transaction %s holds", id, holder)
		}
	}
}

func (l *rowLocks) release(tx string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range l.byTx[tx] {
		close(l.held[id])
		delete(l.held, id)
		delete(l.owner, id)
	}
	delete(l.byTx, tx)
}

func (l *rowLocks) open() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.held)
}

func txOf(ctx context.Context) string {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("w17-tx-id"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// LockPaymentForRefund reads the row; inside a transaction it locks it first,
// as the generated FOR-UPDATE variant does.
func (s *memStore) LockPaymentForRefund(ctx context.Context, in *pb.LockPaymentForRefundReq, _ ...grpc.CallOption) (*pb.LockPaymentForRefundResp, error) {
	s.runHook("acquire:LockPaymentForRefund")
	if tx := txOf(ctx); tx != "" {
		if err := s.locks.acquire(ctx, tx, in.GetId()); err != nil {
			return nil, err
		}
	}
	if err := s.enter("LockPaymentForRefund"); err != nil {
		return nil, s.leave("", err)
	}
	p, ok := s.payments[in.GetId()]
	if !ok {
		return nil, s.leave("LockPaymentForRefund", noRow())
	}
	return &pb.LockPaymentForRefundResp{Id: p.GetId(), Amount: p.GetAmount(), Status: int32(p.GetStatus()),
			ReceivedAmount: p.GetReceivedAmount(), ReceivedCurrency: p.GetReceivedCurrency()},
		s.leave("LockPaymentForRefund", nil)
}

// runHook runs (once) the onceBefore hook registered under name: a point in a
// call that enter's hook cannot reach — before a row lock is taken, where a
// concurrent request that held the lock first has already committed.
func (s *memStore) runHook(name string) {
	s.mu.Lock()
	fn := s.before[name]
	delete(s.before, name)
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// fakeDistTx is the coordinator: Begin hands out ids, Commit and Rollback end
// the transaction and release its row locks.
type fakeDistTx struct {
	store *memStore
	mu    sync.Mutex
	n     int
	begun int
	ended map[string]string // tx id → "commit" | "rollback"
	// commitErr fails the next Commit (the transaction is gone either way).
	commitErr error
	// isolations is the isolation level every Begin asked for, in order.
	isolations []distxpb.Isolation
}

func (d *fakeDistTx) Begin(_ context.Context, in *distxpb.BeginRequest, _ ...grpc.CallOption) (*distxpb.BeginResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	d.begun++
	d.isolations = append(d.isolations, in.GetIsolation())
	return &distxpb.BeginResponse{TxId: fmt.Sprintf("tx-%d", d.n)}, nil
}

func (d *fakeDistTx) end(tx, how string) {
	d.mu.Lock()
	if d.ended == nil {
		d.ended = map[string]string{}
	}
	d.ended[tx] = how
	d.mu.Unlock()
	if d.store != nil {
		d.store.locks.release(tx)
	}
}

func (d *fakeDistTx) Commit(_ context.Context, in *distxpb.CommitRequest, _ ...grpc.CallOption) (*distxpb.CommitResponse, error) {
	d.mu.Lock()
	err := d.commitErr
	d.commitErr = nil
	d.mu.Unlock()
	if err != nil {
		d.end(in.GetTxId(), "rollback")
		return nil, err
	}
	d.end(in.GetTxId(), "commit")
	return &distxpb.CommitResponse{}, nil
}

func (d *fakeDistTx) Rollback(_ context.Context, in *distxpb.RollbackRequest, _ ...grpc.CallOption) (*distxpb.RollbackResponse, error) {
	d.end(in.GetTxId(), "rollback")
	return &distxpb.RollbackResponse{}, nil
}

// getIntent answers GET /v1/payment_intents/{id}.
func (f *stripeFake) getIntent(w http.ResponseWriter, id string) {
	f.mu.Lock()
	f.requests["GET /v1/payment_intents/{id}"]++
	obj, ok := f.intentObjects()[id]
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		st, body := stripeErr(w, http.StatusNotFound, "invalid_request_error", "No such payment_intent: '"+id+"'")
		w.WriteHeader(st)
		_, _ = w.Write(body)
		return
	}
	st, body := okJSON(obj)
	w.WriteHeader(st)
	_, _ = w.Write(body)
}

// LockCustomerForSubscribe reads the customer; inside a transaction it locks
// the row first, as the generated FOR-UPDATE variant does.
func (s *memStore) LockCustomerForSubscribe(ctx context.Context, in *pb.LockCustomerForSubscribeReq, _ ...grpc.CallOption) (*pb.LockCustomerForSubscribeResp, error) {
	if tx := txOf(ctx); tx != "" {
		if err := s.locks.acquire(ctx, tx, in.GetId()); err != nil {
			return nil, err
		}
	}
	if err := s.enter("LockCustomerForSubscribe"); err != nil {
		return nil, s.leave("", err)
	}
	if _, ok := s.customers[in.GetId()]; !ok {
		return nil, s.leave("LockCustomerForSubscribe", noRow())
	}
	return &pb.LockCustomerForSubscribeResp{Id: in.GetId()}, s.leave("LockCustomerForSubscribe", nil)
}

// ListOpenSubscriptions: status <> 4 (CANCELED), newest first.
func (s *memStore) ListOpenSubscriptions(_ context.Context, in *pb.ListOpenSubscriptionsReq, _ ...grpc.CallOption) (*pb.ListOpenSubscriptionsResp, error) {
	if err := s.enter("ListOpenSubscriptions"); err != nil {
		return nil, s.leave("", err)
	}
	var rows []*pb.Subscription
	for _, sub := range s.subs {
		if sub.GetCustomerId() == in.GetCustomerId() && sub.GetPlanId() == in.GetPlanId() && sub.GetStatus() != pb.Subscription_CANCELED {
			rows = append(rows, sub)
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].GetId() > rows[j].GetId() })
	out := &pb.ListOpenSubscriptionsResp{}
	for _, sub := range rows {
		out.Subscriptions = append(out.Subscriptions, &pb.OpenSubscription{Id: sub.GetId(), ProviderSubscriptionId: sub.GetProviderSubscriptionId(), Status: int32(sub.GetStatus())})
	}
	return out, s.leave("ListOpenSubscriptions", nil)
}
