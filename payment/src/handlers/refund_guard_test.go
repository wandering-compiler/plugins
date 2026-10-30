package handlers

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

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
	return &pb.LockPaymentForRefundResp{Id: p.GetId(), Amount: p.GetAmount(), Status: int32(p.GetStatus())},
		s.leave("LockPaymentForRefund", nil)
}

// fakeDistTx is the coordinator: Begin hands out ids, Commit and Rollback end
// the transaction and release its row locks.
type fakeDistTx struct {
	store *memStore
	mu    sync.Mutex
	n     int
	begun int
	ended map[string]string // tx id → "commit" | "rollback"
}

func (d *fakeDistTx) Begin(context.Context, *distxpb.BeginRequest, ...grpc.CallOption) (*distxpb.BeginResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.n++
	d.begun++
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
