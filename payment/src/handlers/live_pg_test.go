package handlers

// Live proof of the row-lock paths (base/refund-within-captured,
// subscriptions/one-open-per-plan) against a real PostgreSQL: the store's
// model (memStore) cannot show what the database does to an INSERT whose
// foreign key names a row another connection holds FOR UPDATE.
//
// PAYMENT_LIVE_PG_DSN names a throwaway database; without it the tests skip.
// The tables are dropped and created by the test. In Docker:
//
//	docker network create pay-live
//	docker run -d --name pay-live-pg --network pay-live -e POSTGRES_PASSWORD=live postgres:18
//	docker run --rm --network pay-live -e PAYMENT_LIVE_PG_DSN='postgres://postgres:live@pay-live-pg:5432/postgres?sslmode=disable' \
//	  -v "$PWD":/w -w /w/payment/src golang:1.26 go test ./handlers/ -run TestLivePG -count=1 -v
//
// What runs for real: the SDK's transaction coordinator (distx.Server over
// txregistry.Memory) and every statement the paths under a row lock make,
// on the connection the generated storage would make it on — the adopted
// transaction when the call's context names one (w17-tx-id), a fresh
// transaction of its own otherwise. The rows' other columns live in memStore.

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/txregistry"
)

const livePGConn = "main"

// liveDistTx hands the coordinator's server to the handler as its client, the
// way a composed binary's in-process hop does.
type liveDistTx struct{ srv *distx.Server }

func (d liveDistTx) Begin(ctx context.Context, in *distxpb.BeginRequest, _ ...grpc.CallOption) (*distxpb.BeginResponse, error) {
	return d.srv.Begin(ctx, in)
}

func (d liveDistTx) Commit(ctx context.Context, in *distxpb.CommitRequest, _ ...grpc.CallOption) (*distxpb.CommitResponse, error) {
	return d.srv.Commit(ctx, in)
}

func (d liveDistTx) Rollback(ctx context.Context, in *distxpb.RollbackRequest, _ ...grpc.CallOption) (*distxpb.RollbackResponse, error) {
	return d.srv.Rollback(ctx, in)
}

// pgStore is memStore with the statements that matter made in PostgreSQL:
// the parent rows (customer, plan, payment), the two row locks, and the child
// inserts that name a locked row (refund, subscription).
type pgStore struct {
	*memStore
	db  *sql.DB
	reg *txregistry.Memory
}

func livePG(t *testing.T) (*rig, *pgStore) {
	t.Helper()
	dsn := os.Getenv("PAYMENT_LIVE_PG_DSN")
	if dsn == "" {
		t.Skip("PAYMENT_LIVE_PG_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, q := range []string{
		`DROP TABLE IF EXISTS refund, subscription, payment, plan, customer`,
		`CREATE TABLE customer (id text PRIMARY KEY)`,
		`CREATE TABLE plan (id text PRIMARY KEY)`,
		`CREATE TABLE payment (id text PRIMARY KEY, customer_id text NOT NULL REFERENCES customer(id) ON DELETE RESTRICT)`,
		`CREATE TABLE refund (id text PRIMARY KEY, payment_id text NOT NULL REFERENCES payment(id) ON DELETE RESTRICT)`,
		`CREATE TABLE subscription (id text PRIMARY KEY, customer_id text NOT NULL REFERENCES customer(id) ON DELETE RESTRICT, plan_id text NOT NULL REFERENCES plan(id) ON DELETE RESTRICT)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	reg := txregistry.NewMemory(map[string]*sql.DB{livePGConn: db})
	r := newRig(t)
	st := &pgStore{memStore: r.store, db: db, reg: reg}
	r.h.Query, r.h.Mutation = st, st
	r.h.DistTx = liveDistTx{srv: distx.NewServer(reg)}
	r.h.Connection = livePGConn
	return r, st
}

// conn is the generated storage's choice of connection: the transaction ctx
// names, adopted (the in-process hop moves the caller's outgoing metadata to
// the incoming side), or nil for a statement of its own.
func (p *pgStore) conn(ctx context.Context) (*sql.Tx, func(), error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	tx, adopted, release, err := txregistry.AdoptTx(metadata.NewIncomingContext(ctx, md), p.reg, livePGConn)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "tx adoption: %v", err)
	}
	if !adopted {
		release()
		return nil, nil, nil
	}
	return tx, release, nil
}

// exec runs a write as a generated mutation does: in the adopted transaction,
// or in a fresh one it commits itself (a second pooled connection).
func (p *pgStore) exec(ctx context.Context, q string, args ...any) error {
	tx, release, err := p.conn(ctx)
	if err != nil {
		return err
	}
	if tx != nil {
		defer release()
		_, err = tx.ExecContext(ctx, q, args...)
		return wrapPG(err)
	}
	fresh, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return wrapPG(err)
	}
	if _, err := fresh.ExecContext(ctx, q, args...); err != nil {
		_ = fresh.Rollback()
		return wrapPG(err)
	}
	return wrapPG(fresh.Commit())
}

// lockRow runs `SELECT … FOR UPDATE`, which the generated storage makes only
// inside an adopted transaction.
func (p *pgStore) lockRow(ctx context.Context, table, id string) error {
	tx, release, err := p.conn(ctx)
	if err != nil {
		return err
	}
	if tx == nil {
		return status.Errorf(codes.FailedPrecondition, "a row lock on %s outside a transaction", table)
	}
	defer release()
	var got string
	return wrapPG(tx.QueryRowContext(ctx, `SELECT id FROM `+table+` WHERE id = $1 FOR UPDATE`, id).Scan(&got))
}

func wrapPG(err error) error {
	if err == nil {
		return nil
	}
	return status.Errorf(codes.Unavailable, "postgres: %v", err)
}

func (p *pgStore) CreateCustomer(ctx context.Context, in *pb.CreateCustomerReq, opts ...grpc.CallOption) (*pb.CreateCustomerResp, error) {
	resp, err := p.memStore.CreateCustomer(ctx, in, opts...)
	if err != nil {
		return resp, err
	}
	return resp, p.exec(ctx, `INSERT INTO customer (id) VALUES ($1)`, resp.GetCustomer().GetId())
}

func (p *pgStore) CreatePlan(ctx context.Context, in *pb.CreatePlanReq, opts ...grpc.CallOption) (*pb.CreatePlanResp, error) {
	resp, err := p.memStore.CreatePlan(ctx, in, opts...)
	if err != nil {
		return resp, err
	}
	return resp, p.exec(ctx, `INSERT INTO plan (id) VALUES ($1)`, resp.GetPlan().GetId())
}

func (p *pgStore) CreatePayment(ctx context.Context, in *pb.CreatePaymentReq, opts ...grpc.CallOption) (*pb.CreatePaymentResp, error) {
	resp, err := p.memStore.CreatePayment(ctx, in, opts...)
	if err != nil {
		return resp, err
	}
	return resp, p.exec(ctx, `INSERT INTO payment (id, customer_id) VALUES ($1, $2)`, resp.GetPayment().GetId(), in.GetCustomerId())
}

func (p *pgStore) LockPaymentForRefund(ctx context.Context, in *pb.LockPaymentForRefundReq, _ ...grpc.CallOption) (*pb.LockPaymentForRefundResp, error) {
	if err := p.lockRow(ctx, "payment", in.GetId()); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pay := p.payments[in.GetId()]
	return &pb.LockPaymentForRefundResp{Id: pay.GetId(), Amount: pay.GetAmount(), Status: int32(pay.GetStatus()),
		ReceivedAmount: pay.GetReceivedAmount(), ReceivedCurrency: pay.GetReceivedCurrency()}, nil
}

func (p *pgStore) LockCustomerForSubscribe(ctx context.Context, in *pb.LockCustomerForSubscribeReq, _ ...grpc.CallOption) (*pb.LockCustomerForSubscribeResp, error) {
	if err := p.lockRow(ctx, "customer", in.GetId()); err != nil {
		return nil, err
	}
	return &pb.LockCustomerForSubscribeResp{Id: in.GetId()}, nil
}

// CreateRefund inserts in PostgreSQL first: that statement is where a
// foreign-key check behind a row lock waits.
func (p *pgStore) CreateRefund(ctx context.Context, in *pb.CreateRefundReq, opts ...grpc.CallOption) (*pb.CreateRefundResp, error) {
	if err := p.exec(ctx, `INSERT INTO refund (id, payment_id) VALUES ($1, $2)`, in.GetIdempotencyKey(), in.GetPaymentId()); err != nil {
		return nil, err
	}
	return p.memStore.CreateRefund(ctx, in, opts...)
}

func (p *pgStore) CreateSubscription(ctx context.Context, in *pb.CreateSubscriptionReq, opts ...grpc.CallOption) (*pb.CreateSubscriptionResp, error) {
	if err := p.exec(ctx, `INSERT INTO subscription (id, customer_id, plan_id) VALUES ($1, $2, $3)`, in.GetProviderSubscriptionId(), in.GetCustomerId(), in.GetPlanId()); err != nil {
		return nil, err
	}
	return p.memStore.CreateSubscription(ctx, in, opts...)
}

func (p *pgStore) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// liveBound is what a refund or a subscribe may take here: provider calls go
// to the in-process fake, so anything near it is a wait on a lock.
const liveBound = 3 * time.Second

// A refund records itself under its own row lock: the Refund row, whose
// foreign key names the locked payment, is inserted on the lock holder's own
// transaction and lands at once. Inserted on another connection it waited for
// the lock this call held — until the transaction's timeout (60 s) or the
// caller's deadline, after the provider had refunded.
func TestLivePG_ARefundIsRecordedUnderItsOwnLockAtOnce(t *testing.T) {
	r, st := livePG(t)
	p := r.paid("user-a", 100000, "k")

	ctx, cancel := context.WithTimeout(bg, 2*liveBound)
	defer cancel()
	start := time.Now()
	resp, err := r.h.RefundPayment(ctx, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: 40000, IdempotencyKey: "r1"})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("RefundPayment after %v: %v", took, err)
	}
	if took > liveBound {
		t.Fatalf("RefundPayment took %v — the record waited on the refund's own row lock", took)
	}
	if resp.GetRefund().GetId() == "" {
		t.Fatal("no refund in the answer")
	}
	if n := st.count(t, "refund"); n != 1 {
		t.Errorf("committed refund rows = %d, want 1", n)
	}
	if n := st.reg.Active(); n != 0 {
		t.Errorf("%d transactions still open after the refund", n)
	}

	// The second refund takes the lock the first released and counts it.
	start = time.Now()
	if _, err := r.h.RefundPayment(ctx, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: 70000, IdempotencyKey: "r2"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a refund past what remains: %v, want InvalidArgument", err)
	}
	if took := time.Since(start); took > liveBound {
		t.Fatalf("the refused refund took %v", took)
	}
}

// A subscribe records itself under the customer's row lock the same way: the
// Subscription row names the locked customer.
func TestLivePG_ASubscribeIsRecordedUnderItsOwnLockAtOnce(t *testing.T) {
	r, st := livePG(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: 290000, Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(bg, 2*liveBound)
	defer cancel()
	start := time.Now()
	view, err := r.h.Subscribe(ctx, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s1"})
	took := time.Since(start)
	if err != nil {
		t.Fatalf("Subscribe after %v: %v", took, err)
	}
	if took > liveBound {
		t.Fatalf("Subscribe took %v — the record waited on the subscribe's own row lock", took)
	}
	if view.GetSubscription().GetId() == "" {
		t.Fatal("no subscription in the answer")
	}
	if n := st.count(t, "subscription"); n != 1 {
		t.Errorf("committed subscription rows = %d, want 1", n)
	}
	if n := st.reg.Active(); n != 0 {
		t.Errorf("%d transactions still open after the subscribe", n)
	}
	// A second click is answered by the open subscription, under the same
	// lock, at once.
	start = time.Now()
	again, err := r.h.Subscribe(ctx, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s2"})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second subscribe: %v", err)
	}
	if err == nil && again.GetSubscription().GetId() != view.GetSubscription().GetId() {
		t.Error("a second subscription to the same plan was started")
	}
	if n := st.count(t, "subscription"); n != 1 {
		t.Errorf("committed subscription rows = %d, want 1", n)
	}
	if took := time.Since(start); took > liveBound {
		t.Fatalf("the second subscribe took %v", took)
	}
}
