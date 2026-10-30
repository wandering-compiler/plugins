package handlers

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/typere"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// memStore is a STATEFUL stand-in for the generated storage tier
// (PaymentQuery + PaymentMutation), written to the DQL in proto/ rather
// than to what a handler happens to expect:
//
//   - every UNIQUE column refuses a duplicate with the real error shape
//     (InvalidArgument + w17.ErrorDetail{UNIQUE_VIOLATION});
//   - every transition-guarded UPDATE matches zero rows exactly when its
//     WHERE would (MarkPaymentSucceeded `status <> 3`, MarkPaymentFailed
//     `status <> 3 AND status <> 4`, MarkSubscriptionStatus `status <> 4`,
//     MarkTopupGranted `granted_at IS NULL`) and then returns NotFound,
//     the shape sql.ErrNoRows takes through grpcerr;
//   - ApplyCredit / RecordUsage are one transaction: a refused ledger
//     insert or the CreditBalance `balance >= 0` CHECK leaves nothing;
//   - DECIMAL(20, 4) columns store the value the way the database hands
//     it back ("20" reads back as "20.0000"), rounding a fifth fractional
//     digit and refusing a 17th integer digit;
//   - a mutation with a (w17.event_emit) records its event only when it
//     returns successfully — the generated emit wrapper's contract.
//
// The per-call fakes in payment_service_test.go answer whatever a test
// primes them with, which is how a handler that misread a guard could
// stay green; sequences (retry, redelivery, out-of-order, concurrent
// delivery) are asserted against this one.
type memStore struct {
	pb.PaymentQueryClient
	pb.PaymentMutationClient

	mu  sync.Mutex
	seq int

	customers map[string]*pb.Customer // by id
	payments  map[string]*pb.Payment  // by id
	refunds   map[string]*pb.Refund   // by id
	processed map[string]string       // provider_event_id → event_type
	ledger    map[string]*pb.CreditLedger
	balances  map[string]*big.Rat // user_id → balance
	topups    map[string]*pb.CreditTopup
	usage     map[string]*pb.UsageRecord // by idempotency_key
	meters    map[string]*pb.UsageMeter  // by user|meter|period
	plans     map[string]*pb.Plan        // by slug
	subs      map[string]*pb.Subscription
	disputes  map[string]*pb.Dispute // by id

	emitted []string // event names, in emit order

	// fault injection, keyed by method name
	failBefore map[string][]error // returned BEFORE the op (nothing applied)
	failAfter  map[string][]error // returned AFTER the op committed (lost response)
	before     map[string]func()  // runs (unlocked) before the op, once
	calls      map[string]int

	// locks models LockPaymentForRefund's row lock (refund_guard_test.go).
	locks rowLocks
}

func newMemStore() *memStore {
	return &memStore{
		customers:  map[string]*pb.Customer{},
		payments:   map[string]*pb.Payment{},
		refunds:    map[string]*pb.Refund{},
		processed:  map[string]string{},
		ledger:     map[string]*pb.CreditLedger{},
		balances:   map[string]*big.Rat{},
		topups:     map[string]*pb.CreditTopup{},
		usage:      map[string]*pb.UsageRecord{},
		meters:     map[string]*pb.UsageMeter{},
		plans:      map[string]*pb.Plan{},
		subs:       map[string]*pb.Subscription{},
		disputes:   map[string]*pb.Dispute{},
		failBefore: map[string][]error{},
		failAfter:  map[string][]error{},
		before:     map[string]func(){},
		calls:      map[string]int{},
	}
}

// injectBefore makes the next call of method fail with err, applying nothing.
func (s *memStore) injectBefore(method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failBefore[method] = append(s.failBefore[method], err)
}

// injectAfter makes the next call of method COMMIT and then fail with err
// — the response lost after the write landed.
func (s *memStore) injectAfter(method string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failAfter[method] = append(s.failAfter[method], err)
}

// onceBefore runs fn (without the store lock) before the next call of method.
func (s *memStore) onceBefore(method string, fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.before[method] = fn
}

// enter records the call and runs any one-shot hook, then takes the
// lock; the returned error (if any) is an injected pre-failure.
func (s *memStore) enter(method string) error {
	s.mu.Lock()
	fn := s.before[method]
	delete(s.before, method)
	s.mu.Unlock()
	if fn != nil {
		fn()
	}
	s.mu.Lock()
	s.calls[method]++
	if errs := s.failBefore[method]; len(errs) > 0 {
		s.failBefore[method] = errs[1:]
		return errs[0]
	}
	return nil
}

// leave unlocks; err is the op's own result, replaced by an injected
// post-commit failure when one is queued and the op succeeded.
func (s *memStore) leave(method string, err error) error {
	defer s.mu.Unlock()
	if err == nil {
		if errs := s.failAfter[method]; len(errs) > 0 {
			s.failAfter[method] = errs[1:]
			return errs[0]
		}
	}
	return err
}

func (s *memStore) callCount(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

// callsSince is every store call made since before (a callsSince(nil)
// snapshot), by method name.
func (s *memStore) callsSince(before map[string]int) map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for m, n := range s.calls {
		if d := n - before[m]; d != 0 {
			out[m] = d
		}
	}
	return out
}

func (s *memStore) events(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.emitted {
		if e == name {
			n++
		}
	}
	return n
}

func (s *memStore) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%04d", prefix, s.seq)
}

// ── error shapes ──────────────────────────────────────────────────────

func storeConstraintErr(code, msg string) error {
	st, err := status.New(codes.InvalidArgument, msg).WithDetails(&w17pb.ErrorDetail{Code: code, Message: msg})
	if err != nil {
		panic(err)
	}
	return st.Err()
}

func uniqueErr(col string) error {
	return storeConstraintErr(codeUniqueViolation, col+" already exists")
}
func noRows(method string) error {
	return status.Error(codes.NotFound, "PaymentMutation."+method+": sql: no rows in result set")
}

// decimal4 parses s as a DECIMAL(20, 4) value the way the database
// does: rounded to 4 fractional digits, at most 16 integer digits.
func decimal4(s string) (*big.Rat, error) {
	r, ok := new(big.Rat).SetString(strings.TrimSpace(s))
	if !ok || strings.ContainsAny(s, "eE/") {
		return nil, storeConstraintErr(codeInvalidValue, fmt.Sprintf("invalid input syntax for type numeric: %q", s))
	}
	rounded, _ := new(big.Rat).SetString(r.FloatString(4))
	limit := new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(16), nil))
	if new(big.Rat).Abs(rounded).Cmp(limit) >= 0 {
		return nil, storeConstraintErr(codeInvalidValue, "numeric field overflow")
	}
	return rounded, nil
}

func fmt4(r *big.Rat) string { return r.FloatString(4) }

// subscriptionStatusCheck is the Subscription.status column's CHECK IN: the
// enum's declared numbers WITHOUT the zero sentinel (the migrator excludes
// it), so STATUS_UNSPECIFIED — or a number the enum does not declare — is
// refused like the database refuses it.
func subscriptionStatusCheck(st int32) error {
	if _, ok := pb.Subscription_Status_name[st]; !ok || st == 0 {
		return storeConstraintErr(codeInvalidValue, fmt.Sprintf("subscription status %d violates its CHECK", st))
	}
	return nil
}

// noRow is what generated storage answers for a single-row read that finds
// nothing: the SELECT is QueryRow+Scan and grpcerr.Wrap maps sql.ErrNoRows to
// NotFound. An empty response here instead hid every handler that treated "no
// row" as a failure — CreateCustomer for a new user among them.
func noRow() error { return status.Error(codes.NotFound, "sql: no rows in result set") }

func clone[T proto.Message](m T) T { return proto.Clone(m).(T) }

// ── PaymentQuery ──────────────────────────────────────────────────────

func (s *memStore) GetCustomerByUserId(_ context.Context, in *pb.GetCustomerByUserIdReq, _ ...grpc.CallOption) (*pb.GetCustomerByUserIdResp, error) {
	if err := s.enter("GetCustomerByUserId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Customer
	for _, c := range s.customers {
		if c.GetUserId() == in.GetUserId() {
			out = clone(c)
		}
	}
	if out == nil {
		return nil, s.leave("GetCustomerByUserId", noRow())
	}
	return &pb.GetCustomerByUserIdResp{Customer: out}, s.leave("GetCustomerByUserId", nil)
}

func (s *memStore) GetCustomerByProviderId(_ context.Context, in *pb.GetCustomerByProviderIdReq, _ ...grpc.CallOption) (*pb.GetCustomerByProviderIdResp, error) {
	if err := s.enter("GetCustomerByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Customer
	for _, c := range s.customers {
		if c.GetProviderCustomerId() == in.GetProviderCustomerId() {
			out = clone(c)
		}
	}
	if out == nil {
		return nil, s.leave("GetCustomerByProviderId", noRow())
	}
	return &pb.GetCustomerByProviderIdResp{Customer: out}, s.leave("GetCustomerByProviderId", nil)
}

func (s *memStore) GetPayment(_ context.Context, in *pb.GetPaymentReq, _ ...grpc.CallOption) (*pb.GetPaymentResp, error) {
	if err := s.enter("GetPayment"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Payment
	if p, ok := s.payments[in.GetId()]; ok {
		out = clone(p)
	}
	if out == nil {
		return nil, s.leave("GetPayment", noRow())
	}
	return &pb.GetPaymentResp{Payment: out}, s.leave("GetPayment", nil)
}

func (s *memStore) GetPaymentByProviderId(_ context.Context, in *pb.GetPaymentByProviderIdReq, _ ...grpc.CallOption) (*pb.GetPaymentByProviderIdResp, error) {
	if err := s.enter("GetPaymentByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	out := s.paymentByProvider(in.GetProviderPaymentId())
	if out == nil {
		return nil, s.leave("GetPaymentByProviderId", noRow())
	}
	return &pb.GetPaymentByProviderIdResp{Payment: out}, s.leave("GetPaymentByProviderId", nil)
}

func (s *memStore) GetPaymentByIdempotencyKey(_ context.Context, in *pb.GetPaymentByIdempotencyKeyReq, _ ...grpc.CallOption) (*pb.GetPaymentByIdempotencyKeyResp, error) {
	if err := s.enter("GetPaymentByIdempotencyKey"); err != nil {
		return nil, s.leave("", err)
	}
	for _, p := range s.payments {
		if p.GetIdempotencyKey() == in.GetIdempotencyKey() {
			return &pb.GetPaymentByIdempotencyKeyResp{Payment: clone(p)}, s.leave("GetPaymentByIdempotencyKey", nil)
		}
	}
	return nil, s.leave("GetPaymentByIdempotencyKey", noRow())
}

func (s *memStore) paymentByProvider(pid string) *pb.Payment {
	for _, p := range s.payments {
		if p.GetProviderPaymentId() == pid {
			return clone(p)
		}
	}
	return nil
}

func (s *memStore) GetRefundByProviderId(_ context.Context, in *pb.GetRefundByProviderIdReq, _ ...grpc.CallOption) (*pb.GetRefundByProviderIdResp, error) {
	if err := s.enter("GetRefundByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Refund
	for _, r := range s.refunds {
		if r.GetProviderRefundId() == in.GetProviderRefundId() {
			out = clone(r)
		}
	}
	if out == nil {
		return nil, s.leave("GetRefundByProviderId", noRow())
	}
	return &pb.GetRefundByProviderIdResp{Refund: out}, s.leave("GetRefundByProviderId", nil)
}

func (s *memStore) GetRefundByIdempotencyKey(_ context.Context, in *pb.GetRefundByIdempotencyKeyReq, _ ...grpc.CallOption) (*pb.GetRefundByIdempotencyKeyResp, error) {
	if err := s.enter("GetRefundByIdempotencyKey"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Refund
	for _, r := range s.refunds {
		if r.GetIdempotencyKey() != "" && r.GetIdempotencyKey() == in.GetIdempotencyKey() {
			out = clone(r)
		}
	}
	if out == nil {
		return nil, s.leave("GetRefundByIdempotencyKey", noRow())
	}
	return &pb.GetRefundByIdempotencyKeyResp{Refund: out}, s.leave("GetRefundByIdempotencyKey", nil)
}

func (s *memStore) GetCreditBalance(_ context.Context, in *pb.GetCreditBalanceReq, _ ...grpc.CallOption) (*pb.GetCreditBalanceResp, error) {
	if err := s.enter("GetCreditBalance"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.CreditBalance
	if b, ok := s.balances[in.GetUserId()]; ok {
		out = &pb.CreditBalance{UserId: in.GetUserId(), Balance: fmt4(b)}
	}
	if out == nil {
		return nil, s.leave("GetCreditBalance", noRow())
	}
	return &pb.GetCreditBalanceResp{Balance: out}, s.leave("GetCreditBalance", nil)
}

func (s *memStore) GetCreditLedgerByKey(_ context.Context, in *pb.GetCreditLedgerByKeyReq, _ ...grpc.CallOption) (*pb.GetCreditLedgerByKeyResp, error) {
	if err := s.enter("GetCreditLedgerByKey"); err != nil {
		return nil, s.leave("", err)
	}
	e, ok := s.ledger[in.GetIdempotencyKey()]
	if !ok {
		return nil, s.leave("GetCreditLedgerByKey", noRow())
	}
	return &pb.GetCreditLedgerByKeyResp{Entry: clone(e)}, s.leave("GetCreditLedgerByKey", nil)
}

func (s *memStore) GetCreditTopupByProviderId(_ context.Context, in *pb.GetCreditTopupByProviderIdReq, _ ...grpc.CallOption) (*pb.GetCreditTopupByProviderIdResp, error) {
	if err := s.enter("GetCreditTopupByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.CreditTopup
	if t, ok := s.topups[in.GetProviderPaymentId()]; ok {
		out = clone(t)
	}
	if out == nil {
		return nil, s.leave("GetCreditTopupByProviderId", noRow())
	}
	return &pb.GetCreditTopupByProviderIdResp{Topup: out}, s.leave("GetCreditTopupByProviderId", nil)
}

func meterKey(user, meter, period string) string { return user + "|" + meter + "|" + period }

func (s *memStore) GetUsageMeter(_ context.Context, in *pb.GetUsageMeterReq, _ ...grpc.CallOption) (*pb.GetUsageMeterResp, error) {
	if err := s.enter("GetUsageMeter"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.UsageMeter
	if m, ok := s.meters[meterKey(in.GetUserId(), in.GetMeter(), in.GetPeriod())]; ok {
		out = clone(m)
	}
	if out == nil {
		return nil, s.leave("GetUsageMeter", noRow())
	}
	return &pb.GetUsageMeterResp{Meter: out}, s.leave("GetUsageMeter", nil)
}

func (s *memStore) GetUsageRecordByKey(_ context.Context, in *pb.GetUsageRecordByKeyReq, _ ...grpc.CallOption) (*pb.GetUsageRecordByKeyResp, error) {
	if err := s.enter("GetUsageRecordByKey"); err != nil {
		return nil, s.leave("", err)
	}
	r, ok := s.usage[in.GetIdempotencyKey()]
	if !ok {
		return nil, s.leave("GetUsageRecordByKey", noRow())
	}
	return &pb.GetUsageRecordByKeyResp{Record: clone(r)}, s.leave("GetUsageRecordByKey", nil)
}

func (s *memStore) GetPlanBySlug(_ context.Context, in *pb.GetPlanBySlugReq, _ ...grpc.CallOption) (*pb.GetPlanBySlugResp, error) {
	if err := s.enter("GetPlanBySlug"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Plan
	if p, ok := s.plans[in.GetSlug()]; ok {
		out = clone(p)
	}
	if out == nil {
		return nil, s.leave("GetPlanBySlug", noRow())
	}
	return &pb.GetPlanBySlugResp{Plan: out}, s.leave("GetPlanBySlug", nil)
}

func (s *memStore) GetPlanByProviderPriceId(_ context.Context, in *pb.GetPlanByProviderPriceIdReq, _ ...grpc.CallOption) (*pb.GetPlanByProviderPriceIdResp, error) {
	if err := s.enter("GetPlanByProviderPriceId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Plan
	for _, p := range s.plans {
		if p.GetProviderPriceId() == in.GetProviderPriceId() {
			out = clone(p)
		}
	}
	if out == nil {
		return nil, s.leave("GetPlanByProviderPriceId", noRow())
	}
	return &pb.GetPlanByProviderPriceIdResp{Plan: out}, s.leave("GetPlanByProviderPriceId", nil)
}

func (s *memStore) GetSubscriptionByProviderId(_ context.Context, in *pb.GetSubscriptionByProviderIdReq, _ ...grpc.CallOption) (*pb.GetSubscriptionByProviderIdResp, error) {
	if err := s.enter("GetSubscriptionByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Subscription
	for _, sub := range s.subs {
		if sub.GetProviderSubscriptionId() == in.GetProviderSubscriptionId() {
			out = clone(sub)
		}
	}
	if out == nil {
		return nil, s.leave("GetSubscriptionByProviderId", noRow())
	}
	return &pb.GetSubscriptionByProviderIdResp{Subscription: out}, s.leave("GetSubscriptionByProviderId", nil)
}

func (s *memStore) GetSubscription(_ context.Context, in *pb.GetSubscriptionReq, _ ...grpc.CallOption) (*pb.GetSubscriptionResp, error) {
	if err := s.enter("GetSubscription"); err != nil {
		return nil, s.leave("", err)
	}
	var out *pb.Subscription
	if sub, ok := s.subs[in.GetId()]; ok {
		out = clone(sub)
	}
	if out == nil {
		return nil, s.leave("GetSubscription", noRow())
	}
	return &pb.GetSubscriptionResp{Subscription: out}, s.leave("GetSubscription", nil)
}

// ── PaymentMutation ───────────────────────────────────────────────────

func (s *memStore) CreateCustomer(_ context.Context, in *pb.CreateCustomerReq, _ ...grpc.CallOption) (*pb.CreateCustomerResp, error) {
	if err := s.enter("CreateCustomer"); err != nil {
		return nil, s.leave("", err)
	}
	for _, c := range s.customers {
		if c.GetUserId() == in.GetUserId() {
			return nil, s.leave("CreateCustomer", uniqueErr("user_id"))
		}
		if c.GetProviderCustomerId() == in.GetProviderCustomerId() {
			return nil, s.leave("CreateCustomer", uniqueErr("provider_customer_id"))
		}
	}
	c := &pb.Customer{Id: s.nextID("cust"), UserId: in.GetUserId(), ProviderCustomerId: in.GetProviderCustomerId(), Email: in.GetEmail(), CreatedAt: timestamppb.Now()}
	s.customers[c.Id] = c
	return &pb.CreateCustomerResp{Customer: clone(c)}, s.leave("CreateCustomer", nil)
}

func (s *memStore) CreatePayment(_ context.Context, in *pb.CreatePaymentReq, _ ...grpc.CallOption) (*pb.CreatePaymentResp, error) {
	if err := s.enter("CreatePayment"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("CreatePayment", err)
	}
	if len(in.GetCurrency()) > 3 || len(in.GetIdempotencyKey()) > 255 {
		return nil, s.leave("CreatePayment", storeConstraintErr(codeInvalidValue, "value too long"))
	}
	for _, p := range s.payments {
		if p.GetProviderPaymentId() == in.GetProviderPaymentId() {
			return nil, s.leave("CreatePayment", uniqueErr("provider_payment_id"))
		}
		if p.GetIdempotencyKey() == in.GetIdempotencyKey() {
			return nil, s.leave("CreatePayment", uniqueErr("idempotency_key"))
		}
	}
	now := timestamppb.Now()
	p := &pb.Payment{
		Id: s.nextID("pay"), CustomerId: in.GetCustomerId(), ProviderPaymentId: in.GetProviderPaymentId(),
		Amount: fmt4(amt), Currency: in.GetCurrency(), Status: pb.Payment_Status(in.GetStatus()),
		IdempotencyKey: in.GetIdempotencyKey(), Description: in.GetDescription(), CreatedAt: now, UpdatedAt: now,
	}
	s.payments[p.Id] = p
	s.emitted = append(s.emitted, "PaymentCreated")
	return &pb.CreatePaymentResp{Payment: clone(p)}, s.leave("CreatePayment", nil)
}

func (s *memStore) setPaymentStatus(method, pid string, to pb.Payment_Status, refused ...pb.Payment_Status) (*pb.Payment, error) {
	for _, p := range s.payments {
		if p.GetProviderPaymentId() != pid {
			continue
		}
		for _, r := range refused {
			if p.GetStatus() == r {
				return nil, noRows(method)
			}
		}
		p.Status = to
		p.UpdatedAt = timestamppb.Now()
		return clone(p), nil
	}
	return nil, noRows(method)
}

func (s *memStore) MarkPaymentSucceeded(_ context.Context, in *pb.MarkPaymentSucceededReq, _ ...grpc.CallOption) (*pb.MarkPaymentSucceededResp, error) {
	if err := s.enter("MarkPaymentSucceeded"); err != nil {
		return nil, s.leave("", err)
	}
	p, err := s.setPaymentStatus("MarkPaymentSucceeded", in.GetProviderPaymentId(), pb.Payment_SUCCEEDED, pb.Payment_SUCCEEDED, pb.Payment_CANCELED, pb.Payment_REFUNDED)
	if err != nil {
		return nil, s.leave("MarkPaymentSucceeded", err)
	}
	s.emitted = append(s.emitted, "PaymentSucceeded")
	return &pb.MarkPaymentSucceededResp{Payment: p}, s.leave("MarkPaymentSucceeded", nil)
}

func (s *memStore) MarkPaymentFailed(_ context.Context, in *pb.MarkPaymentFailedReq, _ ...grpc.CallOption) (*pb.MarkPaymentFailedResp, error) {
	if err := s.enter("MarkPaymentFailed"); err != nil {
		return nil, s.leave("", err)
	}
	p, err := s.setPaymentStatus("MarkPaymentFailed", in.GetProviderPaymentId(), pb.Payment_FAILED, pb.Payment_SUCCEEDED, pb.Payment_FAILED, pb.Payment_CANCELED, pb.Payment_REFUNDED)
	if err != nil {
		return nil, s.leave("MarkPaymentFailed", err)
	}
	s.emitted = append(s.emitted, "PaymentFailed")
	return &pb.MarkPaymentFailedResp{Payment: p}, s.leave("MarkPaymentFailed", nil)
}

// MarkPaymentRefunded: `WHERE … AND status = 3`.
func (s *memStore) MarkPaymentRefunded(_ context.Context, in *pb.MarkPaymentRefundedReq, _ ...grpc.CallOption) (*pb.MarkPaymentRefundedResp, error) {
	if err := s.enter("MarkPaymentRefunded"); err != nil {
		return nil, s.leave("", err)
	}
	p, err := s.setPaymentStatus("MarkPaymentRefunded", in.GetProviderPaymentId(), pb.Payment_REFUNDED,
		pb.Payment_STATUS_UNSPECIFIED, pb.Payment_REQUIRES_ACTION, pb.Payment_PROCESSING, pb.Payment_FAILED, pb.Payment_CANCELED, pb.Payment_REFUNDED)
	if err != nil {
		return nil, s.leave("MarkPaymentRefunded", err)
	}
	s.emitted = append(s.emitted, "PaymentRefunded")
	return &pb.MarkPaymentRefundedResp{Payment: p}, s.leave("MarkPaymentRefunded", nil)
}

// MarkPaymentCanceled: not from SUCCEEDED, CANCELED or REFUNDED.
func (s *memStore) MarkPaymentCanceled(_ context.Context, in *pb.MarkPaymentCanceledReq, _ ...grpc.CallOption) (*pb.MarkPaymentCanceledResp, error) {
	if err := s.enter("MarkPaymentCanceled"); err != nil {
		return nil, s.leave("", err)
	}
	p, err := s.setPaymentStatus("MarkPaymentCanceled", in.GetProviderPaymentId(), pb.Payment_CANCELED,
		pb.Payment_SUCCEEDED, pb.Payment_CANCELED, pb.Payment_REFUNDED)
	if err != nil {
		return nil, s.leave("MarkPaymentCanceled", err)
	}
	s.emitted = append(s.emitted, "PaymentCanceled")
	return &pb.MarkPaymentCanceledResp{Payment: p}, s.leave("MarkPaymentCanceled", nil)
}

// SumRefundsForPayment: COALESCE(SUM(amount), 0) over the refunds that are
// not FAILED (3) or CANCELED (4).
func (s *memStore) SumRefundsForPayment(_ context.Context, in *pb.SumRefundsForPaymentReq, _ ...grpc.CallOption) (*pb.SumRefundsForPaymentResp, error) {
	if err := s.enter("SumRefundsForPayment"); err != nil {
		return nil, s.leave("", err)
	}
	total := new(big.Rat)
	for _, r := range s.refunds {
		if r.GetPaymentId() == in.GetPaymentId() && r.GetStatus() != pb.Refund_FAILED && r.GetStatus() != pb.Refund_CANCELED {
			a, _ := decimal4(r.GetAmount())
			total.Add(total, a)
		}
	}
	return &pb.SumRefundsForPaymentResp{Total: fmt4(total)}, s.leave("SumRefundsForPayment", nil)
}

func (s *memStore) CreateRefund(_ context.Context, in *pb.CreateRefundReq, _ ...grpc.CallOption) (*pb.CreateRefundResp, error) {
	if err := s.enter("CreateRefund"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("CreateRefund", err)
	}
	for _, r := range s.refunds {
		if r.GetProviderRefundId() == in.GetProviderRefundId() {
			return nil, s.leave("CreateRefund", uniqueErr("provider_refund_id"))
		}
		if in.GetIdempotencyKey() != "" && r.GetIdempotencyKey() == in.GetIdempotencyKey() {
			return nil, s.leave("CreateRefund", uniqueErr("idempotency_key"))
		}
	}
	if err := refundStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("CreateRefund", err)
	}
	r := &pb.Refund{Id: s.nextID("ref"), PaymentId: in.GetPaymentId(), ProviderRefundId: in.GetProviderRefundId(), Amount: fmt4(amt), Currency: in.GetCurrency(), CreatedAt: timestamppb.Now(), IdempotencyKey: in.GetIdempotencyKey(),
		Status: pb.Refund_Status(in.GetStatus())}
	s.refunds[r.Id] = r
	s.emitted = append(s.emitted, "RefundCreated")
	return &pb.CreateRefundResp{Refund: clone(r)}, s.leave("CreateRefund", nil)
}

// RecordProviderRefund: INSERT without idempotency_key (NULL, so it never
// collides on that column).
func (s *memStore) RecordProviderRefund(_ context.Context, in *pb.RecordProviderRefundReq, _ ...grpc.CallOption) (*pb.RecordProviderRefundResp, error) {
	if err := s.enter("RecordProviderRefund"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("RecordProviderRefund", err)
	}
	if err := refundStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("RecordProviderRefund", err)
	}
	for _, r := range s.refunds {
		if r.GetProviderRefundId() == in.GetProviderRefundId() {
			return nil, s.leave("RecordProviderRefund", uniqueErr("provider_refund_id"))
		}
	}
	r := &pb.Refund{Id: s.nextID("ref"), PaymentId: in.GetPaymentId(), ProviderRefundId: in.GetProviderRefundId(), Amount: fmt4(amt), Currency: in.GetCurrency(), CreatedAt: timestamppb.Now(),
		Status: pb.Refund_Status(in.GetStatus())}
	s.refunds[r.Id] = r
	s.emitted = append(s.emitted, "ProviderRefundRecorded")
	return &pb.RecordProviderRefundResp{Refund: clone(r)}, s.leave("RecordProviderRefund", nil)
}

// MarkRefundStatus: `WHERE … AND status <> 3 AND status <> 4 AND status <> :status`.
func (s *memStore) MarkRefundStatus(_ context.Context, in *pb.MarkRefundStatusReq, _ ...grpc.CallOption) (*pb.MarkRefundStatusResp, error) {
	if err := s.enter("MarkRefundStatus"); err != nil {
		return nil, s.leave("", err)
	}
	if err := refundStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("MarkRefundStatus", err)
	}
	for _, r := range s.refunds {
		if r.GetProviderRefundId() != in.GetProviderRefundId() {
			continue
		}
		st := r.GetStatus()
		if st == pb.Refund_FAILED || st == pb.Refund_CANCELED || int32(st) == in.GetStatus() {
			break
		}
		r.Status = pb.Refund_Status(in.GetStatus())
		s.emitted = append(s.emitted, "RefundStatusChanged:"+r.Status.String())
		return &pb.MarkRefundStatusResp{Refund: clone(r)}, s.leave("MarkRefundStatus", nil)
	}
	return nil, s.leave("MarkRefundStatus", noRows("MarkRefundStatus"))
}

// MarkPaymentRefundReversed: `WHERE … AND status = 6`.
func (s *memStore) MarkPaymentRefundReversed(_ context.Context, in *pb.MarkPaymentRefundReversedReq, _ ...grpc.CallOption) (*pb.MarkPaymentRefundReversedResp, error) {
	if err := s.enter("MarkPaymentRefundReversed"); err != nil {
		return nil, s.leave("", err)
	}
	p, err := s.setPaymentStatus("MarkPaymentRefundReversed", in.GetProviderPaymentId(), pb.Payment_SUCCEEDED,
		pb.Payment_STATUS_UNSPECIFIED, pb.Payment_REQUIRES_ACTION, pb.Payment_PROCESSING, pb.Payment_SUCCEEDED, pb.Payment_FAILED, pb.Payment_CANCELED)
	if err != nil {
		return nil, s.leave("MarkPaymentRefundReversed", err)
	}
	s.emitted = append(s.emitted, "PaymentRefundReversed")
	return &pb.MarkPaymentRefundReversedResp{Payment: p}, s.leave("MarkPaymentRefundReversed", nil)
}

// refundStatusCheck is the Refund.status column's CHECK IN (the zero sentinel
// excluded).
func refundStatusCheck(st int32) error {
	if _, ok := pb.Refund_Status_name[st]; !ok || st == 0 {
		return storeConstraintErr(codeInvalidValue, fmt.Sprintf("refund status %d violates its CHECK", st))
	}
	return nil
}

// ── disputes ──────────────────────────────────────────────────────────

func (s *memStore) GetDisputeByProviderId(_ context.Context, in *pb.GetDisputeByProviderIdReq, _ ...grpc.CallOption) (*pb.GetDisputeByProviderIdResp, error) {
	if err := s.enter("GetDisputeByProviderId"); err != nil {
		return nil, s.leave("", err)
	}
	for _, d := range s.disputes {
		if d.GetProviderDisputeId() == in.GetProviderDisputeId() {
			return &pb.GetDisputeByProviderIdResp{Dispute: clone(d)}, s.leave("GetDisputeByProviderId", nil)
		}
	}
	return nil, s.leave("GetDisputeByProviderId", noRow())
}

func disputeStatusCheck(st int32) error {
	if _, ok := pb.Dispute_Status_name[st]; !ok || st == 0 {
		return storeConstraintErr(codeInvalidValue, fmt.Sprintf("dispute status %d violates its CHECK", st))
	}
	return nil
}

func (s *memStore) CreateDispute(_ context.Context, in *pb.CreateDisputeReq, _ ...grpc.CallOption) (*pb.CreateDisputeResp, error) {
	if err := s.enter("CreateDispute"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("CreateDispute", err)
	}
	if err := disputeStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("CreateDispute", err)
	}
	for _, d := range s.disputes {
		if d.GetProviderDisputeId() == in.GetProviderDisputeId() {
			return nil, s.leave("CreateDispute", uniqueErr("provider_dispute_id"))
		}
	}
	d := &pb.Dispute{Id: s.nextID("dp"), PaymentId: in.GetPaymentId(), ProviderDisputeId: in.GetProviderDisputeId(), Amount: fmt4(amt), Currency: in.GetCurrency(),
		Status: pb.Dispute_Status(in.GetStatus()), ProviderEventAt: in.GetProviderEventAt(), CreatedAt: timestamppb.Now()}
	s.disputes[d.Id] = d
	s.emitted = append(s.emitted, "DisputeOpened:"+d.Status.String())
	return &pb.CreateDisputeResp{Dispute: clone(d)}, s.leave("CreateDispute", nil)
}

// MarkDisputeStatus: `WHERE … AND status <> 5 AND status <> 6 AND
// (provider_event_at IS NULL OR provider_event_at <= :provider_event_at)`.
func (s *memStore) MarkDisputeStatus(_ context.Context, in *pb.MarkDisputeStatusReq, _ ...grpc.CallOption) (*pb.MarkDisputeStatusResp, error) {
	if err := s.enter("MarkDisputeStatus"); err != nil {
		return nil, s.leave("", err)
	}
	if err := disputeStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("MarkDisputeStatus", err)
	}
	for _, d := range s.disputes {
		if d.GetProviderDisputeId() != in.GetProviderDisputeId() {
			continue
		}
		if d.GetStatus() == pb.Dispute_WON || d.GetStatus() == pb.Dispute_LOST {
			break
		}
		if at := d.GetProviderEventAt(); at != nil && at.AsTime().After(in.GetProviderEventAt().AsTime()) {
			break
		}
		d.Status = pb.Dispute_Status(in.GetStatus())
		d.ProviderEventAt = in.GetProviderEventAt()
		return &pb.MarkDisputeStatusResp{Dispute: clone(d)}, s.leave("MarkDisputeStatus", nil)
	}
	return nil, s.leave("MarkDisputeStatus", noRows("MarkDisputeStatus"))
}

// MarkDisputeClosed: `WHERE … AND closed_at IS NULL AND (status = 5 OR
// status = 6)`, stamping closed_at.
func (s *memStore) MarkDisputeClosed(_ context.Context, in *pb.MarkDisputeClosedReq, _ ...grpc.CallOption) (*pb.MarkDisputeClosedResp, error) {
	if err := s.enter("MarkDisputeClosed"); err != nil {
		return nil, s.leave("", err)
	}
	for _, d := range s.disputes {
		if d.GetProviderDisputeId() != in.GetProviderDisputeId() || d.GetClosedAt() != nil ||
			(d.GetStatus() != pb.Dispute_WON && d.GetStatus() != pb.Dispute_LOST) {
			continue
		}
		d.ClosedAt = timestamppb.Now()
		s.emitted = append(s.emitted, "DisputeClosed:"+d.Status.String())
		return &pb.MarkDisputeClosedResp{Dispute: clone(d)}, s.leave("MarkDisputeClosed", nil)
	}
	return nil, s.leave("MarkDisputeClosed", noRows("MarkDisputeClosed"))
}

// SumLostDisputesForPayment: SUM(amount) over status = 6 (LOST).
func (s *memStore) SumLostDisputesForPayment(_ context.Context, in *pb.SumLostDisputesForPaymentReq, _ ...grpc.CallOption) (*pb.SumLostDisputesForPaymentResp, error) {
	if err := s.enter("SumLostDisputesForPayment"); err != nil {
		return nil, s.leave("", err)
	}
	total := new(big.Rat)
	for _, d := range s.disputes {
		if d.GetPaymentId() == in.GetPaymentId() && d.GetStatus() == pb.Dispute_LOST {
			a, _ := decimal4(d.GetAmount())
			total.Add(total, a)
		}
	}
	return &pb.SumLostDisputesForPaymentResp{Total: fmt4(total)}, s.leave("SumLostDisputesForPayment", nil)
}

// SumTopupCredit: SUM(delta) WHERE user_id AND ref IN (payment_id,
// provider_payment_id) AND reason IN (the four bound reasons).
func (s *memStore) SumTopupCredit(_ context.Context, in *pb.SumTopupCreditReq, _ ...grpc.CallOption) (*pb.SumTopupCreditResp, error) {
	if err := s.enter("SumTopupCredit"); err != nil {
		return nil, s.leave("", err)
	}
	total := new(big.Rat)
	for _, e := range s.ledger {
		if e.GetUserId() != in.GetUserId() || (e.GetRef() != in.GetPaymentId() && e.GetRef() != in.GetProviderPaymentId()) {
			continue
		}
		switch e.GetReason() {
		case in.GetReasonGrant(), in.GetReasonRefund(), in.GetReasonRefused(), in.GetReasonReconcile():
			d, _ := decimal4(e.GetDelta())
			total.Add(total, d)
		}
	}
	return &pb.SumTopupCreditResp{Total: fmt4(total)}, s.leave("SumTopupCredit", nil)
}

// SetTopupCreditOwed: `WHERE provider_payment_id = … AND reconciled_step <
// :reconciled_step`.
func (s *memStore) SetTopupCreditOwed(_ context.Context, in *pb.SetTopupCreditOwedReq, _ ...grpc.CallOption) (*pb.SetTopupCreditOwedResp, error) {
	if err := s.enter("SetTopupCreditOwed"); err != nil {
		return nil, s.leave("", err)
	}
	owed, err := decimal4(in.GetCreditOwed())
	if err != nil {
		return nil, s.leave("SetTopupCreditOwed", err)
	}
	t, ok := s.topups[in.GetProviderPaymentId()]
	if !ok || t.GetReconciledStep() >= in.GetReconciledStep() {
		return nil, s.leave("SetTopupCreditOwed", noRows("SetTopupCreditOwed"))
	}
	t.CreditOwed = fmt4(owed)
	t.ReconciledStep = in.GetReconciledStep()
	return &pb.SetTopupCreditOwedResp{ProviderPaymentId: t.ProviderPaymentId}, s.leave("SetTopupCreditOwed", nil)
}

// owed is the top-up's recorded credit_owed ("0.0000" when none).
func (s *memStore) owed(t *testing.T, providerPaymentID string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	tp, ok := s.topups[providerPaymentID]
	if !ok {
		t.Fatalf("no top-up %s", providerPaymentID)
	}
	if tp.GetCreditOwed() == "" {
		return "0.0000"
	}
	return tp.GetCreditOwed()
}

func (s *memStore) dispute(t *testing.T, providerID string) *pb.Dispute {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.disputes {
		if d.GetProviderDisputeId() == providerID {
			return clone(d)
		}
	}
	return nil
}

func (s *memStore) refundByProvider(t *testing.T, providerID string) *pb.Refund {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.refunds {
		if r.GetProviderRefundId() == providerID {
			return clone(r)
		}
	}
	return nil
}

// SetRefundIdempotencyKey: `WHERE id = :id AND idempotency_key IS NULL`,
// and the column is UNIQUE.
func (s *memStore) SetRefundIdempotencyKey(_ context.Context, in *pb.SetRefundIdempotencyKeyReq, _ ...grpc.CallOption) (*pb.SetRefundIdempotencyKeyResp, error) {
	if err := s.enter("SetRefundIdempotencyKey"); err != nil {
		return nil, s.leave("", err)
	}
	r, ok := s.refunds[in.GetId()]
	if !ok || r.GetIdempotencyKey() != "" {
		return nil, s.leave("SetRefundIdempotencyKey", noRows("SetRefundIdempotencyKey"))
	}
	for _, o := range s.refunds {
		if o.GetIdempotencyKey() == in.GetIdempotencyKey() {
			return nil, s.leave("SetRefundIdempotencyKey", uniqueErr("idempotency_key"))
		}
	}
	r.IdempotencyKey = in.GetIdempotencyKey()
	return &pb.SetRefundIdempotencyKeyResp{Id: r.Id}, s.leave("SetRefundIdempotencyKey", nil)
}

func (s *memStore) MarkWebhookProcessed(_ context.Context, in *pb.MarkWebhookProcessedReq, _ ...grpc.CallOption) (*pb.MarkWebhookProcessedResp, error) {
	if err := s.enter("MarkWebhookProcessed"); err != nil {
		return nil, s.leave("", err)
	}
	if _, dup := s.processed[in.GetProviderEventId()]; dup {
		return nil, s.leave("MarkWebhookProcessed", uniqueErr("provider_event_id"))
	}
	s.processed[in.GetProviderEventId()] = in.GetEventType()
	return &pb.MarkWebhookProcessedResp{ProviderEventId: in.GetProviderEventId()}, s.leave("MarkWebhookProcessed", nil)
}

func (s *memStore) ApplyCredit(_ context.Context, in *pb.ApplyCreditReq, _ ...grpc.CallOption) (*pb.ApplyCreditResp, error) {
	if err := s.enter("ApplyCredit"); err != nil {
		return nil, s.leave("", err)
	}
	delta, err := decimal4(in.GetDelta())
	if err != nil {
		return nil, s.leave("ApplyCredit", err)
	}
	// ApplyCreditReq.reason is a SLUG, and the generated storage refuses any
	// other value before the write. A reason the column cannot hold used to
	// pass here and fail every top-up refund against a real store.
	if !typere.Slug.MatchString(in.GetReason()) || len(in.GetReason()) > 64 {
		return nil, s.leave("ApplyCredit", status.Errorf(codes.InvalidArgument, "reason: %q is not a slug of at most 64 characters", in.GetReason()))
	}
	// op "ledger"
	if _, dup := s.ledger[in.GetIdempotencyKey()]; dup {
		return nil, s.leave("ApplyCredit", uniqueErr("idempotency_key"))
	}
	// op "balance" — same transaction; the CHECK rolls both back.
	cur := new(big.Rat)
	if b, ok := s.balances[in.GetUserId()]; ok {
		cur.Set(b)
	}
	next := new(big.Rat).Add(cur, delta)
	if next.Sign() < 0 {
		return nil, s.leave("ApplyCredit", storeConstraintErr(codeInvalidValue, "credit_balance_nonneg"))
	}
	s.ledger[in.GetIdempotencyKey()] = &pb.CreditLedger{Id: s.nextID("led"), UserId: in.GetUserId(), Delta: fmt4(delta), Reason: in.GetReason(), Ref: in.GetRef(), IdempotencyKey: in.GetIdempotencyKey()}
	s.balances[in.GetUserId()] = next
	s.emitted = append(s.emitted, "CreditApplied")
	return &pb.ApplyCreditResp{UserId: in.GetUserId(), Balance: fmt4(next)}, s.leave("ApplyCredit", nil)
}

func (s *memStore) CreateCreditTopup(_ context.Context, in *pb.CreateCreditTopupReq, _ ...grpc.CallOption) (*pb.CreateCreditTopupResp, error) {
	if err := s.enter("CreateCreditTopup"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("CreateCreditTopup", err)
	}
	if _, dup := s.topups[in.GetProviderPaymentId()]; dup {
		return nil, s.leave("CreateCreditTopup", uniqueErr("provider_payment_id"))
	}
	t := &pb.CreditTopup{Id: s.nextID("top"), ProviderPaymentId: in.GetProviderPaymentId(), UserId: in.GetUserId(), Amount: fmt4(amt), CreatedAt: timestamppb.Now()}
	s.topups[t.ProviderPaymentId] = t
	return &pb.CreateCreditTopupResp{Topup: clone(t)}, s.leave("CreateCreditTopup", nil)
}

func (s *memStore) MarkTopupGranted(_ context.Context, in *pb.MarkTopupGrantedReq, _ ...grpc.CallOption) (*pb.MarkTopupGrantedResp, error) {
	if err := s.enter("MarkTopupGranted"); err != nil {
		return nil, s.leave("", err)
	}
	t, ok := s.topups[in.GetProviderPaymentId()]
	if !ok || t.GetGrantedAt() != nil {
		return nil, s.leave("MarkTopupGranted", noRows("MarkTopupGranted"))
	}
	t.GrantedAt = timestamppb.Now()
	return &pb.MarkTopupGrantedResp{ProviderPaymentId: t.ProviderPaymentId}, s.leave("MarkTopupGranted", nil)
}

func (s *memStore) RecordUsage(_ context.Context, in *pb.RecordUsageReq, _ ...grpc.CallOption) (*pb.RecordUsageResp, error) {
	if err := s.enter("RecordUsage"); err != nil {
		return nil, s.leave("", err)
	}
	if _, dup := s.usage[in.GetIdempotencyKey()]; dup {
		return nil, s.leave("RecordUsage", uniqueErr("idempotency_key"))
	}
	s.usage[in.GetIdempotencyKey()] = &pb.UsageRecord{UserId: in.GetUserId(), Meter: in.GetMeter(), Period: in.GetPeriod(), Quantity: in.GetQuantity(), IdempotencyKey: in.GetIdempotencyKey()}
	k := meterKey(in.GetUserId(), in.GetMeter(), in.GetPeriod())
	m, ok := s.meters[k]
	if !ok {
		m = &pb.UsageMeter{Id: s.nextID("meter"), UserId: in.GetUserId(), Meter: in.GetMeter(), Period: in.GetPeriod()}
		s.meters[k] = m
	}
	m.Total += in.GetQuantity()
	s.emitted = append(s.emitted, "UsageRecorded")
	return &pb.RecordUsageResp{UserId: m.UserId, Meter: m.Meter, Period: m.Period, Total: m.Total}, s.leave("RecordUsage", nil)
}

func (s *memStore) CreatePlan(_ context.Context, in *pb.CreatePlanReq, _ ...grpc.CallOption) (*pb.CreatePlanResp, error) {
	if err := s.enter("CreatePlan"); err != nil {
		return nil, s.leave("", err)
	}
	amt, err := decimal4(in.GetAmount())
	if err != nil {
		return nil, s.leave("CreatePlan", err)
	}
	if _, dup := s.plans[in.GetSlug()]; dup {
		return nil, s.leave("CreatePlan", uniqueErr("slug"))
	}
	p := &pb.Plan{Id: s.nextID("plan"), Slug: in.GetSlug(), Name: in.GetName(), Amount: fmt4(amt), Currency: in.GetCurrency(), Interval: in.GetInterval(), ProviderPriceId: in.GetProviderPriceId(), Enabled: true}
	s.plans[p.Slug] = p
	return &pb.CreatePlanResp{Plan: clone(p)}, s.leave("CreatePlan", nil)
}

func (s *memStore) CreateSubscription(_ context.Context, in *pb.CreateSubscriptionReq, _ ...grpc.CallOption) (*pb.CreateSubscriptionResp, error) {
	if err := s.enter("CreateSubscription"); err != nil {
		return nil, s.leave("", err)
	}
	if err := subscriptionStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("CreateSubscription", err)
	}
	for _, sub := range s.subs {
		if sub.GetProviderSubscriptionId() == in.GetProviderSubscriptionId() {
			return nil, s.leave("CreateSubscription", uniqueErr("provider_subscription_id"))
		}
	}
	sub := &pb.Subscription{Id: s.nextID("sub"), CustomerId: in.GetCustomerId(), PlanId: in.GetPlanId(), ProviderSubscriptionId: in.GetProviderSubscriptionId(), Status: pb.Subscription_Status(in.GetStatus()), CurrentPeriodEnd: in.GetCurrentPeriodEnd(), ProviderEventAt: in.GetProviderEventAt()}
	s.subs[sub.Id] = sub
	s.emitted = append(s.emitted, "SubscriptionStarted")
	return &pb.CreateSubscriptionResp{Subscription: clone(sub)}, s.leave("CreateSubscription", nil)
}

func (s *memStore) MarkSubscriptionStatus(_ context.Context, in *pb.MarkSubscriptionStatusReq, _ ...grpc.CallOption) (*pb.MarkSubscriptionStatusResp, error) {
	if err := s.enter("MarkSubscriptionStatus"); err != nil {
		return nil, s.leave("", err)
	}
	if err := subscriptionStatusCheck(in.GetStatus()); err != nil {
		return nil, s.leave("MarkSubscriptionStatus", err)
	}
	for _, sub := range s.subs {
		if sub.GetProviderSubscriptionId() != in.GetProviderSubscriptionId() {
			continue
		}
		if sub.GetStatus() == pb.Subscription_CANCELED {
			break
		}
		// provider_event_at IS NULL OR provider_event_at <= :provider_event_at
		if at := sub.GetProviderEventAt(); at != nil && at.AsTime().After(in.GetProviderEventAt().AsTime()) {
			break
		}
		sub.Status = pb.Subscription_Status(in.GetStatus())
		sub.CurrentPeriodEnd = in.GetCurrentPeriodEnd()
		sub.ProviderEventAt = in.GetProviderEventAt()
		s.emitted = append(s.emitted, "SubscriptionStatusChanged")
		return &pb.MarkSubscriptionStatusResp{Subscription: clone(sub)}, s.leave("MarkSubscriptionStatus", nil)
	}
	return nil, s.leave("MarkSubscriptionStatus", noRows("MarkSubscriptionStatus"))
}

// ── read-back helpers for assertions ──────────────────────────────────

func (s *memStore) balance(t *testing.T, userID string) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.balances[userID]; ok {
		return fmt4(b)
	}
	return "0.0000"
}

func (s *memStore) paymentStatus(t *testing.T, pid string) pb.Payment_Status {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.paymentByProvider(pid)
	if p == nil {
		t.Fatalf("no local payment for %s", pid)
	}
	return p.GetStatus()
}

func (s *memStore) count(table string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch table {
	case "customers":
		return len(s.customers)
	case "payments":
		return len(s.payments)
	case "refunds":
		return len(s.refunds)
	case "processed":
		return len(s.processed)
	case "ledger":
		return len(s.ledger)
	case "subs":
		return len(s.subs)
	case "plans":
		return len(s.plans)
	case "usage":
		return len(s.usage)
	}
	panic("unknown table " + table)
}

func (s *memStore) isProcessed(eventID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.processed[eventID]
	return ok
}
