package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// ── fakes ───────────────────────────────────────────────────────────

type fakeBackend struct {
	ensureID   string
	ensureErr  error
	createRes  backend.PaymentResult
	createErr  error
	lastCharge backend.PaymentSpec

	// subscriptions knobs
	priceID  string
	subRes   backend.SubscriptionResult
	lastPlan backend.PlanSpec
	lastSub  backend.SubscriptionSpec

	// refund knobs
	refundRes      backend.RefundResult
	lastRefund     backend.Money
	lastRefundFor  string
	lastRefundIdem string // provider Idempotency-Key the handler passed (Q43-pay-2)
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) EnsureCustomer(_ context.Context, _ backend.CustomerSpec) (string, error) {
	return f.ensureID, f.ensureErr
}
func (f *fakeBackend) CreatePayment(_ context.Context, spec backend.PaymentSpec) (backend.PaymentResult, error) {
	f.lastCharge = spec
	return f.createRes, f.createErr
}
func (f *fakeBackend) RefundPayment(_ context.Context, providerPaymentID string, amount backend.Money, idemKey string) (backend.RefundResult, error) {
	f.lastRefund = amount
	f.lastRefundFor = providerPaymentID
	f.lastRefundIdem = idemKey
	return f.refundRes, nil
}
func (f *fakeBackend) UpsertPlan(_ context.Context, spec backend.PlanSpec) (string, error) {
	f.lastPlan = spec
	return f.priceID, nil
}
func (f *fakeBackend) StartSubscription(_ context.Context, spec backend.SubscriptionSpec) (backend.SubscriptionResult, error) {
	f.lastSub = spec
	return f.subRes, nil
}

type fakeQuery struct {
	pb.PaymentQueryClient
	customer     *pb.Customer
	payment      *pb.Payment
	balance      *pb.CreditBalance // prepaid
	usageMeter   *pb.UsageMeter    // usage
	plan         *pb.Plan          // subscriptions
	subscription *pb.Subscription
	creditTopup  *pb.CreditTopup // prepaid top-up
}

func (q *fakeQuery) GetCustomerByUserId(_ context.Context, _ *pb.GetCustomerByUserIdReq, _ ...grpc.CallOption) (*pb.GetCustomerByUserIdResp, error) {
	return &pb.GetCustomerByUserIdResp{Customer: q.customer}, nil
}
func (q *fakeQuery) GetPayment(_ context.Context, _ *pb.GetPaymentReq, _ ...grpc.CallOption) (*pb.GetPaymentResp, error) {
	return &pb.GetPaymentResp{Payment: q.payment}, nil
}
func (q *fakeQuery) GetCreditBalance(_ context.Context, _ *pb.GetCreditBalanceReq, _ ...grpc.CallOption) (*pb.GetCreditBalanceResp, error) {
	return &pb.GetCreditBalanceResp{Balance: q.balance}, nil
}
func (q *fakeQuery) GetUsageMeter(_ context.Context, _ *pb.GetUsageMeterReq, _ ...grpc.CallOption) (*pb.GetUsageMeterResp, error) {
	return &pb.GetUsageMeterResp{Meter: q.usageMeter}, nil
}
func (q *fakeQuery) GetPlanBySlug(_ context.Context, _ *pb.GetPlanBySlugReq, _ ...grpc.CallOption) (*pb.GetPlanBySlugResp, error) {
	return &pb.GetPlanBySlugResp{Plan: q.plan}, nil
}
func (q *fakeQuery) GetSubscription(_ context.Context, _ *pb.GetSubscriptionReq, _ ...grpc.CallOption) (*pb.GetSubscriptionResp, error) {
	return &pb.GetSubscriptionResp{Subscription: q.subscription}, nil
}
func (q *fakeQuery) GetCreditTopupByProviderId(_ context.Context, _ *pb.GetCreditTopupByProviderIdReq, _ ...grpc.CallOption) (*pb.GetCreditTopupByProviderIdResp, error) {
	return &pb.GetCreditTopupByProviderIdResp{Topup: q.creditTopup}, nil
}

type fakeMutation struct {
	pb.PaymentMutationClient
	createdCustomer *pb.Customer
	createPayReq    *pb.CreatePaymentReq

	// webhook test knobs
	markProcessedErr error  // e.g. AlreadyExists to simulate a duplicate
	succeededErr     error  // transient failure on MarkPaymentSucceeded
	succeededFor     string // captured provider_payment_id
	failedFor        string
	markedProcessed  bool // MarkWebhookProcessed was invoked (Q43-pay-1)

	// prepaid test knobs
	applyErr  error // constraint error to simulate
	lastApply *pb.ApplyCreditReq
	applyResp *pb.ApplyCreditResp

	// usage test knobs
	recordErr  error
	lastRecord *pb.RecordUsageReq

	// subscriptions test knobs
	createPlanErr  error
	lastCreatePlan *pb.CreatePlanReq
	lastCreateSub  *pb.CreateSubscriptionReq
	lastMarkSub    *pb.MarkSubscriptionStatusReq

	// top-up test knobs
	lastCreateTopup *pb.CreateCreditTopupReq
	markGrantedFor  string

	// refund test knobs
	lastCreateRefund *pb.CreateRefundReq
}

func (m *fakeMutation) MarkSubscriptionStatus(_ context.Context, in *pb.MarkSubscriptionStatusReq, _ ...grpc.CallOption) (*pb.MarkSubscriptionStatusResp, error) {
	m.lastMarkSub = in
	return &pb.MarkSubscriptionStatusResp{Subscription: &pb.Subscription{ProviderSubscriptionId: in.GetProviderSubscriptionId(), Status: pb.Subscription_Status(in.GetStatus())}}, nil
}
func (m *fakeMutation) CreateCreditTopup(_ context.Context, in *pb.CreateCreditTopupReq, _ ...grpc.CallOption) (*pb.CreateCreditTopupResp, error) {
	m.lastCreateTopup = in
	return &pb.CreateCreditTopupResp{Topup: &pb.CreditTopup{ProviderPaymentId: in.GetProviderPaymentId(), UserId: in.GetUserId(), Amount: in.GetAmount()}}, nil
}
func (m *fakeMutation) MarkTopupGranted(_ context.Context, in *pb.MarkTopupGrantedReq, _ ...grpc.CallOption) (*pb.MarkTopupGrantedResp, error) {
	m.markGrantedFor = in.GetProviderPaymentId()
	return &pb.MarkTopupGrantedResp{ProviderPaymentId: in.GetProviderPaymentId()}, nil
}

func (m *fakeMutation) CreatePlan(_ context.Context, in *pb.CreatePlanReq, _ ...grpc.CallOption) (*pb.CreatePlanResp, error) {
	m.lastCreatePlan = in
	if m.createPlanErr != nil {
		return nil, m.createPlanErr
	}
	return &pb.CreatePlanResp{Plan: &pb.Plan{
		Id: "plan-1", Slug: in.GetSlug(), Name: in.GetName(), Amount: in.GetAmount(),
		Currency: in.GetCurrency(), Interval: in.GetInterval(), ProviderPriceId: in.GetProviderPriceId(),
	}}, nil
}
func (m *fakeMutation) CreateSubscription(_ context.Context, in *pb.CreateSubscriptionReq, _ ...grpc.CallOption) (*pb.CreateSubscriptionResp, error) {
	m.lastCreateSub = in
	return &pb.CreateSubscriptionResp{Subscription: &pb.Subscription{
		Id: "sub-1", CustomerId: in.GetCustomerId(), PlanId: in.GetPlanId(),
		ProviderSubscriptionId: in.GetProviderSubscriptionId(), Status: pb.Subscription_Status(in.GetStatus()),
	}}, nil
}

func (m *fakeMutation) RecordUsage(_ context.Context, in *pb.RecordUsageReq, _ ...grpc.CallOption) (*pb.RecordUsageResp, error) {
	m.lastRecord = in
	if m.recordErr != nil {
		return nil, m.recordErr
	}
	// Default: echo the quantity as the new meter total.
	return &pb.RecordUsageResp{UserId: in.GetUserId(), Meter: in.GetMeter(), Period: in.GetPeriod(), Total: in.GetQuantity()}, nil
}

func (m *fakeMutation) ApplyCredit(_ context.Context, in *pb.ApplyCreditReq, _ ...grpc.CallOption) (*pb.ApplyCreditResp, error) {
	m.lastApply = in
	if m.applyErr != nil {
		return nil, m.applyErr
	}
	if m.applyResp != nil {
		return m.applyResp, nil
	}
	// Default: echo the delta as the new balance (good enough for the
	// non-error path assertions).
	return &pb.ApplyCreditResp{UserId: in.GetUserId(), Balance: in.GetDelta()}, nil
}

func (m *fakeMutation) MarkWebhookProcessed(_ context.Context, in *pb.MarkWebhookProcessedReq, _ ...grpc.CallOption) (*pb.MarkWebhookProcessedResp, error) {
	m.markedProcessed = true
	if m.markProcessedErr != nil {
		return nil, m.markProcessedErr
	}
	return &pb.MarkWebhookProcessedResp{ProviderEventId: in.GetProviderEventId()}, nil
}
func (m *fakeMutation) MarkPaymentSucceeded(_ context.Context, in *pb.MarkPaymentSucceededReq, _ ...grpc.CallOption) (*pb.MarkPaymentSucceededResp, error) {
	if m.succeededErr != nil {
		return nil, m.succeededErr
	}
	m.succeededFor = in.GetProviderPaymentId()
	return &pb.MarkPaymentSucceededResp{Payment: &pb.Payment{ProviderPaymentId: in.GetProviderPaymentId(), Status: pb.Payment_SUCCEEDED}}, nil
}
func (m *fakeMutation) MarkPaymentFailed(_ context.Context, in *pb.MarkPaymentFailedReq, _ ...grpc.CallOption) (*pb.MarkPaymentFailedResp, error) {
	m.failedFor = in.GetProviderPaymentId()
	return &pb.MarkPaymentFailedResp{Payment: &pb.Payment{ProviderPaymentId: in.GetProviderPaymentId(), Status: pb.Payment_FAILED}}, nil
}

func (m *fakeMutation) CreateCustomer(_ context.Context, in *pb.CreateCustomerReq, _ ...grpc.CallOption) (*pb.CreateCustomerResp, error) {
	c := &pb.Customer{Id: "cust-1", UserId: in.GetUserId(), ProviderCustomerId: in.GetProviderCustomerId(), Email: in.GetEmail()}
	m.createdCustomer = c
	return &pb.CreateCustomerResp{Customer: c}, nil
}
func (m *fakeMutation) CreatePayment(_ context.Context, in *pb.CreatePaymentReq, _ ...grpc.CallOption) (*pb.CreatePaymentResp, error) {
	m.createPayReq = in
	return &pb.CreatePaymentResp{Payment: &pb.Payment{
		Id: "pay-1", CustomerId: in.GetCustomerId(), ProviderPaymentId: in.GetProviderPaymentId(),
		Amount: in.GetAmount(), Currency: in.GetCurrency(), Status: pb.Payment_Status(in.GetStatus()),
	}}, nil
}
func (m *fakeMutation) CreateRefund(_ context.Context, in *pb.CreateRefundReq, _ ...grpc.CallOption) (*pb.CreateRefundResp, error) {
	m.lastCreateRefund = in
	return &pb.CreateRefundResp{Refund: &pb.Refund{
		Id: "ref-1", PaymentId: in.GetPaymentId(), ProviderRefundId: in.GetProviderRefundId(),
		Amount: in.GetAmount(), Currency: in.GetCurrency(),
	}}, nil
}

func newHandler(q *fakeQuery, m *fakeMutation, be backend.Backend) *PaymentServiceHandler {
	return &PaymentServiceHandler{Query: q, Mutation: m, Backend: be, DefaultCurrency: "usd"}
}

// ── tests ───────────────────────────────────────────────────────────

func TestCreateCustomer(t *testing.T) {
	be := &fakeBackend{ensureID: "cus_abc"}
	m := &fakeMutation{}
	h := newHandler(&fakeQuery{}, m, be)

	resp, err := h.CreateCustomer(context.Background(), &pb.NewCustomerReq{UserId: "u1", Email: "a@b.c"})
	if err != nil {
		t.Fatalf("CreateCustomer: %v", err)
	}
	if resp.GetCustomer().GetProviderCustomerId() != "cus_abc" {
		t.Errorf("provider id = %q, want cus_abc", resp.GetCustomer().GetProviderCustomerId())
	}
}

func TestCreateCustomer_RequiresUserID(t *testing.T) {
	h := newHandler(&fakeQuery{}, &fakeMutation{}, &fakeBackend{})
	_, err := h.CreateCustomer(context.Background(), &pb.NewCustomerReq{})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

func TestCreatePayment_CreatesCustomerOnFirstCharge(t *testing.T) {
	be := &fakeBackend{
		ensureID:  "cus_new",
		createRes: backend.PaymentResult{ProviderPaymentID: "pi_1", Status: "requires_confirmation", ClientSecret: "pi_1_secret"},
	}
	m := &fakeMutation{}
	h := newHandler(&fakeQuery{customer: nil}, m, be) // no existing customer

	resp, err := h.CreatePayment(context.Background(), &pb.ChargeReq{
		UserId: "u1", Amount: "19.99", Currency: "EUR", IdempotencyKey: "idem-1", Description: "pro plan",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if resp.GetClientSecret() != "pi_1_secret" {
		t.Errorf("client_secret = %q", resp.GetClientSecret())
	}
	// backend got the new provider-customer id + lowercased currency.
	if be.lastCharge.ProviderCustomerID != "cus_new" {
		t.Errorf("charge customer = %q, want cus_new", be.lastCharge.ProviderCustomerID)
	}
	if be.lastCharge.Amount.Currency != "eur" {
		t.Errorf("currency = %q, want eur", be.lastCharge.Amount.Currency)
	}
	// persisted payment carries the provider id + an intent status.
	if m.createPayReq.GetProviderPaymentId() != "pi_1" {
		t.Errorf("persisted provider id = %q", m.createPayReq.GetProviderPaymentId())
	}
	if m.createPayReq.GetStatus() != int32(pb.Payment_REQUIRES_ACTION) {
		t.Errorf("intent status = %d, want REQUIRES_ACTION", m.createPayReq.GetStatus())
	}
}

func TestCreatePayment_UsesExistingCustomerAndDefaultCurrency(t *testing.T) {
	be := &fakeBackend{createRes: backend.PaymentResult{ProviderPaymentID: "pi_2", Status: "succeeded"}}
	m := &fakeMutation{}
	existing := &pb.Customer{Id: "cust-9", UserId: "u1", ProviderCustomerId: "cus_existing"}
	h := newHandler(&fakeQuery{customer: existing}, m, be)

	_, err := h.CreatePayment(context.Background(), &pb.ChargeReq{UserId: "u1", Amount: "5.00"}) // no currency
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if be.lastCharge.ProviderCustomerID != "cus_existing" {
		t.Errorf("should reuse existing customer, got %q", be.lastCharge.ProviderCustomerID)
	}
	if be.lastCharge.Amount.Currency != "usd" {
		t.Errorf("default currency not applied: %q", be.lastCharge.Amount.Currency)
	}
	if m.createPayReq.GetStatus() != int32(pb.Payment_SUCCEEDED) {
		t.Errorf("succeeded status not mapped: %d", m.createPayReq.GetStatus())
	}
}

// Q45-pay-1: a non-positive amount must be rejected BEFORE the backend is
// called — a negative amount reaches Stripe as a credit/reversal (customer
// credited instead of charged = merchant loss); zero is a meaningless charge.
func TestCreatePayment_RejectsNonPositiveAmount(t *testing.T) {
	for _, amt := range []string{"-100.00", "0", "0.00", "abc"} {
		be := &fakeBackend{createRes: backend.PaymentResult{ProviderPaymentID: "pi_x"}}
		h := newHandler(&fakeQuery{customer: &pb.Customer{Id: "c", ProviderCustomerId: "cus"}}, &fakeMutation{}, be)
		_, err := h.CreatePayment(context.Background(), &pb.ChargeReq{UserId: "u1", Amount: amt, Currency: "usd", IdempotencyKey: "k"})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("amount %q: want InvalidArgument, got %v", amt, err)
		}
		if be.lastCharge.Amount.Amount != "" {
			t.Errorf("amount %q: backend must NOT be charged (got %q)", amt, be.lastCharge.Amount.Amount)
		}
	}
}

func TestCreatePayment_ProviderFailureIsUnavailable(t *testing.T) {
	be := &fakeBackend{ensureID: "c", createErr: errors.New("card declined")}
	h := newHandler(&fakeQuery{customer: &pb.Customer{Id: "x", ProviderCustomerId: "c"}}, &fakeMutation{}, be)
	_, err := h.CreatePayment(context.Background(), &pb.ChargeReq{UserId: "u1", Amount: "1.00", Currency: "usd"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

func TestRefundPayment_Full(t *testing.T) {
	be := &fakeBackend{refundRes: backend.RefundResult{ProviderRefundID: "re_1", Status: "succeeded"}}
	m := &fakeMutation{}
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-7", ProviderPaymentId: "pi_7", Amount: "20.00", Currency: "usd"}}
	h := newHandler(q, m, be)

	resp, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-7", IdempotencyKey: "idem-full"}) // no amount → full
	if err != nil {
		t.Fatalf("RefundPayment: %v", err)
	}
	if be.lastRefundFor != "pi_7" || be.lastRefund.Amount != "20.00" || be.lastRefund.Currency != "usd" {
		t.Errorf("backend refund = %q %+v", be.lastRefundFor, be.lastRefund)
	}
	if be.lastRefundIdem != "idem-full" {
		t.Errorf("provider idempotency key = %q, want the caller-supplied idem-full", be.lastRefundIdem)
	}
	if m.lastCreateRefund.GetProviderRefundId() != "re_1" || m.lastCreateRefund.GetAmount() != "20.00" {
		t.Errorf("persisted refund = %+v", m.lastCreateRefund)
	}
	if resp.GetRefund().GetId() != "ref-1" {
		t.Errorf("refund id = %q", resp.GetRefund().GetId())
	}
}

func TestRefundPayment_Partial(t *testing.T) {
	be := &fakeBackend{refundRes: backend.RefundResult{ProviderRefundID: "re_2"}}
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-8", ProviderPaymentId: "pi_8", Amount: "20.00", Currency: "usd"}}
	h := newHandler(q, &fakeMutation{}, be)
	if _, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-8", Amount: "5.00", IdempotencyKey: "idem-partial"}); err != nil {
		t.Fatalf("RefundPayment: %v", err)
	}
	if be.lastRefund.Amount != "5.00" {
		t.Errorf("partial refund amount = %q, want 5.00", be.lastRefund.Amount)
	}
}

func TestRefundPayment_NotFound(t *testing.T) {
	h := newHandler(&fakeQuery{payment: nil}, &fakeMutation{}, &fakeBackend{})
	_, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "ghost", IdempotencyKey: "k"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestRefundPayment_RequiresID(t *testing.T) {
	h := newHandler(&fakeQuery{}, &fakeMutation{}, &fakeBackend{})
	if _, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
}

// Q43-pay-2: a refund must carry a caller-supplied idempotency key —
// the handler can no longer derive one from (payment_id, amount) (that
// collided two legitimate same-amount partial refunds into one provider
// replay, silently shorting the customer).
func TestRefundPayment_RequiresIdempotencyKey(t *testing.T) {
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-9", ProviderPaymentId: "pi_9", Amount: "20.00", Currency: "usd"}}
	h := newHandler(q, &fakeMutation{}, &fakeBackend{})
	if _, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-9", Amount: "5.00"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a missing idempotency_key, got %v", err)
	}
}

// Q43-pay-2: two legitimate same-amount partial refunds with DISTINCT
// caller keys must reach the provider as DISTINCT Idempotency-Keys — the
// old derived "refund:<id>:<amount>" key collapsed them, so the second
// hit Stripe's idempotency replay and was silently swallowed. The handler
// must forward the caller key verbatim.
func TestRefundPayment_DistinctKeysNotCollapsed(t *testing.T) {
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-10", ProviderPaymentId: "pi_10", Amount: "20.00", Currency: "usd"}}
	be := &fakeBackend{refundRes: backend.RefundResult{ProviderRefundID: "re_a"}}
	h := newHandler(q, &fakeMutation{}, be)

	if _, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-10", Amount: "5.00", IdempotencyKey: "refund-A"}); err != nil {
		t.Fatalf("first refund: %v", err)
	}
	firstKey := be.lastRefundIdem
	if _, err := h.RefundPayment(context.Background(), &pb.RefundPaymentReq{PaymentId: "pay-10", Amount: "5.00", IdempotencyKey: "refund-B"}); err != nil {
		t.Fatalf("second refund: %v", err)
	}
	if firstKey == be.lastRefundIdem {
		t.Fatalf("two distinct same-amount refunds collapsed to one provider key %q — the customer would be shorted", be.lastRefundIdem)
	}
	if firstKey != "refund-A" || be.lastRefundIdem != "refund-B" {
		t.Errorf("provider keys = (%q, %q), want (refund-A, refund-B)", firstKey, be.lastRefundIdem)
	}
}

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig(&PaymentServiceHandler{Query: &fakeQuery{}, Mutation: &fakeMutation{}}); err == nil {
		t.Error("want error when backend nil")
	}
	if err := ValidateConfig(&PaymentServiceHandler{Backend: &fakeBackend{}}); err == nil {
		t.Error("want error when clients nil")
	}
}
