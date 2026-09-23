// Package handlers holds the payment plugin's authored business logic —
// the PaymentService implementation. Storage primitives (PaymentQuery /
// PaymentMutation) are codegen-emitted from DQL; this layer composes
// them with the backend driver (provider API calls).
package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// PaymentServiceHandler implements pb.PaymentServiceServer. Constructed
// once per activation by RegisterPlugin with the in-process storage
// clients + the configured backend driver.
type PaymentServiceHandler struct {
	Query    pb.PaymentQueryClient
	Mutation pb.PaymentMutationClient
	Backend  backend.Backend

	// WebhookSecret verifies inbound Stripe webhook signatures (read by
	// the stripe_webhooks-gated IngestStripe in webhook_stripe.go).
	WebhookSecret string
	// DefaultCurrency (ISO-4217, lowercase) applies when a charge omits
	// a currency.
	DefaultCurrency string
}

// ValidateConfig fails loud at startup on a mis-wired handler so a
// bundle never boots half-configured.
func ValidateConfig(h *PaymentServiceHandler) error {
	if h.Backend == nil {
		return fmt.Errorf("payment plugin: no backend configured")
	}
	if h.Query == nil || h.Mutation == nil {
		return fmt.Errorf("payment plugin: storage clients not wired")
	}
	return nil
}

// Shutdown is the bundle drain hook. No background work in Slice 1.
func (h *PaymentServiceHandler) Shutdown(context.Context) error { return nil }

// CreateCustomer establishes the principal ↔ provider-customer link:
// create the provider customer object, then persist the local row.
func (h *PaymentServiceHandler) CreateCustomer(ctx context.Context, req *pb.NewCustomerReq) (*pb.NewCustomerResp, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	providerID, err := h.Backend.EnsureCustomer(ctx, backend.CustomerSpec{
		UserID: req.GetUserId(),
		Email:  req.GetEmail(),
	})
	if err != nil {
		return nil, providerFailure(err)
	}
	resp, err := h.Mutation.CreateCustomer(ctx, &pb.CreateCustomerReq{
		UserId:             req.GetUserId(),
		ProviderCustomerId: providerID,
		Email:              req.GetEmail(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.NewCustomerResp{Customer: resp.GetCustomer()}, nil
}

// CreatePayment creates a charge: ensure the Customer exists, call the
// backend to create the provider payment (idempotency-keyed), then
// persist the local Payment at its initial status.
func (h *PaymentServiceHandler) CreatePayment(ctx context.Context, req *pb.ChargeReq) (*pb.ChargeResp, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	if strings.TrimSpace(req.GetAmount()) == "" {
		return nil, invalidArg("amount is required")
	}
	// Q45-pay-1: reject a non-positive amount before the provider call — a
	// negative amount reaches Stripe as a credit/reversal (customer credited
	// instead of charged), a zero is a meaningless charge.
	if !isPositiveDecimal(req.GetAmount()) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	currency := strings.ToLower(strings.TrimSpace(req.GetCurrency()))
	if currency == "" {
		currency = h.DefaultCurrency
	}
	if currency == "" {
		return nil, invalidArg("currency is required (no default_currency configured)")
	}

	cust, err := h.resolveCustomer(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}

	pr, err := h.Backend.CreatePayment(ctx, backend.PaymentSpec{
		ProviderCustomerID: cust.GetProviderCustomerId(),
		Amount:             backend.Money{Amount: req.GetAmount(), Currency: currency},
		IdempotencyKey:     req.GetIdempotencyKey(),
		Description:        req.GetDescription(),
	})
	if err != nil {
		return nil, providerFailure(err)
	}

	created, err := h.Mutation.CreatePayment(ctx, &pb.CreatePaymentReq{
		CustomerId:        cust.GetId(),
		ProviderPaymentId: pr.ProviderPaymentID,
		Amount:            req.GetAmount(),
		Currency:          currency,
		Status:            int32(mapInitialStatus(pr.Status)),
		IdempotencyKey:    req.GetIdempotencyKey(),
		Description:       req.GetDescription(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.ChargeResp{Payment: created.GetPayment(), ClientSecret: pr.ClientSecret}, nil
}

// RefundPayment reverses a payment (full when amount is empty), via the
// provider, and records the local Refund.
func (h *PaymentServiceHandler) RefundPayment(ctx context.Context, req *pb.RefundPaymentReq) (*pb.RefundPaymentResp, error) {
	if req.GetPaymentId() == "" {
		return nil, invalidArg("payment_id is required")
	}
	// Q43-pay-2: the idempotency key IS the provider Idempotency-Key for
	// the refund, so it must be unique per distinct refund and stable
	// across retries. Deriving it from (payment_id, amount) — as this
	// handler used to — collided two legitimate same-amount partial
	// refunds into one provider replay, silently shorting the customer.
	// The caller owns it now (mirrors GrantCredit / ReportUsage).
	if req.GetIdempotencyKey() == "" {
		return nil, invalidArg("idempotency_key is required (the refund must be idempotent; supply a unique key per distinct refund)")
	}
	got, err := h.Query.GetPayment(ctx, &pb.GetPaymentReq{Id: req.GetPaymentId()})
	if err != nil {
		return nil, err
	}
	payment := got.GetPayment()
	if payment == nil {
		return nil, notFound("payment not found")
	}
	amount := strings.TrimSpace(req.GetAmount())
	if amount == "" {
		amount = payment.GetAmount() // full refund
	}

	res, err := h.Backend.RefundPayment(ctx, payment.GetProviderPaymentId(),
		backend.Money{Amount: amount, Currency: payment.GetCurrency()},
		req.GetIdempotencyKey())
	if err != nil {
		return nil, providerFailure(err)
	}

	created, err := h.Mutation.CreateRefund(ctx, &pb.CreateRefundReq{
		PaymentId:        payment.GetId(),
		ProviderRefundId: res.ProviderRefundID,
		Amount:           amount,
		Currency:         payment.GetCurrency(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.RefundPaymentResp{Refund: created.GetRefund()}, nil
}

// resolveCustomer returns the principal's Customer row, creating it (and
// the provider customer object) on first charge.
func (h *PaymentServiceHandler) resolveCustomer(ctx context.Context, userID string) (*pb.Customer, error) {
	got, err := h.Query.GetCustomerByUserId(ctx, &pb.GetCustomerByUserIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	if got.GetCustomer() != nil {
		return got.GetCustomer(), nil
	}
	providerID, err := h.Backend.EnsureCustomer(ctx, backend.CustomerSpec{UserID: userID})
	if err != nil {
		return nil, providerFailure(err)
	}
	created, err := h.Mutation.CreateCustomer(ctx, &pb.CreateCustomerReq{
		UserId:             userID,
		ProviderCustomerId: providerID,
	})
	if err != nil {
		return nil, err
	}
	return created.GetCustomer(), nil
}

// mapInitialStatus maps the provider's payment status string onto the
// local Payment.Status enum at intent time. Unknown → REQUIRES_ACTION
// (safe default: the webhook will reconcile the terminal state).
func mapInitialStatus(providerStatus string) pb.Payment_Status {
	switch providerStatus {
	case "succeeded":
		return pb.Payment_SUCCEEDED
	case "processing":
		return pb.Payment_PROCESSING
	case "canceled":
		return pb.Payment_CANCELED
	default:
		return pb.Payment_REQUIRES_ACTION
	}
}
