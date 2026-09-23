package handlers

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
	"github.com/wandering-compiler/platform/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// init wires the payment-succeeded webhook hook to the top-up grant.
// Present only when prepaid is staged, so a top-up charge funds credit
// only when the feature is on (and stripe_webhooks delivers the event).
func init() {
	onPaymentSucceededWebhook = grantTopupOnPaymentSuccess
}

// GrantCredit adds credit to a principal's balance (signed +).
func (h *PaymentServiceHandler) GrantCredit(ctx context.Context, req *pb.GrantCreditReq) (*pb.CreditView, error) {
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), false, orDefault(req.GetReason(), "grant"), req.GetRef(), req.GetIdempotencyKey())
}

// SpendCredit deducts credit (signed −). Returns FailedPrecondition when
// the balance is insufficient (the CreditBalance non-negative CHECK
// rejects the overdraw and the transaction rolls back).
func (h *PaymentServiceHandler) SpendCredit(ctx context.Context, req *pb.SpendCreditReq) (*pb.CreditView, error) {
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), true, orDefault(req.GetReason(), "spend"), req.GetRef(), req.GetIdempotencyKey())
}

// applyCredit is the shared grant/spend path. `spend` negates the
// (unsigned) amount. The atomic ledger+balance write lives in the
// ApplyCredit mutation; this layer maps its two constraint outcomes:
//
//   - UNIQUE_VIOLATION on idempotency_key → the apply already happened
//     (a retry); idempotent — return the current balance, no error.
//   - INVALID_VALUE → the balance CHECK rejected an overdraw (the only
//     INVALID_VALUE-class constraint on this path) → FailedPrecondition.
func (h *PaymentServiceHandler) applyCredit(ctx context.Context, userID, amount string, spend bool, reason, ref, idem string) (*pb.CreditView, error) {
	if userID == "" {
		return nil, invalidArg("user_id is required")
	}
	if !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	if idem == "" {
		return nil, invalidArg("idempotency_key is required (the apply must be idempotent)")
	}
	delta := amount
	if spend {
		delta = "-" + amount
	}
	resp, err := h.Mutation.ApplyCredit(ctx, &pb.ApplyCreditReq{
		UserId:         userID,
		Delta:          delta,
		Reason:         reason,
		Ref:            ref,
		IdempotencyKey: idem,
	})
	if err != nil {
		switch constraintCode(err) {
		case codeUniqueViolation:
			return h.currentBalance(ctx, userID)
		case codeInvalidValue:
			return nil, status.Error(codes.FailedPrecondition, "insufficient credit balance")
		}
		return nil, err
	}
	return &pb.CreditView{UserId: resp.GetUserId(), Balance: resp.GetBalance()}, nil
}

func (h *PaymentServiceHandler) currentBalance(ctx context.Context, userID string) (*pb.CreditView, error) {
	got, err := h.Query.GetCreditBalance(ctx, &pb.GetCreditBalanceReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	balance := "0"
	if b := got.GetBalance(); b != nil && b.GetBalance() != "" {
		balance = b.GetBalance()
	}
	return &pb.CreditView{UserId: userID, Balance: balance}, nil
}

// isPositiveDecimal reports whether s is a non-zero, non-negative
// decimal string (digits + at most one dot). Grant/spend take an
// unsigned amount; the sign is the handler's to apply.
func isPositiveDecimal(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	dots, nonZero := 0, false
	for _, r := range s {
		switch {
		case r >= '1' && r <= '9':
			nonZero = true
		case r == '0':
		case r == '.':
			dots++
		default:
			return false
		}
	}
	return dots <= 1 && nonZero
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// TopUpCredit funds a credit top-up: charge the principal via the
// provider and record a pending CreditTopup. The credit itself is
// granted when the payment-succeeded webhook fires
// (grantTopupOnPaymentSuccess) — 1:1 with the charged amount. Requires
// the stripe_webhooks feature for the grant to land.
func (h *PaymentServiceHandler) TopUpCredit(ctx context.Context, req *pb.TopUpCreditReq) (*pb.TopUpCreditResp, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
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
		Description:        "credit top-up",
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
		Description:       "credit top-up",
	})
	if err != nil {
		return nil, err
	}

	// Record the pending top-up so the webhook can grant credit on
	// success. A duplicate (retry) is fine — provider_payment_id unique.
	if _, err := h.Mutation.CreateCreditTopup(ctx, &pb.CreateCreditTopupReq{
		ProviderPaymentId: pr.ProviderPaymentID,
		UserId:            req.GetUserId(),
		Amount:            req.GetAmount(),
	}); err != nil && constraintCode(err) != codeUniqueViolation {
		return nil, err
	}

	return &pb.TopUpCreditResp{Payment: created.GetPayment(), ClientSecret: pr.ClientSecret}, nil
}

// grantTopupOnPaymentSuccess is the payment-succeeded webhook hook: if
// the succeeded charge is a recorded top-up, grant the matching credit
// and stamp it granted. Idempotent — the grant uses a per-charge ledger
// key (applyCredit treats a duplicate as a no-op) and granted_at guards
// double-stamping.
func grantTopupOnPaymentSuccess(ctx context.Context, h *PaymentServiceHandler, ev stripe.Event) error {
	pid := ev.PaymentIntentID
	if pid == "" {
		return nil
	}
	got, err := h.Query.GetCreditTopupByProviderId(ctx, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: pid})
	if err != nil {
		return err
	}
	topup := got.GetTopup()
	if topup == nil || topup.GetGrantedAt() != nil {
		return nil // not a top-up, or already granted
	}
	if _, err := h.applyCredit(ctx, topup.GetUserId(), topup.GetAmount(), false, "topup", pid, "topup:"+pid); err != nil {
		return err
	}
	_, err = h.Mutation.MarkTopupGranted(ctx, &pb.MarkTopupGrantedReq{ProviderPaymentId: pid})
	return err
}
