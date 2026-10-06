package handlers

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), creditGrant, orDefault(req.GetReason(), "grant"), req.GetRef(), req.GetIdempotencyKey())
}

// SpendCredit deducts credit (signed −). Returns FailedPrecondition when
// the balance is insufficient (the CreditBalance non-negative CHECK
// rejects the overdraw and the transaction rolls back).
func (h *PaymentServiceHandler) SpendCredit(ctx context.Context, req *pb.SpendCreditReq) (*pb.CreditView, error) {
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), creditSpend, orDefault(req.GetReason(), "spend"), req.GetRef(), req.GetIdempotencyKey())
}

// creditKind is what an apply does; it signs the delta and scopes the
// ledger key.
type creditKind string

const (
	creditGrant creditKind = "grant"
	creditSpend creditKind = "spend"
	creditTopup creditKind = "topup" // the webhook's grant for a paid top-up; idem = provider payment id
)

// applyCredit is the shared grant/spend path. A spend negates the
// (unsigned) amount. The atomic ledger+balance write lives in the
// ApplyCredit mutation; this layer maps its two constraint outcomes:
//
//   - UNIQUE_VIOLATION on idempotency_key → the apply already happened
//     (a retry); idempotent — return the current balance, no error.
//   - INVALID_VALUE → the balance CHECK rejected an overdraw (the only
//     INVALID_VALUE-class constraint on this path) → FailedPrecondition.
//
// The ledger key is the caller's key SCOPED by (kind, principal) —
// CreditLedger.idempotency_key is one table-wide UNIQUE, and the caller's
// raw key used to be stored as is. Because a duplicate is answered with
// success, any collision was a silent no-op reported as done: a spend
// reusing an earlier grant's key ("order-1") deducted nothing and
// succeeded (the service delivered for free), and a grant for user-b
// under a key user-a had used granted nothing and succeeded. Scoped, a
// duplicate can only be a genuine retry of the same apply.
func (h *PaymentServiceHandler) applyCredit(ctx context.Context, userID, amount string, kind creditKind, reason, ref, idem string) (*pb.CreditView, error) {
	if userID == "" {
		return nil, invalidArg("user_id is required")
	}
	// Trimmed BEFORE the sign is applied: " 5" passed validation and
	// became the delta "- 5", which the database refused as malformed
	// input instead of spending 5.
	amount = strings.TrimSpace(amount)
	if !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	if idem == "" {
		return nil, invalidArg("idempotency_key is required (the apply must be idempotent)")
	}
	if err := idempotencyKeyTooLong(idem); err != nil {
		return nil, err
	}
	delta := amount
	if kind == creditSpend {
		delta = "-" + amount
	}
	resp, err := h.Mutation.ApplyCredit(ctx, &pb.ApplyCreditReq{
		UserId:         userID,
		Delta:          delta,
		Reason:         reason,
		Ref:            ref,
		IdempotencyKey: scopedKey("credit", string(kind), userID, idem),
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

// TopUpCredit funds a credit top-up: charge the principal via the
// provider and record a pending CreditTopup. The credit itself is
// granted when the payment-succeeded webhook fires
// (grantTopupOnPaymentSuccess) — 1:1 with the charged amount. Requires
// the stripe_webhooks feature for the grant to land.
//
// Credit has no currency of its own, so a top-up is charged in the
// configured default_currency and nothing else. Any caller-chosen
// currency used to be accepted and granted 1:1, so 1000 of the weakest
// currency bought the same 1000 credits as 1000 of the default.
func (h *PaymentServiceHandler) TopUpCredit(ctx context.Context, req *pb.TopUpCreditReq) (*pb.TopUpCreditResp, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	amount := strings.TrimSpace(req.GetAmount())
	if !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	currency, err := h.chargeCurrency(req.GetCurrency())
	if err != nil {
		return nil, err
	}
	if h.DefaultCurrency != "" && currency != h.DefaultCurrency {
		return nil, invalidArg("a credit top-up is charged in the default currency only")
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	cust, err := h.resolveCustomer(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	payment, clientSecret, err := h.charge(ctx, cust, amount, currency, idempotencyKeyOrNew(req.GetIdempotencyKey()), "credit top-up")
	if err != nil {
		return nil, err
	}

	// Record the pending top-up so the webhook can grant credit on
	// success. A duplicate (retry) is fine — provider_payment_id unique.
	if _, err := h.Mutation.CreateCreditTopup(ctx, &pb.CreateCreditTopupReq{
		ProviderPaymentId: payment.GetProviderPaymentId(),
		UserId:            req.GetUserId(),
		Amount:            amount,
	}); err != nil && constraintCode(err) != codeUniqueViolation {
		return nil, err
	}

	return &pb.TopUpCreditResp{Payment: payment, ClientSecret: clientSecret}, nil
}

// grantTopupOnPaymentSuccess is the payment-succeeded webhook hook: if
// the succeeded charge is a recorded top-up, grant the matching credit
// and stamp it granted. Idempotent — the grant uses a per-charge ledger
// key (applyCredit treats a duplicate as a no-op) and granted_at guards
// double-stamping — which is what lets IngestStripe re-run it on every
// delivery of the event until it has completed once.
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
	if _, err := h.applyCredit(ctx, topup.GetUserId(), topup.GetAmount(), creditTopup, "topup", pid, pid); err != nil {
		return err
	}
	// The stamp is guarded (granted_at IS NULL), so a concurrent delivery
	// that stamped first leaves this one matching no row → NotFound. The
	// grant is already done either way; failing here only made the
	// provider redeliver an event that had fully taken effect.
	if _, err := h.Mutation.MarkTopupGranted(ctx, &pb.MarkTopupGrantedReq{ProviderPaymentId: pid}); err != nil && !guardRefused(err) {
		return err
	}
	return nil
}
