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
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), creditGrant, orDefault(req.GetReason(), "grant"), req.GetRef(), req.GetIdempotencyKey())
}

// SpendCredit deducts credit (signed −). Returns FailedPrecondition when
// the balance is insufficient (the CreditBalance non-negative CHECK
// rejects the overdraw and the transaction rolls back).
func (h *PaymentServiceHandler) SpendCredit(ctx context.Context, req *pb.SpendCreditReq) (*pb.CreditView, error) {
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), creditSpend, orDefault(req.GetReason(), "spend"), req.GetRef(), req.GetIdempotencyKey())
}

// ledgerKey is the stored CreditLedger key for one apply. A caller's grant
// or spend key is scoped by (kind, principal) — see applyCredit. A top-up's
// is the provider payment id, globally unique, under the "topup:" key every
// earlier version wrote: a grant that committed and then failed to stamp is
// retried by redelivery, and a retry under a NEW key would grant twice.
// Scoped caller keys ("v2:" + hash) cannot collide with it.
func ledgerKey(kind creditKind, userID, idem string) string {
	if kind == creditTopup {
		return "topup:" + idem
	}
	return scopedKey("credit", string(kind), userID, idem)
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
	if kind != creditTopup {
		dup, err := h.appliedUnderRawKey(ctx, userID, amount, kind, idem)
		if err != nil {
			return nil, err
		}
		if dup {
			return h.currentBalance(ctx, userID)
		}
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
		IdempotencyKey: ledgerKey(kind, userID, idem),
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

// appliedUnderRawKey reports whether this grant / spend was already applied
// by a version that stored the caller's RAW key (rc.2 and earlier).
//
// The scoped key cannot find such an apply: a grant or spend made before the
// upgrade and retried after it would land a second time — credit granted
// twice, or a service paid for twice. So before applying under the scoped
// key the ledger is read under the raw key too (one extra single-row read per
// apply), and a row there is THIS apply when it is the same principal, the
// same direction (grant +, spend −) and the same amount. A row that differs
// in any of them is the cross-principal / cross-kind collision the scoped key
// exists to fix, and the apply proceeds under the scoped key.
//
// Keys in the "topup:" namespace are not looked up: that is where the
// webhook writes a top-up's grant (every version has), so a row there is a
// top-up and never a caller's earlier apply — matching one would turn a
// caller grant into a silent no-op. Keys in the "v2:" namespace are not
// either, for the same reason: that is where scoped keys are stored, so a
// caller key shaped "v2:<hex>" can equal another apply's stored scoped key.
func (h *PaymentServiceHandler) appliedUnderRawKey(ctx context.Context, userID, amount string, kind creditKind, rawKey string) (bool, error) {
	if strings.HasPrefix(rawKey, "topup:") || strings.HasPrefix(rawKey, scopedKeyPrefix) {
		return false, nil
	}
	got, err := h.Query.GetCreditLedgerByKey(ctx, &pb.GetCreditLedgerByKeyReq{IdempotencyKey: rawKey})
	if err != nil {
		if absent(err) {
			return false, nil
		}
		return false, err
	}
	e := got.GetEntry()
	if e == nil || e.GetUserId() != userID {
		return false, nil
	}
	delta := strings.TrimSpace(e.GetDelta())
	debit := strings.HasPrefix(delta, "-")
	if debit != (kind == creditSpend) {
		return false, nil
	}
	return sameDecimal(strings.TrimPrefix(delta, "-"), amount), nil
}

func (h *PaymentServiceHandler) currentBalance(ctx context.Context, userID string) (*pb.CreditView, error) {
	got, err := h.Query.GetCreditBalance(ctx, &pb.GetCreditBalanceReq{UserId: userID})
	if err != nil && !absent(err) { // no balance row yet: zero
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
	payment, clientSecret, err := h.charge(ctx, cust, amount, currency, idempotencyKeyOrNew(req.GetIdempotencyKey()), "credit top-up", backend.OriginTopup)
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
	if err != nil && !absent(err) {
		return err
	}
	topup := got.GetTopup()
	if topup == nil {
		if ev.Origin == backend.OriginTopup && h.madeHere(ev) {
			// A top-up whose CreditTopup row has not landed yet — the
			// success can arrive between the Payment INSERT and the
			// top-up's. Acknowledging it would strand the credit for good.
			return errNoLocalRecord
		}
		return nil // not a top-up
	}
	if topup.GetGrantedAt() != nil {
		return nil // already granted
	}
	// The ledger key stays "topup:<provider payment id>", the key every
	// earlier version wrote. A grant whose first attempt committed under it
	// and then failed to stamp is retried by redelivery; under any other key
	// that retry would grant the credit a second time. The provider id is
	// unique on its own, so the key needs no principal scoping.
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
