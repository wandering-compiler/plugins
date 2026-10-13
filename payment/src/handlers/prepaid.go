package handlers

import (
	"context"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// init wires the payment-succeeded webhook hook to the top-up grant.
// Present only when prepaid is staged, so a top-up charge funds credit
// only when the feature is on (and stripe_webhooks delivers the event).
func init() {
	onPaymentSucceededWebhook = grantTopupOnPaymentSuccess
	isTopupPayment = recordedTopup
}

// recordedTopup reports whether a CreditTopup row records p as a top-up.
func recordedTopup(ctx context.Context, h *PaymentServiceHandler, p *pb.Payment) (bool, error) {
	got, err := h.Query.GetCreditTopupByProviderId(ctx, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: p.GetProviderPaymentId()})
	if err != nil {
		if absent(err) {
			return false, nil
		}
		return false, err
	}
	return got.GetTopup() != nil, nil
}

// GrantCredit adds credit to a principal's balance (signed +).
func (h *PaymentServiceHandler) GrantCredit(ctx context.Context, req *pb.GrantCreditReq) (*pb.CreditView, error) {
	if isTopupReason(req.GetReason()) {
		return nil, invalidArg("reason: the top-up reasons are the plugin's own")
	}
	return h.applyCredit(ctx, req.GetUserId(), req.GetAmount(), creditGrant, orDefault(req.GetReason(), "grant"), req.GetRef(), req.GetIdempotencyKey())
}

// SpendCredit deducts credit (signed −). Returns FailedPrecondition when
// the balance is insufficient (the CreditBalance non-negative CHECK
// rejects the overdraw and the transaction rolls back).
func (h *PaymentServiceHandler) SpendCredit(ctx context.Context, req *pb.SpendCreditReq) (*pb.CreditView, error) {
	if isTopupReason(req.GetReason()) {
		return nil, invalidArg("reason: the top-up reasons are the plugin's own")
	}
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
	creditTopup creditKind = "topup" // the grant key every earlier version wrote for a paid top-up; idem = provider payment id

	// One step of a top-up's credit reconciliation; idem = provider payment
	// id + step number (topupStepKey). Its own kind, so no caller's
	// SpendCredit / GrantCredit key can name it.
	creditTopupStep creditKind = "topup-step"
)

// debit reports whether an apply of this kind takes credit away.
func (k creditKind) debit() bool { return k == creditSpend }

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
	if kind == creditGrant || kind == creditSpend { // only caller keys were ever stored raw
		dup, err := h.appliedUnderRawKey(ctx, userID, amount, kind, idem)
		if err != nil {
			return nil, err
		}
		if dup {
			return h.currentBalance(ctx, userID)
		}
	}
	delta := amount
	if kind.debit() {
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
	// Through the gateway this acts for the signed-in caller only; see
	// actingFor.
	uid, err := actingFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	req.UserId = uid
	// The credit is granted by the provider's webhook. Without the webhook
	// surface the charge would go through and the credit never land.
	if !webhooksStaged {
		return nil, status.Error(codes.FailedPrecondition, "payment: top-ups need the stripe_webhooks feature, which grants the credit when the provider confirms the payment")
	}
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
	payment, clientSecret, err := h.charge(ctx, cust, amount, currency, req.GetIdempotencyKey(), topupDescription, backend.OriginTopup)
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

// grantTopupOnPaymentSuccess is the payment-succeeded webhook hook: if the
// succeeded charge is a recorded top-up, reconcile its credit, which grants
// it (settleTopup). Idempotent, which is what lets IngestStripe re-run it on
// every delivery of the event until it has completed once.
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
	pay, err := h.paymentByProviderID(ctx, pid)
	if err != nil || pay == nil {
		return err
	}
	return h.settleTopup(ctx, pay, "0", reasonTopupGrant, false)
}

// GetMyCreditBalance returns the signed-in caller's balance.
func (h *PaymentServiceHandler) GetMyCreditBalance(ctx context.Context, _ *pb.GetMyCreditBalanceReq) (*pb.GetCreditBalanceResp, error) {
	caller, err := signedInCaller(ctx)
	if err != nil {
		return nil, err
	}
	got, err := h.Query.GetCreditBalance(ctx, &pb.GetCreditBalanceReq{UserId: caller})
	if absent(err) {
		// No credit yet: the balance row appears with the first apply. A
		// wallet that holds nothing is zero, not missing.
		return &pb.GetCreditBalanceResp{Balance: &pb.CreditBalance{UserId: caller, Balance: "0"}}, nil
	}
	return got, err
}

func init() {
	takeBackRefundedCredit = takeBackTopupCredit
	reconcileTopupCredit = func(ctx context.Context, h *PaymentServiceHandler, payment *pb.Payment) error {
		return h.settleTopup(ctx, payment, "0", reasonTopupReconcile, false)
	}
}

// ── a top-up's credit: one reconciliation ───────────────────────────
//
// Every path that changes what a top-up is worth — its success, a refund
// through RefundPayment, a refund made at the provider, its outcome, a lost
// dispute, a retry — ends in settleTopup, and nothing else writes a top-up's
// credit. The rule:
//
//	target = amount − pending and succeeded refunds − lost disputes,
//	         never below zero, and zero until the payment has succeeded
//	held   = the sum of the ledger rows the plugin wrote for this top-up
//	apply    target − held
//
// An increase is applied whole. A decrease takes only what the balance holds
// — its `>= 0` CHECK is the guard every spend relies on, so it is never driven
// negative — and the rest is owed (CreditTopup.credit_owed). Owed credit is
// held and not yet taken, so a later reconciliation takes it when the balance
// has grown, and one whose target rose (a refund failed) needs less: the debt
// goes first, spendable credit only after it.
//
// Concurrency: each write is the ledger row of one reconciliation STEP, keyed
// by (payment, step) — topupStepKey — and the unique key is the arbiter. A
// reconciliation finds the next free step, then reads the target and the held
// credit, then writes that step; one that lost the step to a concurrent
// reconciliation reads again and computes again. Every change to the target
// is written before its writer reconciles, and every reconciliation that
// wrote checks again until a pass finds nothing to change: of a change and a
// write that race, either the change's reconciliation reads the write, or
// the writer's next pass reads the change. credit_owed is written with its
// step, and an older step never overwrites a newer one.

// The ledger reasons a top-up's rows carry, and the only rows SumTopupCredit
// counts: GrantCredit and SpendCredit refuse them.
const (
	reasonTopupGrant     = "topup"                // the success hook's reconciliation (and every earlier grant)
	reasonTopupRefund    = "topup-refund"         // RefundPayment's take-back before the provider is asked
	reasonTopupRefused   = "topup-refund-refused" // its undo when the provider refuses for good
	reasonTopupReconcile = "topup-reconcile"      // every other reconciliation
)

func isTopupReason(r string) bool {
	switch strings.TrimSpace(r) {
	case reasonTopupGrant, reasonTopupRefund, reasonTopupRefused, reasonTopupReconcile:
		return true
	}
	return false
}

// topupStepKey is the ledger key of one reconciliation step of a top-up.
func topupStepKey(userID, providerPaymentID string, step int64) string {
	return ledgerKey(creditTopupStep, userID, providerPaymentID+"#"+strconv.FormatInt(step, 10))
}

// settleTopup reconciles the credit of the top-up paid by payment (no-op for
// a payment that is no top-up). pending is a refund RefundPayment is about to
// ask the provider for, not recorded yet; strict refuses a decrease the
// balance cannot cover whole (FailedPrecondition) instead of leaving it owed —
// RefundPayment's "spent credit is not refunded as money".
func (h *PaymentServiceHandler) settleTopup(ctx context.Context, payment *pb.Payment, pending, reason string, strict bool) error {
	pid := payment.GetProviderPaymentId()
	for attempt := 0; attempt < 8; attempt++ {
		got, err := h.Query.GetCreditTopupByProviderId(ctx, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: pid})
		if absent(err) {
			return nil // not a top-up
		}
		if err != nil {
			return err
		}
		topup := got.GetTopup()
		if topup == nil {
			return nil
		}
		userID := topup.GetUserId()
		// The step first: everything read after it is at least as new as the
		// step before it.
		step, err := h.nextTopupStep(ctx, userID, pid, topup.GetReconciledStep())
		if err != nil {
			return err
		}
		target, paid, err := h.topupTarget(ctx, pid, topup.GetAmount())
		if err != nil {
			return err
		}
		target = decimalShortfall(target, pending)
		sum, err := h.Query.SumTopupCredit(ctx, &pb.SumTopupCreditReq{
			UserId: userID, PaymentId: payment.GetId(), ProviderPaymentId: pid,
			ReasonGrant: reasonTopupGrant, ReasonRefund: reasonTopupRefund, ReasonRefused: reasonTopupRefused, ReasonReconcile: reasonTopupReconcile,
		})
		if err != nil {
			return err
		}
		held := sum.GetTotal()
		apply, owed := decimalSub(target, held), "0"
		if decimalSign(apply) < 0 && !strict {
			need := decimalSub("0", apply)
			bal, err := h.currentBalance(ctx, userID)
			if err != nil {
				return err
			}
			take := decimalMin(need, bal.GetBalance())
			apply, owed = decimalSub("0", take), decimalSub(need, take)
		}
		// Nothing to change: no row. (A step whose owed was never written —
		// its writer stopped between the two writes — needs none either when
		// the owed it would record is the one recorded; otherwise this
		// reconciliation's own step records it.)
		if decimalSign(apply) == 0 && sameDecimal(owed, orDefault(topup.GetCreditOwed(), "0")) {
			return h.stampTopupGranted(ctx, pid, paid)
		}
		_, err = h.Mutation.ApplyCredit(ctx, &pb.ApplyCreditReq{
			UserId: userID, Delta: apply, Reason: reason, Ref: payment.GetId(), IdempotencyKey: topupStepKey(userID, pid, step),
		})
		switch constraintCode(err) {
		case codeUniqueViolation:
			continue // a concurrent reconciliation took this step: read again
		case codeInvalidValue:
			if strict {
				return status.Error(codes.FailedPrecondition, "insufficient credit balance")
			}
			continue // a spend landed after the balance read: read again
		}
		if err != nil {
			return err
		}
		if _, err := h.Mutation.SetTopupCreditOwed(ctx, &pb.SetTopupCreditOwedReq{
			ProviderPaymentId: pid, CreditOwed: owed, ReconciledStep: step,
		}); err != nil && !guardRefused(err) {
			return err // the next reconciliation records it
		}
		// Check again: a change to the target that landed after this
		// reconciliation read it, and whose own reconciliation found nothing
		// to do before this step was written, is seen now. The pass that
		// finds nothing to change ends the loop (and stamps).
	}
	return status.Error(codes.Unavailable, "payment: a top-up's credit kept changing while it was reconciled; retry")
}

// nextTopupStep is the first step from after the last recorded one whose
// ledger row does not exist yet.
func (h *PaymentServiceHandler) nextTopupStep(ctx context.Context, userID, providerPaymentID string, last int64) (int64, error) {
	for step := last + 1; ; step++ {
		_, err := h.Query.GetCreditLedgerByKey(ctx, &pb.GetCreditLedgerByKeyReq{IdempotencyKey: topupStepKey(userID, providerPaymentID, step)})
		if absent(err) {
			return step, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// topupTarget is what the top-up should be worth now, and whether its payment
// has been paid (SUCCEEDED, or REFUNDED after it).
func (h *PaymentServiceHandler) topupTarget(ctx context.Context, providerPaymentID, amount string) (string, bool, error) {
	pay, err := h.paymentByProviderID(ctx, providerPaymentID)
	if err != nil || pay == nil {
		return "0", false, err
	}
	if st := pay.GetStatus(); st != pb.Payment_SUCCEEDED && st != pb.Payment_REFUNDED {
		return "0", false, nil
	}
	refunded, err := h.Query.SumRefundsForPayment(ctx, &pb.SumRefundsForPaymentReq{PaymentId: pay.GetId()})
	if err != nil {
		return "", false, err
	}
	lost, err := lostDisputeTotal(ctx, h, pay)
	if err != nil {
		return "", false, err
	}
	return decimalShortfall(decimalShortfall(amount, refunded.GetTotal()), lost), true, nil
}

// stampTopupGranted stamps granted_at the first time a paid top-up is
// reconciled (guarded: once). RefundPayment refuses a top-up not stamped yet.
func (h *PaymentServiceHandler) stampTopupGranted(ctx context.Context, providerPaymentID string, paid bool) error {
	if !paid {
		return nil
	}
	if _, err := h.Mutation.MarkTopupGranted(ctx, &pb.MarkTopupGrantedReq{ProviderPaymentId: providerPaymentID}); err != nil && !guardRefused(err) {
		return err
	}
	return nil
}

// takeBackTopupCredit takes, before the provider is asked, the credit a
// refund of a top-up is about to return as money: a reconciliation that
// counts the refund as pending, strictly — credit already spent is not
// refunded as money (FailedPrecondition), and a top-up not granted yet is not
// refunded at all. A retry of the same refund finds the credit already taken
// and takes nothing more. The undo, for a refusal the provider will repeat,
// is a reconciliation without the pending refund: it gives the credit back.
func takeBackTopupCredit(ctx context.Context, h *PaymentServiceHandler, payment *pb.Payment, amount, _ string) (func() error, error) {
	got, err := h.Query.GetCreditTopupByProviderId(ctx, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: payment.GetProviderPaymentId()})
	if err != nil {
		if absent(err) {
			return nil, nil // not a top-up
		}
		return nil, err
	}
	if got.GetTopup() == nil {
		return nil, nil
	}
	if got.GetTopup().GetGrantedAt() == nil {
		return nil, status.Error(codes.FailedPrecondition, "payment: the top-up's credit is not granted yet; refund it after the payment has settled")
	}
	if err := h.settleTopup(ctx, payment, amount, reasonTopupRefund, true); err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return nil, status.Error(codes.FailedPrecondition, "payment: the top-up's credit is already spent; it cannot be refunded")
		}
		return nil, err
	}
	undo := func() error { return h.settleTopup(ctx, payment, "0", reasonTopupRefused, false) }
	return undo, nil
}
