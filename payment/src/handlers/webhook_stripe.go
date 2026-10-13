package handlers

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// stripeSignatureMetadataKey is the lowercase gRPC-metadata key the
// gateway forwards the Stripe-Signature header under (declared in the
// plugin.yaml preset's forward_headers). gRPC lowercases header names.
const stripeSignatureMetadataKey = "stripe-signature"

// IngestStripe is the inbound Stripe webhook sink (gated
// stripe_webhooks). It verifies the signature, dispatches the terminal
// status to the reconciliation mutations (which emit PaymentSucceeded /
// PaymentFailed), then records the dedup row.
//
// Ordering matters: the idempotent side effects run FIRST and
// the dedup INSERT runs LAST. Recording dedup first stranded the event on
// any transient side-effect failure (the dedup row outlived the failed
// handler, so the provider's redelivery short-circuited handled=false and
// the side effect never re-ran).
//
// That ordering means a redelivery ALWAYS reaches the reconciliation
// mutation again — the ledger is never read first, so it cannot stop
// anything. The mutations therefore carry their own transition guards
// (`… AND status <> 3`), so a redelivered or out-of-order event matches
// zero rows and the generated emit wrapper, which fires after every
// successful return, does not publish a second PaymentSucceeded.
//
// A guard that matched zero rows arrives here as NotFound, and it is
// ambiguous, so reconcile looks the provider object up to tell:
//
//   - the row EXISTS: it is already in (or past) the target state — a
//     redelivery, or an out-of-order event (a late payment_failed after
//     the success; a subscription update after its deletion). Nothing to
//     change; acknowledge.
//   - the row does NOT exist yet — the local INSERT has not landed. Fail
//     WITHOUT recording the event, so the provider redelivers and the
//     whole chain runs again once it has.
//
// The dedup ledger used to be that discriminator (a unique violation
// read as "processed before"). It cannot be: an out-of-order event has
// its OWN event id, so its first delivery always inserted cleanly and
// was failed as "no local record", and a first delivery that failed
// wrote the ledger row on its way out, so every later delivery of it was
// acknowledged as a duplicate whether or not the row had appeared.
//
// The payment-succeeded hook (prepaid top-up grant) runs on a refused
// guard too, when the row exists: it is idempotent, and it is the only
// way a grant whose first attempt failed after MarkPaymentSucceeded had
// committed is ever retried. Reached only on a real transition, as it
// used to be, a transient failure in the grant left the payment
// SUCCEEDED and the credit never granted — the customer charged for
// credit they never got.
func (h *PaymentServiceHandler) IngestStripe(ctx context.Context, req *pb.IngestStripeReq) (*pb.IngestStripeResp, error) {
	sig := metadataValue(ctx, stripeSignatureMetadataKey)
	ev, err := stripe.VerifyAndParse(req.GetRawPayload(), sig, h.WebhookSecret)
	if err != nil {
		// Opaque: a forged / malformed webhook gets the same answer.
		return nil, status.Error(codes.Unauthenticated, "invalid webhook signature")
	}

	if err := h.reconcile(ctx, ev); err != nil {
		if errors.Is(err, errNoLocalRecord) {
			// Not recorded in the ledger: the redelivery must run the
			// reconciliation again, not be acknowledged as a duplicate.
			return nil, status.Errorf(codes.NotFound,
				"webhook %s: no local record for provider object %q", ev.Type, ev.ObjectID)
		}
		return nil, err
	}

	// Dedup ledger, written LAST: a unique-PK violation ⇒ this
	// event was already fully processed. Storage surfaces it as
	// InvalidArgument + ErrorDetail code=UNIQUE_VIOLATION, not
	// AlreadyExists.
	if _, err := h.Mutation.MarkWebhookProcessed(ctx, &pb.MarkWebhookProcessedReq{
		ProviderEventId: ev.ID,
		EventType:       ev.Type,
	}); err != nil {
		if constraintCode(err) == codeUniqueViolation {
			return &pb.IngestStripeResp{Handled: false, EventId: ev.ID, EventType: ev.Type}, nil
		}
		return nil, err
	}
	return &pb.IngestStripeResp{Handled: true, EventId: ev.ID, EventType: ev.Type}, nil
}

// reconcile dispatches one verified event onto the reconciliation
// mutations. errNoLocalRecord means the provider object has no local
// row yet; any other error is returned verbatim — a transient failure
// must NOT reach the dedup ledger.
func (h *PaymentServiceHandler) reconcile(ctx context.Context, ev stripe.Event) error {
	switch {
	case ev.Type == "payment_intent.succeeded":
		_, err := h.Mutation.MarkPaymentSucceeded(ctx, &pb.MarkPaymentSucceededReq{
			ProviderPaymentId: ev.PaymentIntentID,
		})
		if guardRefused(err) {
			// Already in a state the guard protects (SUCCEEDED, or the
			// terminal CANCELED / REFUNDED), or absent: not landed yet, or
			// not this installation's object.
			err = h.requirePayment(ctx, ev)
		}
		if err != nil {
			return err
		}
		// Cross-feature: grant credit if this payment was a top-up
		// (prepaid feature; no-op when prepaid is off — hook is nil).
		// Idempotent, so it runs on every delivery until one completes.
		if onPaymentSucceededWebhook != nil {
			return onPaymentSucceededWebhook(ctx, h, ev)
		}
	case ev.Type == "payment_intent.payment_failed":
		_, err := h.Mutation.MarkPaymentFailed(ctx, &pb.MarkPaymentFailedReq{
			ProviderPaymentId: ev.PaymentIntentID,
		})
		if guardRefused(err) {
			// Already in a state the guard protects — FAILED (redelivery),
			// SUCCEEDED (a late failure of an earlier attempt; SUCCEEDED is
			// absorbing), or the terminal CANCELED / REFUNDED — or absent:
			// not landed yet, or not this installation's object.
			err = h.requirePayment(ctx, ev)
		}
		return err
	case ev.Type == "payment_intent.canceled":
		_, err := h.Mutation.MarkPaymentCanceled(ctx, &pb.MarkPaymentCanceledReq{
			ProviderPaymentId: ev.PaymentIntentID,
		})
		if guardRefused(err) {
			// Already terminal or SUCCEEDED, or absent: resolved like the
			// failure above.
			err = h.requirePayment(ctx, ev)
		}
		return err
	case isRefundEvent(ev.Type):
		// A refund was made, or its outcome changed — through this plugin
		// or at the provider directly.
		return h.reconcileRefunds(ctx, ev.ChargePaymentIntent)
	case strings.HasPrefix(ev.Type, "charge.dispute."):
		return h.reconcileDispute(ctx, ev)
	case strings.HasPrefix(ev.Type, "customer.subscription."):
		// Cross-feature: reconcile subscription lifecycle (subscriptions
		// feature; no-op when off — hook is nil). The hook resolves its
		// own refused guard (its lookup is feature-gated).
		if onSubscriptionWebhook != nil {
			return onSubscriptionWebhook(ctx, h, ev)
		}
	}
	// Other event types are acknowledged (recorded in the dedup ledger)
	// but need no state change.
	return nil
}

// requirePayment resolves a refused payment guard: nil when the local
// Payment exists (it is already in a state the guard protects);
// errNoLocalRecord when this installation made the object and its row has
// not landed yet; nil — acknowledged — when it did not (madeHere). The
// provider sends events for objects the plugin never made (a subscription's
// invoice payments, dashboard charges, another app on the account) and for
// objects ANOTHER installation on the same account made; failing those
// would have them redelivered for days.
func (h *PaymentServiceHandler) requirePayment(ctx context.Context, ev stripe.Event) error {
	got, err := h.Query.GetPaymentByProviderId(ctx, &pb.GetPaymentByProviderIdReq{ProviderPaymentId: ev.PaymentIntentID})
	if err != nil && !absent(err) {
		return err
	}
	if got.GetPayment() != nil || !h.madeHere(ev) {
		return nil
	}
	return errNoLocalRecord
}

// isRefundEvent reports whether an event type announces a refund or a change
// of its outcome: charge.refunded (a Charge, partly or fully refunded) and the
// Refund events (refund.created / refund.updated / refund.failed, and the
// older charge.refund.updated). All carry the PaymentIntent the refunds
// belong to as data.object.payment_intent.
func isRefundEvent(typ string) bool {
	return typ == "charge.refunded" || typ == "charge.refund.updated" || strings.HasPrefix(typ, "refund.")
}

// reconcileRefunds brings a payment's local refunds and status in line with
// the provider's refunds of it.
//
// The provider's CURRENT list is the truth, not the event's own snapshot. A
// snapshot is as old as its event and events arrive in any order: a
// charge.refunded that says "fully refunded", delivered after the refund.failed
// that undid it, would put REFUNDED back. Nor does every snapshot name the
// refunds (a Charge stopped embedding them in newer API versions), and only
// the list says which refunds this plugin has not recorded — those made at the
// provider directly.
//
// A refund recorded FAILED or CANCELED stays so whatever a later read says:
// the provider never revives one, so a read that disagrees is older than the
// failure (MarkRefundStatus is guarded the same way).
//
// The payment's status comes first, from that total, so a top-up refunded in
// full before its credit was ever granted reads REFUNDED (its grant is then
// refused) before its refunds are recorded. Then every refund: an unknown one
// is recorded (and a top-up's credit taken back), a known one takes the
// provider's outcome, and a failed or canceled one gives a top-up's credit
// back. Every step is idempotent, and any failure leaves the event unrecorded,
// so the provider's redelivery runs the whole reconciliation again.
func (h *PaymentServiceHandler) reconcileRefunds(ctx context.Context, providerPaymentID string) error {
	if providerPaymentID == "" {
		return nil // a charge without a PaymentIntent: never one this plugin made
	}
	payment, err := h.paymentByProviderID(ctx, providerPaymentID)
	if err != nil || payment == nil {
		// No local payment: not this installation's. A refund needs a
		// succeeded payment, whose row landed before its client secret left.
		return err
	}
	refunds, err := h.Backend.ListRefunds(ctx, providerPaymentID)
	if err != nil {
		return providerFailure(err)
	}
	seen := make([]seenRefund, 0, len(refunds))
	counted := "0"
	for _, r := range refunds {
		got, err := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: r.ProviderRefundID})
		if err != nil && !absent(err) {
			return err
		}
		sr := seenRefund{RefundResult: r, row: got.GetRefund(), outcome: mapRefundStatus(r.Status)}
		if sr.row != nil && !refundCounts(sr.row.GetStatus()) {
			sr.outcome = sr.row.GetStatus()
		}
		if refundCounts(sr.outcome) {
			counted = decimalSum(counted, r.Amount.Amount)
		}
		seen = append(seen, sr)
	}
	if err := h.settleRefundedStatus(ctx, payment, counted); err != nil {
		return err
	}
	if payment, err = h.paymentByProviderID(ctx, providerPaymentID); err != nil || payment == nil {
		return err
	}
	for _, sr := range seen {
		if err := h.reconcileRefund(ctx, payment, sr); err != nil {
			return err
		}
	}
	return nil
}

// seenRefund is one provider refund with its local row (nil when none) and
// the outcome to record.
type seenRefund struct {
	backend.RefundResult
	row     *pb.Refund
	outcome pb.Refund_Status
}

// settleRefundedStatus moves the payment to REFUNDED once what the provider
// counts as refunded reaches its amount, and back to SUCCEEDED when a refund
// that had completed it has since failed (PaymentRefundReversed).
func (h *PaymentServiceHandler) settleRefundedStatus(ctx context.Context, payment *pb.Payment, counted string) error {
	pid := payment.GetProviderPaymentId()
	if decimalAtLeast(counted, payment.GetAmount()) {
		_, err := h.Mutation.MarkPaymentRefunded(ctx, &pb.MarkPaymentRefundedReq{ProviderPaymentId: pid})
		if guardRefused(err) {
			return h.refundNotSettled(ctx, pid)
		}
		return err
	}
	_, err := h.Mutation.MarkPaymentRefundReversed(ctx, &pb.MarkPaymentRefundReversedReq{ProviderPaymentId: pid})
	if guardRefused(err) {
		return nil // not REFUNDED: nothing to reverse (or a redelivery reversed it)
	}
	return err
}

// reconcileRefund applies one provider refund to its local row.
func (h *PaymentServiceHandler) reconcileRefund(ctx context.Context, payment *pb.Payment, r seenRefund) error {
	outcome, row := r.outcome, r.row
	if row == nil {
		var err error
		if row, err = h.recordProviderRefund(ctx, payment, r.RefundResult, outcome); err != nil {
			return err
		}
	}
	if row.GetStatus() != outcome {
		// Guarded: FAILED and CANCELED never move back, so an older state
		// (from a lagging read) changes nothing.
		if _, err := h.Mutation.MarkRefundStatus(ctx, &pb.MarkRefundStatusReq{
			ProviderRefundId: r.ProviderRefundID,
			Status:           int32(outcome),
		}); err != nil && !guardRefused(err) {
			return err
		}
	}
	if !refundCounts(outcome) {
		return giveBackRefundCredit(ctx, h, payment, r.ProviderRefundID, r.Key)
	}
	return nil
}

// recordProviderRefund records a provider refund no local row knows.
//
// One carrying a RefundPayment key is this plugin's own, whose local insert
// has not landed (it is in flight, or it failed and the caller has not
// retried). It is recorded under that key, so the caller's retry finds it, and
// its credit was taken back before the provider was asked.
//
// One without a key was made at the provider directly. Its credit is taken
// back here, as far as the balance holds it, and what could not be taken is
// recorded on the row as the credit shortfall. A refund first seen failed or
// canceled took nothing and takes nothing.
//
// A concurrent writer (the other delivery, or RefundPayment itself) recording
// it first is the answer: its row is returned.
func (h *PaymentServiceHandler) recordProviderRefund(ctx context.Context, payment *pb.Payment, r backend.RefundResult, outcome pb.Refund_Status) (*pb.Refund, error) {
	currency := r.Amount.Currency
	if currency == "" {
		currency = payment.GetCurrency()
	}
	var created interface{ GetRefund() *pb.Refund }
	var err error
	if r.Key != "" {
		created, err = h.Mutation.CreateRefund(ctx, &pb.CreateRefundReq{
			PaymentId:        payment.GetId(),
			ProviderRefundId: r.ProviderRefundID,
			Amount:           r.Amount.Amount,
			Currency:         currency,
			IdempotencyKey:   refundKey(r.Key),
			Status:           int32(outcome),
			CreditShortfall:  "0",
		})
	}
	if r.Key == "" || (constraintCode(err) == codeUniqueViolation && !h.refundRecorded(ctx, r.ProviderRefundID)) {
		// No key, or a key some other refund already holds (refused at
		// RefundPayment, so not one it made): recorded without the key.
		shortfall := "0"
		if r.Key == "" && refundCounts(outcome) {
			if shortfall, err = takeBackReversedCredit(ctx, h, payment, r.Amount.Amount, "refund:"+r.ProviderRefundID); err != nil {
				return nil, err
			}
		}
		created, err = h.Mutation.RecordProviderRefund(ctx, &pb.RecordProviderRefundReq{
			PaymentId:        payment.GetId(),
			ProviderRefundId: r.ProviderRefundID,
			Amount:           r.Amount.Amount,
			Currency:         currency,
			Status:           int32(outcome),
			CreditShortfall:  shortfall,
		})
	}
	if err == nil {
		return created.GetRefund(), nil
	}
	if constraintCode(err) != codeUniqueViolation {
		return nil, err
	}
	got, gerr := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: r.ProviderRefundID})
	if gerr != nil {
		return nil, gerr
	}
	return got.GetRefund(), nil
}

// refundRecorded reports whether a local row holds the provider refund (a read
// failure counts as recorded: the caller's insert then surfaces its own error).
func (h *PaymentServiceHandler) refundRecorded(ctx context.Context, providerRefundID string) bool {
	_, err := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: providerRefundID})
	return !absent(err)
}

// reconcileDispute records a dispute's status from its charge.dispute.* event
// and, once the dispute is LOST, takes a top-up's credit back like a refund
// made at the provider (the shortfall is recorded on the dispute).
//
// An open dispute (needs_response, under_review) takes nothing yet, although
// the provider has already withdrawn the disputed amount: most disputes are
// won, and a credit taken at opening would have to be given back on a win,
// which out-of-order events make unsafe to do exactly once. The credit stays
// spendable until the dispute is lost; whatever is spent by then is the
// shortfall. An inquiry (warning_*) withdraws nothing and takes nothing.
//
// The dispute's own event is used, not a fresh read: its status only moves
// forward to WON or LOST, both terminal, and between the open states the
// event's creation time orders the writes.
func (h *PaymentServiceHandler) reconcileDispute(ctx context.Context, ev stripe.Event) error {
	if ev.ChargePaymentIntent == "" || ev.ObjectID == "" {
		return nil
	}
	payment, err := h.paymentByProviderID(ctx, ev.ChargePaymentIntent)
	if err != nil || payment == nil {
		return err // no local payment: not this installation's
	}
	amount, currency := ev.Amount.Amount, ev.Amount.Currency
	if amount == "" {
		amount, currency = payment.GetAmount(), payment.GetCurrency()
	}
	outcome := mapDisputeStatus(ev.ObjectStatus)
	shortfall := "0"
	if outcome == pb.Dispute_LOST {
		if shortfall, err = takeBackReversedCredit(ctx, h, payment, amount, "dispute:"+ev.ObjectID); err != nil {
			return err
		}
	}
	mark := func() error {
		_, err := h.Mutation.MarkDisputeStatus(ctx, &pb.MarkDisputeStatusReq{
			ProviderDisputeId: ev.ObjectID,
			Status:            int32(outcome),
			CreditShortfall:   shortfall,
			ProviderEventAt:   eventTime(ev.Created),
		})
		return err
	}
	err = mark()
	if !guardRefused(err) {
		return err
	}
	got, err := h.Query.GetDisputeByProviderId(ctx, &pb.GetDisputeByProviderIdReq{ProviderDisputeId: ev.ObjectID})
	if err != nil && !absent(err) {
		return err
	}
	if got.GetDispute() != nil {
		return nil // already closed, or a newer event applied: this one is stale
	}
	_, err = h.Mutation.CreateDispute(ctx, &pb.CreateDisputeReq{
		PaymentId:         payment.GetId(),
		ProviderDisputeId: ev.ObjectID,
		Amount:            amount,
		Currency:          currency,
		Status:            int32(outcome),
		CreditShortfall:   shortfall,
		ProviderEventAt:   eventTime(ev.Created),
	})
	if constraintCode(err) == codeUniqueViolation {
		// A concurrent delivery created it: apply this status over it.
		if err = mark(); guardRefused(err) {
			return nil
		}
	}
	return err
}

// mapDisputeStatus maps the provider's dispute status onto Dispute.Status.
func mapDisputeStatus(providerStatus string) pb.Dispute_Status {
	switch providerStatus {
	case "warning_needs_response", "warning_under_review":
		return pb.Dispute_INQUIRY
	case "warning_closed":
		return pb.Dispute_INQUIRY_CLOSED
	case "needs_response":
		return pb.Dispute_NEEDS_RESPONSE
	case "under_review":
		return pb.Dispute_UNDER_REVIEW
	case "won":
		return pb.Dispute_WON
	case "lost":
		return pb.Dispute_LOST
	default:
		return pb.Dispute_UNRECOGNIZED_STATUS
	}
}

// paymentByProviderID is the local payment for a provider id, nil when there
// is none.
func (h *PaymentServiceHandler) paymentByProviderID(ctx context.Context, providerPaymentID string) (*pb.Payment, error) {
	got, err := h.Query.GetPaymentByProviderId(ctx, &pb.GetPaymentByProviderIdReq{ProviderPaymentId: providerPaymentID})
	if err != nil && !absent(err) {
		return nil, err
	}
	return got.GetPayment(), nil
}

// refundNotSettled resolves a refused MarkPaymentRefunded on a fully refunded
// charge. Already REFUNDED (a redelivery), CANCELED, or absent (not a payment
// this installation made): acknowledged. Still before SUCCEEDED locally — the
// payment_intent.succeeded delivery is late or being retried, which Stripe
// does not order against charge.refunded: an error, so the event is NOT
// recorded and its redelivery settles the status once SUCCEEDED has landed.
// Acknowledged, the REFUNDED was lost for good, and the late success then
// read SUCCEEDED (and granted a top-up's credit) on a refunded payment.
func (h *PaymentServiceHandler) refundNotSettled(ctx context.Context, providerPaymentID string) error {
	got, err := h.Query.GetPaymentByProviderId(ctx, &pb.GetPaymentByProviderIdReq{ProviderPaymentId: providerPaymentID})
	if err != nil && !absent(err) {
		return err
	}
	p := got.GetPayment()
	if p == nil {
		return nil
	}
	switch p.GetStatus() {
	case pb.Payment_REFUNDED, pb.Payment_CANCELED:
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"charge.refunded for %q before its success landed locally; redeliver", providerPaymentID)
}

// metadataValue reads the first value for a lowercase metadata key from
// the incoming gRPC context (empty if absent).
func metadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vs := md.Get(key); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func init() { webhooksStaged = true }
