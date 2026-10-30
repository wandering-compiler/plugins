package handlers

import (
	"context"
	"errors"
	"log/slog"
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
		held, err := h.holdAmountMismatch(ctx, ev)
		if err != nil || held {
			return err
		}
		_, err = h.Mutation.MarkPaymentSucceeded(ctx, &pb.MarkPaymentSucceededReq{
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
// Every refund first: an unknown one is recorded, a known one takes the
// provider's outcome. Then the payment's status, from the LOCAL rows — never
// from this read, which a concurrent delivery may already have overtaken
// (settleRefundedStatus). Then a top-up's credit, from the same rows
// (reconcileTopupCredit). Every step is idempotent, and any failure leaves
// the event unrecorded, so the provider's redelivery runs the whole
// reconciliation again.
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
	for _, r := range refunds {
		got, err := h.Query.GetRefundByProviderId(ctx, &pb.GetRefundByProviderIdReq{ProviderRefundId: r.ProviderRefundID})
		if err != nil && !absent(err) {
			return err
		}
		sr := seenRefund{RefundResult: r, row: got.GetRefund(), outcome: mapRefundStatus(r.Status)}
		if sr.row != nil && !refundCounts(sr.row.GetStatus()) {
			sr.outcome = sr.row.GetStatus()
		}
		if err := h.reconcileRefund(ctx, payment, sr); err != nil {
			return err
		}
	}
	if err := h.settleRefundedStatus(ctx, payment); err != nil {
		return err
	}
	return reconcileTopupCredit(ctx, h, payment)
}

// seenRefund is one provider refund with its local row (nil when none) and
// the outcome to record.
type seenRefund struct {
	backend.RefundResult
	row     *pb.Refund
	outcome pb.Refund_Status
}

// settleRefundedStatus moves the payment to REFUNDED once its recorded
// pending and succeeded refunds reach its amount, and back to SUCCEEDED when a
// refund that had completed it has since failed (PaymentRefundReversed).
//
// Two deliveries can race: one about to mark REFUNDED from rows it read while
// the refund still counted, one that has just recorded the refund's failure
// and found the payment not REFUNDED yet, so nothing to reverse. Each writes
// first and reads the other's half after: the marker re-reads the rows once
// REFUNDED has landed and reverses it if they no longer reach the amount, so
// whichever runs last sees both writes and the payment cannot stay REFUNDED
// on a failed refund. (The cost is a PaymentRefunded followed by a
// PaymentRefundReversed in that interleaving.)
func (h *PaymentServiceHandler) settleRefundedStatus(ctx context.Context, payment *pb.Payment) error {
	pid := payment.GetProviderPaymentId()
	full, err := h.refundedInFull(ctx, payment)
	if err != nil {
		return err
	}
	if full {
		_, err := h.Mutation.MarkPaymentRefunded(ctx, &pb.MarkPaymentRefundedReq{ProviderPaymentId: pid})
		if guardRefused(err) {
			err = h.refundNotSettled(ctx, pid)
		}
		if err != nil {
			return err
		}
		if full, err = h.refundedInFull(ctx, payment); err != nil || full {
			return err
		}
	}
	if _, err := h.Mutation.MarkPaymentRefundReversed(ctx, &pb.MarkPaymentRefundReversedReq{ProviderPaymentId: pid}); err != nil && !guardRefused(err) {
		return err // refused: not REFUNDED, nothing to reverse
	}
	return nil
}

// refundedInFull reports whether the payment's recorded pending and succeeded
// refunds reach its amount.
func (h *PaymentServiceHandler) refundedInFull(ctx context.Context, payment *pb.Payment) (bool, error) {
	sum, err := h.Query.SumRefundsForPayment(ctx, &pb.SumRefundsForPaymentReq{PaymentId: payment.GetId()})
	if err != nil {
		return false, err
	}
	return decimalAtLeast(sum.GetTotal(), payment.GetAmount()), nil
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
	return nil
}

// recordProviderRefund records a provider refund no local row knows.
//
// One carrying a RefundPayment key is this plugin's own, whose local insert
// has not landed (it is in flight, or it failed and the caller has not
// retried). It is recorded under that key, so the caller's retry finds it.
// One without a key was made at the provider directly. Either way a top-up's
// credit follows from the rows (reconcileTopupCredit), not from here.
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
		})
	}
	if r.Key == "" || (constraintCode(err) == codeUniqueViolation && !h.refundRecorded(ctx, r.ProviderRefundID)) {
		// No key, or a key some other refund already holds (refused at
		// RefundPayment, so not one it made): recorded without the key.
		created, err = h.Mutation.RecordProviderRefund(ctx, &pb.RecordProviderRefundReq{
			PaymentId:        payment.GetId(),
			ProviderRefundId: r.ProviderRefundID,
			Amount:           r.Amount.Amount,
			Currency:         currency,
			Status:           int32(outcome),
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

// reconcileDispute records a dispute's status from its charge.dispute.* event,
// then reconciles a top-up's credit, whose target a LOST dispute lowers by its
// amount (reconcileTopupCredit).
//
// An open dispute (needs_response, under_review) lowers nothing yet, although
// the provider has already withdrawn the disputed amount: most disputes are
// won. The credit stays spendable until the dispute is lost; whatever is spent
// by then is owed. An inquiry (warning_*) withdraws nothing.
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
	if err := h.recordDispute(ctx, ev, payment); err != nil {
		return err
	}
	return reconcileTopupCredit(ctx, h, payment)
}

// recordDispute writes the dispute's status, creating its row the first time,
// then announces it closed if it is (announceDisputeClosed). The announcement
// runs after every write, stale ones included: one that failed is retried by
// the provider's redelivery, whose own status write then changes nothing.
func (h *PaymentServiceHandler) recordDispute(ctx context.Context, ev stripe.Event, payment *pb.Payment) error {
	if err := h.writeDispute(ctx, ev, payment); err != nil {
		return err
	}
	return h.announceDisputeClosed(ctx, ev.ObjectID)
}

// announceDisputeClosed emits DisputeClosed for a dispute that is WON or LOST
// and not yet announced (MarkDisputeClosed). Zero rows — still open, or
// announced already — is done.
func (h *PaymentServiceHandler) announceDisputeClosed(ctx context.Context, providerDisputeID string) error {
	_, err := h.Mutation.MarkDisputeClosed(ctx, &pb.MarkDisputeClosedReq{ProviderDisputeId: providerDisputeID})
	if guardRefused(err) {
		return nil
	}
	return err
}

// writeDispute writes the dispute's status, creating its row the first time.
func (h *PaymentServiceHandler) writeDispute(ctx context.Context, ev stripe.Event, payment *pb.Payment) error {
	amount, currency := ev.Amount.Amount, ev.Amount.Currency
	if amount == "" {
		amount, currency = payment.GetAmount(), payment.GetCurrency()
	}
	outcome := mapDisputeStatus(ev.ObjectStatus)
	mark := func() error {
		_, err := h.Mutation.MarkDisputeStatus(ctx, &pb.MarkDisputeStatusReq{
			ProviderDisputeId: ev.ObjectID,
			Status:            int32(outcome),
			ProviderEventAt:   eventTime(ev.Created),
		})
		return err
	}
	err := mark()
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
	case pb.Payment_REFUNDED, pb.Payment_CANCELED, pb.Payment_AMOUNT_MISMATCH:
		// A held payment never reads REFUNDED: its refunds are recorded and
		// it stays held, so there is nothing for a redelivery to wait for.
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"charge.refunded for %q before its success landed locally; redeliver", providerPaymentID)
}

// holdAmountMismatch checks a succeeded payment's received amount and
// currency against its local row, before anything trusts the success. A
// payment that took something else — its intent was changed at the provider
// by something other than this plugin — is held at AMOUNT_MISMATCH
// (MarkPaymentAmountMismatch, which emits PaymentAmountMismatch) instead of
// SUCCEEDED: no PaymentSucceeded, and no top-up credit for money that did not
// arrive. held reports that it was, or already is, held.
//
// What was received comes from the signed event (amount_received); an event
// without it is read from the provider (GetPayment). A payment with no local
// row, or past the point a success could move it, is left to the success path
// and its guards as before.
func (h *PaymentServiceHandler) holdAmountMismatch(ctx context.Context, ev stripe.Event) (held bool, err error) {
	local, err := h.paymentByProviderID(ctx, ev.PaymentIntentID)
	if err != nil || local == nil {
		return false, err
	}
	switch local.GetStatus() {
	case pb.Payment_AMOUNT_MISMATCH:
		return true, nil
	case pb.Payment_SUCCEEDED, pb.Payment_CANCELED, pb.Payment_REFUNDED:
		return false, nil
	}
	received := ev.Received
	if received.Currency == "" {
		obj, err := h.Backend.GetPayment(ctx, ev.PaymentIntentID)
		if err != nil {
			return false, providerFailure(err)
		}
		received = obj.Received
	}
	if received.Currency == "" {
		return false, status.Errorf(codes.FailedPrecondition,
			"payment %s: the provider reported no received amount to check the success against; redeliver", ev.PaymentIntentID)
	}
	if strings.EqualFold(received.Currency, local.GetCurrency()) && sameDecimal(received.Amount, local.GetAmount()) {
		return false, nil
	}
	slog.Warn("payment: a payment succeeded for another amount than was asked; held",
		"payment_id", local.GetId(), "amount", local.GetAmount(), "currency", local.GetCurrency(),
		"received_amount", received.Amount, "received_currency", received.Currency)
	_, err = h.Mutation.MarkPaymentAmountMismatch(ctx, &pb.MarkPaymentAmountMismatchReq{
		ProviderPaymentId: ev.PaymentIntentID,
		ReceivedAmount:    received.Amount,
		ReceivedCurrency:  strings.ToLower(received.Currency),
	})
	if guardRefused(err) {
		return true, nil // a concurrent delivery held it, or another write moved it first
	}
	return err == nil, err
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

func init() {
	webhooksStaged = true
	lostDisputeTotal = func(ctx context.Context, h *PaymentServiceHandler, payment *pb.Payment) (string, error) {
		got, err := h.Query.SumLostDisputesForPayment(ctx, &pb.SumLostDisputesForPaymentReq{PaymentId: payment.GetId()})
		if err != nil {
			return "", err
		}
		return got.GetTotal(), nil
	}
}
