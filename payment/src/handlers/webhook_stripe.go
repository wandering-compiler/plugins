package handlers

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
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
// Ordering matters (Q43-pay-1): the idempotent side effects run FIRST and
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

	// Dedup ledger, written LAST (Q43-pay-1): a unique-PK violation ⇒ this
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
			// Already in a state the guard protects, or absent.
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
			// Already FAILED (redelivery) or SUCCEEDED (a late failure of
			// an earlier attempt — SUCCEEDED is absorbing), or absent.
			err = h.requirePayment(ctx, ev)
		}
		return err
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
// errNoLocalRecord when the object is this plugin's and its row has not
// landed yet; nil — acknowledged — when the object is not this plugin's at
// all. The provider sends events for objects the plugin never made (a
// subscription's invoice payments, dashboard charges, another app on the
// account); failing those would have them redelivered for days.
func (h *PaymentServiceHandler) requirePayment(ctx context.Context, ev stripe.Event) error {
	got, err := h.Query.GetPaymentByProviderId(ctx, &pb.GetPaymentByProviderIdReq{ProviderPaymentId: ev.PaymentIntentID})
	if err != nil && !absent(err) {
		return err
	}
	if got.GetPayment() != nil || ev.Origin == "" {
		return nil
	}
	return errNoLocalRecord
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
