package handlers

import (
	"context"
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
// successful return, does not publish a second PaymentSucceeded. What
// used to be "an idempotent write" was only idempotent in the database;
// the EVENT was not.
//
// A guard that matched zero rows arrives here as NotFound, and it is
// ambiguous:
//
//   - the row is already in the target state — a redelivery, or an
//     out-of-order duplicate. Nothing to do; the provider must be told
//     to stop.
//   - there is no such provider id here YET. That is a real race:
//     TopUpCredit calls the provider before its own CreatePayment INSERT
//     (prepaid.go), so a fast webhook can outrun the local row. This one
//     must fail so the provider redelivers, or the reconciliation is
//     lost for good.
//
// The dedup ledger discriminates them, which is the one thing it can
// still do from last position: a unique violation means this exact event
// id was fully processed before, so the first reading holds; a clean
// insert means it was not, so the second does. Writing that ledger row
// on the failing branch does not re-create the stranding Q43-pay-1
// removed — stranding needed a read-first short-circuit, and there is
// none: the redelivery re-runs the whole chain either way.
func (h *PaymentServiceHandler) IngestStripe(ctx context.Context, req *pb.IngestStripeReq) (*pb.IngestStripeResp, error) {
	sig := metadataValue(ctx, stripeSignatureMetadataKey)
	ev, err := stripe.VerifyAndParse(req.GetRawPayload(), sig, h.WebhookSecret)
	if err != nil {
		// Opaque: a forged / malformed webhook gets the same answer.
		return nil, status.Error(codes.Unauthenticated, "invalid webhook signature")
	}

	applied, err := h.reconcile(ctx, ev)
	if err != nil {
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
			// Seen before ⇒ a zero-row guard above was a redelivery.
			return &pb.IngestStripeResp{Handled: false, EventId: ev.ID, EventType: ev.Type}, nil
		}
		return nil, err
	}
	if !applied {
		// First sighting of this event id, yet the guard matched nothing
		// ⇒ the provider object has no local row here yet. Fail so the
		// provider redelivers once the local INSERT has landed.
		return nil, status.Errorf(codes.NotFound,
			"webhook %s: no local record for provider object %q", ev.Type, ev.ObjectID)
	}

	return &pb.IngestStripeResp{Handled: true, EventId: ev.ID, EventType: ev.Type}, nil
}

// reconcile dispatches one verified event onto the reconciliation
// mutations. It reports whether the event actually moved local state:
// false means a transition-guarded statement matched no row (see
// IngestStripe for how that is disambiguated). Any other error is
// returned verbatim — a transient failure must NOT reach the dedup
// ledger.
func (h *PaymentServiceHandler) reconcile(ctx context.Context, ev stripe.Event) (bool, error) {
	switch {
	case ev.Type == "payment_intent.succeeded":
		_, err := h.Mutation.MarkPaymentSucceeded(ctx, &pb.MarkPaymentSucceededReq{
			ProviderPaymentId: ev.PaymentIntentID,
		})
		if guardRefused(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		// Cross-feature: grant credit if this payment was a top-up
		// (prepaid feature; no-op when prepaid is off — hook is nil).
		// Reached only on a real transition, so a redelivery cannot
		// re-run it.
		if onPaymentSucceededWebhook != nil {
			if err := onPaymentSucceededWebhook(ctx, h, ev); err != nil {
				return false, err
			}
		}
	case ev.Type == "payment_intent.payment_failed":
		_, err := h.Mutation.MarkPaymentFailed(ctx, &pb.MarkPaymentFailedReq{
			ProviderPaymentId: ev.PaymentIntentID,
		})
		if guardRefused(err) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	case strings.HasPrefix(ev.Type, "customer.subscription."):
		// Cross-feature: reconcile subscription lifecycle (subscriptions
		// feature; no-op when off — hook is nil).
		if onSubscriptionWebhook != nil {
			err := onSubscriptionWebhook(ctx, h, ev)
			if guardRefused(err) {
				return false, nil
			}
			if err != nil {
				return false, err
			}
		}
		// Other event types are acknowledged (recorded in the dedup
		// ledger) but need no state change.
	}
	return true, nil
}

// guardRefused reports whether err is the shape a transition-guarded
// statement produces when its WHERE matched no row: the generated
// single-row RETURNING scan gets sql.ErrNoRows and grpcerr.Wrap maps it
// to NotFound.
func guardRefused(err error) bool {
	return err != nil && status.Code(err) == codes.NotFound
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
