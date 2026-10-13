package handlers

import (
	"context"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// Cross-feature webhook hooks. The webhook ingestion handler
// (stripe_webhooks-gated) calls these AFTER it verifies + dedups an
// event; feature-gated files populate them in init() (subscriptions.go,
// prepaid.go). They are declared here in an ALWAYS-STAGED file so a
// feature can register its hook regardless of whether the webhook
// surface is also enabled — and so the webhook handler can call through
// a nil-checked pointer with no compile-time coupling to features that
// may be absent. This is the same hook pattern the auth plugin uses for
// its sign_in × two_factor / devices interactions.
type webhookHook func(ctx context.Context, h *PaymentServiceHandler, ev stripe.Event) error

var (
	// onSubscriptionWebhook — set by subscriptions.go; reconciles a
	// Subscription's status from a customer.subscription.* event.
	onSubscriptionWebhook webhookHook

	// onPaymentSucceededWebhook — set by prepaid.go; grants credit when a
	// succeeded payment_intent is a recorded top-up.
	onPaymentSucceededWebhook webhookHook
)

// installID is this installation's identity, written on every provider
// object it creates (backend.InstallID of the webhook signing secret).
func (h *PaymentServiceHandler) installID() string {
	return backend.InstallID(h.WebhookSecret)
}

// madeHere reports whether the event's object was created by THIS
// installation: it carries the origin mark and this installation's id. Only
// such an object is worth failing (so the provider redelivers) while its
// local row has not landed. Everything else — unmarked objects, and objects
// another installation sharing the provider account created — has no local
// row and never will, and is acknowledged. Here (always staged) because the
// core webhook and both feature hooks read it.
func (h *PaymentServiceHandler) madeHere(ev stripe.Event) bool {
	return h.markedHere(backend.Marks{Origin: ev.Origin, Install: ev.Install})
}

// markedHere reports whether an object's marks say THIS installation created
// it (see madeHere). The provider reconciliation reads it too.
func (h *PaymentServiceHandler) markedHere(m backend.Marks) bool {
	id := h.installID()
	return m.Origin != "" && id != "" && m.Install == id
}

// ── provider reconciliation hooks ───────────────────────────────────
//
// ReconcileProvider (handlers/reconcile_provider.go, staged with
// stripe_webhooks) reaches the feature-owned records through these, set in
// init() by the feature's own file; nil (or the base value) when the
// feature is off. Declared here, in an always-staged file, for the reason
// the webhook hooks above are.

// reconcileOutcome is what the provider reconciliation did with one provider
// object; ReconcileCounts has a counter for each.
type reconcileOutcome int

const (
	reconcileInSync reconcileOutcome = iota
	reconcileCreated
	reconcileUpdated
	reconcileForeign
	reconcileSuperseded
	reconcileFailed
)

var (
	// reconcileSubscription — set by subscriptions.go; records one provider
	// subscription (a local row for an orphan, the status of a lagging one).
	// readAt is when the provider was read: a webhook event older than it
	// must not overwrite what the read recorded.
	reconcileSubscription func(ctx context.Context, h *PaymentServiceHandler, sub backend.SubscriptionObject, readAt time.Time) (reconcileOutcome, error)

	// ensureTopupRecord — set by prepaid.go; records the CreditTopup of a
	// top-up payment whose row never landed (TopUpCredit writes the Payment
	// first and the CreditTopup second, and a failure between them leaves the
	// charge without its credit record). Idempotent.
	ensureTopupRecord func(ctx context.Context, h *PaymentServiceHandler, payment *pb.Payment, userID string) error

	// topupState — set by prepaid.go; a fingerprint of a top-up's credit
	// record ("" when the payment is no top-up), so the reconciliation can
	// tell whether its pass changed it.
	topupState = func(ctx context.Context, h *PaymentServiceHandler, providerPaymentID string) (string, error) {
		return "", nil
	}
)

// eventTime is the provider's creation time of an event — its order, which
// delivery order is not. An event without one (the provider always sends it)
// counts as now. Here (always staged): the core webhook (disputes) and the
// subscriptions hook read it.
func eventTime(unix int64) *timestamppb.Timestamp {
	if unix <= 0 {
		return timestamppb.Now()
	}
	return timestamppb.New(time.Unix(unix, 0))
}
