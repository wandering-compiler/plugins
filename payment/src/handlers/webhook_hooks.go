package handlers

import (
	"context"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
	"github.com/wandering-compiler/platform/plugins/payment/lib/backend/stripe"
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
	id := h.installID()
	return ev.Origin != "" && id != "" && ev.Install == id
}
