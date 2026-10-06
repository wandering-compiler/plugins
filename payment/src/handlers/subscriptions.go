package handlers

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
	"github.com/wandering-compiler/platform/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// init wires the subscription webhook reconciler. Present only when the
// subscriptions feature is staged, so the webhook handler dispatches
// customer.subscription.* events here only when the feature is on.
func init() {
	onSubscriptionWebhook = reconcileSubscriptionWebhook
}

// reconcileSubscriptionWebhook maps a provider customer.subscription.*
// event onto the local Subscription via MarkSubscriptionStatus (which
// emits SubscriptionStatusChanged). The provider is authoritative for
// lifecycle status.
func reconcileSubscriptionWebhook(ctx context.Context, h *PaymentServiceHandler, ev stripe.Event) error {
	if ev.ObjectID == "" {
		return nil
	}
	_, err := h.Mutation.MarkSubscriptionStatus(ctx, &pb.MarkSubscriptionStatusReq{
		ProviderSubscriptionId: ev.ObjectID,
		Status:                 int32(mapSubscriptionStatus(ev.ObjectStatus)),
		CurrentPeriodEnd:       unixToTimestamp(ev.CurrentPeriodEnd),
		ProviderEventAt:        eventTime(ev.Created),
	})
	if !guardRefused(err) {
		return err
	}
	// The guard matched nothing: the subscription is already CANCELED (a
	// late update after the deletion) or holds a NEWER event than this
	// one (out-of-order delivery) — acknowledge either —
	// or it has no local row yet, which must fail unrecorded so the
	// provider redelivers (see IngestStripe).
	got, lerr := h.Query.GetSubscriptionByProviderId(ctx, &pb.GetSubscriptionByProviderIdReq{ProviderSubscriptionId: ev.ObjectID})
	if lerr != nil && !guardRefused(lerr) {
		return lerr
	}
	if got.GetSubscription() == nil && ev.Origin != "" {
		// This plugin's subscription, its row not landed yet. One it did not
		// create (no origin mark) has no row and never will: acknowledged.
		return errNoLocalRecord
	}
	return nil
}

// CreatePlan defines a plan locally and pushes its price to the
// provider. Idempotent on slug: an existing plan with the SAME terms is
// returned without a second provider price (the local Plan is the dedup
// anchor). An existing plan with different terms is AlreadyExists — it
// used to be returned as if created, so a caller defining "pro" at 99
// got the old 29 plan back with no error and every subscriber was
// charged the old price.
func (h *PaymentServiceHandler) CreatePlan(ctx context.Context, req *pb.DefinePlanReq) (*pb.PlanView, error) {
	slug := strings.TrimSpace(req.GetSlug())
	if slug == "" {
		return nil, invalidArg("slug is required")
	}
	amount := strings.TrimSpace(req.GetAmount())
	currency := strings.ToLower(strings.TrimSpace(req.GetCurrency()))
	if amount == "" || currency == "" {
		return nil, invalidArg("amount and currency are required")
	}
	// Q45-pay-3: reject a non-positive amount before the provider call — a
	// negative unit price reaches the provider and every future subscription
	// on the plan credits the customer instead of charging them.
	if !isPositiveDecimal(amount) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	if !isCurrencyCode(currency) {
		return nil, invalidArg("currency must be a 3-letter ISO-4217 code")
	}
	if req.GetInterval() != "month" && req.GetInterval() != "year" {
		return nil, invalidArg(`interval must be "month" or "year"`)
	}
	sameTerms := func(p *pb.Plan) (*pb.PlanView, error) {
		if sameDecimal(p.GetAmount(), amount) && p.GetCurrency() == currency && p.GetInterval() == req.GetInterval() {
			return &pb.PlanView{Plan: p}, nil
		}
		return nil, status.Error(codes.AlreadyExists, "a plan with this slug already exists with different terms")
	}

	// Idempotent: if the plan already exists, return it (no second push).
	if existing, err := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug}); err != nil && !absent(err) {
		return nil, err
	} else if existing.GetPlan() != nil {
		return sameTerms(existing.GetPlan())
	}

	priceID, err := h.Backend.UpsertPlan(ctx, backend.PlanSpec{
		Slug:     slug,
		Name:     orDefault(req.GetName(), slug),
		Amount:   backend.Money{Amount: amount, Currency: currency},
		Interval: req.GetInterval(),
	})
	if err != nil {
		return nil, providerFailure(err)
	}

	created, err := h.Mutation.CreatePlan(ctx, &pb.CreatePlanReq{
		Slug:            slug,
		Name:            orDefault(req.GetName(), slug),
		Amount:          amount,
		Currency:        currency,
		Interval:        req.GetInterval(),
		ProviderPriceId: priceID,
	})
	if err != nil {
		// Lost a race — another CreatePlan inserted the slug first.
		if constraintCode(err) == codeUniqueViolation {
			existing, gerr := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug})
			if gerr == nil && existing.GetPlan() != nil {
				return sameTerms(existing.GetPlan())
			}
		}
		return nil, err
	}
	return &pb.PlanView{Plan: created.GetPlan()}, nil
}

// sameDecimal compares two non-negative decimal strings by value, so the
// DECIMAL(20, 4) column's "29.0000" equals a request's "29" / "29.00".
func sameDecimal(a, b string) bool {
	norm := func(s string) string {
		i, f, _ := strings.Cut(strings.TrimSpace(s), ".")
		return strings.TrimLeft(i, "0") + "." + strings.TrimRight(f, "0")
	}
	return norm(a) == norm(b)
}

// Subscribe enrolls the principal's customer on a plan via the provider,
// then persists the local Subscription. The provider customer is
// ensured first (reusing the core resolveCustomer path).
func (h *PaymentServiceHandler) Subscribe(ctx context.Context, req *pb.SubscribeReq) (*pb.SubscriptionView, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	slug := strings.TrimSpace(req.GetPlanSlug())
	if slug == "" {
		return nil, invalidArg("plan_slug is required")
	}
	// Q45-pay-2: the idempotency key IS the provider Idempotency-Key for
	// StartSubscription, so it must be unique per distinct subscribe and
	// stable across retries. Deriving it from (user_id, plan_slug) — as this
	// handler used to — collided a re-subscribe-after-cancel onto the first
	// (canceled) subscription via the provider's replay, silently leaving the
	// user unsubscribed. The caller owns it now (mirrors CreatePayment /
	// RefundPayment).
	if req.GetIdempotencyKey() == "" {
		return nil, invalidArg("idempotency_key is required (the subscribe must be idempotent; supply a unique key per distinct subscribe)")
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	planResp, err := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug})
	if err != nil && !absent(err) {
		return nil, err
	}
	plan := planResp.GetPlan()
	if plan == nil {
		return nil, notFound("plan not found")
	}
	if plan.GetProviderPriceId() == "" {
		return nil, invalidArg("plan has no provider price (not pushed to provider)")
	}

	cust, err := h.resolveCustomer(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}

	res, err := h.Backend.StartSubscription(ctx, backend.SubscriptionSpec{
		ProviderCustomerID: cust.GetProviderCustomerId(),
		ProviderPriceID:    plan.GetProviderPriceId(),
		IdempotencyKey:     req.GetIdempotencyKey(),
	})
	if err != nil {
		return nil, providerFailure(err)
	}

	created, err := h.Mutation.CreateSubscription(ctx, &pb.CreateSubscriptionReq{
		CustomerId:             cust.GetId(),
		PlanId:                 plan.GetId(),
		ProviderSubscriptionId: res.ProviderSubscriptionID,
		Status:                 int32(mapSubscriptionStatus(res.Status)),
		CurrentPeriodEnd:       unixToTimestamp(res.CurrentPeriodEnd),
	})
	if err != nil {
		// A retried subscribe (same key) gets the same provider
		// subscription replayed, and its local row already exists: that
		// row is the answer — only when it is this customer's.
		if constraintCode(err) == codeUniqueViolation {
			got, gerr := h.Query.GetSubscriptionByProviderId(ctx, &pb.GetSubscriptionByProviderIdReq{ProviderSubscriptionId: res.ProviderSubscriptionID})
			if gerr != nil && !absent(gerr) {
				return nil, gerr
			}
			if sub := got.GetSubscription(); sub != nil && sub.GetCustomerId() == cust.GetId() {
				return &pb.SubscriptionView{Subscription: sub}, nil
			}
			return nil, status.Error(codes.AlreadyExists, "idempotency_key already used for a different subscription")
		}
		return nil, err
	}
	return &pb.SubscriptionView{Subscription: created.GetSubscription()}, nil
}

// mapSubscriptionStatus maps the provider status string onto the local
// Subscription.Status enum. Unknown → ACTIVE (the subscription was
// created; a webhook reconciles the precise terminal state).
func mapSubscriptionStatus(providerStatus string) pb.Subscription_Status {
	switch providerStatus {
	case "trialing":
		return pb.Subscription_TRIALING
	case "active":
		return pb.Subscription_ACTIVE
	case "past_due", "unpaid":
		return pb.Subscription_PAST_DUE
	case "canceled", "incomplete_expired":
		return pb.Subscription_CANCELED
	default:
		return pb.Subscription_ACTIVE
	}
}

// unixToTimestamp converts provider Unix seconds to a proto timestamp
// (nil when the provider supplied none).
func unixToTimestamp(sec int64) *timestamppb.Timestamp {
	if sec <= 0 {
		return nil
	}
	return timestamppb.New(time.Unix(sec, 0).UTC())
}

// eventTime is the provider's creation time of an event — its order, which
// delivery order is not. An event without one (the provider always sends it)
// counts as now.
func eventTime(unix int64) *timestamppb.Timestamp {
	if unix <= 0 {
		return timestamppb.Now()
	}
	return timestamppb.New(time.Unix(unix, 0))
}
