package handlers

import (
	"context"
	"strings"
	"time"

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
	})
	return err
}

// CreatePlan defines a plan locally and pushes its price to the
// provider. Idempotent on slug: an existing plan is returned without a
// second provider price (the local Plan is the dedup anchor).
func (h *PaymentServiceHandler) CreatePlan(ctx context.Context, req *pb.DefinePlanReq) (*pb.PlanView, error) {
	slug := strings.TrimSpace(req.GetSlug())
	if slug == "" {
		return nil, invalidArg("slug is required")
	}
	if strings.TrimSpace(req.GetAmount()) == "" || strings.TrimSpace(req.GetCurrency()) == "" {
		return nil, invalidArg("amount and currency are required")
	}
	// Q45-pay-3: reject a non-positive amount before the provider call — a
	// negative unit price reaches the provider and every future subscription
	// on the plan credits the customer instead of charging them.
	if !isPositiveDecimal(req.GetAmount()) {
		return nil, invalidArg("amount must be a positive decimal")
	}
	if req.GetInterval() != "month" && req.GetInterval() != "year" {
		return nil, invalidArg(`interval must be "month" or "year"`)
	}

	// Idempotent: if the plan already exists, return it (no second push).
	if existing, err := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug}); err != nil {
		return nil, err
	} else if existing.GetPlan() != nil {
		return &pb.PlanView{Plan: existing.GetPlan()}, nil
	}

	priceID, err := h.Backend.UpsertPlan(ctx, backend.PlanSpec{
		Slug:     slug,
		Name:     orDefault(req.GetName(), slug),
		Amount:   backend.Money{Amount: req.GetAmount(), Currency: strings.ToLower(req.GetCurrency())},
		Interval: req.GetInterval(),
	})
	if err != nil {
		return nil, providerFailure(err)
	}

	created, err := h.Mutation.CreatePlan(ctx, &pb.CreatePlanReq{
		Slug:            slug,
		Name:            orDefault(req.GetName(), slug),
		Amount:          req.GetAmount(),
		Currency:        strings.ToLower(req.GetCurrency()),
		Interval:        req.GetInterval(),
		ProviderPriceId: priceID,
	})
	if err != nil {
		// Lost a race — another CreatePlan inserted the slug first.
		if constraintCode(err) == codeUniqueViolation {
			existing, gerr := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug})
			if gerr == nil && existing.GetPlan() != nil {
				return &pb.PlanView{Plan: existing.GetPlan()}, nil
			}
		}
		return nil, err
	}
	return &pb.PlanView{Plan: created.GetPlan()}, nil
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

	planResp, err := h.Query.GetPlanBySlug(ctx, &pb.GetPlanBySlugReq{Slug: slug})
	if err != nil {
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
