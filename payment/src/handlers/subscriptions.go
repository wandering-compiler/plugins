package handlers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// init wires the subscription webhook reconciler. Present only when the
// subscriptions feature is staged, so the webhook handler dispatches
// customer.subscription.* events here only when the feature is on.
func init() {
	onSubscriptionWebhook = reconcileSubscriptionWebhook
	reconcileSubscription = reconcileProviderSubscription
}

// reconcileProviderSubscription is the provider reconciliation of one
// subscription (see ReconcileProvider). One this installation did not start
// is foreign. One without a local row gets it, the way Subscribe writes it
// (CreateSubscription, which emits SubscriptionStarted), in the provider's
// current status. One whose row lags takes the provider's status the way
// the webhook gives it (MarkSubscriptionStatus, which emits
// SubscriptionStatusChanged).
//
// Both writes carry the time of the read as the provider event time, so the
// webhook's out-of-order guard holds across the two writers: an event created
// before the read (a redelivery still in flight) cannot put an older status
// back, and one created after it applies. The time is the PROVIDER's
// (sub.ReadAt, its answer's Date), the clock it stamps its events with: a
// local clock running ahead would refuse every newer event until the next
// run. A row that already holds a newer event, or is CANCELED, refuses the
// update: in sync.
func reconcileProviderSubscription(ctx context.Context, h *PaymentServiceHandler, sub backend.SubscriptionObject) (reconcileOutcome, error) {
	if sub.Origin != backend.OriginSubscription || !h.markedHere(sub.Marks) {
		return reconcileForeign, nil
	}
	st := mapSubscriptionStatus(sub.Status)
	end := unixToTimestamp(sub.CurrentPeriodEnd)
	var at *timestamppb.Timestamp // NULL without the provider's time: the next event wins
	if sub.ReadAt > 0 {
		at = timestamppb.New(time.Unix(sub.ReadAt, 0))
	}
	row, err := h.subscriptionByProviderID(ctx, sub.ProviderSubscriptionID)
	if err != nil {
		return reconcileFailed, err
	}
	if row == nil {
		cust, err := h.customerByProviderID(ctx, sub.ProviderCustomerID)
		if err != nil {
			return reconcileFailed, err
		}
		if cust == nil {
			return reconcileFailed, fmt.Errorf("subscription %s: no local customer for %s", sub.ProviderSubscriptionID, sub.ProviderCustomerID)
		}
		plan, err := h.Query.GetPlanByProviderPriceId(ctx, &pb.GetPlanByProviderPriceIdReq{ProviderPriceId: sub.ProviderPriceID})
		if err != nil && !absent(err) {
			return reconcileFailed, err
		}
		if plan.GetPlan() == nil {
			return reconcileFailed, fmt.Errorf("subscription %s: no local plan for price %s", sub.ProviderSubscriptionID, sub.ProviderPriceID)
		}
		_, err = h.Mutation.CreateSubscription(ctx, &pb.CreateSubscriptionReq{
			CustomerId:             cust.GetId(),
			PlanId:                 plan.GetPlan().GetId(),
			ProviderSubscriptionId: sub.ProviderSubscriptionID,
			Status:                 int32(st),
			CurrentPeriodEnd:       end,
			ProviderEventAt:        at,
		})
		if err == nil {
			return reconcileCreated, nil
		}
		if constraintCode(err) != codeUniqueViolation {
			return reconcileFailed, err
		}
		// Subscribe's retry or a concurrent run recorded it first: bring
		// that row up to date like any other.
		if row, err = h.subscriptionByProviderID(ctx, sub.ProviderSubscriptionID); err != nil {
			return reconcileFailed, err
		}
		if row == nil {
			return reconcileFailed, fmt.Errorf("subscription %s: the insert was refused and no row holds it", sub.ProviderSubscriptionID)
		}
	}
	if row.GetStatus() == st && sameInstant(row.GetCurrentPeriodEnd(), end) {
		return reconcileInSync, nil
	}
	if at == nil {
		// Unordered against the webhook's events, an update could put back
		// a status a newer event already replaced.
		return reconcileFailed, fmt.Errorf("subscription %s: the provider's answer carried no time to order the update by", sub.ProviderSubscriptionID)
	}
	_, err = h.Mutation.MarkSubscriptionStatus(ctx, &pb.MarkSubscriptionStatusReq{
		ProviderSubscriptionId: sub.ProviderSubscriptionID,
		Status:                 int32(st),
		CurrentPeriodEnd:       end,
		ProviderEventAt:        at,
	})
	switch {
	case err == nil:
		return reconcileUpdated, nil
	case guardRefused(err):
		return reconcileInSync, nil // CANCELED, or a newer event already applied
	}
	return reconcileFailed, err
}

// subscriptionByProviderID is the local subscription of a provider id, nil
// when there is none.
func (h *PaymentServiceHandler) subscriptionByProviderID(ctx context.Context, providerSubscriptionID string) (*pb.Subscription, error) {
	got, err := h.Query.GetSubscriptionByProviderId(ctx, &pb.GetSubscriptionByProviderIdReq{ProviderSubscriptionId: providerSubscriptionID})
	if err != nil && !absent(err) {
		return nil, err
	}
	return got.GetSubscription(), nil
}

// sameInstant reports whether two optional timestamps name the same second
// (both absent counts).
func sameInstant(a, b *timestamppb.Timestamp) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.AsTime().Unix() == b.AsTime().Unix()
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
	if got.GetSubscription() == nil && h.madeHere(ev) {
		// This installation's subscription, its row not landed yet. One it
		// did not create (no origin mark, or another installation's) has no
		// row and never will: acknowledged.
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
	// Reject a non-positive amount before the provider call — a
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

// Subscribe enrolls the principal's customer on a plan via the provider,
// then persists the local Subscription. The provider customer is
// ensured first (reusing the core resolveCustomer path).
func (h *PaymentServiceHandler) Subscribe(ctx context.Context, req *pb.SubscribeReq) (*pb.SubscriptionView, error) {
	// Through the gateway this acts for the signed-in caller only; see
	// actingFor.
	uid, err := actingFor(ctx, req.GetUserId())
	if err != nil {
		return nil, err
	}
	req.UserId = uid
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	slug := strings.TrimSpace(req.GetPlanSlug())
	if slug == "" {
		return nil, invalidArg("plan_slug is required")
	}
	// The idempotency key IS the provider Idempotency-Key for
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

	// The subscription keeps no key locally, so a retry after the provider
	// forgot the key (a day) would start a second one — even when the first
	// was recorded. The key in the subscription's metadata recognises it.
	res, found, err := h.Backend.FindSubscription(ctx, cust.GetProviderCustomerId(), req.GetIdempotencyKey())
	if err != nil {
		return nil, providerFailure(err)
	}
	if found && res.ProviderPriceID != plan.GetProviderPriceId() {
		// The key names a subscription to another plan, which the provider's
		// idempotency check would refuse too. Recording it would file that
		// subscription under this plan.
		return nil, status.Error(codes.AlreadyExists, "idempotency_key already used for a different subscription")
	}
	if !found {
		res, err = h.Backend.StartSubscription(ctx, backend.SubscriptionSpec{
			ProviderCustomerID: cust.GetProviderCustomerId(),
			ProviderPriceID:    plan.GetProviderPriceId(),
			IdempotencyKey:     req.GetIdempotencyKey(),
			Install:            h.installID(),
		})
		if err != nil {
			return nil, providerFailure(err)
		}
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
// Subscription.Status enum, one to one. Only TRIALING and ACTIVE mean
// "paid up".
//
// It used to round everything it did not name — incomplete, paused, any
// status the provider adds later — up to ACTIVE, so a subscription whose
// first payment had not gone through read as active, and a consumer
// granting access on ACTIVE gave it away. An unknown status is now
// UNRECOGNIZED_STATUS: not entitling, and storable (STATUS_UNSPECIFIED is
// not — the column's CHECK excludes the zero sentinel, so a webhook carrying
// it would fail on every redelivery).
func mapSubscriptionStatus(providerStatus string) pb.Subscription_Status {
	switch providerStatus {
	case "trialing":
		return pb.Subscription_TRIALING
	case "active":
		return pb.Subscription_ACTIVE
	case "incomplete":
		return pb.Subscription_INCOMPLETE
	case "past_due":
		return pb.Subscription_PAST_DUE
	case "unpaid":
		return pb.Subscription_UNPAID
	case "paused":
		return pb.Subscription_PAUSED
	case "canceled", "incomplete_expired": // both terminal at the provider
		return pb.Subscription_CANCELED
	default:
		return pb.Subscription_UNRECOGNIZED_STATUS
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

// GetMySubscription returns one of the caller's subscriptions. Another
// customer's subscription answers NotFound.
func (h *PaymentServiceHandler) GetMySubscription(ctx context.Context, req *pb.GetMySubscriptionReq) (*pb.GetSubscriptionResp, error) {
	customer, err := h.callerCustomerID(ctx)
	if err != nil {
		return nil, err
	}
	got, err := h.Query.GetSubscription(ctx, &pb.GetSubscriptionReq{Id: req.GetId()})
	if err := ownRow(err, got.GetSubscription().GetCustomerId(), customer); err != nil {
		return nil, err
	}
	return got, nil
}
