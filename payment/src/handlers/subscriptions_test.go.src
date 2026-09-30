package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

func subHandler(q *fakeQuery, m *fakeMutation, be *fakeBackend) *PaymentServiceHandler {
	return &PaymentServiceHandler{Query: q, Mutation: m, Backend: be}
}

func TestCreatePlan(t *testing.T) {
	be := &fakeBackend{priceID: "price_123"}
	m := &fakeMutation{}
	h := subHandler(&fakeQuery{plan: nil}, m, be) // not yet existing
	view, err := h.CreatePlan(context.Background(), &pb.DefinePlanReq{
		Slug: "pro", Name: "Pro", Amount: "29.00", Currency: "USD", Interval: "month",
	})
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if be.lastPlan.Slug != "pro" || be.lastPlan.Amount.Currency != "usd" {
		t.Errorf("pushed plan = %+v", be.lastPlan)
	}
	if m.lastCreatePlan.GetProviderPriceId() != "price_123" {
		t.Errorf("persisted price id = %q", m.lastCreatePlan.GetProviderPriceId())
	}
	if view.GetPlan().GetSlug() != "pro" {
		t.Errorf("plan slug = %q", view.GetPlan().GetSlug())
	}
}

func TestCreatePlan_IdempotentReturnsExisting(t *testing.T) {
	be := &fakeBackend{priceID: "price_should_not_be_used"}
	q := &fakeQuery{plan: &pb.Plan{Id: "plan-9", Slug: "pro", ProviderPriceId: "price_old"}}
	h := subHandler(q, &fakeMutation{}, be)
	view, err := h.CreatePlan(context.Background(), &pb.DefinePlanReq{Slug: "pro", Amount: "1", Currency: "usd", Interval: "month"})
	if err != nil {
		t.Fatalf("CreatePlan: %v", err)
	}
	if view.GetPlan().GetId() != "plan-9" {
		t.Errorf("should return existing plan, got %q", view.GetPlan().GetId())
	}
	if be.lastPlan.Slug != "" {
		t.Error("must NOT push to provider when plan already exists")
	}
}

func TestCreatePlan_ValidatesInterval(t *testing.T) {
	h := subHandler(&fakeQuery{}, &fakeMutation{}, &fakeBackend{})
	_, err := h.CreatePlan(context.Background(), &pb.DefinePlanReq{Slug: "x", Amount: "1", Currency: "usd", Interval: "week"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for bad interval, got %v", err)
	}
}

// Q45-pay-3: a non-positive plan amount must be rejected BEFORE the backend
// is called — a negative unit price reaches the provider and every future
// subscription on the plan credits the customer instead of charging them.
func TestCreatePlan_RejectsNonPositiveAmount(t *testing.T) {
	for _, amt := range []string{"-29.00", "0", "0.00", "abc"} {
		be := &fakeBackend{priceID: "price_x"}
		h := subHandler(&fakeQuery{plan: nil}, &fakeMutation{}, be)
		_, err := h.CreatePlan(context.Background(), &pb.DefinePlanReq{Slug: "pro", Amount: amt, Currency: "usd", Interval: "month"})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("amount %q: want InvalidArgument, got %v", amt, err)
		}
		if be.lastPlan.Slug != "" {
			t.Errorf("amount %q: backend must NOT be pushed (got %+v)", amt, be.lastPlan)
		}
	}
}

func TestSubscribe(t *testing.T) {
	be := &fakeBackend{subRes: backend.SubscriptionResult{ProviderSubscriptionID: "sub_x", Status: "active", CurrentPeriodEnd: 1893456000}}
	m := &fakeMutation{}
	q := &fakeQuery{
		plan:     &pb.Plan{Id: "plan-1", Slug: "pro", ProviderPriceId: "price_1"},
		customer: &pb.Customer{Id: "cust-1", ProviderCustomerId: "cus_1"},
	}
	h := subHandler(q, m, be)

	view, err := h.Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "pro", IdempotencyKey: "sub-key-1"})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if be.lastSub.ProviderPriceID != "price_1" || be.lastSub.ProviderCustomerID != "cus_1" {
		t.Errorf("started sub = %+v", be.lastSub)
	}
	if be.lastSub.IdempotencyKey != "sub-key-1" {
		t.Errorf("provider idempotency key = %q, want the caller-supplied sub-key-1", be.lastSub.IdempotencyKey)
	}
	if m.lastCreateSub.GetStatus() != int32(pb.Subscription_ACTIVE) {
		t.Errorf("status = %d, want ACTIVE", m.lastCreateSub.GetStatus())
	}
	if m.lastCreateSub.GetCurrentPeriodEnd() == nil {
		t.Error("current_period_end not set from provider unix ts")
	}
	if view.GetSubscription().GetProviderSubscriptionId() != "sub_x" {
		t.Errorf("provider sub id = %q", view.GetSubscription().GetProviderSubscriptionId())
	}
}

func TestSubscribe_PlanNotFound(t *testing.T) {
	h := subHandler(&fakeQuery{plan: nil}, &fakeMutation{}, &fakeBackend{})
	_, err := h.Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "ghost", IdempotencyKey: "k"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestSubscribe_PlanWithoutProviderPrice(t *testing.T) {
	q := &fakeQuery{plan: &pb.Plan{Id: "p", Slug: "pro"}} // no provider_price_id
	_, err := subHandler(q, &fakeMutation{}, &fakeBackend{}).Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "pro", IdempotencyKey: "k"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument (no provider price), got %v", err)
	}
}

// Q45-pay-2: Subscribe must carry a caller-supplied idempotency key — the
// handler can no longer derive one from (user_id, plan_slug). That derived
// key collided a re-subscribe-after-cancel onto the original (now canceled)
// subscription via the provider's idempotency replay, silently leaving the
// user unsubscribed (no recurring charge, no active sub).
func TestSubscribe_RequiresIdempotencyKey(t *testing.T) {
	q := &fakeQuery{
		plan:     &pb.Plan{Id: "plan-1", Slug: "pro", ProviderPriceId: "price_1"},
		customer: &pb.Customer{Id: "cust-1", ProviderCustomerId: "cus_1"},
	}
	_, err := subHandler(q, &fakeMutation{}, &fakeBackend{}).Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "pro"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for a missing idempotency_key, got %v", err)
	}
}

// Q45-pay-2: two subscribe calls for the same (user, plan) with DISTINCT
// caller keys must reach the provider as DISTINCT Idempotency-Keys — the old
// derived "sub:<user>:<slug>" key collapsed a re-subscribe onto the first
// (canceled) subscription. The handler must forward the caller key verbatim.
func TestSubscribe_DistinctKeysNotCollapsed(t *testing.T) {
	q := &fakeQuery{
		plan:     &pb.Plan{Id: "plan-1", Slug: "pro", ProviderPriceId: "price_1"},
		customer: &pb.Customer{Id: "cust-1", ProviderCustomerId: "cus_1"},
	}
	be := &fakeBackend{subRes: backend.SubscriptionResult{ProviderSubscriptionID: "sub_a", Status: "active"}}
	h := subHandler(q, &fakeMutation{}, be)

	if _, err := h.Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "pro", IdempotencyKey: "subscribe-A"}); err != nil {
		t.Fatalf("first subscribe: %v", err)
	}
	firstKey := be.lastSub.IdempotencyKey
	if _, err := h.Subscribe(context.Background(), &pb.SubscribeReq{UserId: "u1", PlanSlug: "pro", IdempotencyKey: "subscribe-B"}); err != nil {
		t.Fatalf("second subscribe: %v", err)
	}
	if firstKey == be.lastSub.IdempotencyKey {
		t.Fatalf("two subscribes collapsed to one provider key %q — a re-subscribe would replay the canceled sub", be.lastSub.IdempotencyKey)
	}
	if firstKey != "subscribe-A" || be.lastSub.IdempotencyKey != "subscribe-B" {
		t.Errorf("provider keys = (%q, %q), want (subscribe-A, subscribe-B)", firstKey, be.lastSub.IdempotencyKey)
	}
}

// Note: reading a subscription is now a direct storage query
// (PaymentQuery.GetSubscription via REST preset) — no business handler.
