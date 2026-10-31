package handlers

import (
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// Subscribe starts a subscription that waits for its first payment, hands the
// client that payment, and allows one open subscription per (principal,
// plan).

func subRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t)
	for _, slug := range []string{"pro", "team"} {
		if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: slug, Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func subscribe(r *rig, plan, key string) (*pb.SubscriptionView, error) {
	return r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: plan, IdempotencyKey: key})
}

func (r *rig) setLocalSubStatus(providerID string, st pb.Subscription_Status) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	for _, s := range r.store.subs {
		if s.GetProviderSubscriptionId() == providerID {
			s.Status = st
		}
	}
}

// The first payment waits for the client, which gets its client secret; the
// card it is paid with pays the renewals. The create pins the API version
// the client secret is read under.
func TestSubscribe_TheFirstPaymentIsTheClients(t *testing.T) {
	r := subRig(t)
	v, err := subscribe(r, "pro", "k1")
	if err != nil {
		t.Fatal(err)
	}
	sub := v.GetSubscription()
	if sub.GetStatus() != pb.Subscription_INCOMPLETE || v.GetClientSecret() != "pi_"+sub.GetProviderSubscriptionId()+"_secret" {
		t.Errorf("subscribe = %v with secret %q, want INCOMPLETE with its first payment's secret", sub.GetStatus(), v.GetClientSecret())
	}
	form := r.stripe.subForms[0]
	for k, want := range map[string]string{
		"payment_behavior": "default_incomplete",
		"payment_settings[save_default_payment_method]": "on_subscription",
		"expand[]": "latest_invoice.payment_intent",
	} {
		if got := form.Get(k); got != want {
			t.Errorf("create sent %s=%q, want %q", k, got, want)
		}
	}
	if got := r.stripe.subVersions[0]; got != "2024-06-20" {
		t.Errorf("create sent Stripe-Version %q, want the pinned 2024-06-20", got)
	}
}

// A second subscribe — another click, another key — while the first awaits its
// payment hands back that subscription and its payment, not a second one.
func TestSubscribe_ASecondClickPaysTheFirstSubscription(t *testing.T) {
	r := subRig(t)
	first, err := subscribe(r, "pro", "k1")
	if err != nil {
		t.Fatal(err)
	}
	again, err := subscribe(r, "pro", "k2")
	if err != nil {
		t.Fatalf("second click: %v", err)
	}
	if again.GetSubscription().GetId() != first.GetSubscription().GetId() || again.GetClientSecret() != first.GetClientSecret() {
		t.Errorf("second click = %s / %q, want the first subscription %s with its payment",
			again.GetSubscription().GetId(), again.GetClientSecret(), first.GetSubscription().GetId())
	}
	if n := len(r.stripe.subs); n != 1 {
		t.Errorf("provider subscriptions = %d, want 1", n)
	}
	if n := r.store.count("subs"); n != 1 {
		t.Errorf("local subscriptions = %d, want 1", n)
	}
}

// A live subscription to the plan is the principal's subscription already.
func TestSubscribe_ALiveSubscriptionIsNotStartedTwice(t *testing.T) {
	for _, st := range []pb.Subscription_Status{pb.Subscription_ACTIVE, pb.Subscription_TRIALING, pb.Subscription_PAST_DUE, pb.Subscription_PAUSED, pb.Subscription_UNPAID} {
		r := subRig(t)
		v, err := subscribe(r, "pro", "k1")
		if err != nil {
			t.Fatal(err)
		}
		r.setLocalSubStatus(v.GetSubscription().GetProviderSubscriptionId(), st)
		_, err = subscribe(r, "pro", "k2")
		if status.Code(err) != codes.AlreadyExists {
			t.Errorf("subscribe beside a %v subscription = %v, want AlreadyExists", st, err)
		}
		if n := len(r.stripe.subs); n != 1 {
			t.Errorf("%v: provider subscriptions = %d, want 1", st, n)
		}
	}
}

// Another plan is another subscription; a canceled one frees its plan.
func TestSubscribe_AnotherPlanOrAfterCancelIsANewSubscription(t *testing.T) {
	r := subRig(t)
	pro, err := subscribe(r, "pro", "k1")
	if err != nil {
		t.Fatal(err)
	}
	r.setLocalSubStatus(pro.GetSubscription().GetProviderSubscriptionId(), pb.Subscription_ACTIVE)
	if _, err := subscribe(r, "team", "k2"); err != nil {
		t.Fatalf("a second plan: %v", err)
	}
	r.setLocalSubStatus(pro.GetSubscription().GetProviderSubscriptionId(), pb.Subscription_CANCELED)
	again, err := subscribe(r, "pro", "k3")
	if err != nil {
		t.Fatalf("after the cancel: %v", err)
	}
	if again.GetSubscription().GetId() == pro.GetSubscription().GetId() {
		t.Error("the canceled subscription was handed back")
	}
	if n := len(r.stripe.subs); n != 3 {
		t.Errorf("provider subscriptions = %d, want 3", n)
	}
}

// A waiting subscription the provider has expired meanwhile (its webhook not
// here yet) is brought up to date and frees the plan; one the provider
// reports paid is the principal's subscription, and is recorded as such.
func TestSubscribe_AWaitingSubscriptionIsJudgedByTheProvider(t *testing.T) {
	r := subRig(t)
	v, err := subscribe(r, "pro", "k1")
	if err != nil {
		t.Fatal(err)
	}
	old := v.GetSubscription().GetProviderSubscriptionId()
	r.stripe.setSubStatus(old, "incomplete_expired")
	fresh, err := subscribe(r, "pro", "k2")
	if err != nil {
		t.Fatalf("after the expiry: %v", err)
	}
	if fresh.GetSubscription().GetProviderSubscriptionId() == old || fresh.GetClientSecret() == "" {
		t.Errorf("after the expiry = %s / %q, want a new subscription with its payment", fresh.GetSubscription().GetProviderSubscriptionId(), fresh.GetClientSecret())
	}
	if got := r.store.subs[v.GetSubscription().GetId()].GetStatus(); got != pb.Subscription_CANCELED {
		t.Errorf("the expired subscription reads %v locally, want CANCELED", got)
	}

	paid := fresh.GetSubscription().GetProviderSubscriptionId()
	r.stripe.setSubStatus(paid, "active")
	_, err = subscribe(r, "pro", "k3")
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("beside a subscription the provider reports paid = %v, want AlreadyExists", err)
	}
	if got := r.store.subs[fresh.GetSubscription().GetId()].GetStatus(); got != pb.Subscription_ACTIVE {
		t.Errorf("the paid subscription reads %v locally, want ACTIVE", got)
	}
	if n := len(r.stripe.subs); n != 2 {
		t.Errorf("provider subscriptions = %d, want 2", n)
	}
}

// Many clicks at once start one subscription: the customer's row lock makes
// them run one after the other, and each later one finds the first waiting.
func TestSubscribe_ConcurrentClicksStartOneSubscription(t *testing.T) {
	r := subRig(t)
	if _, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	views := make([]*pb.SubscriptionView, 8)
	errs := make([]error, 8)
	for i := range views {
		wg.Add(1)
		go func() {
			defer wg.Done()
			views[i], errs[i] = subscribe(r, "pro", "k"+string(rune('a'+i)))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("click %d: %v", i, err)
		}
		if views[i].GetSubscription().GetId() != views[0].GetSubscription().GetId() {
			t.Errorf("click %d got subscription %s, the first %s", i, views[i].GetSubscription().GetId(), views[0].GetSubscription().GetId())
		}
	}
	if n := len(r.stripe.subs); n != 1 {
		t.Errorf("provider subscriptions = %d, want 1", n)
	}
	wantNoLocksLeft(t, r)
}

// A webhook endpoint on API 2025-03-31 or later renders the period end on
// the subscription's item; it is stored all the same, not as NULL.
func TestWebhook_APeriodEndOnTheItemIsStored(t *testing.T) {
	r := subRig(t)
	v, err := subscribe(r, "pro", "k1")
	if err != nil {
		t.Fatal(err)
	}
	sid := v.GetSubscription().GetProviderSubscriptionId()
	deliverOK(t, r, eventJSON("evt_basil", "customer.subscription.updated", sid, map[string]any{
		"status": "active",
		"items":  map[string]any{"data": []map[string]any{{"current_period_end": 1900000000}}},
	}))
	got := r.store.subs[v.GetSubscription().GetId()]
	if got.GetStatus() != pb.Subscription_ACTIVE || got.GetCurrentPeriodEnd().GetSeconds() != 1900000000 {
		t.Errorf("after a 2025-shaped event: %v, period end %v; want ACTIVE until 1900000000", got.GetStatus(), got.GetCurrentPeriodEnd())
	}
}
