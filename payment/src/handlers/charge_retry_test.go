package handlers

import (
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// base gap 2: a charge retried after the provider forgot its key is
// answered from the recorded payment once that payment is past confirmation.
// It used to reach the provider, mint a second, unconfirmed intent (an
// orphan) and answer AlreadyExists instead of the payment the key recorded.
func TestFlow_ChargeRetriedAfterTheProviderForgotTheKey_IsTheRecordedPayment(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "order-1")
	if _, err := r.deliver(eventJSON("evt_ok", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	r.stripe.forgetKeys() // a day later
	before := r.stripe.count("/v1/payment_intents")
	for _, amount := range []string{"10", "10.00"} {
		resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: amount, Currency: "usd", IdempotencyKey: "order-1"})
		if err != nil {
			t.Fatalf("retry of a succeeded charge as %s: %v", amount, err)
		}
		if resp.GetPayment().GetId() != p.GetId() || resp.GetPayment().GetStatus() != pb.Payment_SUCCEEDED {
			t.Errorf("retry as %s answered %v, want the recorded payment %s", amount, resp.GetPayment(), p.GetId())
		}
	}
	if n := r.stripe.count("/v1/payment_intents"); n != before {
		t.Errorf("the retry reached the provider (%d → %d intents) — an orphan intent", before, n)
	}
	if n := r.store.count("payments"); n != 1 {
		t.Errorf("payment rows = %d, want 1", n)
	}
}

// The key names one payment: a retry for another amount or currency is not
// it, after the provider's window as within it.
func TestFlow_ChargeKeyReusedForADifferentPayment_IsRefusedLocally(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "order-1")
	if _, err := r.deliver(eventJSON("evt_ok", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	r.stripe.forgetKeys()
	before := r.stripe.count("/v1/payment_intents")
	for _, req := range []*pb.ChargeReq{
		{UserId: "user-a", Amount: "11", Currency: "usd", IdempotencyKey: "order-1"},
		{UserId: "user-a", Amount: "10", Currency: "eur", IdempotencyKey: "order-1"},
	} {
		_, err := r.h.CreatePayment(bg, req)
		wantCode(t, err, codes.AlreadyExists, req.GetAmount()+" "+req.GetCurrency()+" under the key of 10 usd")
	}
	if n := r.stripe.count("/v1/payment_intents"); n != before {
		t.Errorf("a refused retry reached the provider (%d → %d intents)", before, n)
	}
}

// A payment still waiting for the client's confirmation is NOT answered
// locally: inside the window the provider replays it with the client secret
// the client needs, and nothing stores that secret here.
func TestFlow_ChargeRetriedBeforeConfirmation_StillGetsTheClientSecret(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10", "order-1")
	if p.GetStatus() != pb.Payment_REQUIRES_ACTION {
		t.Fatalf("a new charge is %v, want REQUIRES_ACTION", p.GetStatus())
	}
	resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "10", Currency: "usd", IdempotencyKey: "order-1"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetPayment().GetId() != p.GetId() || resp.GetClientSecret() == "" {
		t.Errorf("retry before confirmation = %v (secret %q), want the same payment with its client secret", resp.GetPayment(), resp.GetClientSecret())
	}
}

// A charge sent without a key is a new charge every time: the local lookup
// must not answer it from anything.
func TestFlow_ChargeWithoutAKey_IsNeverAnsweredLocally(t *testing.T) {
	r := newRig(t)
	resp1, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "10", Currency: "usd"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(eventJSON("evt_ok", "payment_intent.succeeded", resp1.GetPayment().GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	resp2, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "10", Currency: "usd"})
	if err != nil {
		t.Fatal(err)
	}
	if resp2.GetPayment().GetId() == resp1.GetPayment().GetId() {
		t.Error("two keyless charges answered as one payment")
	}
}

// base gap 3 / subscriptions gap 4: the customer and the price are created
// under an idempotency key, so a retried create gets the object the first
// one made instead of an orphan.
func TestFlow_CustomerAndPlanCreatesCarryAnIdempotencyKey(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.createCustomer(bg, "user-a", "a@example.test"); err != nil {
		t.Fatal(err)
	}
	r.store.dropAll("customers") // the local link lost; the retry creates again
	if _, err := r.h.createCustomer(bg, "user-a", "a@example.test"); err != nil {
		t.Fatal(err)
	}
	if n := len(r.stripe.customers); n != 1 {
		t.Errorf("provider customers = %d, want 1 — the retry made an orphan", n)
	}
	// Another address is another create.
	r.store.dropAll("customers")
	if _, err := r.h.createCustomer(bg, "user-a", "b@example.test"); err != nil {
		t.Fatal(err)
	}
	if n := len(r.stripe.customers); n != 2 {
		t.Errorf("provider customers = %d after a create with another address, want 2", n)
	}

	plan := &pb.DefinePlanReq{Slug: "pro", Name: "Pro", Amount: "9", Currency: "usd", Interval: "month"}
	if _, err := r.h.CreatePlan(bg, plan); err != nil {
		t.Fatal(err)
	}
	r.store.dropAll("plans")
	if _, err := r.h.CreatePlan(bg, plan); err != nil {
		t.Fatal(err)
	}
	if n := r.stripe.count("/v1/prices"); n != 1 {
		t.Errorf("provider prices created = %d, want 1 — the retry made an orphan", n)
	}
}

// dropAll empties one table: the local link a lost write never recorded.
func (s *memStore) dropAll(table string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch table {
	case "customers":
		s.customers = map[string]*pb.Customer{}
	case "plans":
		s.plans = map[string]*pb.Plan{}
	default:
		panic("dropAll: unknown table " + table)
	}
}
