package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// rig wires a PaymentServiceHandler to the stateful store (memStore) and
// a real Stripe driver talking to the wire-format fake (stripeFake).
type rig struct {
	t      *testing.T
	store  *memStore
	stripe *stripeFake
	h      *PaymentServiceHandler
}

func newRig(t *testing.T) *rig {
	t.Helper()
	store := newMemStore()
	sf := newStripeFake(t)
	return &rig{t: t, store: store, stripe: sf, h: &PaymentServiceHandler{
		Query: store, Mutation: store, Backend: sf.backend(),
		WebhookSecret: testWebhookSecret, DefaultCurrency: "usd",
	}}
}

var bg = context.Background()

func (r *rig) deliverSigned(body []byte, sig string) (*pb.IngestStripeResp, error) {
	ctx := metadata.NewIncomingContext(bg, metadata.Pairs("stripe-signature", sig))
	return r.h.IngestStripe(ctx, &pb.IngestStripeReq{RawPayload: body})
}

// deliver signs body the way Stripe does, now.
func (r *rig) deliver(body []byte) (*pb.IngestStripeResp, error) {
	return r.deliverSigned(body, signedAt(body, testWebhookSecret, time.Now().Unix()))
}

func (r *rig) charge(user, amount, key string) *pb.Payment {
	r.t.Helper()
	resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: user, Amount: amount, Currency: "usd", IdempotencyKey: key})
	if err != nil {
		r.t.Fatalf("CreatePayment(%s, %s): %v", user, amount, err)
	}
	return resp.GetPayment()
}

func (r *rig) topUp(user, amount, key string) *pb.Payment {
	r.t.Helper()
	resp, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: user, Amount: amount, IdempotencyKey: key})
	if err != nil {
		r.t.Fatalf("TopUpCredit(%s, %s): %v", user, amount, err)
	}
	return resp.GetPayment()
}

func wantCode(t *testing.T, err error, want codes.Code, what string) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: want %v, got %v", what, want, err)
	}
}

var errTransient = status.Error(codes.Unavailable, "connection reset by peer")

// ── charges: idempotency ──────────────────────────────────────────────

// A retry after the local INSERT committed but its response was lost:
// the provider replays the same intent for the same key, the local
// INSERT hits the unique key — and the retry must get the payment, not
// an InvalidArgument UNIQUE_VIOLATION (which a client reads as "the
// charge failed" while it exists and is confirmable).
func TestFlow_ChargeRetryAfterLostResponse_ReturnsSamePayment(t *testing.T) {
	r := newRig(t)
	r.store.injectAfter("CreatePayment", errTransient)

	_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "19.99", Currency: "usd", IdempotencyKey: "order-1"})
	wantCode(t, err, codes.Unavailable, "first attempt (response lost)")

	resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "19.99", Currency: "usd", IdempotencyKey: "order-1"})
	if err != nil {
		t.Fatalf("retry with the same idempotency key must succeed, got %v", err)
	}
	if n := r.store.count("payments"); n != 1 {
		t.Errorf("local payments = %d, want 1", n)
	}
	if n := r.stripe.count("/v1/payment_intents"); n != 1 {
		t.Errorf("provider intents created = %d, want 1 (the retry must replay, not charge twice)", n)
	}
	p := resp.GetPayment()
	if p.GetIdempotencyKey() != "order-1" || p.GetAmount() != "19.9900" {
		t.Errorf("returned payment = %+v", p)
	}
	if resp.GetClientSecret() != p.GetProviderPaymentId()+"_secret_fake" {
		t.Errorf("client_secret = %q — the retry must still hand back the confirm token", resp.GetClientSecret())
	}
	if in := r.stripe.intent(p.GetProviderPaymentId()); in.amount != 1999 || in.currency != "usd" {
		t.Errorf("provider intent = %+v, want 1999 usd", in)
	}
}

func TestFlow_ChargeRepeatedAfterSuccess_IsIdempotent(t *testing.T) {
	r := newRig(t)
	a := r.charge("user-a", "5.00", "order-2")
	b := r.charge("user-a", "5.00", "order-2")
	if a.GetId() != b.GetId() {
		t.Fatalf("same key returned two payments: %s, %s", a.GetId(), b.GetId())
	}
	if n := r.stripe.count("/v1/payment_intents"); n != 1 {
		t.Errorf("provider intents = %d, want 1", n)
	}
}

// ChargeReq documents "Empty → the handler derives one". The handler
// passed "" through to a UNIQUE column, so the second key-less charge
// ever created a provider intent and then failed the local INSERT.
func TestFlow_KeylessCharges_DoNotCollide(t *testing.T) {
	r := newRig(t)
	a := r.charge("user-a", "5.00", "")
	b := r.charge("user-a", "5.00", "")
	if a.GetId() == b.GetId() || a.GetProviderPaymentId() == b.GetProviderPaymentId() {
		t.Fatalf("two key-less charges collapsed into one: %+v / %+v", a, b)
	}
	for _, p := range []*pb.Payment{a, b} {
		if !strings.HasPrefix(p.GetIdempotencyKey(), "auto:") {
			t.Errorf("derived key = %q, want an auto: key", p.GetIdempotencyKey())
		}
	}
	if a.GetIdempotencyKey() == b.GetIdempotencyKey() {
		t.Error("derived keys must differ per call")
	}
	// TopUpCredit shares the path.
	r.topUp("user-a", "1.00", "")
	r.topUp("user-a", "1.00", "")
	if n := r.store.count("payments"); n != 4 {
		t.Errorf("payments = %d, want 4", n)
	}
}

// Tenant isolation on the replay path: another principal reusing a key
// must never be handed the first principal's payment.
func TestFlow_IdempotencyKeyReusedByAnotherUser_NeverLeaksThePayment(t *testing.T) {
	r := newRig(t)
	a := r.charge("user-a", "5.00", "shared-key")

	// Inside the provider's key window: same key, different customer →
	// the provider refuses (idempotency_error) — a caller error.
	_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-b", Amount: "5.00", Currency: "usd", IdempotencyKey: "shared-key"})
	wantCode(t, err, codes.InvalidArgument, "key reused with other parameters")

	// After the provider forgot the key: it mints a NEW intent, the local
	// INSERT conflicts on the idempotency key of user-a's row — and the
	// replay lookup finds no row for the new intent.
	r.stripe.forgetKeys()
	resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-b", Amount: "5.00", Currency: "usd", IdempotencyKey: "shared-key"})
	wantCode(t, err, codes.AlreadyExists, "key reused after the provider window")
	if resp != nil || strings.Contains(err.Error(), a.GetId()) || strings.Contains(err.Error(), a.GetProviderPaymentId()) {
		t.Errorf("user-b's failure must not carry user-a's payment: resp=%v err=%v", resp, err)
	}
	if n := r.store.count("payments"); n != 1 {
		t.Errorf("payments = %d, want only user-a's", n)
	}

	// And user-a's own retry after the window: the provider mints a new
	// intent, the lookup finds no row for it — AlreadyExists, not some
	// other payment.
	r.stripe.forgetKeys()
	_, err = r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "5.00", Currency: "usd", IdempotencyKey: "shared-key"})
	wantCode(t, err, codes.AlreadyExists, "own key reused after the provider window")
}

// Each principal is charged on its OWN provider customer.
func TestFlow_ChargesUseThePrincipalsOwnProviderCustomer(t *testing.T) {
	r := newRig(t)
	a := r.charge("user-a", "1.00", "a-1")
	b := r.charge("user-b", "1.00", "b-1")
	a2 := r.charge("user-a", "2.00", "a-2")
	if a.GetCustomerId() == b.GetCustomerId() {
		t.Fatal("two principals share one customer row")
	}
	if a.GetCustomerId() != a2.GetCustomerId() {
		t.Error("a principal's second charge created a second customer")
	}
	ia, ib := r.stripe.intent(a.GetProviderPaymentId()), r.stripe.intent(b.GetProviderPaymentId())
	if ia.customer == "" || ia.customer == ib.customer {
		t.Errorf("provider customers: a=%q b=%q", ia.customer, ib.customer)
	}
	if n := r.stripe.count("/v1/customers"); n != 2 {
		t.Errorf("provider customers created = %d, want 2", n)
	}
}

// Two first-charges for one principal race past the "no customer yet"
// read; the loser's INSERT hits the unique user_id. It used to surface
// that as an error (failing a valid charge); it must adopt the winner.
func TestFlow_FirstChargeRace_AdoptsTheWinningCustomer(t *testing.T) {
	r := newRig(t)
	r.store.onceBefore("CreateCustomer", func() {
		if _, err := r.store.CreateCustomer(bg, &pb.CreateCustomerReq{UserId: "user-a", ProviderCustomerId: "cus_winner"}); err != nil {
			t.Errorf("seed winner: %v", err)
		}
	})
	p := r.charge("user-a", "3.00", "race-1")
	if n := r.store.count("customers"); n != 1 {
		t.Fatalf("customers = %d, want 1", n)
	}
	got, _ := r.store.GetCustomerByUserId(bg, &pb.GetCustomerByUserIdReq{UserId: "user-a"})
	if p.GetCustomerId() != got.GetCustomer().GetId() {
		t.Errorf("payment customer = %s, want the winner %s", p.GetCustomerId(), got.GetCustomer().GetId())
	}
}

func TestFlow_CreateCustomer_IsIdempotentPerPrincipal(t *testing.T) {
	r := newRig(t)
	a, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("CreateCustomer: %v", err)
	}
	b, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("second CreateCustomer must return the existing link, got %v", err)
	}
	if a.GetCustomer().GetId() != b.GetCustomer().GetId() {
		t.Error("second call created a second customer")
	}
	if n := r.stripe.count("/v1/customers"); n != 1 {
		t.Errorf("provider customers = %d, want 1 (no orphan per repeated call)", n)
	}
}

// ── charges: amounts, currencies, provider failures ───────────────────

func TestFlow_ChargeAmountAndCurrencyRefusals_NeverReachTheProvider(t *testing.T) {
	cases := []struct {
		name, amount, currency string
		want                   codes.Code
	}{
		{"fifth fractional digit (DB would round)", "1.00001", "usd", codes.InvalidArgument},
		{"17 integer digits (DB overflow)", "10000000000000000", "usd", codes.InvalidArgument},
		{"cents on a 2-decimal currency past scale", "10.001", "usd", codes.InvalidArgument},
		{"fraction on a zero-decimal currency", "1.5", "jpy", codes.InvalidArgument},
		{"currency not 3 letters", "1.00", "dollars", codes.InvalidArgument},
		{"currency with digits", "1.00", "us1", codes.InvalidArgument},
		{"exponent", "1e3", "usd", codes.InvalidArgument},
		{"negative", "-1.00", "usd", codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: c.amount, Currency: c.currency, IdempotencyKey: "k"})
			wantCode(t, err, c.want, c.amount+" "+c.currency)
			if n := r.stripe.count("/v1/payment_intents"); n != 0 {
				t.Errorf("provider was charged %d time(s) for a refused amount", n)
			}
			if n := r.store.count("payments"); n != 0 {
				t.Errorf("local payment recorded for a refused amount")
			}
		})
	}
}

func TestFlow_ChargeAmountNormalisation(t *testing.T) {
	r := newRig(t)
	resp, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: " 1000 ", Currency: " JPY ", IdempotencyKey: "jp"})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	p := resp.GetPayment()
	if p.GetCurrency() != "jpy" || p.GetAmount() != "1000.0000" {
		t.Errorf("stored = %s %s", p.GetAmount(), p.GetCurrency())
	}
	if in := r.stripe.intent(p.GetProviderPaymentId()); in.amount != 1000 {
		t.Errorf("zero-decimal currency sent as %d minor units, want 1000", in.amount)
	}
	// The largest amount the column holds converts exactly.
	resp, err = r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "9999999999999999.99", Currency: "usd", IdempotencyKey: "max"})
	if err != nil {
		t.Fatalf("max amount: %v", err)
	}
	if in := r.stripe.intent(resp.GetPayment().GetProviderPaymentId()); in.amount != 999999999999999999 {
		t.Errorf("max amount sent as %d", in.amount)
	}
}

// Provider failures map by class: a declined card or an invalid request
// fails identically on every retry, so it must not be Unavailable (which
// gRPC retry policies retry automatically); only transient ones are.
func TestFlow_ProviderErrorMapping(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig)
		want  codes.Code
	}{
		{"card declined (402 card_error)", func(r *rig) {
			c, _ := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a"})
			r.stripe.declineCustomer(c.GetCustomer().GetProviderCustomerId())
		}, codes.FailedPrecondition},
		{"provider 500", func(r *rig) { r.stripe.failNext(http.StatusInternalServerError) }, codes.Unavailable},
		{"rate limited 429", func(r *rig) { r.stripe.failNext(http.StatusTooManyRequests) }, codes.Unavailable},
		{"concurrent key in flight 409", func(r *rig) { r.stripe.failNext(http.StatusConflict) }, codes.Unavailable},
		{"bad api key 401", func(r *rig) { r.stripe.failNext(http.StatusUnauthorized) }, codes.Unavailable},
		{"invalid request 400", func(r *rig) { r.stripe.failNext(http.StatusBadRequest) }, codes.InvalidArgument},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			c.setup(r)
			// The customer exists already for the decline case; for the
			// others the injected failure hits the customer create or
			// the intent — either way the charge must fail with c.want.
			if c.want != codes.FailedPrecondition {
				if _, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a"}); status.Code(err) != c.want {
					t.Fatalf("customer create: want %v, got %v", c.want, err)
				}
				c.setup(r)
			}
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "5.00", Currency: "usd", IdempotencyKey: "k"})
			wantCode(t, err, c.want, "charge")
			if n := r.store.count("payments"); n != 0 {
				t.Error("a failed provider call must not record a local payment")
			}
		})
	}
}

// A transient provider failure is retryable with the same key, and the
// retry charges once.
func TestFlow_TransientProviderFailure_RetrySucceedsOnce(t *testing.T) {
	r := newRig(t)
	r.charge("user-a", "1.00", "warmup") // customer exists
	r.stripe.failNext(http.StatusServiceUnavailable)
	_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "7.00", Currency: "usd", IdempotencyKey: "retry-me"})
	wantCode(t, err, codes.Unavailable, "transient")
	p := r.charge("user-a", "7.00", "retry-me")
	if p.GetAmount() != "7.0000" {
		t.Errorf("amount = %s", p.GetAmount())
	}
	if n := r.stripe.count("/v1/payment_intents"); n != 2 { // warmup + one
		t.Errorf("intents = %d, want 2", n)
	}
}

// ── webhooks: ordering, redelivery, outrunning ────────────────────────

func TestFlow_LateFailureAfterSuccess_IsAcknowledgedAndChangesNothing(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "10.00", "o-1")
	pid := p.GetProviderPaymentId()
	if _, err := r.deliver(eventJSON("evt_ok", "payment_intent.succeeded", pid, nil)); err != nil {
		t.Fatalf("succeeded: %v", err)
	}
	// A failure from an EARLIER attempt, delivered late: its own event id,
	// so the dedup ledger has never seen it. It used to come back
	// NotFound ("no local record") on its first delivery.
	resp, err := r.deliver(eventJSON("evt_late_fail", "payment_intent.payment_failed", pid, nil))
	if err != nil {
		t.Fatalf("a late out-of-order failure must be acknowledged, got %v", err)
	}
	if !resp.GetHandled() {
		t.Error("first sighting of an event id is handled=true")
	}
	if st := r.store.paymentStatus(t, pid); st != pb.Payment_SUCCEEDED {
		t.Errorf("status = %v — SUCCEEDED must be absorbing", st)
	}
	if n := r.store.events("PaymentFailed"); n != 0 {
		t.Errorf("PaymentFailed emitted %d times after the success", n)
	}
	if !r.store.isProcessed("evt_late_fail") {
		t.Error("the acknowledged event must be recorded")
	}
}

func TestFlow_FailureThenRetriedSuccess(t *testing.T) {
	r := newRig(t)
	pid := r.charge("user-a", "10.00", "o-2").GetProviderPaymentId()
	if _, err := r.deliver(eventJSON("evt_f", "payment_intent.payment_failed", pid, nil)); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if st := r.store.paymentStatus(t, pid); st != pb.Payment_FAILED {
		t.Fatalf("status = %v, want FAILED", st)
	}
	// Redelivered failure: no second emit, handled=false.
	resp, err := r.deliver(eventJSON("evt_f", "payment_intent.payment_failed", pid, nil))
	if err != nil || resp.GetHandled() {
		t.Fatalf("redelivered failure: handled=%v err=%v", resp.GetHandled(), err)
	}
	// FAILED → SUCCEEDED stays open (the customer retried the card).
	if _, err := r.deliver(eventJSON("evt_s", "payment_intent.succeeded", pid, nil)); err != nil {
		t.Fatalf("succeeded: %v", err)
	}
	if st := r.store.paymentStatus(t, pid); st != pb.Payment_SUCCEEDED {
		t.Errorf("status = %v, want SUCCEEDED", st)
	}
	if r.store.events("PaymentFailed") != 1 || r.store.events("PaymentSucceeded") != 1 {
		t.Errorf("events: failed=%d succeeded=%d, want 1/1", r.store.events("PaymentFailed"), r.store.events("PaymentSucceeded"))
	}
}

// The webhook outruns the local row: every delivery must fail (and stay
// unrecorded) until the row exists, then reconcile. The old discriminator
// wrote the ledger on the first failing delivery, so the SECOND delivery
// was acknowledged as a duplicate while the row was still missing — the
// success was lost for good.
func TestFlow_WebhookOutrunsLocalRow_FailsUntilTheRowLands(t *testing.T) {
	r := newRig(t)
	body := eventJSON("evt_fast", "payment_intent.succeeded", "pi_not_yet", nil)
	for i := 1; i <= 2; i++ {
		_, err := r.deliver(body)
		wantCode(t, err, codes.NotFound, "delivery before the row exists")
		if r.store.isProcessed("evt_fast") {
			t.Fatalf("delivery %d recorded the event although nothing was reconciled", i)
		}
	}
	if _, err := r.store.CreatePayment(bg, &pb.CreatePaymentReq{CustomerId: "cust-x", ProviderPaymentId: "pi_not_yet", Amount: "1", Currency: "usd", Status: int32(pb.Payment_REQUIRES_ACTION), IdempotencyKey: "late"}); err != nil {
		t.Fatal(err)
	}
	resp, err := r.deliver(body)
	if err != nil || !resp.GetHandled() {
		t.Fatalf("delivery after the row landed: handled=%v err=%v", resp.GetHandled(), err)
	}
	if st := r.store.paymentStatus(t, "pi_not_yet"); st != pb.Payment_SUCCEEDED {
		t.Errorf("status = %v", st)
	}
	// Same for a failure event.
	_, err = r.deliver(eventJSON("evt_fail_unknown", "payment_intent.payment_failed", "pi_ghost", nil))
	wantCode(t, err, codes.NotFound, "failure for an unknown intent")
}

// A transient store failure in the guard itself or the ledger write must
// surface (provider redelivers) and leave the event unrecorded.
func TestFlow_TransientStoreFailures_AreNotAcknowledged(t *testing.T) {
	for _, method := range []string{"MarkPaymentSucceeded", "GetPaymentByProviderId", "MarkWebhookProcessed"} {
		t.Run(method, func(t *testing.T) {
			r := newRig(t)
			pid := r.charge("user-a", "1.00", "k").GetProviderPaymentId()
			if method == "GetPaymentByProviderId" {
				// reach the lookup: the guard must refuse first
				if _, err := r.deliver(eventJSON("evt_0", "payment_intent.succeeded", pid, nil)); err != nil {
					t.Fatal(err)
				}
			}
			r.store.injectBefore(method, errTransient)
			_, err := r.deliver(eventJSON("evt_1", "payment_intent.succeeded", pid, nil))
			wantCode(t, err, codes.Unavailable, method)
			if r.store.isProcessed("evt_1") {
				t.Error("event recorded despite the failure")
			}
			resp, err := r.deliver(eventJSON("evt_1", "payment_intent.succeeded", pid, nil))
			if err != nil || !resp.GetHandled() {
				t.Fatalf("redelivery: handled=%v err=%v", resp.GetHandled(), err)
			}
			if r.store.events("PaymentSucceeded") != 1 {
				t.Errorf("PaymentSucceeded = %d, want 1", r.store.events("PaymentSucceeded"))
			}
		})
	}
}

func TestFlow_UnhandledEventTypes_AreAcknowledgedOnce(t *testing.T) {
	r := newRig(t)
	body := eventJSON("evt_misc", "charge.dispute.created", "dp_1", nil)
	resp, err := r.deliver(body)
	if err != nil || !resp.GetHandled() || resp.GetEventType() != "charge.dispute.created" || resp.GetEventId() != "evt_misc" {
		t.Fatalf("resp=%+v err=%v", resp, err)
	}
	resp, err = r.deliver(body)
	if err != nil || resp.GetHandled() {
		t.Fatalf("redelivery: resp=%+v err=%v", resp, err)
	}
}

// ── webhooks: prepaid top-up grant ────────────────────────────────────

// The grant used to run only on a FRESH transition. A transient failure
// in it (after MarkPaymentSucceeded committed) returned an error, the
// redelivery's guard then refused, and the grant never ran again: the
// customer was charged and never credited.
func TestFlow_TopUpGrant_SurvivesATransientFailure(t *testing.T) {
	for _, method := range []string{"GetCreditTopupByProviderId", "ApplyCredit"} {
		t.Run(method, func(t *testing.T) {
			r := newRig(t)
			pid := r.topUp("user-a", "20.00", "top-1").GetProviderPaymentId()
			body := eventJSON("evt_top", "payment_intent.succeeded", pid, nil)

			r.store.injectBefore(method, errTransient)
			_, err := r.deliver(body)
			wantCode(t, err, codes.Unavailable, "delivery with the grant failing")
			if r.store.isProcessed("evt_top") {
				t.Fatal("event recorded although the grant failed")
			}
			if st := r.store.paymentStatus(t, pid); st != pb.Payment_SUCCEEDED {
				t.Fatalf("payment status = %v (the transition itself committed)", st)
			}

			resp, err := r.deliver(body)
			if err != nil || !resp.GetHandled() {
				t.Fatalf("redelivery: handled=%v err=%v", resp.GetHandled(), err)
			}
			if got := r.store.balance(t, "user-a"); got != "20.0000" {
				t.Fatalf("balance = %s after the redelivery — the charged credit was never granted", got)
			}
			// …and exactly once, however often it is redelivered.
			for i := 0; i < 3; i++ {
				if resp, err := r.deliver(body); err != nil || resp.GetHandled() {
					t.Fatalf("later redelivery: handled=%v err=%v", resp.GetHandled(), err)
				}
			}
			if got := r.store.balance(t, "user-a"); got != "20.0000" {
				t.Errorf("balance = %s, want 20.0000", got)
			}
			if r.store.events("PaymentSucceeded") != 1 || r.store.events("CreditApplied") != 1 {
				t.Errorf("events: succeeded=%d credit=%d, want 1/1", r.store.events("PaymentSucceeded"), r.store.events("CreditApplied"))
			}
		})
	}
}

// The grant committed but the granted_at stamp failed: the redelivery
// must not grant again and must complete the stamp.
func TestFlow_TopUpStampFailure_DoesNotDoubleGrant(t *testing.T) {
	r := newRig(t)
	pid := r.topUp("user-a", "20.00", "top-2").GetProviderPaymentId()
	body := eventJSON("evt_top2", "payment_intent.succeeded", pid, nil)
	r.store.injectBefore("MarkTopupGranted", errTransient)
	_, err := r.deliver(body)
	wantCode(t, err, codes.Unavailable, "stamp failure")
	if _, err := r.deliver(body); err != nil {
		t.Fatalf("redelivery: %v", err)
	}
	if got := r.store.balance(t, "user-a"); got != "20.0000" {
		t.Errorf("balance = %s, want 20.0000 exactly once", got)
	}
	got, _ := r.store.GetCreditTopupByProviderId(bg, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: pid})
	if got.GetTopup().GetGrantedAt() == nil {
		t.Error("top-up never stamped granted")
	}
}

// Stripe can deliver one event concurrently (a slow handler and its
// retry overlap). Exactly one grant, one emit; no delivery may fail just
// because another stamped first.
func TestFlow_TopUp_ConcurrentDuplicateDeliveries(t *testing.T) {
	r := newRig(t)
	pid := r.topUp("user-a", "20.00", "top-3").GetProviderPaymentId()
	body := eventJSON("evt_top3", "payment_intent.succeeded", pid, nil)

	const n = 8
	var wg sync.WaitGroup
	handled := make(chan bool, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := r.deliver(body)
			if err != nil {
				errs <- err
				return
			}
			handled <- resp.GetHandled()
		}()
	}
	wg.Wait()
	close(errs)
	close(handled)
	for err := range errs {
		t.Errorf("a concurrent delivery failed: %v", err)
	}
	firsts := 0
	for h := range handled {
		if h {
			firsts++
		}
	}
	if firsts != 1 {
		t.Errorf("handled=true answered %d times, want 1", firsts)
	}
	if got := r.store.balance(t, "user-a"); got != "20.0000" {
		t.Errorf("balance = %s, want 20.0000", got)
	}
	if r.store.events("PaymentSucceeded") != 1 || r.store.events("CreditApplied") != 1 {
		t.Errorf("events: succeeded=%d credit=%d", r.store.events("PaymentSucceeded"), r.store.events("CreditApplied"))
	}
}

// A top-up grants the PAYER, nobody else; another tenant's pending
// top-up is untouched by this one's success.
func TestFlow_TopUp_GrantsOnlyThePayer(t *testing.T) {
	r := newRig(t)
	pa := r.topUp("user-a", "20.00", "ta").GetProviderPaymentId()
	pb2 := r.topUp("user-b", "50.00", "tb").GetProviderPaymentId()
	if _, err := r.deliver(eventJSON("evt_a", "payment_intent.succeeded", pa, nil)); err != nil {
		t.Fatal(err)
	}
	if a, b := r.store.balance(t, "user-a"), r.store.balance(t, "user-b"); a != "20.0000" || b != "0.0000" {
		t.Errorf("balances a=%s b=%s, want 20/0", a, b)
	}
	got, _ := r.store.GetCreditTopupByProviderId(bg, &pb.GetCreditTopupByProviderIdReq{ProviderPaymentId: pb2})
	if got.GetTopup().GetGrantedAt() != nil {
		t.Error("user-b's top-up was stamped by user-a's success")
	}
	// A plain (non-top-up) charge succeeding grants nothing.
	plain := r.charge("user-b", "9.00", "plain").GetProviderPaymentId()
	if _, err := r.deliver(eventJSON("evt_plain", "payment_intent.succeeded", plain, nil)); err != nil {
		t.Fatal(err)
	}
	if b := r.store.balance(t, "user-b"); b != "0.0000" {
		t.Errorf("a plain charge granted credit: %s", b)
	}
}

// Credit has no currency: a top-up is charged in default_currency only,
// or 1000 of the weakest currency buys 1000 credits.
func TestFlow_TopUp_RefusesAForeignCurrency(t *testing.T) {
	r := newRig(t)
	for _, cur := range []string{"jpy", "eur", "idr"} {
		_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "1000", Currency: cur, IdempotencyKey: "fx-" + cur})
		wantCode(t, err, codes.InvalidArgument, "top-up in "+cur)
	}
	if n := r.stripe.count("/v1/payment_intents"); n != 0 {
		t.Errorf("provider charged %d time(s) for a refused top-up", n)
	}
	// The default currency, in any case, is fine.
	if _, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "10", Currency: " USD ", IdempotencyKey: "fx-ok"}); err != nil {
		t.Fatalf("default currency top-up: %v", err)
	}
}

// A retried top-up (same key, response lost after the payment row
// committed) answers with the one payment and one pending top-up.
func TestFlow_TopUp_RetryAfterLostResponse(t *testing.T) {
	r := newRig(t)
	r.store.injectAfter("CreateCreditTopup", errTransient)
	_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "15", IdempotencyKey: "top-retry"})
	wantCode(t, err, codes.Unavailable, "first attempt")
	p := r.topUp("user-a", "15", "top-retry")
	if n := r.store.count("payments"); n != 1 {
		t.Errorf("payments = %d, want 1", n)
	}
	if _, err := r.deliver(eventJSON("evt_tr", "payment_intent.succeeded", p.GetProviderPaymentId(), nil)); err != nil {
		t.Fatal(err)
	}
	if got := r.store.balance(t, "user-a"); got != "15.0000" {
		t.Errorf("balance = %s, want 15.0000", got)
	}
}

// ── refunds ──────────────────────────────────────────────────────────

func TestFlow_Refunds(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "20.00", "o-ref")
	refund := func(amount, key string) (*pb.RefundPaymentResp, error) {
		return r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: amount, IdempotencyKey: key})
	}

	a, err := refund("5.00", "r-1")
	if err != nil {
		t.Fatalf("partial 1: %v", err)
	}
	if _, err := refund("5.00", "r-2"); err != nil {
		t.Fatalf("partial 2 (same amount, distinct key): %v", err)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 1000 {
		t.Fatalf("provider refunded %d, want 1000", got)
	}
	// Retrying r-1 replays at the provider and returns the same refund.
	again, err := refund("5.00", "r-1")
	if err != nil || again.GetRefund().GetId() != a.GetRefund().GetId() {
		t.Fatalf("retry of r-1: %v / %v", again, err)
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 1000 {
		t.Errorf("retry refunded again: %d", got)
	}
	// Over-refund: the provider refuses; it is the caller's error.
	_, err = refund("15.00", "r-3")
	wantCode(t, err, codes.InvalidArgument, "refund above the unrefunded amount")
	// "Full" after partials asks for the whole original amount — refused
	// the same way, never recorded.
	_, err = refund("", "r-4")
	wantCode(t, err, codes.InvalidArgument, "full refund after partials")
	if n := r.store.count("refunds"); n != 2 {
		t.Errorf("refund rows = %d, want 2", n)
	}
	if rf := a.GetRefund(); rf.GetCurrency() != "usd" || rf.GetAmount() != "5.0000" || rf.GetPaymentId() != p.GetId() {
		t.Errorf("refund row = %+v", rf)
	}
}

func TestFlow_Refund_FullAndLostResponse(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "12.34", "o-full")
	r.store.injectAfter("CreateRefund", errTransient)
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), IdempotencyKey: "full-1"})
	wantCode(t, err, codes.Unavailable, "lost response")
	resp, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), IdempotencyKey: "full-1"})
	if err != nil {
		t.Fatalf("retry must return the recorded refund, got %v", err)
	}
	if resp.GetRefund().GetAmount() != "12.3400" {
		t.Errorf("full refund amount = %s", resp.GetRefund().GetAmount())
	}
	if got := r.stripe.intent(p.GetProviderPaymentId()).refunded; got != 1234 {
		t.Errorf("provider refunded %d, want 1234 once", got)
	}
	if n := r.store.count("refunds"); n != 1 {
		t.Errorf("refund rows = %d", n)
	}
}

func TestFlow_Refund_RefusalsNeverReachTheProvider(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "20.00", "o-neg")
	for _, amt := range []string{"-5.00", "0", "0.00", "5.00001", "abc", "1e2"} {
		_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: amt, IdempotencyKey: "neg-" + amt})
		wantCode(t, err, codes.InvalidArgument, "refund "+amt)
	}
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "1", IdempotencyKey: strings.Repeat("k", 256)})
	wantCode(t, err, codes.InvalidArgument, "256-byte key")
	_, err = r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: "no-such-payment", IdempotencyKey: "x"})
	wantCode(t, err, codes.NotFound, "unknown payment")
	if n := r.stripe.count("/v1/refunds"); n != 0 {
		t.Errorf("provider saw %d refund request(s)", n)
	}
}

// A refund row the replay lookup finds for ANOTHER payment is never
// returned as this one's.
func TestFlow_Refund_ReplayLookupChecksThePayment(t *testing.T) {
	r := newRig(t)
	p := r.charge("user-a", "20.00", "o-x")
	// The provider replays a refund id that is locally recorded against a
	// different payment (corrupt state / a reused key across payments).
	r.store.onceBefore("CreateRefund", func() {
		_, _ = r.store.CreateRefund(bg, &pb.CreateRefundReq{PaymentId: "pay-other", ProviderRefundId: "re_fake0003", Amount: "1", Currency: "usd"})
	})
	_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "1", IdempotencyKey: "rx"})
	if err == nil {
		t.Fatal("a refund recorded for another payment was returned as this one's")
	}
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "different refund") {
		t.Errorf("want AlreadyExists naming the key's other refund, got %v", err)
	}
}

// ── subscriptions ────────────────────────────────────────────────────

func TestFlow_SubscriptionLifecycle_OutOfOrderAndUnknown(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Name: "Pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	sv, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "s-1"})
	if err != nil {
		t.Fatal(err)
	}
	sid := sv.GetSubscription().GetProviderSubscriptionId()
	get := func() *pb.Subscription {
		got, _ := r.store.GetSubscriptionByProviderId(bg, &pb.GetSubscriptionByProviderIdReq{ProviderSubscriptionId: sid})
		return got.GetSubscription()
	}

	if _, err := r.deliver(eventJSON("evt_u1", "customer.subscription.updated", sid, map[string]any{"status": "past_due", "current_period_end": 1893456000})); err != nil {
		t.Fatal(err)
	}
	if s := get(); s.GetStatus() != pb.Subscription_PAST_DUE || s.GetCurrentPeriodEnd().GetSeconds() != 1893456000 {
		t.Fatalf("after update: %+v", s)
	}
	if _, err := r.deliver(eventJSON("evt_d", "customer.subscription.deleted", sid, map[string]any{"status": "canceled"})); err != nil {
		t.Fatal(err)
	}
	// A late "updated → active" after the deletion: acknowledged, no revival.
	resp, err := r.deliver(eventJSON("evt_u0", "customer.subscription.updated", sid, map[string]any{"status": "active"}))
	if err != nil {
		t.Fatalf("a late update after deletion must be acknowledged, got %v", err)
	}
	if !resp.GetHandled() {
		t.Error("first sighting → handled=true")
	}
	if s := get(); s.GetStatus() != pb.Subscription_CANCELED {
		t.Errorf("status = %v — CANCELED must be terminal", s.GetStatus())
	}
	if n := r.store.events("SubscriptionStatusChanged"); n != 2 {
		t.Errorf("SubscriptionStatusChanged = %d, want 2 (update + delete)", n)
	}
	// Unknown subscription: fail unrecorded, so the provider redelivers.
	_, err = r.deliver(eventJSON("evt_ghost", "customer.subscription.updated", "sub_ghost", map[string]any{"status": "active"}))
	wantCode(t, err, codes.NotFound, "unknown subscription")
	if r.store.isProcessed("evt_ghost") {
		t.Error("unknown subscription event recorded")
	}
	// An event without an object id is acknowledged (nothing to do).
	if _, err := r.deliver(eventJSON("evt_noobj", "customer.subscription.updated", "", nil)); err != nil {
		t.Errorf("subscription event without object id: %v", err)
	}
}

func TestFlow_Subscribe_RetryAfterLostResponse(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	r.store.injectAfter("CreateSubscription", errTransient)
	_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "sub-k"})
	wantCode(t, err, codes.Unavailable, "lost response")
	sv, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "sub-k"})
	if err != nil {
		t.Fatalf("retry must return the recorded subscription, got %v", err)
	}
	if n := r.store.count("subs"); n != 1 {
		t.Errorf("subscriptions = %d", n)
	}
	if n := r.stripe.count("/v1/subscriptions"); n != 1 {
		t.Errorf("provider subscriptions = %d, want 1", n)
	}
	if sv.GetSubscription().GetStatus() != pb.Subscription_ACTIVE {
		t.Errorf("status = %v", sv.GetSubscription().GetStatus())
	}
}

// Another customer's subscription under the replayed provider id is
// never returned (the replay lookup checks the customer).
func TestFlow_Subscribe_ReplayLookupChecksTheCustomer(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
		t.Fatal(err)
	}
	r.store.onceBefore("CreateSubscription", func() {
		_, _ = r.store.CreateSubscription(bg, &pb.CreateSubscriptionReq{CustomerId: "cust-other", PlanId: "p", ProviderSubscriptionId: "sub_fake0003", Status: 2})
	})
	_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "sx"})
	if status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), "different subscription") {
		t.Fatalf("want AlreadyExists naming the key's other subscription, got %v", err)
	}
}

func TestFlow_CreatePlan_IdempotentOnTermsNotJustSlug(t *testing.T) {
	r := newRig(t)
	first, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "USD", Interval: "month"})
	if err != nil {
		t.Fatal(err)
	}
	same, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29.00", Currency: "usd", Interval: "month"})
	if err != nil || same.GetPlan().GetId() != first.GetPlan().GetId() {
		t.Fatalf("same terms: %v / %v", same, err)
	}
	for _, c := range []*pb.DefinePlanReq{
		{Slug: "pro", Amount: "99", Currency: "usd", Interval: "month"},
		{Slug: "pro", Amount: "29", Currency: "eur", Interval: "month"},
		{Slug: "pro", Amount: "29", Currency: "usd", Interval: "year"},
	} {
		_, err := r.h.CreatePlan(bg, c)
		wantCode(t, err, codes.AlreadyExists, "plan with different terms")
	}
	if n := r.stripe.count("/v1/prices"); n != 1 {
		t.Errorf("provider prices = %d, want 1", n)
	}
	// Losing the insert race to a same-terms plan adopts it; to a
	// different-terms plan refuses.
	r.store.onceBefore("CreatePlan", func() {
		_, _ = r.store.CreatePlan(bg, &pb.CreatePlanReq{Slug: "team", Amount: "49", Currency: "usd", Interval: "month", ProviderPriceId: "price_winner"})
	})
	won, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "team", Amount: "49.0", Currency: "usd", Interval: "month"})
	if err != nil || won.GetPlan().GetProviderPriceId() != "price_winner" {
		t.Fatalf("race, same terms: %v / %v", won, err)
	}
	r.store.onceBefore("CreatePlan", func() {
		_, _ = r.store.CreatePlan(bg, &pb.CreatePlanReq{Slug: "biz", Amount: "1", Currency: "usd", Interval: "month"})
	})
	_, err = r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "biz", Amount: "2", Currency: "usd", Interval: "month"})
	wantCode(t, err, codes.AlreadyExists, "race, different terms")
}

func TestFlow_CreatePlan_Refusals(t *testing.T) {
	r := newRig(t)
	for _, c := range []*pb.DefinePlanReq{
		{Slug: "", Amount: "1", Currency: "usd", Interval: "month"},
		{Slug: "x", Amount: "", Currency: "usd", Interval: "month"},
		{Slug: "x", Amount: "1", Currency: " ", Interval: "month"},
		{Slug: "x", Amount: "1", Currency: "usdx", Interval: "month"},
		{Slug: "x", Amount: "1.00001", Currency: "usd", Interval: "month"},
		{Slug: "x", Amount: "1", Currency: "usd", Interval: "day"},
	} {
		_, err := r.h.CreatePlan(bg, c)
		wantCode(t, err, codes.InvalidArgument, "plan "+c.String())
	}
	// A provider-side refusal of the price (fractional yen) is the
	// caller's error, and nothing is recorded.
	_, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "yen", Amount: "100.5", Currency: "jpy", Interval: "month"})
	wantCode(t, err, codes.InvalidArgument, "fractional jpy price")
	if r.store.count("plans") != 0 || r.stripe.count("/v1/prices") != 0 {
		t.Error("a refused plan reached the provider or the store")
	}
}

// ── prepaid ──────────────────────────────────────────────────────────

func TestFlow_Credit_SpendGrantInvariants(t *testing.T) {
	r := newRig(t)
	grant := func(amount, key string) (*pb.CreditView, error) {
		return r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: amount, IdempotencyKey: key})
	}
	spend := func(amount, key string) (*pb.CreditView, error) {
		return r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: amount, IdempotencyKey: key})
	}
	if v, err := grant("10", "g1"); err != nil || v.GetBalance() != "10.0000" {
		t.Fatalf("grant: %v %v", v, err)
	}
	// Whitespace around the amount used to become the delta "- 4.5".
	if v, err := spend(" 4.5 ", "s1"); err != nil || v.GetBalance() != "5.5000" {
		t.Fatalf("spend with whitespace: %v %v", v, err)
	}
	// Retried spend: no second deduction.
	if v, err := spend(" 4.5 ", "s1"); err != nil || v.GetBalance() != "5.5000" {
		t.Fatalf("retried spend: %v %v", v, err)
	}
	// Overdraw: refused, nothing written.
	ledger := r.store.count("ledger")
	_, err := spend("5.5001", "s2")
	wantCode(t, err, codes.FailedPrecondition, "overdraw")
	if r.store.count("ledger") != ledger || r.store.balance(t, "user-a") != "5.5000" {
		t.Error("a refused overdraw changed the ledger or balance")
	}
	// Spending to exactly zero is allowed.
	if v, err := spend("5.5", "s3"); err != nil || v.GetBalance() != "0.0000" {
		t.Fatalf("spend to zero: %v %v", v, err)
	}
	// Sub-scale amounts were silently rounded by the column (a grant of
	// 0.00004 stored a zero delta); they are refused now.
	_, err = grant("0.00004", "g-tiny")
	wantCode(t, err, codes.InvalidArgument, "sub-scale grant")
	// Another principal's balance is untouched throughout.
	if b := r.store.balance(t, "user-b"); b != "0.0000" {
		t.Errorf("user-b balance = %s", b)
	}
	// Balance read for a principal with no row is "0".
	v, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-c", Amount: "1", IdempotencyKey: "g1"})
	_ = v
	if err != nil {
		t.Fatalf("grant user-c: %v", err)
	}
}

// The ledger key column is one table-wide UNIQUE and a duplicate is
// answered with SUCCESS. With the caller's raw key stored, a reused key
// was a silent no-op reported as done: user-b's grant under user-a's key
// granted nothing; a spend reusing a grant's key deducted nothing (the
// service was delivered for free). Keys are scoped per (kind, principal).
func TestFlow_Credit_KeyReuseAcrossPrincipalsAndKinds_IsNotASilentNoOp(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "100", IdempotencyKey: "order-1"}); err != nil {
		t.Fatal(err)
	}
	v, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-b", Amount: "1", IdempotencyKey: "order-1"})
	if err != nil {
		t.Fatal(err)
	}
	if v.GetUserId() != "user-b" || v.GetBalance() != "1.0000" {
		t.Errorf("user-b's grant under a key user-a used = %+v, want balance 1.0000", v)
	}
	v, err = r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "30", IdempotencyKey: "order-1"})
	if err != nil {
		t.Fatal(err)
	}
	if v.GetBalance() != "70.0000" {
		t.Errorf("spend reusing the grant's key: balance %s, want 70.0000 — it was a free spend", v.GetBalance())
	}
	// A caller grant cannot pre-empt the top-up grant keyed on a payment id.
	pid := r.topUp("user-a", "5", "t").GetProviderPaymentId()
	if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: pid}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.deliver(eventJSON("evt_pre", "payment_intent.succeeded", pid, nil)); err != nil {
		t.Fatal(err)
	}
	if b := r.store.balance(t, "user-a"); b != "76.0000" {
		t.Errorf("balance = %s, want 76.0000 (70 + 1 grant + 5 top-up)", b)
	}
}

func TestFlow_Usage_KeyReuseAcrossPrincipalsAndMeters_IsNotASilentNoOp(t *testing.T) {
	r := newRig(t)
	report := func(user, meter string) int64 {
		v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: user, Meter: meter, Period: "2026-06", Quantity: 4, IdempotencyKey: "job-1"})
		if err != nil {
			t.Fatal(err)
		}
		return v.GetTotal()
	}
	if got := report("user-a", "renders"); got != 4 {
		t.Fatalf("a: %d", got)
	}
	if got := report("user-b", "renders"); got != 4 {
		t.Errorf("user-b's usage under a key user-a used recorded %d, want 4", got)
	}
	if got := report("user-a", "seconds"); got != 4 {
		t.Errorf("another meter under the same key recorded %d, want 4", got)
	}
	if got := report("user-a", "renders"); got != 4 {
		t.Errorf("a genuine retry counted again: %d", got)
	}
}

func TestFlow_Credit_ConcurrentSpendsNeverOverdraw(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "10", IdempotencyKey: "g"}); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "spend-" + string(rune('a'+i))})
			mu.Lock()
			defer mu.Unlock()
			switch status.Code(err) {
			case codes.OK:
				ok++
			case codes.FailedPrecondition:
				refused++
			default:
				t.Errorf("spend %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 10 || refused != 10 {
		t.Errorf("spends ok=%d refused=%d, want 10/10", ok, refused)
	}
	if b := r.store.balance(t, "user-a"); b != "0.0000" {
		t.Errorf("balance = %s, want 0.0000", b)
	}
}

// ── usage ────────────────────────────────────────────────────────────

func TestFlow_Usage_ConcurrentRetriesCountOnce(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"})
			if err != nil || v.GetTotal() != 7 {
				t.Errorf("report: %v %v", v, err)
			}
		}()
	}
	wg.Wait()
	v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 3, IdempotencyKey: "batch-2"})
	if err != nil || v.GetTotal() != 10 {
		t.Fatalf("second batch: %v %v", v, err)
	}
	// Another period / principal is a separate meter.
	v, err = r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-b", Meter: "api_calls", Period: "2026-06", Quantity: 1, IdempotencyKey: "b-1"})
	if err != nil || v.GetTotal() != 1 {
		t.Fatalf("user-b: %v %v", v, err)
	}
	if r.store.events("UsageRecorded") != 3 {
		t.Errorf("UsageRecorded = %d, want 3", r.store.events("UsageRecorded"))
	}
}

func TestFlow_Usage_TransientFailureSurfaces(t *testing.T) {
	r := newRig(t)
	r.store.injectBefore("RecordUsage", errTransient)
	_, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "m", Period: "p", Quantity: 1, IdempotencyKey: "k"})
	wantCode(t, err, codes.Unavailable, "transient record")
	// duplicate whose meter read fails
	if _, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "m", Period: "p", Quantity: 1, IdempotencyKey: "k"}); err != nil {
		t.Fatal(err)
	}
	r.store.injectBefore("GetUsageMeter", errTransient)
	_, err = r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "m", Period: "p", Quantity: 1, IdempotencyKey: "k"})
	wantCode(t, err, codes.Unavailable, "transient meter read on the duplicate path")
	_, err = r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "m", Period: "p", Quantity: 1, IdempotencyKey: strings.Repeat("k", 256)})
	wantCode(t, err, codes.InvalidArgument, "256-byte key")
}

// ── store failures on the read paths surface verbatim ─────────────────

func TestFlow_StoreReadFailuresSurface(t *testing.T) {
	cases := []struct {
		method string
		call   func(r *rig) error
	}{
		{"GetCustomerByUserId", func(r *rig) error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"})
			return err
		}},
		{"GetCustomerByUserId", func(r *rig) error {
			_, err := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a"})
			return err
		}},
		{"GetPayment", func(r *rig) error {
			_, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: "p", IdempotencyKey: "k"})
			return err
		}},
		{"GetPlanBySlug", func(r *rig) error {
			_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: "k"})
			return err
		}},
		{"GetPlanBySlug", func(r *rig) error {
			_, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "1", Currency: "usd", Interval: "month"})
			return err
		}},
		{"CreatePayment", func(r *rig) error {
			_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"})
			return err
		}},
		{"CreateCustomer", func(r *rig) error {
			_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"})
			return err
		}},
		{"GetCreditBalance", func(r *rig) error {
			if _, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"}); err != nil {
				return err
			}
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"})
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			r := newRig(t)
			r.store.injectBefore(c.method, errTransient)
			if err := c.call(r); status.Code(err) != codes.Unavailable {
				t.Fatalf("want the store's Unavailable surfaced, got %v", err)
			}
		})
	}
}

// A store failure on the replay lookup after a unique violation is
// surfaced, not turned into an AlreadyExists.
func TestFlow_ReplayLookupFailureSurfaces(t *testing.T) {
	r := newRig(t)
	r.charge("user-a", "1.00", "k")
	r.store.injectBefore("GetPaymentByProviderId", errTransient)
	_, err := r.h.CreatePayment(bg, &pb.ChargeReq{UserId: "user-a", Amount: "1.00", IdempotencyKey: "k"})
	wantCode(t, err, codes.Unavailable, "lookup failure on the replay path")

	p := r.charge("user-a", "5", "k2")
	if _, err := r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "1", IdempotencyKey: "rk"}); err != nil {
		t.Fatal(err)
	}
	r.store.injectBefore("GetRefundByProviderId", errTransient)
	_, err = r.h.RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: p.GetId(), Amount: "1", IdempotencyKey: "rk"})
	wantCode(t, err, codes.Unavailable, "refund lookup failure")
	if errors.Is(err, errNoLocalRecord) {
		t.Error("unexpected sentinel")
	}
}

func TestFlow_SubscriptionFailurePaths(t *testing.T) {
	setup := func(t *testing.T) *rig {
		r := newRig(t)
		if _, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"}); err != nil {
			t.Fatal(err)
		}
		return r
	}
	sub := func(r *rig, key string) error {
		_, err := r.h.Subscribe(bg, &pb.SubscribeReq{UserId: "user-a", PlanSlug: "pro", IdempotencyKey: key})
		return err
	}
	t.Run("customer resolve fails", func(t *testing.T) {
		r := setup(t)
		r.store.injectBefore("GetCustomerByUserId", errTransient)
		wantCode(t, sub(r, "k"), codes.Unavailable, "subscribe")
	})
	t.Run("card declined at the provider", func(t *testing.T) {
		r := setup(t)
		c, _ := r.h.CreateCustomer(bg, &pb.NewCustomerReq{UserId: "user-a"})
		r.stripe.failNext(http.StatusPaymentRequired)
		wantCode(t, sub(r, "k"), codes.FailedPrecondition, "declined subscribe")
		if r.store.count("subs") != 0 {
			t.Error("a declined subscription was recorded")
		}
		_ = c
	})
	t.Run("replay lookup fails", func(t *testing.T) {
		r := setup(t)
		if err := sub(r, "k"); err != nil {
			t.Fatal(err)
		}
		r.store.injectBefore("GetSubscriptionByProviderId", errTransient)
		wantCode(t, sub(r, "k"), codes.Unavailable, "replay lookup")
	})
	t.Run("webhook lookup fails", func(t *testing.T) {
		r := setup(t)
		_, _ = r.store.CreateSubscription(bg, &pb.CreateSubscriptionReq{ProviderSubscriptionId: "sub_c", Status: int32(pb.Subscription_CANCELED)})
		r.store.injectBefore("GetSubscriptionByProviderId", errTransient)
		_, err := r.deliver(eventJSON("evt_l", "customer.subscription.updated", "sub_c", map[string]any{"status": "active"}))
		wantCode(t, err, codes.Unavailable, "lookup after a refused guard")
		if r.store.isProcessed("evt_l") {
			t.Error("recorded despite the failure")
		}
	})
	t.Run("plan insert fails", func(t *testing.T) {
		r := newRig(t)
		r.store.injectBefore("CreatePlan", errTransient)
		_, err := r.h.CreatePlan(bg, &pb.DefinePlanReq{Slug: "pro", Amount: "29", Currency: "usd", Interval: "month"})
		wantCode(t, err, codes.Unavailable, "plan insert")
	})
}

func TestFlow_TopUpFailurePaths(t *testing.T) {
	r := newRig(t)
	r.store.injectBefore("GetCustomerByUserId", errTransient)
	_, err := r.h.TopUpCredit(bg, &pb.TopUpCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "k"})
	wantCode(t, err, codes.Unavailable, "customer resolve")

	// The hook ignores an event without a payment id and touches nothing.
	before := r.store.callCount("GetCreditTopupByProviderId")
	if err := grantTopupOnPaymentSuccess(bg, r.h, stripeEvent("", "")); err != nil {
		t.Fatal(err)
	}
	if r.store.callCount("GetCreditTopupByProviderId") != before {
		t.Error("hook queried the store for an empty payment id")
	}
}

// A concurrent delivery stamped granted_at between this delivery's grant
// and its stamp: the guarded stamp matches nothing (NotFound). The grant
// is done; failing here only made the provider redeliver a fully applied
// event (and alarm on the endpoint).
func TestFlow_TopUpStampLostToAConcurrentDelivery_IsNotAFailure(t *testing.T) {
	r := newRig(t)
	pid := r.topUp("user-a", "20.00", "top-c").GetProviderPaymentId()
	r.store.onceBefore("MarkTopupGranted", func() {
		if _, err := r.store.MarkTopupGranted(bg, &pb.MarkTopupGrantedReq{ProviderPaymentId: pid}); err != nil {
			t.Errorf("concurrent stamp: %v", err)
		}
	})
	resp, err := r.deliver(eventJSON("evt_c", "payment_intent.succeeded", pid, nil))
	if err != nil || !resp.GetHandled() {
		t.Fatalf("handled=%v err=%v", resp.GetHandled(), err)
	}
	if b := r.store.balance(t, "user-a"); b != "20.0000" {
		t.Errorf("balance = %s", b)
	}
}

// The refund amount is validated by the HANDLER, not left to whichever
// driver is configured: a non-positive or over-precise amount never
// reaches Backend.RefundPayment.
func TestRefundPayment_ValidatesAmountBeforeTheBackend(t *testing.T) {
	q := &fakeQuery{payment: &pb.Payment{Id: "pay-1", ProviderPaymentId: "pi_1", Amount: "20.0000", Currency: "usd"}}
	for _, amt := range []string{"-5.00", "0", "5.00001", "1e2", "abc"} {
		be := &fakeBackend{}
		_, err := newHandler(q, &fakeMutation{}, be).RefundPayment(bg, &pb.RefundPaymentReq{PaymentId: "pay-1", Amount: amt, IdempotencyKey: "k"})
		wantCode(t, err, codes.InvalidArgument, "refund "+amt)
		if be.lastRefundFor != "" {
			t.Errorf("amount %q reached the backend", amt)
		}
	}
}

func TestMetadataValue_KeyAbsent(t *testing.T) {
	ctx := metadata.NewIncomingContext(bg, metadata.Pairs("x-other", "v"))
	if metadataValue(ctx, "stripe-signature") != "" {
		t.Error("absent key must read empty")
	}
}
