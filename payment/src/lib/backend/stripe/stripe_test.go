package stripe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// testBackend points a real *Backend at an httptest server (same-package
// access to the unexported fields).
func testBackend(srv *httptest.Server) *Backend {
	return &Backend{apiKey: "sk_test", baseURL: srv.URL, httpClient: &http.Client{Timeout: 5 * time.Second}}
}

func TestEnsureCustomer(t *testing.T) {
	var gotAuth, gotEmail, gotMeta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/customers" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = r.ParseForm()
		gotAuth = r.Header.Get("Authorization")
		gotEmail = r.Form.Get("email")
		gotMeta = r.Form.Get("metadata[user_id]")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cus_123"}`))
	}))
	defer srv.Close()

	id, err := testBackend(srv).EnsureCustomer(context.Background(), backend.CustomerSpec{UserID: "u1", Email: "a@b.c"})
	if err != nil {
		t.Fatalf("EnsureCustomer: %v", err)
	}
	if id != "cus_123" {
		t.Errorf("id = %q, want cus_123", id)
	}
	if gotAuth != "Bearer sk_test" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotEmail != "a@b.c" || gotMeta != "u1" {
		t.Errorf("form: email=%q meta=%q", gotEmail, gotMeta)
	}
}

func TestCreatePayment(t *testing.T) {
	var gotAmount, gotCurrency, gotCustomer, gotIdem, gotOrigin, gotInstall string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/payment_intents" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = r.ParseForm()
		gotAmount = r.Form.Get("amount")
		gotCurrency = r.Form.Get("currency")
		gotCustomer = r.Form.Get("customer")
		gotOrigin = r.Form.Get("metadata[w17_payment]")
		gotInstall = r.Form.Get("metadata[w17_install]")
		gotIdem = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"pi_1","status":"requires_confirmation","client_secret":"pi_1_secret"}`))
	}))
	defer srv.Close()

	res, err := testBackend(srv).CreatePayment(context.Background(), backend.PaymentSpec{
		ProviderCustomerID: "cus_1",
		Amount:             backend.Money{Amount: "19.99", Currency: "USD"},
		IdempotencyKey:     "idem-1",
		Description:        "pro",
		Origin:             backend.OriginTopup,
		Install:            "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("CreatePayment: %v", err)
	}
	if gotAmount != "1999" {
		t.Errorf("amount = %q, want 1999 (minor units)", gotAmount)
	}
	if gotCurrency != "usd" {
		t.Errorf("currency = %q, want usd", gotCurrency)
	}
	if gotCustomer != "cus_1" {
		t.Errorf("customer = %q", gotCustomer)
	}
	if gotIdem != "idem-1" {
		t.Errorf("idempotency-key = %q", gotIdem)
	}
	if gotOrigin != "topup" {
		t.Errorf("metadata[w17_payment] = %q, want topup — the webhook tells the plugin's objects apart by it", gotOrigin)
	}
	if gotInstall != "0123456789abcdef" {
		t.Errorf("metadata[w17_install] = %q — without it another installation on the account cannot tell the object is not its own", gotInstall)
	}
	if res.ProviderPaymentID != "pi_1" || res.ClientSecret != "pi_1_secret" || res.Status != "requires_confirmation" {
		t.Errorf("result = %+v", res)
	}
}

func TestRefundPayment(t *testing.T) {
	var pi, amount string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/refunds" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		pi = r.Form.Get("payment_intent")
		amount = r.Form.Get("amount")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"re_1","status":"succeeded"}`))
	}))
	defer srv.Close()

	res, err := testBackend(srv).RefundPayment(context.Background(), "pi_7", backend.Money{Amount: "5.00", Currency: "usd"}, "refund:pay-7:5.00")
	if err != nil {
		t.Fatalf("RefundPayment: %v", err)
	}
	if pi != "pi_7" || amount != "500" {
		t.Errorf("form: payment_intent=%q amount=%q (want pi_7 / 500 minor units)", pi, amount)
	}
	if res.ProviderRefundID != "re_1" {
		t.Errorf("refund id = %q", res.ProviderRefundID)
	}
}

func TestUpsertPlan(t *testing.T) {
	var amount, currency, interval, name string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/prices" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		amount = r.Form.Get("unit_amount")
		currency = r.Form.Get("currency")
		interval = r.Form.Get("recurring[interval]")
		name = r.Form.Get("product_data[name]")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"price_1"}`))
	}))
	defer srv.Close()

	id, err := testBackend(srv).UpsertPlan(context.Background(), backend.PlanSpec{
		Slug: "pro", Name: "Pro", Amount: backend.Money{Amount: "29.00", Currency: "USD"}, Interval: "month",
	})
	if err != nil {
		t.Fatalf("UpsertPlan: %v", err)
	}
	if id != "price_1" {
		t.Errorf("id = %q", id)
	}
	if amount != "2900" || currency != "usd" || interval != "month" || name != "Pro" {
		t.Errorf("form: amount=%q currency=%q interval=%q name=%q", amount, currency, interval, name)
	}
}

func TestStartSubscription(t *testing.T) {
	var customer, price, idem, origin, install string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		customer = r.Form.Get("customer")
		price = r.Form.Get("items[0][price]")
		origin = r.Form.Get("metadata[w17_payment]")
		install = r.Form.Get("metadata[w17_install]")
		idem = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sub_1","status":"active","current_period_end":1893456000}`))
	}))
	defer srv.Close()

	res, err := testBackend(srv).StartSubscription(context.Background(), backend.SubscriptionSpec{
		ProviderCustomerID: "cus_1", ProviderPriceID: "price_1", IdempotencyKey: "sub:u1:pro", Install: "fedcba9876543210",
	})
	if err != nil {
		t.Fatalf("StartSubscription: %v", err)
	}
	if customer != "cus_1" || price != "price_1" || idem != "sub:u1:pro" || origin != "subscription" || install != "fedcba9876543210" {
		t.Errorf("form: customer=%q price=%q idem=%q origin=%q install=%q", customer, price, idem, origin, install)
	}
	if res.ProviderSubscriptionID != "sub_1" || res.Status != "active" || res.CurrentPeriodEnd != 1893456000 {
		t.Errorf("result = %+v", res)
	}
}

func TestCreatePayment_StripeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"Your card was declined.","type":"card_error"}}`))
	}))
	defer srv.Close()

	_, err := testBackend(srv).CreatePayment(context.Background(), backend.PaymentSpec{
		Amount: backend.Money{Amount: "5.00", Currency: "usd"},
	})
	if err == nil {
		t.Fatal("want error on stripe 400")
	}
}

// GetPayment reads one intent by id and answers it in the provider-neutral
// form; an id the provider does not know, or an answer for another id, is an
// error — RefundPayment must never proceed on an empty object.
func TestGetPayment(t *testing.T) {
	var gotPath, gotMethod, gotURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotURI = r.URL.Path, r.Method, r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/payment_intents/pi_1":
			_, _ = w.Write([]byte(`{"id":"pi_1","status":"succeeded","amount":1999,"amount_received":999,"currency":"USD","customer":"cus_1","metadata":{"w17_payment":"charge"}}`))
		case "/v1/payment_intents/pi_other":
			_, _ = w.Write([]byte(`{"id":"pi_1","status":"succeeded","amount":1999,"currency":"usd"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"No such payment_intent"}}`))
		}
	}))
	defer srv.Close()
	b := testBackend(srv)

	p, err := b.GetPayment(context.Background(), "pi_1")
	if err != nil {
		t.Fatalf("GetPayment: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/payment_intents/pi_1" {
		t.Errorf("request %s %s", gotMethod, gotPath)
	}
	if p.ProviderPaymentID != "pi_1" || p.Status != "succeeded" || p.Amount.Amount != "19.99" || p.Amount.Currency != "usd" || p.ProviderCustomerID != "cus_1" ||
		p.Received != (backend.Money{Amount: "9.99", Currency: "usd"}) {
		t.Errorf("payment = %+v", p)
	}
	if _, err := b.GetPayment(context.Background(), "pi_missing"); err == nil {
		t.Error("an unknown intent answered without an error")
	}
	if _, err := b.GetPayment(context.Background(), "pi_other"); err == nil {
		t.Error("an answer for another intent was accepted")
	}
	if _, err := b.GetPayment(context.Background(), ""); !errors.Is(err, backend.ErrInvalidRequest) {
		t.Errorf("an empty id: %v, want ErrInvalidRequest", err)
	}
	// The id is one path segment, whatever it holds.
	if _, err := b.GetPayment(context.Background(), "pi_1/../../v1/refunds"); err == nil || !strings.HasPrefix(gotURI, "/v1/payment_intents/pi_1%2F..%2F..%2Fv1%2Frefunds") {
		t.Errorf("an id with a path in it was sent as %s (err %v)", gotURI, err)
	}
}
