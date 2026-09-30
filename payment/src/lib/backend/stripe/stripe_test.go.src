package stripe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
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
	var gotAmount, gotCurrency, gotCustomer, gotIdem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/payment_intents" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = r.ParseForm()
		gotAmount = r.Form.Get("amount")
		gotCurrency = r.Form.Get("currency")
		gotCustomer = r.Form.Get("customer")
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
	var customer, price, idem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/subscriptions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = r.ParseForm()
		customer = r.Form.Get("customer")
		price = r.Form.Get("items[0][price]")
		idem = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sub_1","status":"active","current_period_end":1893456000}`))
	}))
	defer srv.Close()

	res, err := testBackend(srv).StartSubscription(context.Background(), backend.SubscriptionSpec{
		ProviderCustomerID: "cus_1", ProviderPriceID: "price_1", IdempotencyKey: "sub:u1:pro",
	})
	if err != nil {
		t.Fatalf("StartSubscription: %v", err)
	}
	if customer != "cus_1" || price != "price_1" || idem != "sub:u1:pro" {
		t.Errorf("form: customer=%q price=%q idem=%q", customer, price, idem)
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
