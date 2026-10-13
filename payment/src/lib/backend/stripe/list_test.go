package stripe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// listServer answers GET path with body and records the query it was sent.
func listServer(t *testing.T, path, body string, got *url.Values) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != path {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		*got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Every account-wide list sends the walk's bounds as the provider names them:
// created[gte], limit (clamped to the provider's 1..100) and starting_after.
func TestListPages_SendTheBounds(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/customers", `{"data":[],"has_more":false}`, &got)
	b := testBackend(srv)
	if _, _, err := b.ListCustomerPage(context.Background(), backend.ListQuery{Since: 1700000000, After: "cus_9", Limit: 25}); err != nil {
		t.Fatal(err)
	}
	if got.Get("created[gte]") != "1700000000" || got.Get("starting_after") != "cus_9" || got.Get("limit") != "25" {
		t.Errorf("query = %v", got)
	}
	for _, n := range []int{0, -1, 101} {
		if _, _, err := b.ListCustomerPage(context.Background(), backend.ListQuery{Limit: n}); err != nil {
			t.Fatal(err)
		}
		if got.Get("limit") != "100" || got.Has("created[gte]") || got.Has("starting_after") {
			t.Errorf("limit %d: query = %v", n, got)
		}
	}
}

func TestListCustomerPage_ReadsThePrincipalAndTheMarks(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/customers", `{"data":[
		{"id":"cus_1","email":"a@example.com","metadata":{"user_id":"u1","w17_payment":"customer","w17_install":"abc"}},
		{"id":"cus_2","metadata":{}}],"has_more":true}`, &got)
	cs, more, err := testBackend(srv).ListCustomerPage(context.Background(), backend.ListQuery{})
	if err != nil || !more || len(cs) != 2 {
		t.Fatalf("got %+v more=%v err=%v", cs, more, err)
	}
	want := backend.CustomerObject{ProviderCustomerID: "cus_1", UserID: "u1", Email: "a@example.com", Marks: backend.Marks{Origin: "customer", Install: "abc"}}
	if cs[0] != want {
		t.Errorf("cs[0] = %+v, want %+v", cs[0], want)
	}
	if cs[1].Origin != "" || cs[1].Install != "" || cs[1].UserID != "" {
		t.Errorf("an unmarked customer read marks: %+v", cs[1])
	}
}

// A failed attempt leaves the intent requires_payment_method WITH an error;
// a fresh one has the same status and a null error.
func TestListPaymentPage_TellsAFailedAttemptFromAnOpenIntent(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/payment_intents", `{"data":[
		{"id":"pi_1","status":"requires_payment_method","amount":1999,"currency":"USD","customer":"cus_1","description":"credit top-up",
		 "metadata":{"w17_payment":"topup","w17_install":"abc"},"last_payment_error":{"code":"card_declined"}},
		{"id":"pi_2","status":"requires_payment_method","amount":500,"currency":"usd","customer":"cus_1","last_payment_error":null},
		{"id":"pi_3","status":"succeeded","amount":500,"currency":"usd"}],"has_more":false}`, &got)
	ps, more, err := testBackend(srv).ListPaymentPage(context.Background(), backend.ListQuery{})
	if err != nil || more || len(ps) != 3 {
		t.Fatalf("got %+v more=%v err=%v", ps, more, err)
	}
	want := backend.PaymentObject{
		ProviderPaymentID: "pi_1", ProviderCustomerID: "cus_1", Status: "requires_payment_method",
		Amount: backend.Money{Amount: "19.99", Currency: "usd"}, Description: "credit top-up", Failed: true,
		Marks: backend.Marks{Origin: "topup", Install: "abc"},
	}
	if ps[0] != want {
		t.Errorf("ps[0] = %+v, want %+v", ps[0], want)
	}
	if ps[1].Failed || ps[2].Failed {
		t.Errorf("an intent without a failed attempt read failed: %+v / %+v", ps[1], ps[2])
	}
}

func TestListRefundPage_NamesThePayment(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/refunds", `{"data":[
		{"id":"re_1","status":"pending","amount":400,"currency":"usd","payment_intent":"pi_1","metadata":{"w17_refund":"k"}}],"has_more":false}`, &got)
	rs, _, err := testBackend(srv).ListRefundPage(context.Background(), backend.ListQuery{})
	if err != nil || len(rs) != 1 {
		t.Fatalf("got %+v err=%v", rs, err)
	}
	if got.Has("payment_intent") {
		t.Errorf("the account-wide list was filtered: %v", got)
	}
	r := rs[0]
	if r.ProviderPaymentID != "pi_1" || r.ProviderRefundID != "re_1" || r.Status != "pending" || r.Amount.Amount != "4.00" || r.Key != "k" {
		t.Errorf("refund = %+v", r)
	}
}

// Subscriptions are listed in every status (the provider leaves canceled ones
// out unless asked), with their customer, price and marks.
func TestListSubscriptionPage_AllStatuses(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/subscriptions", `{"data":[
		{"id":"sub_1","status":"canceled","customer":"cus_1","current_period_end":1893456000,
		 "metadata":{"w17_payment":"subscription","w17_install":"abc"},"items":{"data":[{"price":{"id":"price_1"}}]}}],"has_more":false}`, &got)
	ss, _, err := testBackend(srv).ListSubscriptionPage(context.Background(), backend.ListQuery{})
	if err != nil || len(ss) != 1 {
		t.Fatalf("got %+v err=%v", ss, err)
	}
	if got.Get("status") != "all" || got.Has("customer") {
		t.Errorf("query = %v", got)
	}
	s := ss[0]
	if s.ProviderSubscriptionID != "sub_1" || s.ProviderCustomerID != "cus_1" || s.ProviderPriceID != "price_1" ||
		s.Status != "canceled" || s.CurrentPeriodEnd != 1893456000 || s.Origin != "subscription" || s.Install != "abc" {
		t.Errorf("subscription = %+v", s)
	}
}

func TestListPages_RefuseAnObjectWithoutAnID(t *testing.T) {
	ctx := context.Background()
	for path, call := range map[string]func(*Backend) error{
		"/v1/customers":       func(b *Backend) error { _, _, err := b.ListCustomerPage(ctx, backend.ListQuery{}); return err },
		"/v1/payment_intents": func(b *Backend) error { _, _, err := b.ListPaymentPage(ctx, backend.ListQuery{}); return err },
		"/v1/refunds":         func(b *Backend) error { _, _, err := b.ListRefundPage(ctx, backend.ListQuery{}); return err },
		"/v1/subscriptions":   func(b *Backend) error { _, _, err := b.ListSubscriptionPage(ctx, backend.ListQuery{}); return err },
	} {
		var got url.Values
		srv := listServer(t, path, `{"data":[{"status":"x"}],"has_more":false}`, &got)
		if err := call(testBackend(srv)); err == nil {
			t.Errorf("%s: an object without an id was accepted", path)
		}
	}
}

// EnsureCustomer marks the customer as this installation's, as every other
// create does; without an installation id it marks nothing.
func TestEnsureCustomer_MarksTheCustomer(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		_, _ = w.Write([]byte(`{"id":"cus_1"}`))
	}))
	defer srv.Close()
	b := testBackend(srv)
	if _, err := b.EnsureCustomer(context.Background(), backend.CustomerSpec{UserID: "u1", Install: "abc"}); err != nil {
		t.Fatal(err)
	}
	if form.Get("metadata[w17_payment]") != backend.OriginCustomer || form.Get("metadata[w17_install]") != "abc" || form.Get("metadata[user_id]") != "u1" {
		t.Errorf("form = %v", form)
	}
	if _, err := b.EnsureCustomer(context.Background(), backend.CustomerSpec{UserID: "u1"}); err != nil {
		t.Fatal(err)
	}
	if form.Has("metadata[w17_payment]") || form.Has("metadata[w17_install]") {
		t.Errorf("marked without an installation id: %v", form)
	}
}

// created[lte] bounds a walk that continues from a creation time; every
// listed object carries its own.
func TestListPages_UntilAndCreated(t *testing.T) {
	var got url.Values
	srv := listServer(t, "/v1/refunds", `{"data":[{"id":"re_1","created":1700000123,"currency":"usd"}],"has_more":false}`, &got)
	rs, _, err := testBackend(srv).ListRefundPage(context.Background(), backend.ListQuery{Until: 1700000200})
	if err != nil || len(rs) != 1 {
		t.Fatalf("got %+v err=%v", rs, err)
	}
	if got.Get("created[lte]") != "1700000200" {
		t.Errorf("query = %v", got)
	}
	if rs[0].Created != 1700000123 {
		t.Errorf("created = %d", rs[0].Created)
	}
}

// Paging after an object the provider no longer has is ErrListCursorGone; the
// same refusal without starting_after is not.
func TestListPages_ACursorAtAGoneObject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","code":"resource_missing","message":"No such customer: 'cus_9'"}}`))
	}))
	defer srv.Close()
	b := testBackend(srv)
	_, _, err := b.ListCustomerPage(context.Background(), backend.ListQuery{After: "cus_9"})
	if !errors.Is(err, backend.ErrListCursorGone) || !errors.Is(err, backend.ErrInvalidRequest) {
		t.Errorf("after a gone object: %v", err)
	}
	if _, _, err := b.ListCustomerPage(context.Background(), backend.ListQuery{}); errors.Is(err, backend.ErrListCursorGone) || err == nil {
		t.Errorf("without a cursor: %v", err)
	}
}

// A subscription list carries the provider's clock at the answer (its Date),
// the clock its events are stamped with.
func TestListSubscriptionPage_ReadsTheProvidersClock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Tue, 14 Nov 2023 22:13:20 GMT") // 1700000000
		_, _ = w.Write([]byte(`{"data":[{"id":"sub_1","status":"active"}],"has_more":false}`))
	}))
	defer srv.Close()
	ss, _, err := testBackend(srv).ListSubscriptionPage(context.Background(), backend.ListQuery{})
	if err != nil || len(ss) != 1 || ss[0].ReadAt != 1700000000 {
		t.Fatalf("got %+v err=%v", ss, err)
	}
}
