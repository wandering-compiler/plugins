package stripe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

// ── amounts ──────────────────────────────────────────────────────────

// The minor-unit accumulation wrapped silently past int64: "184467440737
// 095516.17" usd is 2^64+1 cents and went out as amount=1 — the provider
// charged one cent while the caller and the local row held the request.
func TestToMinorUnits_RefusesOverflowInsteadOfWrapping(t *testing.T) {
	for _, c := range []struct{ amount, currency string }{
		{"184467440737095516.17", "usd"}, // 2^64 + 1 cents → used to become 1
		{"92233720368547758.08", "usd"},  // MaxInt64 + 1 cents
		{"9223372036854775808", "jpy"},   // MaxInt64 + 1, zero-decimal
		{"-92233720368547758.09", "usd"},
		{strings.Repeat("9", 30), "usd"},
	} {
		got, err := toMinorUnits(c.amount, c.currency)
		if err == nil {
			t.Errorf("toMinorUnits(%q, %s) = %d, want an overflow refusal", c.amount, c.currency, got)
			continue
		}
		if !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("overflow must be classed ErrInvalidRequest, got %v", err)
		}
	}
	// The boundary itself converts exactly.
	if got, err := toMinorUnits("92233720368547758.07", "usd"); err != nil || got != 9223372036854775807 {
		t.Errorf("MaxInt64 cents: %d, %v", got, err)
	}
	if got, err := toMinorUnits("9223372036854775807", "jpy"); err != nil || got != 9223372036854775807 {
		t.Errorf("MaxInt64 yen: %d, %v", got, err)
	}
}

// Storage hands amounts back as DECIMAL(20, 4) — "12.3400". Refusing the
// two zero digits past the currency scale refused every stored amount:
// every full refund (which sends the stored payment amount) failed.
func TestToMinorUnits_AcceptsStoredScaleTrailingZeros(t *testing.T) {
	for _, c := range []struct {
		amount, currency string
		want             int64
	}{
		{"12.3400", "usd", 1234},
		{"20.0000", "usd", 2000},
		{"1000.0000", "jpy", 1000},
		{"0.5000", "eur", 50},
		{"5.", "usd", 500},
		{".5", "usd", 50},
		{"+7", "usd", 700},
		{" 3.10 ", "usd", 310},
	} {
		got, err := toMinorUnits(c.amount, c.currency)
		if err != nil || got != c.want {
			t.Errorf("toMinorUnits(%q, %s) = %d, %v; want %d", c.amount, c.currency, got, err, c.want)
		}
	}
	// A NON-zero digit past the scale is still refused — no silent rounding.
	for _, c := range []struct{ amount, currency string }{{"12.3401", "usd"}, {"1000.5000", "jpy"}, {"0.001", "usd"}} {
		if _, err := toMinorUnits(c.amount, c.currency); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("toMinorUnits(%q, %s): want ErrInvalidRequest, got %v", c.amount, c.currency, err)
		}
	}
	for _, bad := range []string{"-", "+", " ", "1-2", "1.-2", "--1", "1e2", "١"} {
		if _, err := toMinorUnits(bad, "usd"); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("toMinorUnits(%q): want ErrInvalidRequest, got %v", bad, err)
		}
	}
}

func TestPositiveMinorUnits(t *testing.T) {
	for _, bad := range []string{"0", "0.00", "-1", "-0.01", "0.0000"} {
		if _, err := positiveMinorUnits(bad, "usd"); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("positiveMinorUnits(%q): want ErrInvalidRequest, got %v", bad, err)
		}
	}
	if n, err := positiveMinorUnits("0.01", "usd"); err != nil || n != 1 {
		t.Errorf("one cent: %d, %v", n, err)
	}
}

// ── wire behaviour ───────────────────────────────────────────────────

func TestNew_DefaultsAndOptions(t *testing.T) {
	b := New("sk_test_fake")
	if b.Name() != "stripe" || b.baseURL != defaultAPIBase || b.httpClient == nil || b.httpClient.Timeout != 20*time.Second {
		t.Errorf("defaults = %+v", b)
	}
	hc := &http.Client{}
	b = New("sk_test_fake", WithBaseURL("http://127.0.0.1:9/"), WithHTTPClient(hc))
	if b.baseURL != "http://127.0.0.1:9" || b.httpClient != hc {
		t.Errorf("options not applied: %+v", b)
	}
}

// Every amount the driver sends is refused BEFORE a request when it is
// not strictly positive — a negative intent / refund / price is never
// what a caller meant.
func TestDriver_NonPositiveAmountsNeverLeave(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()
	b := testBackend(srv)
	ctx := context.Background()
	for _, amt := range []string{"0", "-5.00", "184467440737095516.17"} {
		m := backend.Money{Amount: amt, Currency: "usd"}
		if _, err := b.CreatePayment(ctx, backend.PaymentSpec{Amount: m}); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("CreatePayment(%s): %v", amt, err)
		}
		if _, err := b.RefundPayment(ctx, "pi_1", m, "k"); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("RefundPayment(%s): %v", amt, err)
		}
		if _, err := b.UpsertPlan(ctx, backend.PlanSpec{Slug: "s", Amount: m, Interval: "month"}); !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("UpsertPlan(%s): %v", amt, err)
		}
	}
	if hits != 0 {
		t.Errorf("%d request(s) left the driver for refused amounts", hits)
	}
}

func TestRefundPayment_EmptyAmountIsAFullRefundAtTheProvider(t *testing.T) {
	var form string
	var hasAmount bool
	var idem string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm.Encode()
		_, hasAmount = r.PostForm["amount"]
		idem = r.Header.Get("Idempotency-Key")
		_, _ = w.Write([]byte(`{"id":"re_9","status":"pending"}`))
	}))
	defer srv.Close()
	res, err := testBackend(srv).RefundPayment(context.Background(), "pi_9", backend.Money{Currency: "usd"}, "rk")
	if err != nil {
		t.Fatal(err)
	}
	if hasAmount || form != "payment_intent=pi_9" || idem != "rk" {
		t.Errorf("form=%q hasAmount=%v idem=%q", form, hasAmount, idem)
	}
	if res.ProviderRefundID != "re_9" || res.Status != "pending" {
		t.Errorf("result = %+v", res)
	}
}

// Optional fields are omitted, not sent empty; no key, no header.
func TestDriver_OmitsEmptyOptionalFields(t *testing.T) {
	var forms []string
	var idemHeaders []bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.PostForm.Encode())
		_, has := r.Header["Idempotency-Key"]
		idemHeaders = append(idemHeaders, has)
		_, _ = w.Write([]byte(`{"id":"obj_1","status":"active"}`))
	}))
	defer srv.Close()
	b := testBackend(srv)
	ctx := context.Background()
	if _, err := b.EnsureCustomer(ctx, backend.CustomerSpec{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CreatePayment(ctx, backend.PaymentSpec{Amount: backend.Money{Amount: "1", Currency: "USD"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.UpsertPlan(ctx, backend.PlanSpec{Slug: "basic", Amount: backend.Money{Amount: "1000", Currency: "jpy"}, Interval: "year"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"",
		"amount=100&currency=usd",
		"currency=jpy&product_data%5Bname%5D=basic&recurring%5Binterval%5D=year&unit_amount=1000",
	}
	for i, w := range want {
		if forms[i] != w {
			t.Errorf("request %d form = %q, want %q", i, forms[i], w)
		}
		if idemHeaders[i] {
			t.Errorf("request %d sent an empty Idempotency-Key header", i)
		}
	}
}

// The failure class decides the gRPC code upstream: declines and invalid
// requests are not retryable; everything else is.
func TestPost_ClassifiesProviderErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   error // nil = transient (no class)
	}{
		{402, `{"error":{"message":"Your card was declined.","type":"card_error"}}`, backend.ErrDeclined},
		{400, `{"error":{"message":"Your card has insufficient funds.","type":"card_error"}}`, backend.ErrDeclined},
		{400, `{"error":{"message":"Invalid currency","type":"invalid_request_error"}}`, backend.ErrInvalidRequest},
		{400, `{"error":{"message":"Keys for idempotent requests…","type":"idempotency_error"}}`, backend.ErrInvalidRequest},
		{404, `{"error":{"message":"No such payment_intent","type":"invalid_request_error"}}`, backend.ErrInvalidRequest},
		{409, `{"error":{"message":"in progress","type":"idempotency_error"}}`, nil},
		{429, `{"error":{"message":"Too many requests","type":"rate_limit_error"}}`, nil},
		{401, `{"error":{"message":"Invalid API Key provided","type":"invalid_request_error"}}`, nil},
		{500, `{"error":{"message":"boom","type":"api_error"}}`, nil},
		{503, `<html>bad gateway</html>`, nil},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		_, err := testBackend(srv).CreatePayment(context.Background(), backend.PaymentSpec{Amount: backend.Money{Amount: "5", Currency: "usd"}})
		srv.Close()
		if err == nil {
			t.Errorf("%d: want an error", c.status)
			continue
		}
		declined, invalid := errors.Is(err, backend.ErrDeclined), errors.Is(err, backend.ErrInvalidRequest)
		switch c.want {
		case nil:
			if declined || invalid {
				t.Errorf("%d %s: classed non-transient: %v", c.status, c.body, err)
			}
		default:
			if !errors.Is(err, c.want) || (declined && invalid) {
				t.Errorf("%d %s: want %v, got %v", c.status, c.body, c.want, err)
			}
		}
		if strings.HasPrefix(c.body, "{") && !strings.Contains(err.Error(), "(") {
			t.Errorf("%d: provider message lost: %v", c.status, err)
		}
		if !strings.HasPrefix(c.body, "{") && !strings.Contains(err.Error(), "http 503") {
			t.Errorf("non-JSON error body: want the status in the error, got %v", err)
		}
	}
}

func TestPost_TransportAndDecodeFailures(t *testing.T) {
	ctx := context.Background()
	m := backend.Money{Amount: "1", Currency: "usd"}

	// Connection refused: transient, unclassified.
	srv := httptest.NewServer(http.NotFoundHandler())
	b := testBackend(srv)
	srv.Close()
	if _, err := b.CreatePayment(ctx, backend.PaymentSpec{Amount: m}); err == nil || errors.Is(err, backend.ErrInvalidRequest) || errors.Is(err, backend.ErrDeclined) {
		t.Errorf("closed server: %v", err)
	}

	// A cancelled context aborts the call.
	block := make(chan struct{})
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := testBackend(srv).CreatePayment(cctx, backend.PaymentSpec{Amount: m}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled context: %v", err)
	}
	close(block)
	srv.Close()

	// 2xx with a body that is not JSON.
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer srv.Close()
	if _, err := testBackend(srv).CreatePayment(ctx, backend.PaymentSpec{Amount: m}); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Errorf("non-JSON 2xx: %v", err)
	}
}

// A 2xx without an object id is a failure, never a success with an empty
// provider id (which every later lookup would then miss).
func TestDriver_RefusesResponsesWithoutAnID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer srv.Close()
	b := testBackend(srv)
	ctx := context.Background()
	m := backend.Money{Amount: "1", Currency: "usd"}
	if _, err := b.EnsureCustomer(ctx, backend.CustomerSpec{UserID: "u"}); err == nil {
		t.Error("customer without id accepted")
	}
	if _, err := b.CreatePayment(ctx, backend.PaymentSpec{Amount: m}); err == nil {
		t.Error("intent without id accepted")
	}
	if _, err := b.UpsertPlan(ctx, backend.PlanSpec{Slug: "s", Amount: m, Interval: "month"}); err == nil {
		t.Error("price without id accepted")
	}
	if _, err := b.StartSubscription(ctx, backend.SubscriptionSpec{ProviderCustomerID: "c", ProviderPriceID: "p"}); err == nil {
		t.Error("subscription without id accepted")
	}
}

func TestDriver_EveryCallSurfacesProviderErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"nope","type":"invalid_request_error"}}`))
	}))
	defer srv.Close()
	b := testBackend(srv)
	ctx := context.Background()
	m := backend.Money{Amount: "1", Currency: "usd"}
	errs := []error{}
	_, err := b.EnsureCustomer(ctx, backend.CustomerSpec{UserID: "u"})
	errs = append(errs, err)
	_, err = b.RefundPayment(ctx, "pi", m, "k")
	errs = append(errs, err)
	_, err = b.UpsertPlan(ctx, backend.PlanSpec{Slug: "s", Amount: m, Interval: "month"})
	errs = append(errs, err)
	_, err = b.StartSubscription(ctx, backend.SubscriptionSpec{ProviderCustomerID: "c", ProviderPriceID: "p"})
	errs = append(errs, err)
	for i, err := range errs {
		if !errors.Is(err, backend.ErrInvalidRequest) {
			t.Errorf("call %d: %v", i, err)
		}
	}
	// A bad base URL fails at request construction.
	bad := &Backend{apiKey: "k", baseURL: "http://bad host", httpClient: srv.Client()}
	if _, err := bad.EnsureCustomer(ctx, backend.CustomerSpec{}); err == nil {
		t.Error("invalid base URL accepted")
	}
}

// ── webhook verification ─────────────────────────────────────────────

func TestVerifyAndParse_ToleranceBoundary(t *testing.T) {
	const now = 1_700_000_000
	pinClock(t, now)
	secret := "whsec_x"
	body := []byte(`{"id":"evt_b","type":"payment_intent.succeeded","data":{"object":{"id":"pi_1"}}}`)
	for _, c := range []struct {
		ts      int64
		wantOld bool
	}{
		{now - 300, false}, {now + 300, false}, {now, false},
		{now - 301, true}, {now + 301, true}, {0, true}, {-1, true},
	} {
		_, err := VerifyAndParse(body, sign(body, secret, itoa(c.ts)), secret)
		if got := errors.Is(err, ErrTimestampTooOld); got != c.wantOld {
			t.Errorf("t=%d (skew %d): too-old=%v, want %v (err %v)", c.ts, now-c.ts, got, c.wantOld, err)
		}
		if !c.wantOld && err != nil {
			t.Errorf("t=%d: in-window event refused: %v", c.ts, err)
		}
	}
}

func TestVerifyAndParse_HeaderVariants(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	body := []byte(`{"id":"evt_h","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"past_due","current_period_end":1893456000}}}`)
	good := sign(body, secret, "123")
	sig := good[strings.Index(good, "v1=")+3:]

	ok := []string{
		good,
		"t=123,v1=" + strings.ToUpper(sig), // hex is case-insensitive
		"t=123,v1=00,v1=" + sig,            // rotation: any one v1 matches
		"v1=" + sig + ",t=123",             // order does not matter
		" t=123 ,  v1=" + sig + " ,v0=ignored,garbage", // whitespace, unknown parts
	}
	for _, h := range ok {
		ev, err := VerifyAndParse(body, h, secret)
		if err != nil {
			t.Errorf("header %q refused: %v", h, err)
			continue
		}
		if ev.ObjectID != "sub_1" || ev.ObjectStatus != "past_due" || ev.CurrentPeriodEnd != 1893456000 || string(ev.Raw) != string(body) {
			t.Errorf("parsed = %+v", ev)
		}
	}
	bad := []string{
		"",
		"t=123",
		"v1=" + sig,
		"t=,v1=" + sig,
		"t=123,v1=",
		"t=123,v0=" + sig,
		"t=124,v1=" + sig,      // timestamp is inside the MAC
		"t=0123,v1=" + sig,     // so is its exact spelling
		"t=123,v1=" + sig[:62], // truncated
		"t=123,v1=nothex" + sig[7:],
	}
	for _, h := range bad {
		if _, err := VerifyAndParse(body, h, secret); !errors.Is(err, ErrBadSignature) {
			t.Errorf("header %q: want ErrBadSignature, got %v", h, err)
		}
	}
}

// A timestamp that is not an integer can only verify if it was signed
// that way; it is refused as a bad signature, never parsed loosely.
func TestVerifyAndParse_NonNumericSignedTimestamp(t *testing.T) {
	pinClock(t, 123)
	body := []byte(`{"id":"evt_n","type":"x"}`)
	if _, err := VerifyAndParse(body, sign(body, "s", "12a"), "s"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

// An authentic event without an id or type cannot be processed exactly
// once (the id is the dedup key); it is refused rather than recorded
// under "".
func TestVerifyAndParse_RequiresIDAndType(t *testing.T) {
	pinClock(t, 123)
	for _, body := range []string{
		`{"type":"payment_intent.succeeded","data":{"object":{"id":"pi_1"}}}`,
		`{"id":"evt_1","data":{"object":{"id":"pi_1"}}}`,
		`{"id":"","type":""}`,
		`null`,
	} {
		_, err := VerifyAndParse([]byte(body), sign([]byte(body), "s", "123"), "s")
		if err == nil || errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: want a malformed-body error, got %v", body, err)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
