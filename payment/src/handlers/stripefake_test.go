package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
	"github.com/wandering-compiler/plugins/payment/lib/backend/stripe"
)

const fakeStripeKey = "sk_test_fake"

// stripeFake is an httptest server speaking the Stripe REST wire format
// the driver depends on (form-encoded requests, JSON bodies, the
// {"error":{…}} envelope) with the provider behaviour the handlers'
// contracts lean on:
//
//   - Idempotency-Key: the same key with the same parameters REPLAYS the
//     first response (same object id); the same key with different
//     parameters is a 400 idempotency_error. forgetKeys() models the
//     provider's 24h key expiry.
//   - PaymentIntents need amount ≥ 1 minor unit; a customer flagged with
//     declineCustomer() gets a 402 card_error.
//   - Refunds cannot exceed what is left unrefunded on the intent.
//   - failNext(status) makes the next request answer that status.
//
// The handlers under test hold a REAL *stripe.Backend pointed at it, so
// minor-unit conversion, header handling and error decoding are all on
// the path.
type stripeFake struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	seq       int
	idem      map[string]idemEntry // Idempotency-Key → first request
	intents   map[string]*fakeIntent
	declined  map[string]bool // customer id → card declines
	failQueue []int
	requests  map[string]int    // path → requests that reached the handler logic
	subStatus string            // status a created subscription reports ("" = active)
	origins   map[string]string // object id → metadata[w17_payment] it was created with
	installs  map[string]string // object id → metadata[w17_install] it was created with
}

type idemEntry struct {
	path, params string
	status       int
	body         []byte
}

type fakeIntent struct {
	id, customer, currency string
	amount, refunded       int64
	origin                 string // metadata[w17_payment], as sent
}

func newStripeFake(t *testing.T) *stripeFake {
	t.Helper()
	f := &stripeFake{
		t:        t,
		idem:     map[string]idemEntry{},
		intents:  map[string]*fakeIntent{},
		declined: map[string]bool{},
		requests: map[string]int{},
		origins:  map[string]string{},
		installs: map[string]string{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// backend returns the real Stripe driver aimed at the fake.
func (f *stripeFake) backend() *stripe.Backend {
	return stripe.New(fakeStripeKey, stripe.WithBaseURL(f.srv.URL), stripe.WithHTTPClient(f.srv.Client()))
}

func (f *stripeFake) failNext(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failQueue = append(f.failQueue, status)
}

func (f *stripeFake) declineCustomer(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.declined[id] = true
}

func (f *stripeFake) forgetKeys() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.idem = map[string]idemEntry{}
}

func (f *stripeFake) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[path]
}

func (f *stripeFake) intent(id string) fakeIntent {
	f.mu.Lock()
	defer f.mu.Unlock()
	if in, ok := f.intents[id]; ok {
		return *in
	}
	f.t.Fatalf("stripe fake: no intent %s", id)
	return fakeIntent{}
}

func stripeErr(w http.ResponseWriter, status int, typ, msg string) (int, []byte) {
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": typ, "message": msg}})
	return status, body
}

func (f *stripeFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+fakeStripeKey {
		f.t.Errorf("stripe fake: Authorization = %q", got)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		f.t.Errorf("stripe fake: Content-Type = %q", ct)
	}
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.failQueue) > 0 {
		st := f.failQueue[0]
		f.failQueue = f.failQueue[1:]
		_, body := stripeErr(w, st, "api_error", "injected "+strconv.Itoa(st))
		w.WriteHeader(st)
		_, _ = w.Write(body)
		return
	}

	key := r.Header.Get("Idempotency-Key")
	params := canonicalForm(r)
	if key != "" {
		if e, ok := f.idem[key]; ok {
			if e.path != r.URL.Path || e.params != params {
				st, body := stripeErr(w, http.StatusBadRequest, "idempotency_error",
					"Keys for idempotent requests can only be used with the same parameters they were first used with.")
				w.WriteHeader(st)
				_, _ = w.Write(body)
				return
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(e.status)
			_, _ = w.Write(e.body)
			return
		}
	}

	f.requests[r.URL.Path]++
	st, body := f.route(w, r)
	if key != "" && st < 500 {
		f.idem[key] = idemEntry{path: r.URL.Path, params: params, status: st, body: body}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(st)
	_, _ = w.Write(body)
}

func canonicalForm(r *http.Request) string {
	keys := make([]string, 0, len(r.PostForm))
	for k := range r.PostForm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s&", k, strings.Join(r.PostForm[k], ","))
	}
	return b.String()
}

func (f *stripeFake) id(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s_fake%04d", prefix, f.seq)
}

func okJSON(v any) (int, []byte) {
	b, _ := json.Marshal(v)
	return http.StatusOK, b
}

func (f *stripeFake) route(w http.ResponseWriter, r *http.Request) (int, []byte) {
	switch r.URL.Path {
	case "/v1/customers":
		return okJSON(map[string]any{"id": f.id("cus"), "object": "customer", "email": r.PostForm.Get("email")})

	case "/v1/payment_intents":
		amount, err := strconv.ParseInt(r.PostForm.Get("amount"), 10, 64)
		if err != nil || amount < 1 {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error", "Invalid positive integer")
		}
		cur := r.PostForm.Get("currency")
		if len(cur) != 3 {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error", "Invalid currency")
		}
		cus := r.PostForm.Get("customer")
		if f.declined[cus] {
			return stripeErr(w, http.StatusPaymentRequired, "card_error", "Your card was declined.")
		}
		in := &fakeIntent{id: f.id("pi"), customer: cus, currency: cur, amount: amount, origin: r.PostForm.Get("metadata[w17_payment]")}
		f.intents[in.id] = in
		f.origins[in.id] = in.origin
		f.installs[in.id] = r.PostForm.Get("metadata[w17_install]")
		return okJSON(map[string]any{
			"id": in.id, "object": "payment_intent", "amount": amount, "currency": cur,
			"status": "requires_payment_method", "client_secret": in.id + "_secret_fake",
		})

	case "/v1/refunds":
		in, ok := f.intents[r.PostForm.Get("payment_intent")]
		if !ok {
			return stripeErr(w, http.StatusNotFound, "invalid_request_error", "No such payment_intent")
		}
		amount := in.amount - in.refunded
		if s := r.PostForm.Get("amount"); s != "" {
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil || n < 1 {
				return stripeErr(w, http.StatusBadRequest, "invalid_request_error", "Invalid positive integer")
			}
			amount = n
		}
		if amount > in.amount-in.refunded {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error",
				"Refund amount is greater than unrefunded amount on charge")
		}
		in.refunded += amount
		return okJSON(map[string]any{"id": f.id("re"), "object": "refund", "amount": amount, "status": "succeeded"})

	case "/v1/prices":
		n, err := strconv.ParseInt(r.PostForm.Get("unit_amount"), 10, 64)
		if err != nil || n < 0 {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error", "Invalid integer")
		}
		return okJSON(map[string]any{"id": f.id("price"), "object": "price", "unit_amount": n})

	case "/v1/subscriptions":
		if r.PostForm.Get("customer") == "" || r.PostForm.Get("items[0][price]") == "" {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error", "Missing required param")
		}
		id := f.id("sub")
		f.origins[id] = r.PostForm.Get("metadata[w17_payment]")
		f.installs[id] = r.PostForm.Get("metadata[w17_install]")
		st := f.subStatus
		if st == "" {
			st = "active"
		}
		return okJSON(map[string]any{"id": id, "object": "subscription", "status": st, "current_period_end": 1893456000})
	}
	return stripeErr(w, http.StatusNotFound, "invalid_request_error", "Unrecognized request URL")
}

// ── signed webhook deliveries ─────────────────────────────────────────

// signedAt builds a Stripe-Signature header for payload at unix time ts.
func signedAt(payload []byte, secret string, ts int64) string {
	t := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t + "."))
	mac.Write(payload)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// stripeEvent builds an already-verified event for calling a hook directly.
func stripeEvent(typ, objectID string) stripe.Event {
	return stripe.Event{ID: "evt_direct", Type: typ, ObjectID: objectID, PaymentIntentID: objectID}
}

// eventJSON renders a Stripe event envelope.
func eventJSON(id, typ, objectID string, extra map[string]any) []byte {
	obj := map[string]any{"id": objectID}
	for k, v := range extra {
		obj[k] = v
	}
	b, _ := json.Marshal(map[string]any{
		"id": id, "object": "event", "type": typ, "created": time.Now().Unix(),
		"data": map[string]any{"object": obj},
	})
	return b
}

// objectEvent renders an event for an object the fake created, carrying the
// metadata Stripe would echo on it — the origin and install marks the plugin
// set.
func (f *stripeFake) objectEvent(id, typ, objectID string, extra map[string]any) []byte {
	f.mu.Lock()
	origin, ok := f.origins[objectID]
	install := f.installs[objectID]
	f.mu.Unlock()
	if !ok {
		f.t.Fatalf("objectEvent: the fake created no object %q", objectID)
	}
	obj := map[string]any{}
	for k, v := range extra {
		obj[k] = v
	}
	md := map[string]string{}
	if origin != "" {
		md["w17_payment"] = origin
	}
	if install != "" {
		md["w17_install"] = install
	}
	if len(md) > 0 {
		obj["metadata"] = md
	}
	return eventJSON(id, typ, objectID, obj)
}

// ownMark is the metadata this installation (WebhookSecret =
// testWebhookSecret) writes on an object it creates with the given origin.
func ownMark(origin string) map[string]string {
	return map[string]string{"w17_payment": origin, "w17_install": backend.InstallID(testWebhookSecret)}
}

// withCreated rewrites an event's created time.
func withCreated(t *testing.T, body []byte, created int64) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["created"] = created
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
