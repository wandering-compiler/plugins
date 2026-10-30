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
	refunds   []*fakeRefund     // in creation order
	// refundStatus is the status a created refund answers with ("" =
	// succeeded); setRefundStatus moves one later.
	refundStatus string
	// erring makes the fake a gateway that errs: it refunds past what is
	// left on the intent, so a test can show the plugin's own guard.
	erring    bool
	subs      []fakeSub // in creation order
	customers []fakeCustomer
	created   map[string]int64 // object id → its created time (Unix seconds)
	order     []string         // every object id, in creation order
	listFail  map[string][]int // GET path → statuses the next lists answer, in turn
	// dateOffset shifts the Date the account-wide lists answer with: the
	// provider's clock, against the local one.
	dateOffset time.Duration
}

// fakeEpoch is the created time of the fake's first object; each object is
// one second newer than the one before.
const fakeEpoch = 1_700_000_000

type fakeCustomer struct {
	id, email string
	md        map[string]string
}

type fakeSub struct {
	id, customer, price, key string // key = metadata[w17_subscribe]
	status                   string // "" = subStatus
}

type fakeRefund struct {
	id, intent, currency, key string // key = metadata[w17_refund]
	status                    string
	amount                    int64
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
	status, description    string
	failed                 bool // last_payment_error set
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
		created:  map[string]int64{},
		listFail: map[string][]int{},
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
	if r.Method == http.MethodGet && f.failList(w, r.URL.Path) {
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/refunds" {
		if r.URL.Query().Get("payment_intent") == "" {
			f.listAccount(w, r, f.refundObjects)
			return
		}
		f.listRefunds(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/subscriptions" {
		if r.URL.Query().Get("customer") == "" {
			f.listAccount(w, r, f.subObjects)
			return
		}
		f.listSubs(w, r)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/customers" {
		f.listAccount(w, r, f.customerObjects)
		return
	}
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/payment_intents/") {
		f.getIntent(w, strings.TrimPrefix(r.URL.Path, "/v1/payment_intents/"))
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/payment_intents" {
		f.listAccount(w, r, f.intentObjects)
		return
	}
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
	id := fmt.Sprintf("%s_fake%04d", prefix, f.seq)
	f.created[id] = fakeEpoch + int64(f.seq)
	f.order = append(f.order, id)
	return id
}

func okJSON(v any) (int, []byte) {
	b, _ := json.Marshal(v)
	return http.StatusOK, b
}

func (f *stripeFake) route(w http.ResponseWriter, r *http.Request) (int, []byte) {
	switch r.URL.Path {
	case "/v1/customers":
		c := fakeCustomer{id: f.id("cus"), email: r.PostForm.Get("email"), md: formMetadata(r)}
		f.customers = append(f.customers, c)
		f.origins[c.id] = c.md["w17_payment"]
		f.installs[c.id] = c.md["w17_install"]
		return okJSON(map[string]any{"id": c.id, "object": "customer", "email": c.email, "metadata": c.md})

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
		in := &fakeIntent{id: f.id("pi"), customer: cus, currency: cur, amount: amount, origin: r.PostForm.Get("metadata[w17_payment]"),
			status: "requires_payment_method", description: r.PostForm.Get("description")}
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
		if amount > in.amount-in.refunded && !f.erring {
			return stripeErr(w, http.StatusBadRequest, "invalid_request_error",
				"Refund amount is greater than unrefunded amount on charge")
		}
		st := f.refundStatus
		if st == "" {
			st = "succeeded"
		}
		if st != "failed" && st != "canceled" {
			in.refunded += amount
		}
		re := &fakeRefund{id: f.id("re"), intent: in.id, currency: in.currency, amount: amount, key: r.PostForm.Get("metadata[w17_refund]"), status: st}
		f.refunds = append(f.refunds, re)
		return okJSON(map[string]any{"id": re.id, "object": "refund", "amount": amount, "status": st,
			"metadata": map[string]string{"w17_refund": re.key}})

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
		f.subs = append(f.subs, fakeSub{id: id, customer: r.PostForm.Get("customer"), price: r.PostForm.Get("items[0][price]"), key: r.PostForm.Get("metadata[w17_subscribe]")})
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

// listRefunds answers GET /v1/refunds?payment_intent=… with the intent's
// refunds, one page, as the provider's list endpoint does.
func (f *stripeFake) listRefunds(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests["GET /v1/refunds"]++
	var data []map[string]any
	for _, re := range f.refunds {
		if re.intent == r.URL.Query().Get("payment_intent") {
			md := map[string]string{}
			if re.key != "" {
				md["w17_refund"] = re.key
			}
			data = append(data, map[string]any{"id": re.id, "object": "refund", "status": re.status,
				"amount": re.amount, "currency": re.currency, "payment_intent": re.intent, "metadata": md})
		}
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": data, "has_more": false})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// listSubs answers GET /v1/subscriptions?customer=… (status=all).
func (f *stripeFake) listSubs(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests["GET /v1/subscriptions"]++
	var data []map[string]any
	for _, s := range f.subs {
		if s.customer == r.URL.Query().Get("customer") {
			st := f.subStatusOf(s)
			data = append(data, map[string]any{"id": s.id, "object": "subscription", "status": st,
				"current_period_end": 1893456000, "metadata": map[string]string{"w17_subscribe": s.key},
				"items": map[string]any{"data": []map[string]any{{"price": map[string]any{"id": s.price}}}}})
		}
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": data, "has_more": false})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// refundAtProvider makes a refund the way the provider's dashboard does: no
// idempotency key, no metadata. It returns the refund id.
func (f *stripeFake) refundAtProvider(intent string, amount int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, ok := f.intents[intent]
	if !ok {
		f.t.Fatalf("refundAtProvider: no intent %s", intent)
	}
	if amount > in.amount-in.refunded {
		f.t.Fatalf("refundAtProvider: %d exceeds what is left on %s", amount, intent)
	}
	in.refunded += amount
	re := &fakeRefund{id: f.id("re"), intent: intent, currency: in.currency, amount: amount, status: "succeeded"}
	f.refunds = append(f.refunds, re)
	return re.id
}

// setRefundStatus moves a refund to another status, as the provider does when
// a refund settles or fails. A failed or canceled refund's amount is
// refundable again.
func (f *stripeFake) setRefundStatus(id, st string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, re := range f.refunds {
		if re.id != id {
			continue
		}
		gone := func(s string) bool { return s == "failed" || s == "canceled" }
		if in := f.intents[re.intent]; in != nil && gone(st) != gone(re.status) {
			if gone(st) {
				in.refunded -= re.amount
			} else {
				in.refunded += re.amount
			}
		}
		re.status = st
		return
	}
	f.t.Fatalf("setRefundStatus: no refund %s", id)
}

// lastRefundID is the id of the newest refund.
func (f *stripeFake) lastRefundID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.refunds) == 0 {
		f.t.Fatal("lastRefundID: no refund")
	}
	return f.refunds[len(f.refunds)-1].id
}

// refundEvent renders a refund.* / charge.refunded event naming the payment
// the refunds belong to. The handler reads the refunds from the provider's
// list, so the snapshot carries only what routes it.
func refundEvent(id, typ, objectID, intent string) []byte {
	return eventJSON(id, typ, objectID, map[string]any{"payment_intent": intent})
}

// disputeEvent renders a charge.dispute.* event for a dispute of amount
// (minor units, usd) on intent, in the given status, created at unix time at.
func disputeEvent(t *testing.T, id, typ, disputeID, intent, st string, amount, at int64) []byte {
	t.Helper()
	return withCreated(t, eventJSON(id, typ, disputeID, map[string]any{
		"payment_intent": intent, "status": st, "amount": amount, "currency": "usd",
	}), at)
}

// ── account-wide lists (the provider reconciliation) ─────────────────

// formMetadata is the metadata[…] of a create request.
func formMetadata(r *http.Request) map[string]string {
	md := map[string]string{}
	for k, vs := range r.PostForm {
		if strings.HasPrefix(k, "metadata[") && strings.HasSuffix(k, "]") && len(vs) > 0 {
			md[strings.TrimSuffix(strings.TrimPrefix(k, "metadata["), "]")] = vs[0]
		}
	}
	return md
}

// marksOf is the origin and install metadata the fake holds for an object.
func (f *stripeFake) marksOf(id string) map[string]string {
	md := map[string]string{}
	if o := f.origins[id]; o != "" {
		md["w17_payment"] = o
	}
	if i := f.installs[id]; i != "" {
		md["w17_install"] = i
	}
	return md
}

func (f *stripeFake) subStatusOf(s fakeSub) string {
	switch {
	case s.status != "":
		return s.status
	case f.subStatus != "":
		return f.subStatus
	}
	return "active"
}

func (f *stripeFake) customerObjects() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, c := range f.customers {
		out[c.id] = map[string]any{"id": c.id, "object": "customer", "email": c.email, "metadata": c.md}
	}
	return out
}

func (f *stripeFake) intentObjects() map[string]map[string]any {
	out := map[string]map[string]any{}
	for id, in := range f.intents {
		var lastErr any
		if in.failed {
			lastErr = map[string]any{"code": "card_declined"}
		}
		out[id] = map[string]any{"id": id, "object": "payment_intent", "status": in.status, "amount": in.amount,
			"currency": in.currency, "customer": in.customer, "description": in.description,
			"metadata": f.marksOf(id), "last_payment_error": lastErr}
	}
	return out
}

func (f *stripeFake) refundObjects() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, re := range f.refunds {
		md := map[string]string{}
		if re.key != "" {
			md["w17_refund"] = re.key
		}
		out[re.id] = map[string]any{"id": re.id, "object": "refund", "status": re.status, "amount": re.amount,
			"currency": re.currency, "payment_intent": re.intent, "metadata": md}
	}
	return out
}

func (f *stripeFake) subObjects() map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, s := range f.subs {
		md := f.marksOf(s.id)
		if s.key != "" {
			md["w17_subscribe"] = s.key
		}
		out[s.id] = map[string]any{"id": s.id, "object": "subscription", "status": f.subStatusOf(s), "customer": s.customer,
			"current_period_end": 1893456000, "metadata": md,
			"items": map[string]any{"data": []map[string]any{{"price": map[string]any{"id": s.price}}}}}
	}
	return out
}

// listAccount answers an account-wide list the way the provider does: newest
// first, created[gte] bounding it, limit (1 to 100, default 10) and
// starting_after paging it.
func (f *stripeFake) listAccount(w http.ResponseWriter, r *http.Request, objects func() map[string]map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests["GET "+r.URL.Path]++
	q := r.URL.Query()
	var gte int64
	var lte int64
	if v := q.Get("created[lte]"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lte = n
	}
	if v := q.Get("created[gte]"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gte = n
	}
	limit := 10
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		limit = n
	}
	all := objects()
	var ids []string
	for i := len(f.order) - 1; i >= 0; i-- { // newest first
		id := f.order[i]
		if _, ok := all[id]; ok && f.created[id] >= gte && (lte == 0 || f.created[id] <= lte) {
			ids = append(ids, id)
		}
	}
	if after := q.Get("starting_after"); after != "" {
		at := -1
		for i, id := range ids {
			if id == after {
				at = i
			}
		}
		if at < 0 {
			body, _ := json.Marshal(map[string]any{"error": map[string]string{
				"type": "invalid_request_error", "code": "resource_missing", "message": "No such object: " + after}})
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(body)
			return
		}
		ids = ids[at+1:]
	}
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	data := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		obj := all[id]
		obj["created"] = f.created[id]
		data = append(data, obj)
	}
	body, _ := json.Marshal(map[string]any{"object": "list", "data": data, "has_more": more})
	w.Header().Set("Content-Type", "application/json")
	if f.dateOffset != 0 {
		w.Header().Set("Date", time.Now().Add(f.dateOffset).UTC().Format(http.TimeFormat))
	}
	_, _ = w.Write(body)
}

// deleteObject removes an object from the account, as a deletion at the
// provider does: lists no longer name it, and paging after it is refused.
func (f *stripeFake) deleteObject(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, o := range f.order {
		if o == id {
			f.order = append(f.order[:i:i], f.order[i+1:]...)
			return
		}
	}
	f.t.Fatalf("deleteObject: no object %s", id)
}

// failList answers a GET of path with the next queued failure, if any.
func (f *stripeFake) failList(w http.ResponseWriter, path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	queue := f.listFail[path]
	if len(queue) == 0 {
		return false
	}
	st := queue[0]
	f.listFail[path] = queue[1:]
	f.requests["GET "+path]++
	_, body := stripeErr(w, st, "api_error", "injected "+strconv.Itoa(st))
	w.WriteHeader(st)
	_, _ = w.Write(body)
	return true
}

// failNextList makes the next lists of path answer these statuses, in turn.
func (f *stripeFake) failNextList(path string, statuses ...int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listFail[path] = append(f.listFail[path], statuses...)
}

// setIntentStatus moves an intent the way the provider does once the customer
// pays (succeeded), an attempt fails (requires_payment_method with an
// error), or it is canceled.
func (f *stripeFake) setIntentStatus(id, st string, failed bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in, ok := f.intents[id]
	if !ok {
		f.t.Fatalf("setIntentStatus: no intent %s", id)
	}
	in.status, in.failed = st, failed
}

// setSubStatus moves one subscription to another status.
func (f *stripeFake) setSubStatus(id, st string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.subs {
		if f.subs[i].id == id {
			f.subs[i].status = st
			return
		}
	}
	f.t.Fatalf("setSubStatus: no subscription %s", id)
}

// foreignIntent makes an intent the plugin did not create — a dashboard
// charge, another app's — carrying md as its metadata. It returns the id.
func (f *stripeFake) foreignIntent(customer string, amount int64, md map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	in := &fakeIntent{id: f.id("pi"), customer: customer, currency: "usd", amount: amount, status: "succeeded"}
	f.intents[in.id] = in
	f.origins[in.id] = md["w17_payment"]
	f.installs[in.id] = md["w17_install"]
	return in.id
}

// foreignCustomer makes a customer the plugin did not create.
func (f *stripeFake) foreignCustomer(md map[string]string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := fakeCustomer{id: f.id("cus"), md: md}
	f.customers = append(f.customers, c)
	return c.id
}

// foreignSub makes a subscription the plugin did not start.
func (f *stripeFake) foreignSub(customer, price string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.id("sub")
	f.subs = append(f.subs, fakeSub{id: id, customer: customer, price: price})
	return id
}
