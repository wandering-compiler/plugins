// Package stripe is the Stripe implementation of backend.Backend.
// It speaks the Stripe REST API directly over net/http — no
// vendored SDK — keeping the plugin dependency-light and the surface
// easy to fake in tests (mirrors the auth plugin's OAuth client).
//
// Money crosses the boundary here: backend.Money carries a decimal
// string, Stripe wants integer minor units, so each amount goes through
// toMinorUnits (exact, no float64).
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

const defaultAPIBase = "https://api.stripe.com"

// Backend is the Stripe driver. Safe for concurrent use.
type Backend struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// Option adjusts a Backend at construction.
type Option func(*Backend)

// WithBaseURL points the driver at another Stripe-compatible API root
// (a local stripe-mock, or a test server speaking the Stripe wire
// format).
func WithBaseURL(u string) Option {
	return func(b *Backend) { b.baseURL = strings.TrimRight(u, "/") }
}

// WithHTTPClient replaces the default client (20s timeout).
func WithHTTPClient(c *http.Client) Option {
	return func(b *Backend) { b.httpClient = c }
}

// New builds a Stripe backend from the secret API key (sk_…).
func New(apiKey string, opts ...Option) *Backend {
	b := &Backend{
		apiKey:     apiKey,
		baseURL:    defaultAPIBase,
		httpClient: &http.Client{Timeout: 20 * time.Second},
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name identifies the driver.
func (b *Backend) Name() string { return "stripe" }

// EnsureCustomer creates a Stripe customer for the principal, under the
// spec's idempotency key: a retry of the same create returns the customer the
// first one made. The local Customer table's unique user_id stays the guard
// across keys.
func (b *Backend) EnsureCustomer(ctx context.Context, spec backend.CustomerSpec) (string, error) {
	form := url.Values{}
	if spec.Email != "" {
		form.Set("email", spec.Email)
	}
	if spec.UserID != "" {
		form.Set("metadata["+customerUserMeta+"]", spec.UserID)
	}
	// Marked like every object the plugin creates, so the provider
	// reconciliation can tell this installation's customers from the rest
	// of the account's.
	if spec.Install != "" {
		form.Set("metadata["+backend.OriginMetadataKey+"]", backend.OriginCustomer)
		form.Set("metadata["+backend.InstallMetadataKey+"]", spec.Install)
	}
	var resp customerResp
	if err := b.post(ctx, "/v1/customers", form, spec.IdempotencyKey, &resp); err != nil {
		return "", err
	}
	if resp.ID == "" {
		return "", fmt.Errorf("stripe: customer create returned no id")
	}
	return resp.ID, nil
}

// CreatePayment creates a Stripe PaymentIntent. The idempotency key is
// sent as the Idempotency-Key header so a retried call returns the same
// intent instead of creating a second charge.
func (b *Backend) CreatePayment(ctx context.Context, spec backend.PaymentSpec) (backend.PaymentResult, error) {
	minor, err := positiveMinorUnits(spec.Amount.Amount, spec.Amount.Currency)
	if err != nil {
		return backend.PaymentResult{}, err
	}
	form := url.Values{}
	form.Set("amount", strconv.FormatInt(minor, 10))
	form.Set("currency", strings.ToLower(spec.Amount.Currency))
	if spec.ProviderCustomerID != "" {
		form.Set("customer", spec.ProviderCustomerID)
	}
	if spec.Description != "" {
		form.Set("description", spec.Description)
	}
	if spec.Origin != "" {
		form.Set("metadata["+backend.OriginMetadataKey+"]", spec.Origin)
	}
	if spec.Install != "" {
		form.Set("metadata["+backend.InstallMetadataKey+"]", spec.Install)
	}
	var resp paymentIntentResp
	if err := b.post(ctx, "/v1/payment_intents", form, spec.IdempotencyKey, &resp); err != nil {
		return backend.PaymentResult{}, err
	}
	if resp.ID == "" {
		return backend.PaymentResult{}, fmt.Errorf("stripe: payment_intent create returned no id")
	}
	return backend.PaymentResult{
		ProviderPaymentID: resp.ID,
		Status:            resp.Status,
		ClientSecret:      resp.ClientSecret,
	}, nil
}

// RefundPayment refunds (part of) a PaymentIntent.
func (b *Backend) RefundPayment(ctx context.Context, providerPaymentID string, amount backend.Money, idemKey string) (backend.RefundResult, error) {
	form := url.Values{}
	form.Set("payment_intent", providerPaymentID)
	if amount.Amount != "" {
		minor, err := positiveMinorUnits(amount.Amount, amount.Currency)
		if err != nil {
			return backend.RefundResult{}, err
		}
		form.Set("amount", strconv.FormatInt(minor, 10))
	}
	// The key also rides in the refund's metadata, where it outlives the
	// provider's idempotency window (a day): FindRefund matches on it.
	form.Set("metadata["+refundKeyMeta+"]", idemKey)
	var resp refundResp
	if err := b.post(ctx, "/v1/refunds", form, idemKey, &resp); err != nil {
		return backend.RefundResult{}, err
	}
	return backend.RefundResult{ProviderRefundID: resp.ID, Status: resp.Status, Key: idemKey}, nil
}

// refundKeyMeta is the refund metadata key carrying the caller's
// idempotency key.
const refundKeyMeta = "w17_refund"

// FindRefund looks for a refund of the PaymentIntent made under idemKey,
// by the key RefundPayment stores in the refund's metadata.
func (b *Backend) FindRefund(ctx context.Context, providerPaymentID, idemKey string) (backend.RefundResult, bool, error) {
	refunds, err := b.ListRefunds(ctx, providerPaymentID)
	if err != nil {
		return backend.RefundResult{}, false, err
	}
	for _, r := range refunds {
		if r.Key == idemKey {
			return r, true, nil
		}
	}
	return backend.RefundResult{}, false, nil
}

// ListRefunds walks the PaymentIntent's refunds page by page; a PaymentIntent
// has few.
func (b *Backend) ListRefunds(ctx context.Context, providerPaymentID string) ([]backend.RefundResult, error) {
	q := url.Values{}
	q.Set("payment_intent", providerPaymentID)
	q.Set("limit", "100")
	var out []backend.RefundResult
	for page := 0; page < 20; page++ {
		var list refundList
		if err := b.get(ctx, "/v1/refunds", q, &list); err != nil {
			return nil, err
		}
		for _, r := range list.Data {
			if r.ID == "" {
				return nil, fmt.Errorf("stripe: /v1/refunds: a refund on %s without an id", providerPaymentID)
			}
			out = append(out, backend.RefundResult{
				ProviderRefundID: r.ID,
				Status:           r.Status,
				Amount:           backend.Money{Amount: fromMinorUnits(r.Amount, r.Currency), Currency: r.Currency},
				Key:              r.Metadata[refundKeyMeta],
			})
		}
		if !list.HasMore || len(list.Data) == 0 {
			return out, nil
		}
		q.Set("starting_after", list.Data[len(list.Data)-1].ID)
	}
	return nil, fmt.Errorf("stripe: /v1/refunds: more refunds on %s than this lookup walks", providerPaymentID)
}

// UpsertPlan creates a recurring Stripe Price (with an inline product)
// for the plan and returns its id, under the spec's idempotency key: a retry
// of the same create returns the price the first one made (the local
// Plan.provider_price_id stays the dedup anchor across keys).
func (b *Backend) UpsertPlan(ctx context.Context, spec backend.PlanSpec) (string, error) {
	minor, err := positiveMinorUnits(spec.Amount.Amount, spec.Amount.Currency)
	if err != nil {
		return "", err
	}
	form := url.Values{}
	form.Set("unit_amount", strconv.FormatInt(minor, 10))
	form.Set("currency", strings.ToLower(spec.Amount.Currency))
	form.Set("recurring[interval]", spec.Interval)
	name := spec.Name
	if name == "" {
		name = spec.Slug
	}
	form.Set("product_data[name]", name)
	var resp priceResp
	if err := b.post(ctx, "/v1/prices", form, spec.IdempotencyKey, &resp); err != nil {
		return "", err
	}
	if resp.ID == "" {
		return "", fmt.Errorf("stripe: price create returned no id")
	}
	return resp.ID, nil
}

// StartSubscription subscribes a customer to a price.
func (b *Backend) StartSubscription(ctx context.Context, spec backend.SubscriptionSpec) (backend.SubscriptionResult, error) {
	form := url.Values{}
	form.Set("customer", spec.ProviderCustomerID)
	form.Set("items[0][price]", spec.ProviderPriceID)
	form.Set("metadata["+backend.OriginMetadataKey+"]", backend.OriginSubscription)
	if spec.Install != "" {
		form.Set("metadata["+backend.InstallMetadataKey+"]", spec.Install)
	}
	// As for refunds: the key outlives the provider's idempotency window
	// in the subscription's metadata, where FindSubscription matches it.
	form.Set("metadata["+subscribeKeyMeta+"]", spec.IdempotencyKey)
	var resp subscriptionResp
	if err := b.post(ctx, "/v1/subscriptions", form, spec.IdempotencyKey, &resp); err != nil {
		return backend.SubscriptionResult{}, err
	}
	if resp.ID == "" {
		return backend.SubscriptionResult{}, fmt.Errorf("stripe: subscription create returned no id")
	}
	return backend.SubscriptionResult{
		ProviderSubscriptionID: resp.ID,
		Status:                 resp.Status,
		CurrentPeriodEnd:       resp.CurrentPeriodEnd,
	}, nil
}

// subscribeKeyMeta is the subscription metadata key carrying the caller's
// idempotency key.
const subscribeKeyMeta = "w17_subscribe"

// FindSubscription looks for a subscription of the customer started under
// idemKey, by the key StartSubscription stores in its metadata, whatever its
// status.
func (b *Backend) FindSubscription(ctx context.Context, providerCustomerID, idemKey string) (backend.SubscriptionResult, bool, error) {
	q := url.Values{}
	q.Set("customer", providerCustomerID)
	q.Set("status", "all")
	q.Set("limit", "100")
	for page := 0; page < 20; page++ {
		var list subscriptionList
		if err := b.get(ctx, "/v1/subscriptions", q, &list); err != nil {
			return backend.SubscriptionResult{}, false, err
		}
		for _, s := range list.Data {
			if s.Metadata[subscribeKeyMeta] == idemKey {
				return backend.SubscriptionResult{
					ProviderSubscriptionID: s.ID,
					Status:                 s.Status,
					CurrentPeriodEnd:       s.CurrentPeriodEnd,
					ProviderPriceID:        s.priceID(),
				}, true, nil
			}
		}
		if !list.HasMore || len(list.Data) == 0 {
			return backend.SubscriptionResult{}, false, nil
		}
		q.Set("starting_after", list.Data[len(list.Data)-1].ID)
	}
	return backend.SubscriptionResult{}, false, fmt.Errorf("stripe: /v1/subscriptions: more subscriptions on %s than this lookup walks", providerCustomerID)
}

// customerUserMeta is the customer metadata key carrying the principal.
const customerUserMeta = "user_id"

// ListCustomerPage lists one page of the account's customers.
func (b *Backend) ListCustomerPage(ctx context.Context, q backend.ListQuery) ([]backend.CustomerObject, bool, error) {
	var list customerList
	if _, err := b.list(ctx, "/v1/customers", q, nil, &list); err != nil {
		return nil, false, err
	}
	out := make([]backend.CustomerObject, 0, len(list.Data))
	for _, c := range list.Data {
		if c.ID == "" {
			return nil, false, fmt.Errorf("stripe: /v1/customers: a customer without an id")
		}
		out = append(out, backend.CustomerObject{
			ProviderCustomerID: c.ID,
			UserID:             c.Metadata[customerUserMeta],
			Email:              c.Email,
			Created:            c.Created,
			Marks:              marks(c.Metadata),
		})
	}
	return out, list.HasMore, nil
}

// ListPaymentPage lists one page of the account's PaymentIntents.
func (b *Backend) ListPaymentPage(ctx context.Context, q backend.ListQuery) ([]backend.PaymentObject, bool, error) {
	var list paymentIntentList
	if _, err := b.list(ctx, "/v1/payment_intents", q, nil, &list); err != nil {
		return nil, false, err
	}
	out := make([]backend.PaymentObject, 0, len(list.Data))
	for _, p := range list.Data {
		if p.ID == "" {
			return nil, false, fmt.Errorf("stripe: /v1/payment_intents: an intent without an id")
		}
		out = append(out, paymentObject(p))
	}
	return out, list.HasMore, nil
}

// GetPayment reads one payment intent by id. An id the provider does not
// know is an error, never an empty object: RefundPayment proceeds only on a
// payment the provider reports succeeded.
func (b *Backend) GetPayment(ctx context.Context, providerPaymentID string) (backend.PaymentObject, error) {
	if providerPaymentID == "" {
		return backend.PaymentObject{}, &backend.InputError{Msg: "stripe: a payment intent id is required"}
	}
	var p paymentIntentObject
	if err := b.get(ctx, "/v1/payment_intents/"+url.PathEscape(providerPaymentID), url.Values{}, &p); err != nil {
		return backend.PaymentObject{}, err
	}
	if p.ID != providerPaymentID {
		return backend.PaymentObject{}, fmt.Errorf("stripe: /v1/payment_intents: asked for %s, answered %q", providerPaymentID, p.ID)
	}
	return paymentObject(p), nil
}

// paymentObject is the provider-neutral form of a payment intent.
func paymentObject(p paymentIntentObject) backend.PaymentObject {
	cur := strings.ToLower(p.Currency)
	return backend.PaymentObject{
		ProviderPaymentID:  p.ID,
		ProviderCustomerID: p.Customer,
		Status:             p.Status,
		Amount:             backend.Money{Amount: fromMinorUnits(p.Amount, cur), Currency: cur},
		Description:        p.Description,
		// A failed attempt leaves the intent requires_payment_method
		// with the attempt's error, which a fresh intent has none of.
		Failed:   p.Status == "requires_payment_method" && len(p.LastPaymentError) > 0 && string(p.LastPaymentError) != "null",
		Created:  p.Created,
		Marks:    marks(p.Metadata),
		Received: received(p.AmountReceived, cur),
	}
}

// received is an intent's amount_received as Money, empty when absent.
func received(minor *int64, cur string) backend.Money {
	if minor == nil || cur == "" {
		return backend.Money{}
	}
	return backend.Money{Amount: fromMinorUnits(*minor, cur), Currency: cur}
}

// ListRefundPage lists one page of the account's refunds, of every payment.
func (b *Backend) ListRefundPage(ctx context.Context, q backend.ListQuery) ([]backend.ListedRefund, bool, error) {
	var list refundList
	if _, err := b.list(ctx, "/v1/refunds", q, nil, &list); err != nil {
		return nil, false, err
	}
	out := make([]backend.ListedRefund, 0, len(list.Data))
	for _, r := range list.Data {
		if r.ID == "" {
			return nil, false, fmt.Errorf("stripe: /v1/refunds: a refund without an id")
		}
		out = append(out, backend.ListedRefund{
			RefundResult: backend.RefundResult{
				ProviderRefundID: r.ID,
				Status:           r.Status,
				Amount:           backend.Money{Amount: fromMinorUnits(r.Amount, r.Currency), Currency: r.Currency},
				Key:              r.Metadata[refundKeyMeta],
			},
			ProviderPaymentID: r.PaymentIntent,
			Created:           r.Created,
		})
	}
	return out, list.HasMore, nil
}

// ListSubscriptionPage lists one page of the account's subscriptions, in any
// status (the list leaves canceled ones out unless asked).
func (b *Backend) ListSubscriptionPage(ctx context.Context, q backend.ListQuery) ([]backend.SubscriptionObject, bool, error) {
	var list subscriptionList
	readAt, err := b.list(ctx, "/v1/subscriptions", q, url.Values{"status": {"all"}}, &list)
	if err != nil {
		return nil, false, err
	}
	out := make([]backend.SubscriptionObject, 0, len(list.Data))
	for _, s := range list.Data {
		if s.ID == "" {
			return nil, false, fmt.Errorf("stripe: /v1/subscriptions: a subscription without an id")
		}
		out = append(out, backend.SubscriptionObject{
			SubscriptionResult: backend.SubscriptionResult{
				ProviderSubscriptionID: s.ID,
				Status:                 s.Status,
				CurrentPeriodEnd:       s.CurrentPeriodEnd,
				ProviderPriceID:        s.priceID(),
			},
			ProviderCustomerID: s.Customer,
			Created:            s.Created,
			ReadAt:             readAt,
			Marks:              marks(s.Metadata),
		})
	}
	return out, list.HasMore, nil
}

// list fetches one page of an account-wide list into out, and answers the
// provider's clock at the answer (its Date header; 0 when absent). A page
// refused because its starting_after object is gone is ErrListCursorGone.
func (b *Backend) list(ctx context.Context, path string, q backend.ListQuery, extra url.Values, out any) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path+"?"+listParams(q, extra).Encode(), nil)
	if err != nil {
		return 0, err
	}
	hdr, err := b.doHeader(req, path, "", out)
	if err != nil {
		var coded *backend.CodedError
		if q.After != "" && errors.As(err, &coded) && coded.Code == "resource_missing" {
			return 0, fmt.Errorf("%w: %w", backend.ErrListCursorGone, err)
		}
		return 0, err
	}
	var at int64
	if t, perr := http.ParseTime(hdr.Get("Date")); perr == nil {
		at = t.Unix()
	}
	return at, nil
}

// listParams is the query of one page of a list: created[gte], created[lte],
// limit (1 to 100, the provider's bounds) and starting_after, plus extra.
func listParams(q backend.ListQuery, extra url.Values) url.Values {
	v := url.Values{}
	for k, vs := range extra {
		v[k] = vs
	}
	if q.Since > 0 {
		v.Set("created[gte]", strconv.FormatInt(q.Since, 10))
	}
	if q.Until > 0 {
		v.Set("created[lte]", strconv.FormatInt(q.Until, 10))
	}
	limit := q.Limit
	if limit < 1 || limit > 100 {
		limit = 100
	}
	v.Set("limit", strconv.Itoa(limit))
	if q.After != "" {
		v.Set("starting_after", q.After)
	}
	return v
}

// marks reads the plugin's marks from an object's metadata.
func marks(md map[string]string) backend.Marks {
	return backend.Marks{Origin: md[backend.OriginMetadataKey], Install: md[backend.InstallMetadataKey]}
}

// post issues a form-encoded POST to the Stripe API with bearer auth +
// an optional idempotency key, and decodes the JSON response into out.
// A non-2xx surfaces the Stripe error message.
func (b *Backend) post(ctx context.Context, path string, form url.Values, idemKey string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.do(req, path, idemKey, out)
}

// get issues a GET with query parameters.
func (b *Backend) get(ctx context.Context, path string, query url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	return b.do(req, path, "", out)
}

func (b *Backend) do(req *http.Request, path, idemKey string, out any) error {
	_, err := b.doHeader(req, path, idemKey, out)
	return err
}

// doHeader is do, answering the response headers of a successful call too.
func (b *Backend) doHeader(req *http.Request, path, idemKey string, out any) (http.Header, error) {
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Accept", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("stripe: %s: read body: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e apiError
		_ = json.Unmarshal(body, &e)
		detail := fmt.Sprintf("http %d", resp.StatusCode)
		if e.Error.Message != "" {
			detail = fmt.Sprintf("%s (%s)", e.Error.Message, e.Error.Type)
		}
		err := fmt.Errorf("stripe: %s: %s", path, detail)
		if class := classifyAPIError(resp.StatusCode, e.Error.Type); class != nil {
			err = fmt.Errorf("stripe: %s: %s: %w", path, detail, class)
		}
		if code := reasonCode(e.Error.DeclineCode, e.Error.Code); code != "" {
			err = &backend.CodedError{Code: code, Err: err}
		}
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return nil, fmt.Errorf("stripe: %s: decode response: %w", path, err)
		}
	}
	return resp.Header, nil
}

// reasonCode picks the most specific machine code a Stripe error names
// (decline_code before code), or "" when neither is a plain identifier. Only
// [a-z0-9_] up to 64 bytes passes: the code may reach the caller, so nothing
// that could carry prose (or anything else the provider put there) does.
func reasonCode(candidates ...string) string {
	for _, c := range candidates {
		if c != "" && len(c) <= 64 && strings.Trim(c, "abcdefghijklmnopqrstuvwxyz0123456789_") == "" {
			return c
		}
	}
	return ""
}

// classifyAPIError maps a Stripe error response onto the provider-
// neutral failure classes (nil = transient, the caller may retry).
//
//   - card_error / 402: the charge was declined → backend.ErrDeclined.
//   - 400 / 404 (invalid_request_error, an idempotency key reused with
//     different parameters, a refund above the unrefunded amount): the
//     request is wrong and fails the same way every time →
//     backend.ErrInvalidRequest.
//   - everything else stays transient: 409 (a concurrent request on the
//     same idempotency key is still in flight), 429 and 5xx clear on a
//     retry; 401 / 403 (a bad or under-privileged API key) are the
//     operator's to fix, not the caller's request.
func classifyAPIError(status int, errType string) error {
	switch {
	case errType == "card_error" || status == http.StatusPaymentRequired:
		return backend.ErrDeclined
	case status == http.StatusBadRequest || status == http.StatusNotFound:
		return backend.ErrInvalidRequest
	}
	return nil
}
