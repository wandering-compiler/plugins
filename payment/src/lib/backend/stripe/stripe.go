// Package stripe is the Stripe implementation of backend.Backend
// (Slice 1). It speaks the Stripe REST API directly over net/http — no
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
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

// EnsureCustomer creates a Stripe customer for the principal. v1 always
// creates (the local Customer table's unique user_id is the idempotency
// guard at the plugin layer); a follow-up can search-or-create.
func (b *Backend) EnsureCustomer(ctx context.Context, spec backend.CustomerSpec) (string, error) {
	form := url.Values{}
	if spec.Email != "" {
		form.Set("email", spec.Email)
	}
	if spec.UserID != "" {
		form.Set("metadata[user_id]", spec.UserID)
	}
	var resp customerResp
	if err := b.post(ctx, "/v1/customers", form, "", &resp); err != nil {
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
	var resp refundResp
	if err := b.post(ctx, "/v1/refunds", form, idemKey, &resp); err != nil {
		return backend.RefundResult{}, err
	}
	return backend.RefundResult{ProviderRefundID: resp.ID, Status: resp.Status}, nil
}

// UpsertPlan creates a recurring Stripe Price (with an inline product)
// for the plan and returns its id. v1 always creates; search-or-reuse
// is a follow-up (the local Plan.provider_price_id is the dedup anchor).
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
	if err := b.post(ctx, "/v1/prices", form, "", &resp); err != nil {
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

// post issues a form-encoded POST to the Stripe API with bearer auth +
// an optional idempotency key, and decodes the JSON response into out.
// A non-2xx surfaces the Stripe error message.
func (b *Backend) post(ctx context.Context, path string, form url.Values, idemKey string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("stripe: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("stripe: %s: read body: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e apiError
		_ = json.Unmarshal(body, &e)
		detail := fmt.Sprintf("http %d", resp.StatusCode)
		if e.Error.Message != "" {
			detail = fmt.Sprintf("%s (%s)", e.Error.Message, e.Error.Type)
		}
		if class := classifyAPIError(resp.StatusCode, e.Error.Type); class != nil {
			return fmt.Errorf("stripe: %s: %s: %w", path, detail, class)
		}
		return fmt.Errorf("stripe: %s: %s", path, detail)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("stripe: %s: decode response: %w", path, err)
		}
	}
	return nil
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
