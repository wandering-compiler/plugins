// Package backend is the provider-agnostic payment-gateway contract.
//
// The public proto surface (Customer / Payment / events / PaymentService)
// names no provider; this interface is where a concrete gateway plugs
// in. Slice 1 ships one implementation — lib/backend/stripe — selected
// at RegisterPlugin time by the `payment_provider` env. The interface
// is INTERNAL and unversioned (not a proto contract): adding a second
// driver (Paddle, Adyen, …) is an additive package, and the first
// non-Stripe driver is expected to pressure-test the shape — acceptable
// precisely because nothing on the wire depends on it.
//
// Money is carried as a decimal string + ISO-4217 currency (matching
// the DECIMAL columns), never float64; a driver converts to the
// provider's unit (e.g. integer minor units) at its boundary.
package backend

import (
	"context"
	"errors"
)

// Provider-failure classes. A driver wraps its errors with one of these
// (errors.Is) when it KNOWS the failure is not transient; anything else
// is treated as transient (network, 5xx, rate limit) and the caller may
// retry. The distinction matters because a gRPC client retry policy
// retries UNAVAILABLE automatically: a request the provider refused as
// invalid, or a card it declined, fails identically on every retry.
var (
	// ErrInvalidRequest — the request itself is wrong (an amount the
	// currency cannot represent, a refund larger than the charge, an
	// idempotency key reused with different parameters). Retrying it
	// unchanged cannot succeed.
	ErrInvalidRequest = errors.New("payment provider rejected the request as invalid")
	// ErrDeclined — the provider refused the charge itself (card
	// declined, insufficient funds). A retry needs a different payment
	// method, not a second attempt.
	ErrDeclined = errors.New("payment declined by the provider")
)

// Money is a currency amount as a decimal string (e.g. "19.99") plus a
// lowercase ISO-4217 currency code. String carrier = exact, lossless —
// the same representation the DECIMAL columns use.
type Money struct {
	Amount   string
	Currency string
}

// CustomerSpec is the input to EnsureCustomer.
type CustomerSpec struct {
	UserID string
	Email  string
}

// PaymentSpec is the input to CreatePayment.
type PaymentSpec struct {
	ProviderCustomerID string
	Amount             Money
	IdempotencyKey     string
	Description        string
	// Origin marks the provider object as this plugin's (OriginCharge,
	// OriginTopup), so a webhook for it can tell "ours, local row not
	// landed yet" from "not ours at all".
	Origin string
}

// OriginMetadataKey is the provider metadata key carrying the Origin of an
// object this plugin created. A webhook names objects the plugin never made
// too — a subscription's invoice payments, a dashboard charge, another app on
// the same account — and those have no local row and never will: only an
// object carrying this key is worth failing (and so redelivering) until its
// row lands.
const (
	OriginMetadataKey  = "w17_payment"
	OriginCharge       = "charge"
	OriginTopup        = "topup"
	OriginSubscription = "subscription"
)

// PaymentResult is what the provider returns for a created payment.
type PaymentResult struct {
	ProviderPaymentID string
	// Status is the provider's payment status, mapped by the caller
	// onto the local Payment.Status enum at intent time.
	Status string
	// ClientSecret is the provider token the frontend uses to confirm
	// the payment (e.g. Stripe PaymentIntent client_secret). Empty when
	// the provider has no such concept.
	ClientSecret string
}

// RefundResult is what the provider returns for a refund.
type RefundResult struct {
	ProviderRefundID string
	Status           string
}

// PlanSpec is the input to UpsertPlan — a recurring price the provider
// should offer. Interval is "month" or "year".
type PlanSpec struct {
	Slug     string
	Name     string
	Amount   Money
	Interval string
}

// SubscriptionSpec is the input to StartSubscription.
type SubscriptionSpec struct {
	ProviderCustomerID string
	ProviderPriceID    string
	IdempotencyKey     string
}

// SubscriptionResult is what the provider returns for a started
// subscription. CurrentPeriodEnd is a Unix timestamp (seconds); 0 when
// the provider didn't supply one.
type SubscriptionResult struct {
	ProviderSubscriptionID string
	Status                 string
	CurrentPeriodEnd       int64
}

// Backend is a payment provider. Implementations are constructed with
// their API credentials and are safe for concurrent use.
type Backend interface {
	// Name identifies the driver (e.g. "stripe") for logs / errors.
	Name() string

	// EnsureCustomer creates (or returns the existing) provider customer
	// for the principal and returns its opaque provider id.
	EnsureCustomer(ctx context.Context, spec CustomerSpec) (providerCustomerID string, err error)

	// CreatePayment creates a payment/charge object at the provider with
	// the given idempotency key (so retries never double-charge).
	CreatePayment(ctx context.Context, spec PaymentSpec) (PaymentResult, error)

	// RefundPayment reverses (part of) a payment. idemKey guards retries.
	RefundPayment(ctx context.Context, providerPaymentID string, amount Money, idemKey string) (RefundResult, error)

	// UpsertPlan creates (or returns) the provider price object for a
	// recurring plan and returns its opaque provider price id.
	UpsertPlan(ctx context.Context, spec PlanSpec) (providerPriceID string, err error)

	// StartSubscription subscribes a provider customer to a price.
	StartSubscription(ctx context.Context, spec SubscriptionSpec) (SubscriptionResult, error)
}
