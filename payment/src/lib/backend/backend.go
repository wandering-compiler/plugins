// Package backend is the provider-agnostic payment-gateway contract.
//
// The public proto surface (Customer / Payment / events / PaymentService)
// names no provider; this interface is where a concrete gateway plugs
// in. There is one implementation — lib/backend/stripe — selected
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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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

// InputError is an invalid request the driver found in the caller's own input
// before calling the provider (an amount the currency cannot represent). Its
// message describes only that input, so it may be shown to the caller; a
// provider's own error text never is. It matches [ErrInvalidRequest].
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// Is makes an InputError an [ErrInvalidRequest].
func (e *InputError) Is(target error) bool { return target == ErrInvalidRequest }

// CodedError is a provider failure that names its reason with the provider's
// machine code (Stripe's decline_code or code: "insufficient_funds",
// "charge_already_refunded"). Code is a fixed identifier the driver checked
// to be one ([a-z0-9_], at most 64 bytes), never the provider's prose, so it
// may be shown to the caller; Err, the full cause, may not.
type CodedError struct {
	Code string
	Err  error
}

func (e *CodedError) Error() string { return e.Err.Error() }

// Unwrap exposes the cause, so the failure class it wraps still matches.
func (e *CodedError) Unwrap() error { return e.Err }

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
	// IdempotencyKey is sent with the create, so a retried first charge (the
	// customer created, the local link not yet written) gets the customer the
	// first attempt made instead of a second, unreferenced one.
	IdempotencyKey string
	// Install is written as the customer's install mark, beside the origin
	// mark OriginCustomer (see PaymentSpec.Install). Empty writes neither.
	Install string
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
	// Install names the installation that created the object (InstallID);
	// written beside Origin. Empty writes no install mark.
	Install string
}

// OriginMetadataKey is the provider metadata key carrying the Origin of an
// object this plugin created. A webhook names objects the plugin never made
// too — a subscription's invoice payments, a dashboard charge, another app on
// the same account — and those have no local row and never will: only an
// object carrying this key AND this installation's InstallMetadataKey is
// worth failing (and so redelivering) until its row lands.
const (
	OriginMetadataKey  = "w17_payment"
	OriginCharge       = "charge"
	OriginTopup        = "topup"
	OriginSubscription = "subscription"
	OriginCustomer     = "customer"
)

// InstallMetadataKey is the provider metadata key carrying the InstallID of
// the installation that created the object.
//
// The origin mark alone says "some w17 payment plugin made this", and one
// provider account is routinely shared by several installations (staging
// and production on the same test-mode account, two apps of one company).
// Each installation's webhook endpoint receives every event of the account,
// so each saw the OTHER's marked objects, found no local row, and failed the
// event — redelivered for days, on every installation but the one that made
// the object. Only an object carrying THIS installation's id is worth failing
// until its row lands; one marked by another installation is acknowledged.
const InstallMetadataKey = "w17_install"

// InstallID derives the installation identity from the webhook signing
// secret: hex(HMAC-SHA256(secret, "w17-install-id"))[:16].
//
// The signing secret is the one value that is per installation by
// construction — the provider issues one per webhook endpoint, and an
// installation that receives webhooks has exactly one endpoint — and that
// every replica of one installation shares. The id is a keyed hash, so it
// is safe to write into provider metadata: it does not help recover the
// secret (the secret is a high-entropy random token, and HMAC is a PRF),
// and it is stable for as long as the secret is.
//
// Empty for an empty secret: an installation without webhooks has no events
// to tell apart, and marks nothing. Rotating the secret changes the id; an
// object created under the old id whose local row has not landed by then is
// treated as foreign (acknowledged), so rotate while no charge is in flight.
func InstallID(webhookSecret string) string {
	if webhookSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write([]byte("w17-install-id"))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

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
	// Status is the provider's refund status ("pending", "succeeded",
	// "failed", "canceled", "requires_action"), mapped by the caller onto
	// the local Refund.Status.
	Status string
	// Amount is the refund's amount, in the payment's currency. FindRefund
	// and ListRefunds must set it: the caller compares it with the amount a
	// retry asks for, and records it for a refund it did not make.
	Amount Money
	// Key is the idempotency key RefundPayment stored on the refund (empty
	// on a refund it did not make). FindRefund and ListRefunds set it.
	Key string
}

// PlanSpec is the input to UpsertPlan — a recurring price the provider
// should offer. Interval is "month" or "year".
type PlanSpec struct {
	Slug     string
	Name     string
	Amount   Money
	Interval string
	// IdempotencyKey is sent with the create, so a retried or racing
	// CreatePlan gets the price the first attempt made instead of an orphan.
	IdempotencyKey string
}

// SubscriptionSpec is the input to StartSubscription.
type SubscriptionSpec struct {
	ProviderCustomerID string
	ProviderPriceID    string
	IdempotencyKey     string
	// Install is written as the object's install mark (see
	// PaymentSpec.Install).
	Install string
}

// SubscriptionResult is what the provider returns for a started
// subscription. CurrentPeriodEnd is a Unix timestamp (seconds); 0 when
// the provider didn't supply one.
type SubscriptionResult struct {
	ProviderSubscriptionID string
	Status                 string
	CurrentPeriodEnd       int64
	// ProviderPriceID is the price the subscription is on. FindSubscription
	// must set it: the caller compares it with the plan a retry asks for,
	// and a key that names a subscription to another plan is refused.
	ProviderPriceID string
	// ClientSecret confirms the subscription's first payment on the client
	// (the provider's token, as for a charge), while the subscription awaits
	// it; empty otherwise, and from FindSubscription. Never stored.
	ClientSecret string
}

// ListQuery selects one page of a provider list, newest object first.
type ListQuery struct {
	// Since bounds the list to objects created at or after it (Unix seconds).
	Since int64
	// After continues the list after this object id, the last of the previous
	// page; empty starts at the newest.
	After string
	// Until bounds the list to objects created at or before it (Unix
	// seconds); 0 = no bound. How a walk continues when the object After
	// names is gone (ErrListCursorGone): from that object's creation time.
	Until int64
	// Limit is the page size, 1 to 100.
	Limit int
}

// Marks are the metadata marks this plugin writes on an object it creates:
// the origin (OriginMetadataKey) and the installation (InstallMetadataKey).
// Both empty on an object no installation of the plugin made.
type Marks struct {
	Origin  string
	Install string
}

// CustomerObject is a provider customer as a list returns it.
type CustomerObject struct {
	ProviderCustomerID string
	// UserID is the principal EnsureCustomer wrote into the customer's
	// metadata; Email its e-mail.
	UserID string
	Email  string
	// Created is the object's creation time (Unix seconds), on every listed
	// object.
	Created int64
	Marks
}

// PaymentObject is a provider payment as a list returns it.
type PaymentObject struct {
	ProviderPaymentID  string
	ProviderCustomerID string
	// Status is the provider's payment status (see PaymentResult.Status).
	Status      string
	Amount      Money
	Description string
	// Failed reports that the last attempt to pay failed: the provider
	// keeps such a payment open for another attempt, under the same status
	// a payment nobody has tried to pay yet has.
	Failed  bool
	Created int64
	Marks
	// Received is what the payment took (amount_received), in its currency;
	// empty (no Currency) when the provider reports none. A succeeded payment
	// is checked against its local row by it (verifyReceived).
	Received Money
}

// ListedRefund is a refund as the account-wide refund list returns it, with
// the payment it belongs to.
type ListedRefund struct {
	RefundResult
	ProviderPaymentID string
	Created           int64
}

// SubscriptionObject is a provider subscription as a list returns it, with
// ProviderPriceID set.
type SubscriptionObject struct {
	SubscriptionResult
	ProviderCustomerID string
	Created            int64
	// ReadAt is the provider's own clock when it answered the list (Unix
	// seconds; 0 when it did not say). The provider stamps its webhook events
	// on the same clock, so a status recorded from this read is ordered
	// against them without trusting the local clock.
	ReadAt int64
	Marks
}

// ErrListCursorGone is a list page refused because the object ListQuery.After
// names no longer exists (deleted at the provider). Continue with Until set
// to that object's creation time instead.
var ErrListCursorGone = errors.New("payment provider: the object a list continues after is gone")

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

	// GetPayment reads one payment object as the provider holds it now.
	// RefundPayment asks it when the local status does not yet say whether
	// the payment succeeded (its webhook has not arrived): the refund goes
	// ahead only for a payment the provider reports succeeded.
	GetPayment(ctx context.Context, providerPaymentID string) (PaymentObject, error)

	// RefundPayment reverses (part of) a payment. idemKey guards retries.
	RefundPayment(ctx context.Context, providerPaymentID string, amount Money, idemKey string) (RefundResult, error)
	// FindRefund returns the refund of providerPaymentID made under idemKey,
	// if the provider holds one, with its Amount set. It is how a retry
	// recognises a refund whose local record was never written, after the
	// provider has forgotten the idempotency key. A provider that cannot
	// look a refund up by key returns (_, false, nil): the old behaviour.
	FindRefund(ctx context.Context, providerPaymentID, idemKey string) (RefundResult, bool, error)
	// ListRefunds returns every refund of providerPaymentID the provider
	// holds, in their current state, with Amount and Key set — the refunds
	// made through RefundPayment and those made at the provider directly. The
	// refund webhooks reconcile against it rather than against the event's
	// own snapshot, which may be older than the refund's current state.
	ListRefunds(ctx context.Context, providerPaymentID string) ([]RefundResult, error)

	// UpsertPlan creates (or returns) the provider price object for a
	// recurring plan and returns its opaque provider price id.
	UpsertPlan(ctx context.Context, spec PlanSpec) (providerPriceID string, err error)

	// StartSubscription subscribes a provider customer to a price.
	StartSubscription(ctx context.Context, spec SubscriptionSpec) (SubscriptionResult, error)
	// FindSubscription returns the customer's subscription started under
	// idemKey, if the provider holds one, whatever its status, with its
	// ProviderPriceID set (see FindRefund).
	FindSubscription(ctx context.Context, providerCustomerID, idemKey string) (SubscriptionResult, bool, error)

	// GetSubscription reads one subscription as the provider holds it now,
	// with the client secret of its first payment while it awaits one.
	// Subscribe asks it for a subscription of the same plan still waiting to
	// be paid, to hand the caller that payment instead of a second
	// subscription.
	GetSubscription(ctx context.Context, providerSubscriptionID string) (SubscriptionObject, error)

	// The account-wide lists the provider reconciliation walks
	// (ReconcileProvider): one page each, newest first, of the objects
	// created at or after q.Since, and whether more follow. Subscriptions are
	// listed whatever their status.
	ListCustomerPage(ctx context.Context, q ListQuery) ([]CustomerObject, bool, error)
	ListPaymentPage(ctx context.Context, q ListQuery) ([]PaymentObject, bool, error)
	ListRefundPage(ctx context.Context, q ListQuery) ([]ListedRefund, bool, error)
	ListSubscriptionPage(ctx context.Context, q ListQuery) ([]SubscriptionObject, bool, error)
}
