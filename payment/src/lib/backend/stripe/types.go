package stripe

import "encoding/json"

// This file is the single place documenting the Stripe API wire surface
// the driver depends on — the JSON RESPONSE shapes it decodes and the
// webhook envelope it parses. (Requests are form-encoded `url.Values`
// built at each call site, so they aren't modeled as structs.) Field
// names + json tags mirror Stripe's API; keeping them together makes
// "what Stripe shape do we rely on" auditable in one read instead of
// scattered as anonymous inline structs across the call sites.
//
// All types are driver-internal (unexported) — the public surface is
// the provider-neutral backend.Backend interface, never these.

// customerResp ← POST /v1/customers
type customerResp struct {
	ID string `json:"id"`
}

// customerList ← GET /v1/customers
type customerList struct {
	Data []struct {
		ID       string            `json:"id"`
		Email    string            `json:"email"`
		Metadata map[string]string `json:"metadata"`
		Created  int64             `json:"created"`
	} `json:"data"`
	HasMore bool `json:"has_more"`
}

// paymentIntentResp ← POST /v1/payment_intents
type paymentIntentResp struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	ClientSecret string `json:"client_secret"`
}

// paymentIntentList ← GET /v1/payment_intents
type paymentIntentList struct {
	Data    []paymentIntentObject `json:"data"`
	HasMore bool                  `json:"has_more"`
}

// paymentIntentObject is one payment intent, listed or read by id.
type paymentIntentObject struct {
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Amount      int64             `json:"amount"` // minor units
	Currency    string            `json:"currency"`
	Customer    string            `json:"customer"` // the id (not expanded)
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
	Created     int64             `json:"created"`
	// The last attempt's error; null when no attempt failed.
	LastPaymentError json.RawMessage `json:"last_payment_error"`
	// What the intent took, in minor units of Currency.
	AmountReceived *int64 `json:"amount_received"`
}

// refundResp ← POST /v1/refunds
type refundResp struct {
	ID            string            `json:"id"`
	Status        string            `json:"status"`
	Amount        int64             `json:"amount"`   // minor units
	Currency      string            `json:"currency"` // lowercase ISO-4217
	Metadata      map[string]string `json:"metadata"`
	PaymentIntent string            `json:"payment_intent"` // on a list item
	Created       int64             `json:"created"`
}

// refundList ← GET /v1/refunds
type refundList struct {
	Data    []refundResp `json:"data"`
	HasMore bool         `json:"has_more"`
}

// priceResp ← POST /v1/prices
type priceResp struct {
	ID string `json:"id"`
}

// subscriptionResp ← POST /v1/subscriptions
type subscriptionResp struct {
	ID               string            `json:"id"`
	Customer         string            `json:"customer"` // the id (not expanded)
	Created          int64             `json:"created"`
	Status           string            `json:"status"`
	CurrentPeriodEnd int64             `json:"current_period_end"`
	Metadata         map[string]string `json:"metadata"`
	Items            subscriptionItems `json:"items"`
	// LatestInvoice is an id, or — expanded with its payment intent — the
	// invoice object; clientSecret reads either.
	LatestInvoice json.RawMessage `json:"latest_invoice"`
}

// clientSecret is the client secret of the subscription's latest invoice's
// payment, while that payment awaits the client; "" when the invoice is not
// expanded, has no payment, or the payment needs nothing from the client.
func (s subscriptionResp) clientSecret() string {
	var inv struct {
		PaymentIntent *struct {
			ClientSecret string `json:"client_secret"`
			Status       string `json:"status"`
		} `json:"payment_intent"`
	}
	if len(s.LatestInvoice) == 0 || s.LatestInvoice[0] != '{' || json.Unmarshal(s.LatestInvoice, &inv) != nil || inv.PaymentIntent == nil {
		return ""
	}
	switch inv.PaymentIntent.Status {
	case "requires_payment_method", "requires_confirmation", "requires_action":
		return inv.PaymentIntent.ClientSecret
	}
	return ""
}

// subscriptionItems is a subscription's items: its price, and — from API
// version 2025-03-31 on — its billing period, which moved there from the
// subscription itself.
type subscriptionItems struct {
	Data []struct {
		Price struct {
			ID string `json:"id"`
		} `json:"price"`
		CurrentPeriodEnd int64 `json:"current_period_end"`
	} `json:"data"`
}

// periodEnd is the end of a subscription's current period: on the
// subscription (the pinned version, and every version before 2025-03-31),
// else on its first (only) item. A webhook endpoint keeps the version it was
// created with, which the plugin cannot pin, so both shapes are read.
func periodEnd(root int64, items subscriptionItems) int64 {
	if root != 0 || len(items.Data) == 0 {
		return root
	}
	return items.Data[0].CurrentPeriodEnd
}

// priceID is the price of the subscription's first (only) item.
func (s subscriptionResp) priceID() string {
	if len(s.Items.Data) == 0 {
		return ""
	}
	return s.Items.Data[0].Price.ID
}

// subscriptionList ← GET /v1/subscriptions
type subscriptionList struct {
	Data    []subscriptionResp `json:"data"`
	HasMore bool               `json:"has_more"`
}

// apiError ← any non-2xx Stripe response body.
type apiError struct {
	Error struct {
		Message     string `json:"message"`
		Type        string `json:"type"`
		Code        string `json:"code"`
		DeclineCode string `json:"decline_code"`
	} `json:"error"`
}

// webhookEnvelope is the parsed shape of an inbound webhook event. For
// payment_intent.* events data.object.id is the payment-intent id; for
// customer.subscription.* it is the subscription id (+ status /
// current_period_end); for charge.dispute.* the dispute id (+ status, amount,
// currency, payment_intent); for refund.* the refund id.
type webhookEnvelope struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	// APIVersion is the version the event was rendered in: the webhook
	// endpoint's, which the plugin cannot pin.
	APIVersion string `json:"api_version"`
	Data       struct {
		Object struct {
			ID               string            `json:"id"`
			Status           string            `json:"status"`
			CurrentPeriodEnd int64             `json:"current_period_end"`
			Items            subscriptionItems `json:"items"`
			Metadata         map[string]string `json:"metadata"`
			// On a charge: the PaymentIntent it belongs to, and whether it
			// is fully refunded.
			PaymentIntent string `json:"payment_intent"`
			Refunded      bool   `json:"refunded"`
			// On a refund or a dispute: its amount (minor units) and currency.
			Amount   int64  `json:"amount"`
			Currency string `json:"currency"`
			// On a payment intent: what it took (minor units of Currency);
			// absent on other objects.
			AmountReceived *int64 `json:"amount_received"`
		} `json:"object"`
	} `json:"data"`
}
