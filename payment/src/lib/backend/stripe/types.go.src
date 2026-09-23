package stripe

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

// paymentIntentResp ← POST /v1/payment_intents
type paymentIntentResp struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	ClientSecret string `json:"client_secret"`
}

// refundResp ← POST /v1/refunds
type refundResp struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// priceResp ← POST /v1/prices
type priceResp struct {
	ID string `json:"id"`
}

// subscriptionResp ← POST /v1/subscriptions
type subscriptionResp struct {
	ID               string `json:"id"`
	Status           string `json:"status"`
	CurrentPeriodEnd int64  `json:"current_period_end"`
}

// apiError ← any non-2xx Stripe response body.
type apiError struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

// webhookEnvelope is the parsed shape of an inbound webhook event. For
// payment_intent.* events data.object.id is the payment-intent id; for
// customer.subscription.* it is the subscription id (+ status /
// current_period_end).
type webhookEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID               string `json:"id"`
			Status           string `json:"status"`
			CurrentPeriodEnd int64  `json:"current_period_end"`
		} `json:"object"`
	} `json:"data"`
}
