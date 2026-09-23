package stripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// toleranceSeconds bounds how far the signed timestamp may be from now
// (the replay window). Matches the Stripe SDK default of 5 minutes.
const toleranceSeconds int64 = 300

// nowFn is the clock seam — overridable in tests so signature fixtures
// with a fixed `t` stay deterministic.
var nowFn = time.Now

// Event is the minimal parsed shape of a Stripe webhook event the
// payment plugin acts on. Raw keeps the verbatim body for any handler
// that needs deeper fields.
type Event struct {
	ID   string
	Type string
	// ObjectID is data.object.id — the payment_intent id for
	// payment_intent.* events, the subscription id for
	// customer.subscription.* events.
	ObjectID string
	// PaymentIntentID aliases ObjectID for payment events (kept for the
	// core webhook dispatch's readability).
	PaymentIntentID string
	// ObjectStatus is data.object.status — the subscription status on
	// customer.subscription.* events (active / past_due / canceled / …).
	ObjectStatus string
	// CurrentPeriodEnd is data.object.current_period_end (Unix seconds)
	// on subscription events; 0 otherwise.
	CurrentPeriodEnd int64
	Raw              []byte
}

// ErrBadSignature is returned when the Stripe-Signature HMAC does not
// match — the request is not authentic and must be rejected.
var ErrBadSignature = errors.New("stripe: webhook signature verification failed")

// ErrTimestampTooOld is returned when the signature is valid but its
// timestamp is outside the replay-tolerance window — a replayed (or
// badly clock-skewed) event.
var ErrTimestampTooOld = errors.New("stripe: webhook timestamp outside tolerance")

// VerifyAndParse verifies the Stripe-Signature header against the raw
// body using the webhook signing secret (HMAC-SHA256, Stripe's scheme:
// signed_payload = "<t>.<body>"), enforces the timestamp tolerance
// (replay guard), then parses the minimal Event shape.
//
// Signature verification prevents forgery (an attacker cannot compute the
// HMAC without the secret); the tolerance window rejects replays of a
// captured-but-stale event early (the dedup ledger also neutralises
// replays by effect, but rejecting old timestamps stops them sooner).
func VerifyAndParse(payload []byte, sigHeader, secret string) (Event, error) {
	if secret == "" {
		return Event{}, fmt.Errorf("stripe: webhook signing secret not configured")
	}
	t, sigs := parseSignatureHeader(sigHeader)
	if t == "" || len(sigs) == 0 {
		return Event{}, ErrBadSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := mac.Sum(nil)

	ok := false
	for _, s := range sigs {
		got, err := hex.DecodeString(s)
		if err != nil {
			continue
		}
		if hmac.Equal(got, expected) {
			ok = true
			break
		}
	}
	if !ok {
		return Event{}, ErrBadSignature
	}

	// Replay guard: the signature is authentic, but reject it if the
	// signed timestamp is too far from now (in either direction).
	ts, perr := strconv.ParseInt(t, 10, 64)
	if perr != nil {
		return Event{}, ErrBadSignature
	}
	if skew := nowFn().Unix() - ts; skew > toleranceSeconds || skew < -toleranceSeconds {
		return Event{}, ErrTimestampTooOld
	}

	var raw webhookEnvelope
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Event{}, fmt.Errorf("stripe: malformed webhook body: %w", err)
	}
	return Event{
		ID:               raw.ID,
		Type:             raw.Type,
		ObjectID:         raw.Data.Object.ID,
		PaymentIntentID:  raw.Data.Object.ID,
		ObjectStatus:     raw.Data.Object.Status,
		CurrentPeriodEnd: raw.Data.Object.CurrentPeriodEnd,
		Raw:              payload,
	}, nil
}

// parseSignatureHeader splits a Stripe-Signature header
// ("t=123,v1=abc,v1=def,v0=...") into the timestamp and the list of v1
// signatures.
func parseSignatureHeader(h string) (t string, v1 []string) {
	for _, part := range strings.Split(h, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			t = kv[1]
		case "v1":
			v1 = append(v1, kv[1])
		}
	}
	return t, v1
}
