package stripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/payment/lib/backend"
)

func sign(payload []byte, secret, t string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t + "."))
	mac.Write(payload)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// pinClock fixes nowFn so a fixture with timestamp `unix` sits inside the
// tolerance window (deterministic — no wall-clock dependence).
func pinClock(t *testing.T, unix int64) {
	t.Helper()
	prev := nowFn
	nowFn = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { nowFn = prev })
}

func TestVerifyAndParse_Valid(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	body := []byte(`{"id":"evt_1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_7"}}}`)
	ev, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
	if err != nil {
		t.Fatalf("VerifyAndParse: %v", err)
	}
	if ev.ID != "evt_1" || ev.Type != "payment_intent.succeeded" || ev.PaymentIntentID != "pi_7" {
		t.Errorf("parsed = %+v", ev)
	}
}

// A dispute (or refund) event carries the payment it belongs to and its
// amount, as a decimal of its currency.
func TestVerifyAndParse_DisputeAmountAndPayment(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	body := []byte(`{"id":"evt_1","type":"charge.dispute.closed","created":120,"data":{"object":{"id":"dp_1","status":"lost","amount":1999,"currency":"USD","payment_intent":"pi_7"}}}`)
	ev, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
	if err != nil {
		t.Fatalf("VerifyAndParse: %v", err)
	}
	if ev.ObjectID != "dp_1" || ev.ObjectStatus != "lost" || ev.ChargePaymentIntent != "pi_7" || ev.Created != 120 ||
		ev.Amount != (backend.Money{Amount: "19.99", Currency: "usd"}) {
		t.Errorf("parsed = %+v", ev)
	}
}

func TestVerifyAndParse_BadSignature(t *testing.T) {
	body := []byte(`{"id":"evt_1"}`)
	_, err := VerifyAndParse(body, sign(body, "wrong", "123"), "right")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyAndParse_EmptySecret(t *testing.T) {
	if _, err := VerifyAndParse([]byte(`{}`), "t=1,v1=ab", ""); err == nil {
		t.Fatal("want error on empty secret")
	}
}

func TestVerifyAndParse_MalformedBodyButValidSig(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	body := []byte(`not json`)
	_, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
	if err == nil || errors.Is(err, ErrBadSignature) {
		t.Fatalf("want a parse error (not signature), got %v", err)
	}
}

// TestVerifyAndParse_TimestampTooOld: an authentic signature whose
// timestamp is outside the tolerance window is rejected (replay guard).
func TestVerifyAndParse_TimestampTooOld(t *testing.T) {
	pinClock(t, 1_000_000) // "now"
	secret := "whsec_x"
	body := []byte(`{"id":"evt_1"}`)
	// Signed at t=123 — ~999k seconds in the past, well past the 300s window.
	_, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
	if !errors.Is(err, ErrTimestampTooOld) {
		t.Fatalf("want ErrTimestampTooOld, got %v", err)
	}
	// A timestamp at "now" passes the window (and then fails only on parse,
	// proving the window check itself accepted it).
	if _, err := VerifyAndParse(body, sign(body, secret, "1000000"), secret); errors.Is(err, ErrTimestampTooOld) {
		t.Fatalf("in-window timestamp wrongly rejected: %v", err)
	}
}

func TestVerifyAndParse_MissingHeaderParts(t *testing.T) {
	if _, err := VerifyAndParse([]byte(`{}`), "garbage", "s"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature for unparseable header, got %v", err)
	}
}

// A payment intent's event carries what it took (amount_received) beside
// what was asked; an event without it reports none, never zero.
func TestVerifyAndParse_PaymentReceived(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	body := []byte(`{"id":"evt_1","type":"payment_intent.succeeded","created":120,"data":{"object":{"id":"pi_1","status":"succeeded","amount":100000,"amount_received":1000,"currency":"CZK"}}}`)
	ev, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
	if err != nil {
		t.Fatalf("VerifyAndParse: %v", err)
	}
	if ev.Received != (backend.Money{Amount: "10.00", Currency: "czk"}) || ev.Amount != (backend.Money{Amount: "1000.00", Currency: "czk"}) {
		t.Errorf("received %+v, amount %+v", ev.Received, ev.Amount)
	}
	body = []byte(`{"id":"evt_2","type":"payment_intent.succeeded","created":120,"data":{"object":{"id":"pi_1","amount":100,"currency":"usd"}}}`)
	if ev, err = VerifyAndParse(body, sign(body, secret, "123"), secret); err != nil || ev.Received != (backend.Money{}) {
		t.Errorf("no amount_received: %+v, %v — want none", ev.Received, err)
	}
	body = []byte(`{"id":"evt_3","type":"payment_intent.succeeded","created":120,"data":{"object":{"id":"pi_1","amount":100,"amount_received":0,"currency":"usd"}}}`)
	if ev, err = VerifyAndParse(body, sign(body, secret, "123"), secret); err != nil || ev.Received != (backend.Money{Amount: "0.00", Currency: "usd"}) {
		t.Errorf("amount_received 0: %+v, %v — want a received 0", ev.Received, err)
	}
}

// A customer.subscription.* event rendered in API 2025-03-31 or later carries
// the period end on its item, not on the subscription; the webhook endpoint
// keeps the version it was made with, so both are read. Its version is kept.
func TestVerifyAndParse_SubscriptionPeriodInEitherShape(t *testing.T) {
	pinClock(t, 123)
	secret := "whsec_x"
	for _, c := range []struct {
		body    string
		want    int64
		version string
	}{
		{`{"id":"evt_1","type":"customer.subscription.updated","created":120,"api_version":"2024-06-20","data":{"object":{"id":"sub_1","status":"active","current_period_end":1800000000}}}`, 1800000000, "2024-06-20"},
		{`{"id":"evt_2","type":"customer.subscription.updated","created":120,"api_version":"2025-03-31.basil","data":{"object":{"id":"sub_1","status":"active","items":{"data":[{"current_period_end":1900000000}]}}}}`, 1900000000, "2025-03-31.basil"},
	} {
		body := []byte(c.body)
		ev, err := VerifyAndParse(body, sign(body, secret, "123"), secret)
		if err != nil {
			t.Fatal(err)
		}
		if ev.CurrentPeriodEnd != c.want || ev.APIVersion != c.version {
			t.Errorf("%s: period end %d, version %q; want %d, %q", c.version, ev.CurrentPeriodEnd, ev.APIVersion, c.want, c.version)
		}
	}
}
