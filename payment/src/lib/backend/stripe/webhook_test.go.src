package stripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
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
