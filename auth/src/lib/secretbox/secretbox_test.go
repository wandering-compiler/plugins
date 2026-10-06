package secretbox

import (
	"encoding/base64"
	"strings"
	"testing"
)

func testKeyB64() string {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(key)
}

func TestSealOpen_RoundTrip(t *testing.T) {
	c, err := NewFromBase64(testKeyB64())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	plain := "JBSWY3DPEHPK3PXP"
	blob, err := c.Seal(plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if strings.Contains(blob, plain) {
		t.Error("ciphertext must not contain the plaintext secret")
	}
	got, err := c.Open(blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != plain {
		t.Errorf("round-trip = %q, want %q", got, plain)
	}
}

func TestSeal_NonceUnique(t *testing.T) {
	c, _ := NewFromBase64(testKeyB64())
	a, _ := c.Seal("same")
	b, _ := c.Seal("same")
	if a == b {
		t.Error("two seals of the same plaintext must differ (random nonce)")
	}
}

func TestOpen_WrongKeyFails(t *testing.T) {
	c1, _ := NewFromBase64(testKeyB64())
	blob, _ := c1.Seal("secret")

	otherKey := make([]byte, KeySize)
	for i := range otherKey {
		otherKey[i] = byte(255 - i)
	}
	c2, _ := New(otherKey)
	if _, err := c2.Open(blob); err == nil {
		t.Error("opening with the wrong key must fail the auth tag")
	}
}

func TestNewFromBase64_EmptyKey(t *testing.T) {
	if _, err := NewFromBase64(""); err != ErrNoKey {
		t.Errorf("empty key should return ErrNoKey, got %v", err)
	}
}

func TestNew_BadKeyLength(t *testing.T) {
	if _, err := New([]byte("too-short")); err == nil {
		t.Error("a non-32-byte key must be rejected")
	}
}
