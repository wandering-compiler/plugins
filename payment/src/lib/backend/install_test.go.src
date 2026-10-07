package backend

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The install id is a keyed hash of the webhook signing secret: stable per
// secret, distinct between secrets, never the secret itself, and empty when
// there is no secret (an installation without webhooks marks nothing).
func TestInstallID(t *testing.T) {
	const secret = "whsec_install_fixture_a"
	id := InstallID(secret)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("w17-install-id"))
	if want := hex.EncodeToString(mac.Sum(nil))[:16]; id != want {
		t.Fatalf("InstallID = %q, want %q", id, want)
	}
	if id != InstallID(secret) {
		t.Error("not deterministic — every replica of one installation must agree")
	}
	if InstallID("whsec_install_fixture_b") == id {
		t.Error("two secrets (two installations) share an id")
	}
	if strings.Contains(secret, id) || strings.Contains(id, strings.TrimPrefix(secret, "whsec_")[:8]) {
		t.Errorf("the id %q exposes the secret", id)
	}
	if InstallID("") != "" {
		t.Error("no secret must mean no install mark")
	}
}
