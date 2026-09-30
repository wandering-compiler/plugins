package totp

import (
	"strings"
	"testing"
	"time"
)

func TestCodeMatchesVerify(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	code, err := Code(secret, now)
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("code %q is not 6 digits", code)
	}
	if !Verify(secret, code, now, 1) {
		t.Error("freshly computed code must verify")
	}
}

func TestVerify_RejectsWrongCode(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)
	if Verify(secret, "000000", now, 1) {
		// astronomically unlikely to actually be the code; guards regressions
		code, _ := Code(secret, now)
		if code != "000000" {
			t.Error("a wrong code must not verify")
		}
	}
	if Verify(secret, "", now, 1) {
		t.Error("empty code must not verify")
	}
}

func TestVerify_SkewWindow(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Unix(1_700_000_000, 0)
	prev := now.Add(-30 * time.Second)
	prevCode, _ := Code(secret, prev)
	if !Verify(secret, prevCode, now, 1) {
		t.Error("previous-window code must verify with skew=1")
	}
	if Verify(secret, prevCode, now, 0) {
		t.Error("previous-window code must NOT verify with skew=0")
	}
}

func TestVerify_BadSecret(t *testing.T) {
	if Verify("not!valid!base32", "123456", time.Now(), 1) {
		t.Error("a malformed secret must fail verification, not panic")
	}
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("JBSWY3DPEHPK3PXP", "Acme", "alice@example.com")
	if !strings.HasPrefix(uri, "otpauth://totp/Acme:alice@example.com?") {
		t.Errorf("unexpected label/prefix: %s", uri)
	}
	for _, want := range []string{"secret=JBSWY3DPEHPK3PXP", "issuer=Acme", "algorithm=SHA1", "digits=6", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI missing %q: %s", want, uri)
		}
	}
}
