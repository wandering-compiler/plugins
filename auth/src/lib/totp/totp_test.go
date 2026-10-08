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

// Match names the step that matched — the one the caller records so a code
// is accepted once. Whatever step it names must be one whose code this is
// (codes of neighbouring windows collide one time in 10^6), inside the skew.
func TestMatch_ReportsTheMatchedStep(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()
	base := now.Unix() / period
	for d := int64(-1); d <= 1; d++ {
		code := mustCode(t, secret, base+d)
		step, ok := Match(secret, code, now, 1)
		if !ok || step < base-1 || step > base+1 || mustCode(t, secret, step) != code {
			t.Errorf("offset %d: step=%d ok=%v", d, step, ok)
		}
	}
	far := mustCode(t, secret, base+5)
	if step, ok := Match(secret, far, now, 1); ok && mustCode(t, secret, step) != far {
		t.Errorf("a code five windows away matched step %d", step)
	}
}

func mustCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	c, err := Code(secret, time.Unix(step*period, 0))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
