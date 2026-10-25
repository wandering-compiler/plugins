package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func es256(t *testing.T, k *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func appleConfig(t *testing.T) (config, *ecdsa.PrivateKey, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	c := config{Issuer: "http://fakeidp:8080", AppleClientID: "com.example.web", AppleTeamID: "TEAM", AppleKeyID: "KID",
		AppleKey: appleKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})))}
	return c, k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// The token endpoint takes the client secret Apple takes and refuses what
// Apple refuses — above all the key itself, which is what a plugin that
// forgot to mint would send.
func TestVerifyAppleSecret(t *testing.T) {
	c, k, p8 := appleConfig(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	good := map[string]any{"iss": "TEAM", "sub": "com.example.web", "aud": "http://fakeidp:8080", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	hdr := map[string]any{"alg": "ES256", "kid": "KID"}
	if err := c.verifyAppleSecret(es256(t, k, hdr, good), "com.example.web", now); err != nil {
		t.Fatalf("a well-formed secret was refused: %v", err)
	}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	for name, secret := range map[string]string{
		"the .p8 key itself": p8,
		"a plain string":     "csec",
		"another key":        es256(t, other, hdr, good),
		"another kid":        es256(t, k, map[string]any{"alg": "ES256", "kid": "X"}, good),
		"another team":       es256(t, k, hdr, with("iss", "X")),
		"another client":     es256(t, k, hdr, with("sub", "X")),
		"another audience":   es256(t, k, hdr, with("aud", "https://appleid.apple.com")),
		"expired":            es256(t, k, hdr, with("exp", now.Add(-time.Minute).Unix())),
		"a year long":        es256(t, k, hdr, with("exp", now.Add(365*24*time.Hour).Unix())),
	} {
		if c.verifyAppleSecret(secret, "com.example.web", now) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// form_post answers with the page whose form POSTs code and state to the
// registered callback; without it, the 302 as before.
func TestAuthorize_FormPost(t *testing.T) {
	c := config{AllowedRedirects: []string{"http://app/auth/oauth/apple/callback"}}
	r := httptest.NewRequest(http.MethodGet, "/authorize?redirect_uri=http://app/auth/oauth/apple/callback&state=s%22t&response_mode=form_post&nonce=n&code_challenge=ch", nil)
	w := httptest.NewRecorder()
	c.authorize(w, r)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, `method="post" action="http://app/auth/oauth/apple/callback"`) ||
		!strings.Contains(body, `name="state" value="s&#34;t"`) || !strings.Contains(body, `name="code" value="fake.`) {
		t.Fatalf("form_post: %d %s", w.Code, body)
	}
	r = httptest.NewRequest(http.MethodGet, "/authorize?redirect_uri=http://app/auth/oauth/apple/callback&state=s", nil)
	w = httptest.NewRecorder()
	c.authorize(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("without form_post: %d, want the 302", w.Code)
	}
}
