package devicekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// RFC 7638 §3.1: the example RSA key's SHA-256 thumbprint. Parse refuses RSA
// (no device signs with it); the canonical-JSON hash under it is the same.
func TestThumbprint_RFC7638Vector(t *testing.T) {
	n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
		"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
		"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
		"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
		"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
		"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
	got := Thumbprint(map[string]string{"e": "AQAB", "kty": "RSA", "n": n})
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
}

// The P-256 key of the RFC 9449 examples, members in the RFC's order, and its
// jkt (RFC 9449 §6.1); the Ed25519 key of RFC 8037 Appendix A and its
// thumbprint (A.3).
const (
	rfc9449JWK = `{"kty":"EC","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","crv":"P-256"}`
	rfc9449JKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	rfc8037JWK = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
	rfc8037JKT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func TestParse_RFCVectors(t *testing.T) {
	for jwk, want := range map[string]Key{
		rfc9449JWK: {Type: "EC", Thumbprint: rfc9449JKT},
		rfc8037JWK: {Type: "OKP", Thumbprint: rfc8037JKT},
	} {
		got, err := Parse(jwk)
		if err != nil || got != want {
			t.Errorf("Parse(%s) = %+v, %v; want %+v", jwk, got, err, want)
		}
	}
}

// A cross-check by an independent spelling of RFC 7638: freshly generated
// keys, written as JWKs with optional members a WebCrypto export adds, hash to
// the SHA-256 of the canonical string assembled by hand.
func TestParse_GeneratedKeysMatchTheCanonicalForm(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return b64(sum[:])
	}
	for i := 0; i < 20; i++ {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ec.PublicKey.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		pt := raw.Bytes() // 0x04 || x || y
		x, y := b64(pt[1:33]), b64(pt[33:])
		jwk := fmt.Sprintf(`{"crv":"P-256","ext":true,"key_ops":["verify"],"kty":"EC","x":%q,"y":%q}`, x, y)
		want := hash(fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, x, y))
		if got, err := Parse(jwk); err != nil || got.Thumbprint != want {
			t.Fatalf("P-256 %s: %+v, %v; want %s", jwk, got, err, want)
		}

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ex := b64(pub)
		jwk = fmt.Sprintf(`{"alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":%q,"use":"sig","kid":"ci"}`, ex)
		want = hash(fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, ex))
		if got, err := Parse(jwk); err != nil || got.Thumbprint != want {
			t.Fatalf("Ed25519 %s: %+v, %v; want %s", jwk, got, err, want)
		}
	}
}

// device/private-key-never-leaves: a JWK with any private member is refused
// as a private key — before the rest is read, so a private key of an
// unsupported type or with a malformed public half is still named for what
// it is — and the error carries no part of it.
func TestParse_RefusesAnyPrivateMember(t *testing.T) {
	const d = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	for _, jwk := range []string{
		`{"kty":"EC","crv":"P-256","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA","d":"` + d + `"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"` + d + `"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","D":"` + d + `"}`,
		`{"kty":"RSA","n":"AQAB","e":"AQAB","p":"` + d + `"}`,
		`{"kty":"oct","k":"` + d + `"}`,
		`{"d":"` + d + `"}`,
	} {
		_, err := Parse(jwk)
		if !errors.Is(err, ErrPrivateKey) {
			t.Errorf("Parse(%s) = %v, want ErrPrivateKey", jwk, err)
		}
		if err != nil && strings.Contains(err.Error(), d[:8]) {
			t.Errorf("the error repeats the private key: %v", err)
		}
	}
}

func TestParse_RefusesOtherKeyTypesAndCurves(t *testing.T) {
	for _, jwk := range []string{
		`{"kty":"RSA","n":"0vx7","e":"AQAB"}`,
		`{"kty":"EC","crv":"P-384","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}`,
		`{"kty":"EC","crv":"secp256k1","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}`,
		`{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"OKP","crv":"Ed448","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		// The key fits, the declared algorithm or use does not.
		`{"kty":"EC","crv":"P-256","alg":"ES384","x":"l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs","y":"9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}`,
		`{"kty":"OKP","crv":"Ed25519","alg":"ES256","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"OKP","crv":"Ed25519","use":"enc","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		`{"kty":"OKP","crv":"Ed25519","key_ops":["sign"],"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
	} {
		if _, err := Parse(jwk); !errors.Is(err, ErrUnsupported) {
			t.Errorf("Parse(%s) = %v, want ErrUnsupported", jwk, err)
		}
	}
}

// A point off the curve, a coordinate of the wrong size or spelling, and
// every shape that is not one JWK object are malformed.
func TestParse_RefusesMalformedKeys(t *testing.T) {
	const x, y = "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
	offCurve := "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDE" // y + 1 in its last byte, still canonical base64url
	for name, jwk := range map[string]string{
		"off the curve":      `{"kty":"EC","crv":"P-256","x":"` + x + `","y":"` + offCurve + `"}`,
		"x and y swapped":    `{"kty":"EC","crv":"P-256","x":"` + y + `","y":"` + x + `"}`,
		"zero point":         `{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		"no y":               `{"kty":"EC","crv":"P-256","x":"` + x + `"}`,
		"short x":            `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcH"}`,
		"padded x":           `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo="}`,
		"standard base64":    `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"non-canonical bits": `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURp"}`,
		"y on an OKP key":    `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","y":"` + y + `"}`,
		"unknown member":     `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","x5c":["MII"]}`,
		"duplicate member":   `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"x is a number":      `{"kty":"OKP","crv":"Ed25519","x":1}`,
		"kty missing":        `{"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"ext not a boolean":  `{"kty":"OKP","crv":"Ed25519","ext":"yes","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`,
		"two objects":        rfc8037JWK + rfc8037JWK,
		"an array":           `[` + rfc8037JWK + `]`,
		"empty":              ``,
		"not JSON":           `kty=OKP`,
		"a PEM public key":   "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----",
		"longer than MaxLen": `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"` + strings.Repeat("a", MaxLen) + `"}`,
	} {
		_, err := Parse(jwk)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Parse = %v, want ErrMalformed", name, err)
		}
		// The point checks are the curve's, not the encoding's.
		if (name == "off the curve" || name == "x and y swapped" || name == "zero point") && (err == nil || !strings.Contains(err.Error(), "not on P-256")) {
			t.Errorf("%s: refused for %v, want the on-curve check", name, err)
		}
	}
}

// An error repeats a value the caller sent only when it is short: a key
// pasted into the wrong member is not echoed back.
func TestParse_ErrorsDoNotEchoLongValues(t *testing.T) {
	long := strings.Repeat("Z", 40)
	for _, jwk := range []string{
		`{"kty":"` + long + `","crv":"P-256","x":"a"}`,
		`{"kty":"OKP","crv":"` + long + `","x":"a"}`,
		`{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","` + long + `":1}`,
	} {
		_, err := Parse(jwk)
		if err == nil || strings.Contains(err.Error(), long[:17]) {
			t.Errorf("Parse(%s) = %v: a long value was echoed", jwk, err)
		}
	}
}
