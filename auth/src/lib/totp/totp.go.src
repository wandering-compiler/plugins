// Package totp implements RFC 6238 time-based one-time passwords — the
// built-in second factor the auth plugin's `two_factor` feature offers
// (Google Authenticator / Authy / 1Password compatible). Self-contained
// stdlib crypto: HMAC-SHA1 HOTP (RFC 4226) over a 30-second time step,
// 6 digits. No external dependency — the plugin module stays thin.
//
// Secrets are base32 (RFC 3548, no padding) so they round-trip through
// authenticator QR codes; the auth handler stores them encrypted at rest
// (see lib/secretbox) and only ever hands plaintext to this package.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// period is the RFC 6238 time step (seconds). 30 is the universal
	// authenticator-app default; not configurable (changing it breaks
	// every enrolled device).
	period = 30
	// digits is the code length. 6 is the authenticator-app default.
	digits = 6
	// defaultSecretBytes is the generated secret size — 160 bits, the
	// RFC 4226 recommended HMAC-SHA1 key length.
	defaultSecretBytes = 20
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a fresh base32-encoded TOTP secret (160 bits of
// crypto/rand entropy). The caller stores it (encrypted) and renders its
// provisioning URI for the user's authenticator app.
func GenerateSecret() (string, error) {
	buf := make([]byte, defaultSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp: read random: %w", err)
	}
	return b32.EncodeToString(buf), nil
}

// Code returns the 6-digit TOTP for `secret` at time `t`. Returns an
// error only when the secret isn't valid base32.
func Code(secret string, t time.Time) (string, error) {
	counter := uint64(t.Unix() / period)
	return hotp(secret, counter)
}

// Verify reports whether `code` matches the TOTP for `secret` at time
// `t`, allowing ±`skew` time steps of clock drift (skew=1 → accept the
// previous, current, and next 30-second windows, the common default).
// Comparison is constant-time. A malformed secret or non-matching code
// returns false (never an error — the caller treats every verify failure
// identically, anti-enumeration).
func Verify(secret, code string, t time.Time, skew int) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	base := t.Unix() / period
	for i := -skew; i <= skew; i++ {
		want, err := hotp(secret, uint64(base+int64(i)))
		if err != nil {
			return false
		}
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// hotp is RFC 4226 HOTP(secret, counter) truncated to `digits`.
func hotp(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("totp: decode secret: %w", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := bin % pow10(digits)
	return fmt.Sprintf("%0*d", digits, mod), nil
}

func pow10(n int) uint32 {
	p := uint32(1)
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans
// (the QR payload). `issuer` is the brand label, `account` the user's
// identifier (typically their email). An empty issuer is omitted.
func ProvisioningURI(secret, issuer, account string) string {
	label := account
	if issuer != "" {
		label = issuer + ":" + account
	}
	q := url.Values{}
	q.Set("secret", secret)
	if issuer != "" {
		q.Set("issuer", issuer)
	}
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}
