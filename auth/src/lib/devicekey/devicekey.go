// Package devicekey reads a device's PUBLIC key given as a JWK (RFC 7517) and
// computes its RFC 7638 thumbprint — the device id the auth plugin binds a
// token to when the key arrives in a request body rather than through the
// gateway's DPoP proof (CreateApiToken, IssueBotToken).
//
// Only the two key types a device signs DPoP proofs with are accepted, the
// ones the gateway verifies (ES256 on P-256, EdDSA on Ed25519). A JWK that
// carries any private member is refused before anything else is read: no API
// of the plugin accepts a private key (device/private-key-never-leaves).
//
// Stdlib only, on purpose. The SDK's lib/dpop computes the same thumbprint
// through go-jose, but this package is staged into the consumer's storage
// module, whose go.mod need not require go-jose (nor an SDK new enough to
// have lib/dpop); the thumbprint is a few lines of canonical JSON, pinned
// here by the RFC 7638, RFC 8037 and RFC 9449 example vectors.
package devicekey

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxLen is the longest JWK accepted, in bytes. A P-256 public key with every
// optional member a WebCrypto export adds is about 200 bytes.
const MaxLen = 1024

// The refusals. Every error Parse returns wraps exactly one of them, and none
// carries a value of the key: only member names.
var (
	// ErrPrivateKey: the JWK carries a private member (RFC 7518 §6.2.2,
	// §6.3.2, §6.4.1; RFC 8037 §2) — whatever else it carries.
	ErrPrivateKey = errors.New("the JWK carries a private key member")
	// ErrUnsupported: a well-formed JWK of a key type, curve, algorithm or
	// use a device does not sign proofs with.
	ErrUnsupported = errors.New("unsupported key")
	// ErrMalformed: not a JWK this package can read — not one JSON object, a
	// member missing, of the wrong type or unknown, a coordinate that is not
	// canonical base64url of the curve's size, or a point not on the curve.
	ErrMalformed = errors.New("malformed JWK")
)

// privateMembers are the JWK members only a private or symmetric key has.
// Matched case-insensitively, so a `D` is not a way past the check.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// Key is a parsed device public key.
type Key struct {
	// Type is "EC" (P-256) or "OKP" (Ed25519).
	Type string
	// Thumbprint is the RFC 7638 SHA-256 thumbprint, base64url without
	// padding: 43 characters, the device id.
	Thumbprint string
}

// Parse reads one public JWK, strictly:
//
//   - exactly one JSON object, at most MaxLen bytes, no duplicate member;
//   - no private member (ErrPrivateKey, checked first);
//   - kty "EC" with crv "P-256" and x, y; or kty "OKP" with crv "Ed25519"
//     and x (ErrUnsupported for any other kty or crv);
//   - coordinates in canonical base64url without padding, 32 bytes each, and
//     a P-256 point on the curve (ErrMalformed);
//   - optional members only from the ones a key export carries: alg (ES256
//     for P-256, EdDSA or Ed25519 for Ed25519), use ("sig"), key_ops (only
//     "verify"), kid (a string) and ext (a boolean). Any other member is
//     refused (ErrMalformed): a member this package does not know is one it
//     cannot vouch for.
func Parse(raw string) (Key, error) {
	if len(raw) > MaxLen {
		return Key{}, fmt.Errorf("%w: longer than %d bytes", ErrMalformed, MaxLen)
	}
	m, err := strictObject([]byte(raw))
	if err != nil {
		return Key{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	for member := range m {
		for _, p := range privateMembers {
			if strings.EqualFold(member, p) {
				return Key{}, fmt.Errorf("%w: %q", ErrPrivateKey, p)
			}
		}
	}
	kty, err := requiredString(m, "kty")
	if err != nil {
		return Key{}, err
	}
	if kty != "EC" && kty != "OKP" {
		return Key{}, fmt.Errorf("%w: kty %s", ErrUnsupported, shown(kty))
	}
	crv, err := requiredString(m, "crv")
	if err != nil {
		return Key{}, err
	}
	x, err := requiredString(m, "x")
	if err != nil {
		return Key{}, err
	}
	var canonical map[string]string
	allowed := map[string]bool{"kty": true, "crv": true, "x": true, "alg": true, "use": true, "key_ops": true, "kid": true, "ext": true}
	switch {
	case kty == "EC" && crv == "P-256":
		allowed["y"] = true
		y, err := requiredString(m, "y")
		if err != nil {
			return Key{}, err
		}
		xb, err := coordinate("x", x)
		if err != nil {
			return Key{}, err
		}
		yb, err := coordinate("y", y)
		if err != nil {
			return Key{}, err
		}
		// crypto/ecdh refuses a point that is not on the curve (and the
		// point at infinity, which has no uncompressed encoding).
		if _, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, xb...), yb...)); err != nil {
			return Key{}, fmt.Errorf("%w: the point is not on P-256", ErrMalformed)
		}
		if err := optionalAlg(m, "ES256"); err != nil {
			return Key{}, err
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x, "y": y}
	case kty == "OKP" && crv == "Ed25519":
		if _, err := coordinate("x", x); err != nil {
			return Key{}, err
		}
		if err := optionalAlg(m, "EdDSA", "Ed25519"); err != nil {
			return Key{}, err
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x}
	default:
		return Key{}, fmt.Errorf("%w: curve %s for kty %s", ErrUnsupported, shown(crv), shown(kty))
	}
	for member := range m {
		if !allowed[member] {
			return Key{}, fmt.Errorf("%w: unknown member %s", ErrMalformed, shown(member))
		}
	}
	if err := optionalMetadata(m); err != nil {
		return Key{}, err
	}
	return Key{Type: kty, Thumbprint: Thumbprint(canonical)}, nil
}

// Thumbprint is the RFC 7638 thumbprint of a JWK given as its REQUIRED
// members (and only those): SHA-256 over the members as a JSON object with
// the keys in lexicographic order and no whitespace, base64url without
// padding.
func Thumbprint(required map[string]string) string {
	// encoding/json writes map keys sorted, and with HTML escaping off a
	// value is written as RFC 7638 §3.3 asks (no escaping a member of a key
	// type here ever needs).
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(required) // a map[string]string always encodes
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// shown quotes a value the caller sent for an error, cut to 16 bytes: a name
// or a curve is that short, and anything longer — a key pasted into the
// wrong member — is not repeated back.
func shown(s string) string {
	if len(s) > 16 {
		return fmt.Sprintf("%q…", s[:16])
	}
	return fmt.Sprintf("%q", s)
}

// coordinate decodes a 32-byte coordinate in canonical base64url without
// padding, and refuses any other spelling of it: the thumbprint hashes the
// string as sent, so one value must have exactly one spelling. Strict refuses
// non-zero trailing bits, but every decoder of the encoding/base64 package
// skips CR and LF — a "\n" inside x would decode to the same key and hash to
// another thumbprint (one go-jose never computes, so the token would be dead
// and the key-kind and one-key checks would see a different key). Hence the
// round trip.
func coordinate(name, s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("%w: %s is not 32 bytes of canonical base64url", ErrMalformed, name)
	}
	return b, nil
}

// isNull reports a JSON null: encoding/json decodes it into a string, a bool
// or a slice without an error, so an optional member that is null would pass
// as absent.
func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func requiredString(m map[string]json.RawMessage, key string) (string, error) {
	raw, ok := m[key]
	if !ok {
		return "", fmt.Errorf("%w: no %s", ErrMalformed, key)
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" {
		return "", fmt.Errorf("%w: %s is not a non-empty string", ErrMalformed, key)
	}
	return s, nil
}

// optionalAlg checks alg, when present, names one of the algorithms the key
// signs with.
func optionalAlg(m map[string]json.RawMessage, algs ...string) error {
	raw, ok := m["alg"]
	if !ok {
		return nil
	}
	var s string
	if isNull(raw) || json.Unmarshal(raw, &s) != nil {
		return fmt.Errorf("%w: alg is not a string", ErrMalformed)
	}
	for _, a := range algs {
		if s == a {
			return nil
		}
	}
	return fmt.Errorf("%w: alg %s", ErrUnsupported, shown(s))
}

// optionalMetadata checks the members a key export adds: use "sig", key_ops
// ["verify"], kid a string, ext a boolean.
func optionalMetadata(m map[string]json.RawMessage) error {
	if raw, ok := m["use"]; ok {
		var s string
		if isNull(raw) || json.Unmarshal(raw, &s) != nil {
			return fmt.Errorf("%w: use is not a string", ErrMalformed)
		}
		if s != "sig" {
			return fmt.Errorf("%w: use %s", ErrUnsupported, shown(s))
		}
	}
	if raw, ok := m["key_ops"]; ok {
		var ops []string
		if isNull(raw) || json.Unmarshal(raw, &ops) != nil {
			return fmt.Errorf("%w: key_ops is not a list of strings", ErrMalformed)
		}
		for _, op := range ops {
			if op != "verify" {
				return fmt.Errorf("%w: key_ops %s", ErrUnsupported, shown(op))
			}
		}
	}
	if raw, ok := m["kid"]; ok {
		var s string
		if isNull(raw) || json.Unmarshal(raw, &s) != nil {
			return fmt.Errorf("%w: kid is not a string", ErrMalformed)
		}
	}
	if raw, ok := m["ext"]; ok {
		var b bool
		if isNull(raw) || json.Unmarshal(raw, &b) != nil {
			return fmt.Errorf("%w: ext is not a boolean", ErrMalformed)
		}
	}
	return nil
}

// strictObject decodes one JSON object with exact, case-sensitive member
// names. It refuses a duplicate member (encoding/json would keep the last
// one silently, so two readers could disagree on the key) and anything after
// the object.
func strictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("not JSON")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errors.New("not JSON")
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("a member name is not a string")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate member %s", shown(key))
		}
		var val json.RawMessage
		if err := dec.Decode(&val); err != nil {
			return nil, errors.New("not JSON")
		}
		out[key] = val
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, errors.New("not JSON")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the JSON object")
	}
	return out, nil
}
