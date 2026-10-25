package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"time"

	"github.com/wandering-compiler/plugins/auth/gen"
	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Sign in with Apple, as configuration of the generic `oauth` feature: two
// things Apple does that the providers before it did not, each a column of
// OAuthProvider rather than a provider-specific branch.
//
//   - It comes back by an HTML form POST (response_mode form_post), which it
//     requires whenever the scopes ask for the address — and this plugin
//     needs the address. OAuthCallbackForm serves that POST; it is the same
//     callback with the code and state in the body, on the route
//     oauth_form_post publishes.
//   - Its client secret is not a string it hands out but a JWT signed with a
//     key it issued (team_id + key_id, the key in `secret`), valid at most six
//     months. The plugin mints one per token exchange, so there is nothing to
//     rotate before it expires.
//
// The state, the PKCE verifier and the OIDC nonce stay keyed by `secret`
// itself — for Apple the key, which does not change between mints — so a
// sign-in started before a mint finishes after it.

var (
	errOAuthResponseMode    = errors.New("oauth provider misconfigured: response_mode must be empty or form_post")
	errOAuthFormPostOff     = errors.New("oauth provider misconfigured: response_mode form_post needs the oauth_form_post feature, without which no route receives the provider's POST")
	errOAuthCallbackByQuery = errors.New("oauth provider returns by the query string, not a form POST")
	errOAuthSigningKey      = errors.New("oauth provider misconfigured: with team_id and key_id, secret must be a PKCS#8 PEM P-256 key, both ids set, and token_url absolute")
)

const (
	responseModeFormPost = "form_post"
	// clientSecretJWTTTL bounds a minted client secret: it is sent once, to
	// the token endpoint, right after it is made.
	clientSecretJWTTTL = 5 * time.Minute
)

// OAuthCallbackForm is OAuthCallback for a provider that returns by a form
// POST. A provider that returns by the query string is refused here: its
// callback is the GET.
func (h *AuthServiceHandler) OAuthCallbackForm(ctx context.Context, req *pb.OAuthCallbackReq) (*pb.OAuthCallbackResp, error) {
	p, err := h.loadEnabledProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, oauthRefusal(err)
	}
	if p.GetResponseMode() != responseModeFormPost {
		return nil, oauthRefusal(errOAuthCallbackByQuery)
	}
	return h.oauthCallback(ctx, p, req)
}

// formPostServed is whether this activation publishes the form POST
// callback (oauth_form_post); a variable so a test can take it away.
var formPostServed = gen.FeatureOauthFormPost

// checkResponseMode refuses a response_mode this plugin cannot receive:
// `fragment` would never reach the server, form_post reaches it only through
// oauth_form_post's route, and anything else is a typo. Refused at the
// authorize step, before the user is sent to a provider whose answer would
// land nowhere.
func checkResponseMode(p *pb.OAuthProvider) error {
	switch p.GetResponseMode() {
	case "":
		return nil
	case responseModeFormPost:
		if !formPostServed {
			return errOAuthFormPostOff
		}
		return nil
	}
	return errOAuthResponseMode
}

// clientSecret is what the token exchange sends as client_secret: `secret`
// itself, or — with team_id and key_id — a JWT minted from the key it holds.
func clientSecret(p *pb.OAuthProvider, now time.Time) (string, error) {
	if p.GetTeamId() == "" && p.GetKeyId() == "" {
		return p.GetSecret(), nil
	}
	if p.GetTeamId() == "" || p.GetKeyId() == "" {
		return "", errOAuthSigningKey
	}
	key, err := parseSigningKey(p.GetSecret())
	if err != nil {
		return "", err
	}
	u, err := url.Parse(p.GetTokenUrl())
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", errOAuthSigningKey
	}
	return signES256JWT(key,
		map[string]any{"alg": "ES256", "kid": p.GetKeyId()},
		map[string]any{
			"iss": p.GetTeamId(),
			"sub": p.GetClientId(),
			"aud": u.Scheme + "://" + u.Host,
			"iat": now.Unix(),
			"exp": now.Add(clientSecretJWTTTL).Unix(),
		})
}

// parseSigningKey reads a PKCS#8 PEM P-256 private key — the .p8 Apple
// issues, as downloaded.
func parseSigningKey(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errOAuthSigningKey
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errOAuthSigningKey
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errOAuthSigningKey
	}
	return ec, nil
}

// signES256JWT is a compact JWS (RFC 7515) over header and claims, signed
// ES256: the signature is r ‖ s, each 32 bytes big-endian (RFC 7518 §3.4),
// not the ASN.1 form ecdsa.SignASN1 makes.
func signES256JWT(key *ecdsa.PrivateKey, header, claims map[string]any) (string, error) {
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
