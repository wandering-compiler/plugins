package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
)

// This file implements the `oauth` feature — generic OAuth2 / OIDC sign-in.
// Staged only when the activation enables `oauth` (plugin.yaml go_files).
// Provider differences live in OAuthProvider rows (URLs + userinfo field
// mapping), never in per-provider Go — one handler serves Google, GitHub,
// Okta, etc. The outbound HTTP token-exchange + userinfo fetch is why this
// is authored Go rather than DQL. Every failure maps to opaque
// Unauthenticated (anti-enumeration, like SignIn).

// oauthHTTPClient performs the outbound token-exchange + userinfo calls.
// A package var (not a handler field) so tests can point it at a fake IdP
// without threading config; the per-provider URLs come from the row.
var oauthHTTPClient = &http.Client{Timeout: 15 * time.Second}

const (
	defaultSubjectPath = "sub"
	defaultEmailPath   = "email"
)

var (
	errOAuthProviderDisabled = errors.New("oauth provider disabled or unknown")
	errOAuthState            = errors.New("oauth state invalid")
	errOAuthNoSubject        = errors.New("oauth userinfo missing subject")
	errOAuthNoEmail          = errors.New("oauth userinfo missing email")
	// The IdP did not assert email_verified, so we refuse to
	// auto-link this external identity to a pre-existing local account
	// (an attacker could otherwise set their IdP profile email to a
	// victim's and inherit the victim's account — CWE-287).
	errOAuthEmailUnverified = errors.New("oauth provider did not verify email ownership; cannot link to an existing account")
	// The mirror of the above on the LOCAL side. Deliberately a separate
	// sentinel: the two refusals have different remedies — one is "use a
	// provider that verifies", the other is "prove you own this address
	// first" — and collapsing them would tell the wrong half of the story
	// to whichever caller hit the other one.
	errOAuthLocalUnverified = errors.New("the existing account for this address has not verified it; verify the address before linking an identity provider to it")
	// The state CSRF token is HMAC'd with the provider's
	// client_secret; an empty secret = an empty (public) HMAC key, so an
	// attacker can forge any state. A confidential server-side client
	// always has a secret (the token exchange needs it too), so reject
	// the misconfiguration rather than sign with a forgeable key.
	errOAuthProviderMisconfigured = errors.New("oauth provider misconfigured: client_secret is required")
	// redirect_after is caller-supplied and echoed back to the
	// client after a successful login. An absolute / protocol-relative URL
	// is an open redirect (CWE-601): an attacker mints an authorize URL with
	// redirect_after=https://evil and phishes a victim, who lands on evil
	// post-login. Restrict it to a site-relative path.
	errOAuthUnsafeRedirect = errors.New("oauth redirect_after must be a site-relative path (no scheme/host)")
	// The browser that starts a sign-in must send a PKCE challenge: it is the
	// only thing that ties the login code the callback hands out to that
	// browser rather than to whoever opens the callback URL.
	errOAuthChallengeMissing = errors.New("oauth code_challenge is required (PKCE S256)")
	errOAuthStateExpired     = errors.New("oauth state expired; start the sign-in again")
	errOAuthCodeInvalid      = errors.New("oauth login code invalid, expired or already used")
	errOAuthVerifierInvalid  = errors.New("oauth code_verifier does not match the sign-in's code_challenge")
	errOAuthIDTokenClaims    = errors.New("oauth id_token audience, expiry or nonce does not match")
)

const (
	// oauthStateTTL bounds how long a started sign-in may take at the
	// provider. A state is not stored, so this is what retires an old one.
	oauthStateTTL = 10 * time.Minute
	// oauthLoginCodeTTL is how long the callback's code may wait for the
	// page to redeem it — a redirect and one request.
	oauthLoginCodeTTL = 2 * time.Minute
)

// OAuthAuthorizeURL builds the IdP authorize URL the client redirects to.
// `state` is HMAC-signed with the provider's client_secret (CSRF guard +
// carries redirect_after), so the callback validates it without server-
// side session storage.
func (h *AuthServiceHandler) OAuthAuthorizeURL(ctx context.Context, req *pb.OAuthAuthorizeURLReq) (*pb.OAuthAuthorizeURLResp, error) {
	p, err := h.loadEnabledProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, oauthRefusal(err)
	}
	if !isSafeRelativeRedirect(req.GetRedirectAfter()) {
		return nil, oauthRefusal(errOAuthUnsafeRedirect)
	}
	if !isPKCEChallenge(req.GetCodeChallenge()) {
		return nil, oauthRefusal(errOAuthChallengeMissing)
	}
	state, nonce, err := signOAuthState(p.GetSecret(), p.GetName(), req.GetRedirectAfter(), challengeDigest(req.GetCodeChallenge()), time.Now())
	if err != nil {
		return nil, oauthRefusal(err)
	}
	q := url.Values{}
	q.Set("client_id", p.GetClientId())
	q.Set("redirect_uri", h.oauthRedirectURI(ctx, p.GetName()))
	q.Set("response_type", "code")
	if s := p.GetScopes(); s != "" {
		q.Set("scope", s)
	}
	q.Set("state", state)
	// Towards the provider: PKCE, so an intercepted provider code is useless
	// without our verifier, and an OIDC nonce, so an id_token minted for
	// another sign-in is refused. Both derive from the state's nonce under the
	// client secret, which is how the callback recovers them with nothing
	// stored. A provider that supports neither ignores them (RFC 6749 §3.1).
	q.Set("code_challenge", s256Challenge(providerVerifier(p.GetSecret(), nonce)))
	q.Set("code_challenge_method", "S256")
	q.Set("nonce", oidcNonce(p.GetSecret(), nonce))

	sep := "?"
	if strings.Contains(p.GetAuthorizeUrl(), "?") {
		sep = "&"
	}
	return &pb.OAuthAuthorizeURLResp{AuthorizeUrl: p.GetAuthorizeUrl() + sep + q.Encode()}, nil
}

// OAuthCallback completes the provider side of the flow: validate state,
// exchange the provider's code, read the subject + email, resolve the account
// (linking an existing one when both sides verified the address) — and hand
// the browser a single-use login code, not a session. It creates no account:
// an identity with none is kept on the code, and OAuthExchange creates it
// with the invitation the page passes there. The callback is a URL; whatever it carries can be put in
// front of anyone. The session is issued by OAuthExchange, to the browser
// holding the verifier of the challenge it sent to OAuthAuthorizeURL.
//
// OAuth bypasses plugin 2FA by default (the IdP is the second factor).
func (h *AuthServiceHandler) OAuthCallback(ctx context.Context, req *pb.OAuthCallbackReq) (*pb.OAuthCallbackResp, error) {
	p, err := h.loadEnabledProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, oauthRefusal(err)
	}
	st, err := verifyOAuthState(p.GetSecret(), p.GetName(), req.GetState(), time.Now())
	if err != nil {
		return nil, oauthRefusal(err)
	}
	// Defense in depth: the authorize side rejects an unsafe redirect_after
	// before signing, but a state from an older build must not be trusted.
	redirectAfter := st.RedirectAfter
	if !isSafeRelativeRedirect(redirectAfter) {
		redirectAfter = ""
	}

	tok, err := h.exchangeCode(ctx, p, req.GetCode(), providerVerifier(p.GetSecret(), st.Nonce))
	if err != nil {
		return nil, oauthRefusal(err)
	}
	subject, email, emailVerified, err := h.fetchIdentity(ctx, p, tok, oidcNonce(p.GetSecret(), st.Nonce))
	if err != nil {
		return nil, oauthRefusal(err)
	}

	userID, err := h.findOAuthAccount(ctx, p.GetId(), subject, email, emailVerified)
	if err != nil {
		return nil, oauthRefusal(err)
	}
	if userID != "" {
		if err := refuseUnsignableAccount(ctx, h, userID); err != nil {
			return nil, oauthRefusal(err)
		}
	}

	code, err := randomURLToken()
	if err != nil {
		return nil, oauthRefusal(err)
	}
	// A known account is named by id. An identity with no account yet is
	// kept as verified by the provider, and OAuthExchange creates the account
	// with the invitation the page passes there.
	codeReq := &pb.CreateOAuthLoginCodeReq{
		CodeHash:      sha256Hex(code),
		CodeChallenge: st.Challenge, // the digest, never the challenge itself
		ExpiresAt:     timestamppb.New(time.Now().Add(oauthLoginCodeTTL)),
	}
	if userID != "" {
		codeReq.UserId = proto.String(userID)
	} else {
		codeReq.ProviderId = proto.String(p.GetId())
		codeReq.ExternalId = subject
		codeReq.Email = normalizeEmail(email)
		codeReq.EmailVerified = emailVerified
	}
	if _, err := h.Mutation.CreateOAuthLoginCode(ctx, codeReq); err != nil {
		return nil, oauthRefusal(err)
	}
	return &pb.OAuthCallbackResp{Code: code, RedirectAfter: redirectAfter}, nil
}

// OAuthExchange redeems the callback's login code with the PKCE verifier and
// issues the session. The consume is a conditional UPDATE, so a code works
// once; it is spent before the verifier is compared, so a wrong verifier
// burns it rather than leaving it open to guesses.
func (h *AuthServiceHandler) OAuthExchange(ctx context.Context, req *pb.OAuthExchangeReq) (*pb.OAuthExchangeResp, error) {
	if len(req.GetCodeVerifier()) < pkceMinVerifierLen || req.GetCode() == "" {
		return nil, oauthRefusal(errOAuthVerifierInvalid)
	}
	consumed, err := h.Mutation.ConsumeOAuthLoginCode(ctx, &pb.ConsumeOAuthLoginCodeReq{CodeHash: sha256Hex(req.GetCode())})
	if err != nil {
		return nil, oauthRefusal(err)
	}
	// Every live code carries its challenge digest; none back means no
	// unconsumed, unexpired code matched.
	if consumed.GetCodeChallenge() == "" {
		return nil, oauthRefusal(errOAuthCodeInvalid)
	}
	if !verifyChallengeDigest(req.GetCodeVerifier(), consumed.GetCodeChallenge()) {
		return nil, oauthRefusal(errOAuthVerifierInvalid)
	}
	userID := consumed.GetUserId()
	if userID == "" {
		// The identity had no account at the callback. A code always names
		// one or the other; a row with neither is refused, never turned into
		// an account for an empty subject.
		providerID, subject, email := consumed.GetProviderId(), consumed.GetExternalId(), consumed.GetEmail()
		if providerID == "" || subject == "" || email == "" {
			return nil, oauthRefusal(errOAuthCodeInvalid)
		}
		// Resolved AGAIN: up to two minutes passed since the callback, and the
		// identity may have gained an account meanwhile (a second tab's code
		// for the same subject redeemed first, or a registration by another
		// path). The callback's rules decide it as they would now: a linked
		// identity wins, and an existing account is linked only when both
		// sides verified the address.
		userID, err = h.findOAuthAccount(ctx, providerID, subject, email, consumed.GetEmailVerified())
		if err != nil {
			return nil, oauthRefusal(err)
		}
		if userID == "" {
			// This is the sign-up, and the invitation (if any) comes with
			// this request.
			userID, err = h.createOAuthAccount(ctx, providerID, subject, email, consumed.GetEmailVerified(), req.GetInviteToken())
			if isEmailTaken(err) {
				// The unique address, lost to a registration racing this one
				// after the lookup above: answered as SignUp answers it.
				return nil, emailTaken(ctx)
			}
			if err != nil {
				// As SignUp answers it: the invitation and allowlist gates
				// refuse with a code and a sentence the page can show. Any
				// other failure (the user insert, the transaction) is
				// classified like the rest, never sent raw.
				return nil, oauthRefusal(err)
			}
		}
	}
	// The account may have changed since the callback; and the device is the
	// one making THIS request — the page, not the provider's redirect.
	if err := refuseUnsignableAccount(ctx, h, userID); err != nil {
		return nil, oauthRefusal(err)
	}
	deviceID, _, err := resolveSignInDevice(ctx, h, userID)
	if err != nil {
		return nil, oauthRefusal(err)
	}
	// Bound to the device, never trusting it: this sign-in skipped the
	// plugin's second factor, and a trusted device skips it later for a
	// password sign-in too.
	token, trustToken, err := issueSession(ctx, h, userID, deviceID, false)
	if err != nil {
		return nil, oauthRefusal(err)
	}
	resp := &pb.OAuthExchangeResp{UserId: userID, Token: token}
	stampDeviceTrust(resp, trustToken) // devices-gated field; seam is a no-op without `devices`
	return resp, nil
}

// loadEnabledProvider resolves a provider by slug and enforces `enabled`.
func (h *AuthServiceHandler) loadEnabledProvider(ctx context.Context, name string) (*pb.OAuthProvider, error) {
	resp, err := h.Query.GetProviderByName(ctx, &pb.GetProviderByNameReq{Name: name})
	if err != nil {
		return nil, err
	}
	p := resp.GetProvider()
	if p == nil || !p.GetEnabled() {
		return nil, errOAuthProviderDisabled
	}
	p.Secret = resp.GetSecret() // decrypted beside the row, not inside it
	// The legacy plaintext column (rc.19 and earlier, or a fixture) is read
	// only while the encrypted `secret` is empty, and moved there; once
	// `secret` is set it wins — it is where the admin writes — and a
	// plaintext copy left beside it is dropped. Letting the legacy value win
	// instead would undo an operator's rotation made before the first sign-in.
	// A failed move or clear costs nothing but a retry on the next read.
	if legacy := p.GetClientSecret(); legacy != "" {
		if p.GetSecret() == "" {
			p.Secret = legacy
			_, _ = h.Mutation.MoveOAuthProviderSecret(ctx, &pb.MoveOAuthProviderSecretReq{Id: p.GetId(), Secret: legacy, Legacy: legacy})
		} else {
			_, _ = h.Mutation.ClearOAuthProviderLegacySecret(ctx, &pb.ClearOAuthProviderLegacySecretReq{Id: p.GetId()})
		}
	}
	// Refuse a provider with no client secret: it would sign
	// the state CSRF token with an empty HMAC key (forgeable), and the
	// token exchange (which also needs the secret) would fail anyway.
	if p.GetSecret() == "" {
		return nil, errOAuthProviderMisconfigured
	}
	return p, nil
}

// oauthRedirectURI builds the callback URL the IdP returns to. Uses the
// configured public base when set, else derives scheme+host from the
// forwarded request metadata (best-effort). Must be identical at authorize
// + callback time (the IdP matches it).
func (h *AuthServiceHandler) oauthRedirectURI(ctx context.Context, provider string) string {
	base := strings.TrimRight(h.OAuthRedirectBase, "/")
	if base == "" {
		if host := hostFromMeta(ctx); host != "" {
			base = "https://" + host
		}
	}
	return base + "/auth/oauth/" + provider + "/callback"
}

// hostFromMeta reads the gateway-forwarded Host header (lowercased into
// metadata). Empty when absent.
func hostFromMeta(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if v := md.Get("host"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// exchangeCode POSTs the authorization code to the provider's token
// endpoint and returns the decoded token response.
func (h *AuthServiceHandler) exchangeCode(ctx context.Context, p *pb.OAuthProvider, code, verifier string) (*oauthTokenResp, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", h.oauthRedirectURI(ctx, p.GetName()))
	form.Set("client_id", p.GetClientId())
	form.Set("client_secret", p.GetSecret())

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.GetTokenUrl(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := oauthHTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("oauth token exchange failed")
	}
	var tr oauthTokenResp
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" && tr.IDToken == "" {
		return nil, errors.New("oauth token response empty")
	}
	return &tr, nil
}

type oauthTokenResp struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// fetchIdentity resolves the external subject + email. With a userinfo_url
// it GETs that endpoint (Bearer access_token); without one (pure OIDC) it
// decodes the id_token claims. Field names come from the provider's
// subject_path / email_path (defaulting to OIDC sub / email).
func (h *AuthServiceHandler) fetchIdentity(ctx context.Context, p *pb.OAuthProvider, tok *oauthTokenResp, nonce string) (subject, email string, emailVerified bool, err error) {
	var claims map[string]any
	if p.GetUserinfoUrl() != "" {
		claims, err = h.fetchUserinfo(ctx, p.GetUserinfoUrl(), tok.AccessToken)
	} else {
		claims, err = decodeIDTokenClaims(tok.IDToken)
		if err == nil {
			err = checkIDTokenClaims(claims, p.GetClientId(), nonce, time.Now())
		}
	}
	if err != nil {
		return "", "", false, err
	}
	subject = claimString(claims, orDefault(p.GetSubjectPath(), defaultSubjectPath))
	email = claimString(claims, orDefault(p.GetEmailPath(), defaultEmailPath))
	// The OIDC-standard `email_verified` claim. Absent /
	// false means the IdP does NOT vouch that this principal owns the
	// email, so it must not auto-link to a pre-existing local account.
	emailVerified = claimBool(claims, "email_verified")
	if subject == "" {
		return "", "", false, errOAuthNoSubject
	}
	if email == "" {
		return "", "", false, errOAuthNoEmail
	}
	return subject, email, emailVerified, nil
}

func (h *AuthServiceHandler) fetchUserinfo(ctx context.Context, userinfoURL, accessToken string) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+accessToken)
	httpReq.Header.Set("Accept", "application/json")
	resp, err := oauthHTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("oauth userinfo fetch failed")
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// decodeIDTokenClaims decodes the (unverified) claims of a JWT id_token —
// the middle segment, base64url JSON. The token came over TLS straight
// from the provider's token endpoint, so signature verification is not
// required for the login decision (a parked hardening: verify against the
// provider JWKS).
func decodeIDTokenClaims(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, errors.New("oauth id_token malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// checkIDTokenClaims refuses an id_token that was not minted for this
// client and this sign-in: `aud` must name the client (a string or an array
// containing it), an `azp` if present must be the client, `exp` must be in
// the future, and `nonce` must be the one
// the authorize step sent. The token arrives straight from the provider's
// token endpoint over TLS, so its signature is not what these checks are
// for; they stop a token issued to another client, or for another sign-in,
// from being accepted.
func checkIDTokenClaims(claims map[string]any, clientID, nonce string, now time.Time) error {
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == clientID
	case []any:
		for _, a := range aud {
			if s, _ := a.(string); s == clientID {
				audOK = true
			}
		}
	}
	// OIDC Core 3.1.3.7: an authorized party, when named, must be this client.
	if azp, present := claims["azp"]; present {
		if s, _ := azp.(string); s != clientID {
			audOK = false
		}
	}
	// Compared as a float: converting an out-of-range float to int64 is
	// implementation-defined in Go, and saturates on some platforms.
	exp, _ := claims["exp"].(float64)
	if !audOK || exp <= float64(now.Unix()) || claimString(claims, "nonce") != nonce {
		return errOAuthIDTokenClaims
	}
	return nil
}

// claimString reads a top-level string claim (numbers coerced to string,
// for providers like GitHub that send a numeric id). Nested JSON paths are
// a parked extension; v1 covers the flat OIDC/userinfo shape.
func claimString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case float64:
		return strings.TrimSuffix(strconv.FormatFloat(v, 'f', -1, 64), ".0")
	case json.Number:
		return v.String()
	}
	return ""
}

// claimBool reads a boolean claim. Providers send `email_verified` as a
// JSON bool, but some send the string "true"/"false" — accept both;
// anything else (absent / null / unexpected) is false (fail-closed).
func claimBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// findOAuthAccount resolves the account an identity signs in to: the one
// already linked to (provider, subject), or an existing account for the
// address, which it links when both sides verified the address. "" with no
// error means no account exists: OAuthExchange creates one, with the
// invitation the page passes there.
func (h *AuthServiceHandler) findOAuthAccount(ctx context.Context, providerID, subject, email string, emailVerified bool) (string, error) {
	if ident, err := h.Query.GetOAuthIdentity(ctx, &pb.GetOAuthIdentityReq{ProviderId: providerID, ExternalId: subject}); err == nil && ident.GetIdentity() != nil {
		return ident.GetIdentity().GetUserId(), nil
	}
	// Canonicalise so the IdP-asserted email matches a password-signup
	// account (and a later password signin) regardless of case.
	email = normalizeEmail(email)
	u, err := h.Query.GetUserByEmail(ctx, &pb.GetUserByEmailReq{Email: email})
	if err != nil || u.GetUser() == nil || u.GetUser().GetId() == "" {
		return "", nil
	}
	// Auto-link to a PRE-EXISTING account only when the IdP asserts the
	// email is verified. Without that, a caller who set their IdP profile
	// email to a victim's would get a session for the victim's account.
	if !emailVerified {
		return "", errOAuthEmailUnverified
	}
	// BOTH SIDES. The local account may itself have been created from a
	// claim nobody verified (an earlier unverified OAuth sign-up, or a
	// password sign-up). Binding a verified assertion to it would hand the
	// victim a session inside an account someone else squatted. The field is
	// gated on `email_verification`, which is why `oauth` requires it.
	if !u.GetUser().GetEmailVerifiedAt().IsValid() {
		return "", errOAuthLocalUnverified
	}
	userID := u.GetUser().GetId()
	if _, err := h.Mutation.CreateOAuthIdentity(ctx, &pb.CreateOAuthIdentityReq{
		UserId:     userID,
		ProviderId: providerID,
		ExternalId: subject,
		Email:      email,
	}); err != nil {
		return "", err
	}
	return userID, nil
}

// createOAuthAccount creates the account for a provider-verified identity
// that has none, as OAuthExchange's half of a sign-up. Creation is what
// `invite_only` and the allowlist govern, through the same gates as SignUp;
// the invitation token comes from the exchange request, so an OPEN
// invitation (which names no address) works too, and its link is spent by
// this registration. The user, its roles, the verified address, the spent
// invitation and the identity link commit together.
func (h *AuthServiceHandler) createOAuthAccount(ctx context.Context, providerID, subject, email string, emailVerified bool, inviteToken string) (string, error) {
	email = normalizeEmail(email)
	if err := signUpAllowlistGate(h, email); err != nil {
		return "", err
	}
	if err := signupInviteGate(ctx, h, email, inviteToken); err != nil {
		return "", err
	}
	randomPw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	hash, err := h.PasswordHash.Hash(randomPw)
	if err != nil {
		return "", err
	}
	roles, err := signupResolveRoleIDs(ctx, h)
	if err != nil {
		return "", err
	}
	txCtx := ctx
	var tx *distx.TxHandle
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return "", err
		}
	}
	userID, err := h.createOAuthUserTx(txCtx, email, hash, roles, emailVerified)
	if err == nil {
		err = signupClaimInvite(txCtx, h, email, inviteToken)
	}
	if err == nil {
		_, err = h.Mutation.CreateOAuthIdentity(txCtx, &pb.CreateOAuthIdentityReq{
			UserId:     userID,
			ProviderId: providerID,
			ExternalId: subject,
			Email:      email,
		})
	}
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return "", err
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return "", err
		}
	}
	return userID, nil
}

func (h *AuthServiceHandler) createOAuthUserTx(txCtx context.Context, email, hash string, roles signupRoles, emailVerified bool) (string, error) {
	created, err := h.Mutation.CreateUser(txCtx, &pb.CreateUserReq{Email: email, PasswordHash: hash})
	if err != nil {
		return "", err
	}
	userID := created.GetUser().GetId()
	if err := signupAssignRoleIDs(txCtx, h, userID, roles); err != nil {
		return "", err
	}
	// The provider vouched for the address the way a returned code does.
	if emailVerified {
		if err := markEmailConfirmed(txCtx, h, userID); err != nil {
			return "", err
		}
	}
	return userID, nil
}

// isSafeRelativeRedirect reports whether a caller-supplied redirect_after
// is a safe post-login destination. Empty = no redirect
// requested (allowed). Otherwise it must be a site-relative path: a single
// leading slash, no scheme, no host — so it can never send the user to an
// attacker-controlled origin. Rejects absolute URLs ("https://evil"),
// protocol-relative ("//evil", which browsers treat as a host), and
// backslash variants ("/\evil" → some browsers normalise to "//evil").
func isSafeRelativeRedirect(s string) bool {
	if s == "" {
		return true
	}
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") {
		return false
	}
	if strings.ContainsAny(s, "\\\x00") || strings.HasPrefix(s, "/\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return true
}

// --- OAuth state: HMAC-signed, keyed by the provider's client_secret ---
// state = base64url(payload) "." base64url(HMAC-SHA256(payload)). Payload
// is JSON{nonce, provider, redirect_after, code_challenge, expiry}.
// Self-contained (no server session store) + provider-scoped (no extra key
// config). It does not by itself bind the flow to a browser — anyone may
// start a sign-in and get a valid state — which is why the browser's PKCE
// challenge travels in it and the callback hands out only a code that
// challenge's verifier redeems.

type oauthStatePayload struct {
	Nonce         string `json:"n"`
	Provider      string `json:"p"`
	RedirectAfter string `json:"r"`
	Challenge     string `json:"c"` // challengeDigest of the browser's code_challenge
	Expires       int64  `json:"e"`
}

func signOAuthState(secret, provider, redirectAfter, challenge string, now time.Time) (state, nonce string, err error) {
	nonce, err = randomToken(16)
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(oauthStatePayload{
		Nonce: nonce, Provider: provider, RedirectAfter: redirectAfter,
		Challenge: challenge, Expires: now.Add(oauthStateTTL).Unix(),
	})
	if err != nil {
		return "", "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + oauthStateSig(secret, payload), nonce, nil
}

func verifyOAuthState(secret, provider, state string, now time.Time) (*oauthStatePayload, error) {
	payload, sig, ok := strings.Cut(state, ".")
	if !ok {
		return nil, errOAuthState
	}
	if !hmac.Equal([]byte(sig), []byte(oauthStateSig(secret, payload))) {
		return nil, errOAuthState
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errOAuthState
	}
	var p oauthStatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, errOAuthState
	}
	if p.Provider != provider || p.Nonce == "" {
		return nil, errOAuthState
	}
	// A state signed before code_challenge was required has none, and one
	// carrying a raw challenge comes from a build that did not digest it;
	// either could only produce a code nobody can redeem — refuse it up front.
	if !isChallengeDigest(p.Challenge) {
		return nil, errOAuthState
	}
	if now.Unix() >= p.Expires {
		return nil, errOAuthStateExpired
	}
	return &p, nil
}

// providerVerifier is the PKCE verifier sent to the provider's token
// endpoint, derived from the state's nonce under the client secret so the
// callback can recompute it. 43 base64url characters (RFC 7636 §4.1).
func providerVerifier(secret, nonce string) string {
	return oauthStateSig(secret, "pkce:"+nonce)
}

// oidcNonce is the OIDC nonce for one sign-in, derived like the verifier.
func oidcNonce(secret, nonce string) string {
	return oauthStateSig(secret, "nonce:"+nonce)
}

// challengeDigest is what the state and the login code carry in place of the
// browser's PKCE challenge: its sha256, hex.
//
// The state is readable — it is base64 JSON in the provider URL and in the
// callback URL — so a raw challenge in it could be lifted. Someone holding a
// victim's challenge could start a sign-in of their own with it and hand the
// victim the callback link; a victim page still holding that challenge's
// verifier (from an abandoned attempt) would then redeem the code into the
// other person's account. A sha256 of a 256-bit challenge gives nothing to
// start a sign-in with, and the exchange recomputes it from the verifier.
func challengeDigest(challenge string) string {
	return sha256Hex(challenge)
}

// verifyChallengeDigest reports whether the verifier's S256 challenge digests
// to the stored digest, compared in constant time. Nothing compares a
// verifier against a raw challenge on this flow.
func verifyChallengeDigest(verifier, digest string) bool {
	return hmac.Equal([]byte(challengeDigest(s256Challenge(verifier))), []byte(digest))
}

// isChallengeDigest accepts exactly what challengeDigest returns: 64 lowercase
// hex characters.
func isChallengeDigest(d string) bool {
	if len(d) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(d); i++ {
		if c := d[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// isPKCEChallenge accepts exactly an S256 challenge: 43 base64url characters.
func isPKCEChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	for _, r := range c {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func oauthStateSig(secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// randomToken returns n bytes of crypto/rand as hex.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// oauthRefusal is how every OAuth handler refuses. The sign-up gates' own
// coded refusals pass through, and so does a refusal this package already
// classified; the causes a person can act on get their code; the rest are
// OAUTH_FAILED. All keep the opaque status message.
//
// The pass-through is by IDENTITY, never "any status that carries details":
// the storage tier attaches an ErrorDetail to its not-found, timeout, abort
// and internal answers too, and passing those on would put another
// service's words on the wire and skip the outage classification below.
func oauthRefusal(cause error) error {
	if errors.Is(cause, errSignUpNotInvited) || errors.Is(cause, errInviteOtherAddress) || errors.Is(cause, errSignUpClosed) {
		return cause
	}
	var classified *authnError
	if errors.As(cause, &classified) && classified.userCode != "" {
		return classified
	}
	switch {
	case errors.Is(cause, errOAuthLocalUnverified):
		return &authnError{cause: cause, userCode: CodeOAuthAccountUnverified, userMsg: MsgOAuthAccountUnverified}
	case errors.Is(cause, errOAuthEmailUnverified):
		return &authnError{cause: cause, userCode: CodeOAuthEmailUnverified, userMsg: MsgOAuthEmailUnverified}
	case errors.Is(cause, errAuthnUserDisabled):
		return &authnError{cause: cause, userCode: CodeAccountDisabled, userMsg: MsgAccountDisabled}
	}
	return &authnError{cause: cause, userCode: CodeOAuthFailed, userMsg: MsgOAuthFailed}
}
