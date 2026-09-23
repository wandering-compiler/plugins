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

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
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
	// Q36-auth-1 — the IdP did not assert email_verified, so we refuse to
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
	// Q36-auth-2 — the state CSRF token is HMAC'd with the provider's
	// client_secret; an empty secret = an empty (public) HMAC key, so an
	// attacker can forge any state. A confidential server-side client
	// always has a secret (the token exchange needs it too), so reject
	// the misconfiguration rather than sign with a forgeable key.
	errOAuthProviderMisconfigured = errors.New("oauth provider misconfigured: client_secret is required")
	// Q45-auth-1 — redirect_after is caller-supplied and echoed back to the
	// client after a successful login. An absolute / protocol-relative URL
	// is an open redirect (CWE-601): an attacker mints an authorize URL with
	// redirect_after=https://evil and phishes a victim, who lands on evil
	// post-login. Restrict it to a site-relative path.
	errOAuthUnsafeRedirect = errors.New("oauth redirect_after must be a site-relative path (no scheme/host)")
)

// OAuthAuthorizeURL builds the IdP authorize URL the client redirects to.
// `state` is HMAC-signed with the provider's client_secret (CSRF guard +
// carries redirect_after), so the callback validates it without server-
// side session storage.
func (h *AuthServiceHandler) OAuthAuthorizeURL(ctx context.Context, req *pb.OAuthAuthorizeURLReq) (*pb.OAuthAuthorizeURLResp, error) {
	p, err := h.loadEnabledProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if !isSafeRelativeRedirect(req.GetRedirectAfter()) {
		return nil, Unauthenticated(errOAuthUnsafeRedirect)
	}
	state, err := signOAuthState(p.GetClientSecret(), p.GetName(), req.GetRedirectAfter())
	if err != nil {
		return nil, Unauthenticated(err)
	}
	q := url.Values{}
	q.Set("client_id", p.GetClientId())
	q.Set("redirect_uri", h.oauthRedirectURI(ctx, p.GetName()))
	q.Set("response_type", "code")
	if s := p.GetScopes(); s != "" {
		q.Set("scope", s)
	}
	q.Set("state", state)

	sep := "?"
	if strings.Contains(p.GetAuthorizeUrl(), "?") {
		sep = "&"
	}
	return &pb.OAuthAuthorizeURLResp{AuthorizeUrl: p.GetAuthorizeUrl() + sep + q.Encode()}, nil
}

// OAuthCallback completes the authorization-code flow: validate state,
// exchange the code for tokens, read the subject + email, find-or-create
// the user, link the identity, and issue a session. OAuth bypasses plugin
// 2FA by default (the IdP is the second factor) — it calls issueSession
// directly, never the SignIn 2FA gate.
func (h *AuthServiceHandler) OAuthCallback(ctx context.Context, req *pb.OAuthCallbackReq) (*pb.OAuthCallbackResp, error) {
	p, err := h.loadEnabledProvider(ctx, req.GetProvider())
	if err != nil {
		return nil, Unauthenticated(err)
	}
	redirectAfter, err := verifyOAuthState(p.GetClientSecret(), p.GetName(), req.GetState())
	if err != nil {
		return nil, Unauthenticated(err)
	}
	// Q45-auth-1 defense-in-depth: even though the authorize side rejects an
	// unsafe redirect_after before signing, a state signed by an older build
	// (or a future code path) must not be trusted — drop an unsafe value so
	// it never reaches the client as an open-redirect target.
	if !isSafeRelativeRedirect(redirectAfter) {
		redirectAfter = ""
	}

	tok, err := h.exchangeCode(ctx, p, req.GetCode())
	if err != nil {
		return nil, Unauthenticated(err)
	}
	subject, email, emailVerified, err := h.fetchIdentity(ctx, p, tok)
	if err != nil {
		return nil, Unauthenticated(err)
	}

	userID, err := h.findOrCreateOAuthUser(ctx, p.GetId(), subject, email, emailVerified)
	if err != nil {
		return nil, Unauthenticated(err)
	}

	// Issue the session through the shared seam (binds + trusts the device
	// under `devices`; no 2FA gate — OAuth bypasses it).
	deviceID, _, err := resolveSignInDevice(ctx, h, userID)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	token, trustToken, err := issueSession(ctx, h, userID, deviceID)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp := &pb.OAuthCallbackResp{UserId: userID, Token: token, RedirectAfter: redirectAfter}
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
	// Q36-auth-2 — refuse a provider with no client_secret: it would sign
	// the state CSRF token with an empty HMAC key (forgeable), and the
	// token exchange (which also needs the secret) would fail anyway.
	if p.GetClientSecret() == "" {
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
func (h *AuthServiceHandler) exchangeCode(ctx context.Context, p *pb.OAuthProvider, code string) (*oauthTokenResp, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", h.oauthRedirectURI(ctx, p.GetName()))
	form.Set("client_id", p.GetClientId())
	form.Set("client_secret", p.GetClientSecret())

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
func (h *AuthServiceHandler) fetchIdentity(ctx context.Context, p *pb.OAuthProvider, tok *oauthTokenResp) (subject, email string, emailVerified bool, err error) {
	var claims map[string]any
	if p.GetUserinfoUrl() != "" {
		claims, err = h.fetchUserinfo(ctx, p.GetUserinfoUrl(), tok.AccessToken)
	} else {
		claims, err = decodeIDTokenClaims(tok.IDToken)
	}
	if err != nil {
		return "", "", false, err
	}
	subject = claimString(claims, orDefault(p.GetSubjectPath(), defaultSubjectPath))
	email = claimString(claims, orDefault(p.GetEmailPath(), defaultEmailPath))
	// Q36-auth-1 — the OIDC-standard `email_verified` claim. Absent /
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

// findOrCreateOAuthUser maps the external (provider, subject) to a local
// user: an existing identity reuses its user; otherwise an existing local
// account with the same email is linked (auto-link policy), else a fresh
// user is created with a random unusable password. The identity row is
// then created.
func (h *AuthServiceHandler) findOrCreateOAuthUser(ctx context.Context, providerID, subject, email string, emailVerified bool) (string, error) {
	if ident, err := h.Query.GetOAuthIdentity(ctx, &pb.GetOAuthIdentityReq{ProviderId: providerID, ExternalId: subject}); err == nil && ident.GetIdentity() != nil {
		return ident.GetIdentity().GetUserId(), nil
	}

	userID, err := h.resolveOrCreateUserByEmail(ctx, email, emailVerified)
	if err != nil {
		return "", err
	}
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

// resolveOrCreateUserByEmail returns the id of the existing account with
// this email, or creates one (random unusable password — OAuth users sign
// in through the IdP).
func (h *AuthServiceHandler) resolveOrCreateUserByEmail(ctx context.Context, email string, emailVerified bool) (string, error) {
	// Canonicalise so the IdP-asserted email matches a password-signup account
	// (and a later password signin) regardless of case (covers both the lookup
	// and the CreateUser below).
	email = normalizeEmail(email)
	if u, err := h.Query.GetUserByEmail(ctx, &pb.GetUserByEmailReq{Email: email}); err == nil && u.GetUser() != nil && u.GetUser().GetId() != "" {
		// Q36-auth-1 — auto-link to a PRE-EXISTING account only when the
		// IdP asserts the email is verified. Without that, a caller who
		// set their IdP profile email to a victim's would get a session
		// for the victim's account (account takeover / CWE-287). Refuse
		// fail-closed; the operator/user must link explicitly instead.
		if !emailVerified {
			return "", errOAuthEmailUnverified
		}
		// BOTH SIDES, and the second one took a verifier to see. The check
		// above interrogates the IdP; the LOCAL account may itself have been
		// created from a claim nobody verified — by this file's own create
		// branch, or by password sign-up. Binding a verified assertion to an
		// unverified claim is the takeover with the roles reversed:
		//
		//  1. the attacker signs in through a provider that does NOT assert
		//     verification, with the victim's address in its profile. No
		//     account exists, so the branch below makes one — for the
		//     victim's address, owned by the attacker.
		//  2. the victim signs in later through a provider that DOES verify.
		//     The lookup finds that account, this check passes, and the
		//     victim is handed a session inside the attacker's account.
		//
		// Requiring verification in the CREATE branch would not have closed
		// it: password sign-up is a second door to the same squat, and
		// gating one leaves the other. The property that has to hold is
		// about the account being linked INTO (T3-7 pass #14, B14-2).
		//
		// `email_verification` is what makes this expressible — the field is
		// gated on it — which is why `oauth` now requires that feature.
		if !u.GetUser().GetEmailVerifiedAt().IsValid() {
			return "", errOAuthLocalUnverified
		}
		return u.GetUser().GetId(), nil
	}
	// The SECOND door. Everything above this line resolves an account that
	// already exists; below it we CREATE one, and creation is what
	// `invite_only` governs. A gate wired only into SignUp would leave
	// invite-only registration open to anyone holding an account at the
	// identity provider — the same hole by a different route.
	//
	// After the auto-link branch on purpose: an invited person who has
	// already registered must keep being able to sign in through the IdP
	// once their invitation has been accepted and is no longer pending.
	if err := signupInviteGate(ctx, h, email); err != nil {
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
	// The BASELINE create, and the reason `oauth` and `tenant_scope` are
	// declared incompatible in plugin.yaml. `tenant_scope` adds a NOT NULL
	// User.tenant_id that this INSERT does not write and gates CreateUser
	// out for exactly that reason; OAuth has no request-borne tenant to
	// resolve (no slug, no signup Host — the caller arrives from the
	// provider's redirect), so it cannot simply switch to
	// a resolved tenant the way SignUp does. With both features on this
	// file no longer compiles, which is the honest outcome: before the
	// gate it compiled and every OAuth-created user failed the NOT NULL
	// constraint at runtime. Making OAuth tenant-aware needs a tenant
	// source of its own (per-provider binding, or the callback URL) and is
	// its own change.
	created, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{Email: email, PasswordHash: hash})
	if err != nil {
		return "", err
	}
	return created.GetUser().GetId(), nil
}

// isSafeRelativeRedirect reports whether a caller-supplied redirect_after
// is a safe post-login destination (Q45-auth-1). Empty = no redirect
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
// is base64url(JSON{nonce, provider, redirect_after}). Self-contained
// (no server session store) + provider-scoped (no extra key config).

type oauthStatePayload struct {
	Nonce         string `json:"n"`
	Provider      string `json:"p"`
	RedirectAfter string `json:"r"`
}

func signOAuthState(secret, provider, redirectAfter string) (string, error) {
	nonce, err := randomToken(16)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(oauthStatePayload{Nonce: nonce, Provider: provider, RedirectAfter: redirectAfter})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	sig := oauthStateSig(secret, payload)
	return payload + "." + sig, nil
}

func verifyOAuthState(secret, provider, state string) (redirectAfter string, err error) {
	payload, sig, ok := strings.Cut(state, ".")
	if !ok {
		return "", errOAuthState
	}
	if !hmac.Equal([]byte(sig), []byte(oauthStateSig(secret, payload))) {
		return "", errOAuthState
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", errOAuthState
	}
	var p oauthStatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", errOAuthState
	}
	if p.Provider != provider {
		return "", errOAuthState
	}
	return p.RedirectAfter, nil
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
