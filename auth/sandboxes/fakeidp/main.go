// Command fakeidp is a deterministic, DEV-ONLY fake OIDC / OAuth2
// provider used as an auth-plugin sandbox to exercise the `oauth`
// feature. It is NOT a
// real IdP and performs NO real authentication: it accepts any client
// and any authorization code and always issues a token for ONE canned
// identity. That determinism is the point — an e2e test (or a developer
// clicking through in dev) can drive the full
// OAuthAuthorizeURL → OAuthCallback → token flow without a browser
// login, and the seeded OAuthProvider row points at this service's
// in-network URLs.
//
// Documented default values (the sandbox's `env:` knobs — override in
// the hand-written compose.yaml / .env, never here):
//
//	PORT     8080                     listen port (container-side)
//	ISSUER   http://fakeidp:8080      iss claim + discovery base
//	SUBJECT  fake-sub-001             the canned external subject (`sub`)
//	EMAIL    oauth-user@example.com   the canned email
//	REDIRECT_ALLOWLIST  (empty)               comma-separated registered callback
//	                                          URLs /authorize may redirect to
//	                                          (empty disables /authorize)
//
// Sign in with Apple, opt-in: the client APPLE_CLIENT_ID is served the way
// Apple serves it, every other client exactly as before.
//
//		APPLE_CLIENT_ID      (empty)                            the Apple client; empty = no Apple mode
//		APPLE_TEAM_ID        (empty)                            the client secret's required `iss`
//		APPLE_KEY_ID         (empty)                            the client secret's required `kid`
//		APPLE_PUBLIC_KEY_PEM (empty)                            the public half of the .p8 key (PKIX PEM)
//		                                                        the client secret must verify with
//		APPLE_SUBJECT        apple-sub-001                      that client's canned `sub`
//		APPLE_EMAIL          apple-user@privaterelay.appleid.com that client's canned email
//
//	  - /authorize with response_mode=form_post (any client) answers 200 with
//	    an HTML form that POSTs code and state to the matched callback, as
//	    Apple does, instead of a 302.
//	  - /token for APPLE_CLIENT_ID requires client_secret to be an ES256 JWT
//	    that verifies with APPLE_PUBLIC_KEY_PEM, with kid APPLE_KEY_ID, iss
//	    APPLE_TEAM_ID, sub the client id, aud ISSUER and an exp in the future
//	    at most six months after iat; anything else — the key itself, a
//	    string, a JWT signed by another key — is 401 invalid_client.
//	  - its id_token carries APPLE_SUBJECT / APPLE_EMAIL, with email_verified
//	    and is_private_email as the strings "true", as Apple sends them.
//
// The e2e test asserts the user it logs in carries EMAIL — so EMAIL is
// part of the documented contract this sandbox launches with.
package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"html"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type config struct {
	Port             string
	Issuer           string
	Subject          string
	Email            string
	AllowedRedirects []string

	// Apple mode (all empty = off): see the package comment.
	AppleClientID string
	AppleTeamID   string
	AppleKeyID    string
	AppleKey      *ecdsa.PublicKey
	AppleSubject  string
	AppleEmail    string
}

func loadConfig() config {
	return config{
		Port:    env("PORT", "8080"),
		Issuer:  env("ISSUER", "http://fakeidp:8080"),
		Subject: env("SUBJECT", "fake-sub-001"),
		Email:   env("EMAIL", "oauth-user@example.com"),
		// Allow-list of registered callback URLs /authorize may bounce back to.
		// It redirects ONLY to the matched entry from THIS list (a server-
		// controlled value), never to the request's redirect_uri — exactly as a
		// real IdP only redirects to a client's pre-registered URI, so it can
		// never be an open redirect. Set it in the sandbox's hand-written
		// compose/.env to the app's OAuth callback URL(s). Empty (default) →
		// /authorize returns 400; the e2e flow never calls it, so that is fine
		// out of the box.
		AllowedRedirects: splitList(env("REDIRECT_ALLOWLIST", "")),

		AppleClientID: env("APPLE_CLIENT_ID", ""),
		AppleTeamID:   env("APPLE_TEAM_ID", ""),
		AppleKeyID:    env("APPLE_KEY_ID", ""),
		AppleKey:      appleKey(env("APPLE_PUBLIC_KEY_PEM", "")),
		AppleSubject:  env("APPLE_SUBJECT", "apple-sub-001"),
		AppleEmail:    env("APPLE_EMAIL", "apple-user@privaterelay.appleid.com"),
	}
}

// appleKey reads the public half of the Apple key. A value that does not
// parse leaves Apple mode with no key, so every client secret is refused —
// loudly in the log, never quietly accepted.
func appleKey(raw string) *ecdsa.PublicKey {
	if raw == "" {
		return nil
	}
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		log.Printf("fakeidp: APPLE_PUBLIC_KEY_PEM is not a PEM block; every Apple client secret will be refused")
		return nil
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if ec, ok := k.(*ecdsa.PublicKey); err == nil && ok {
		return ec
	}
	log.Printf("fakeidp: APPLE_PUBLIC_KEY_PEM is not an EC public key; every Apple client secret will be refused")
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// matchAllowed returns the configured callback that equals uri, or "" if none
// matches. /authorize redirects to the returned (server-controlled) value, so
// the redirect target never flows from the request — no open redirect.
func matchAllowed(uri string, allowed []string) string {
	for _, a := range allowed {
		if uri == a {
			return a
		}
	}
	return ""
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	cfg := loadConfig()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", cfg.discovery)
	mux.HandleFunc("/authorize", cfg.authorize)
	mux.HandleFunc("/token", cfg.token)
	mux.HandleFunc("/userinfo", cfg.userinfo)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	log.Printf("fakeidp: listening on :%s (issuer=%s sub=%s email=%s)", cfg.Port, cfg.Issuer, cfg.Subject, cfg.Email)
	// A header timeout, so a client that opens a connection and never finishes
	// its request cannot hold it open forever.
	srv := &http.Server{Addr: ":" + cfg.Port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("fakeidp: %v", err)
	}
}

// discovery — the OIDC discovery document. Not required by the auth
// plugin (the OAuthProvider row carries explicit URLs), but it makes
// the fake usable by a generic OIDC client too.
func (c config) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                 c.Issuer,
		"authorization_endpoint": c.Issuer + "/authorize",
		"token_endpoint":         c.Issuer + "/token",
		"userinfo_endpoint":      c.Issuer + "/userinfo",
	})
}

// authorize — the browser redirect target. A real IdP would show a login
// form; the fake immediately bounces back with a canned code + the caller's
// state so a manual dev click completes the loop. The e2e test bypasses this
// and calls the callback directly. The redirect target is the configured
// callback that matches the request (a server-controlled value from
// AllowedRedirects), NOT the request's redirect_uri — so it cannot be an open
// redirect even though redirect_uri is attacker-influenced.
func (c config) authorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	target := matchAllowed(redirectURI, c.AllowedRedirects)
	if target == "" {
		http.Error(w, "redirect_uri not in allow-list (set REDIRECT_ALLOWLIST)", http.StatusBadRequest)
		return
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "bad configured callback", http.StatusInternalServerError)
		return
	}
	q := u.Query()
	// The code carries what a real provider would remember about this
	// authorization — the PKCE challenge and the OIDC nonce — so /token can
	// check the one and echo the other with nothing stored.
	code := encodeCode(r.URL.Query().Get("code_challenge"), r.URL.Query().Get("nonce"))
	// response_mode=form_post: Apple's way back — a page whose form the
	// browser POSTs to the callback (the same matched, server-controlled
	// target), the code and state in the body instead of the query.
	if r.URL.Query().Get("response_mode") == "form_post" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body onload="document.forms[0].submit()">` +
			`<form method="post" action="` + html.EscapeString(target) + `">` +
			`<input type="hidden" name="code" value="` + html.EscapeString(code) + `">` +
			`<input type="hidden" name="state" value="` + html.EscapeString(state) + `">` +
			`</form></body></html>`))
		return
	}
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token — the token endpoint. A code minted by /authorize carries its PKCE
// challenge and nonce: the code_verifier must match the challenge (as a real
// provider checks), and the nonce goes into the id_token. Any other code
// (the e2e flow calls the callback directly with an arbitrary one) is
// accepted without either, which the userinfo path does not need. The
// id_token's `aud` is the requesting client_id. Returns both an
// access_token (userinfo path) and an id_token (OIDC id_token path).
func (c config) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := r.PostForm.Get("client_id")
	apple := c.AppleClientID != "" && clientID == c.AppleClientID
	if apple {
		if err := c.verifyAppleSecret(r.PostForm.Get("client_secret"), clientID, time.Now()); err != nil {
			log.Printf("fakeidp: Apple client secret refused: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
	}
	challenge, nonce := decodeCode(r.PostForm.Get("code"))
	if challenge != "" {
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
	}
	idToken := c.idToken(clientID, nonce)
	if apple {
		idToken = c.appleIDToken(clientID, nonce)
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

// verifyAppleSecret checks a client secret the way Apple's token endpoint
// does: an ES256 compact JWS over the client's key, naming the team, the
// client and this provider, not expired and not valid past six months.
func (c config) verifyAppleSecret(secret, clientID string, now time.Time) error {
	if c.AppleKey == nil {
		return errors.New("no APPLE_PUBLIC_KEY_PEM to verify with")
	}
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	var header struct{ Alg, Kid string }
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "ES256" || header.Kid != c.AppleKeyID {
		return errors.New("header is not ES256 with the expected kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("signature is not r||s")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(c.AppleKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("signature does not verify")
	}
	var claims struct {
		Iss, Sub, Aud string
		Iat, Exp      int64
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return err
	}
	switch {
	case claims.Iss != c.AppleTeamID:
		return errors.New("iss is not the team")
	case claims.Sub != clientID:
		return errors.New("sub is not the client")
	case claims.Aud != c.Issuer:
		return errors.New("aud is not this provider")
	case claims.Exp <= now.Unix():
		return errors.New("expired")
	case claims.Exp-claims.Iat > int64(183*24*time.Hour/time.Second):
		return errors.New("valid for more than six months")
	}
	return nil
}

func decodeSegment(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// appleIDToken is idToken for the Apple client: its own subject and
// (private-relay) address, and the two booleans as the strings Apple sends.
func (c config) appleIDToken(clientID, nonce string) string {
	header := b64(map[string]any{"alg": "none", "typ": "JWT"})
	payload := b64(map[string]any{
		"iss":              c.Issuer,
		"sub":              c.AppleSubject,
		"email":            c.AppleEmail,
		"email_verified":   "true",
		"is_private_email": "true",
		"aud":              clientID,
		"nonce":            nonce,
		"iat":              time.Now().Unix(),
		"exp":              time.Now().Add(time.Hour).Unix(),
	})
	return header + "." + payload + ".sig"
}

// encodeCode / decodeCode carry the authorize request's challenge and nonce
// inside the code ("fake." + base64url JSON).
func encodeCode(challenge, nonce string) string {
	return "fake." + b64(map[string]string{"c": challenge, "n": nonce})
}

func decodeCode(code string) (challenge, nonce string) {
	payload, ok := strings.CutPrefix(code, "fake.")
	if !ok {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", ""
	}
	var v map[string]string
	if json.Unmarshal(raw, &v) != nil {
		return "", ""
	}
	return v["c"], v["n"]
}

// userinfo — returns the canned identity claims. The auth plugin maps
// subject_path/email_path (default sub/email) out of this.
func (c config) userinfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"sub":            c.Subject,
		"email":          c.Email,
		"email_verified": true,
		"name":           "Fake OAuth User",
	})
}

// idToken builds an unsigned-but-well-formed JWT (header.payload.sig).
// The auth plugin decodes the middle segment's claims without verifying
// the signature (the token arrived over a trusted channel), so the
// fixed "sig" segment is fine for a dev fake.
func (c config) idToken(clientID, nonce string) string {
	header := b64(map[string]any{"alg": "none", "typ": "JWT"})
	payload := b64(map[string]any{
		"iss":   c.Issuer,
		"sub":   c.Subject,
		"email": c.Email,
		"aud":   clientID,
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	return header + "." + payload + ".sig"
}

func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
