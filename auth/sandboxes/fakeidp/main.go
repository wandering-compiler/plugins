// Command fakeidp is a deterministic, DEV-ONLY fake OIDC / OAuth2
// provider used as an auth-plugin sandbox to exercise the `oauth`
// feature (see docs/specs/plugins/sandbox-services.md). It is NOT a
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
// The e2e test asserts the user it logs in carries EMAIL — so EMAIL is
// part of the documented contract this sandbox launches with.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type config struct {
	Port             string
	Issuer           string
	Subject          string
	Email            string
	AllowedRedirects []string
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
	}
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
	if err := http.ListenAndServe(":"+cfg.Port, mux); err != nil {
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
	q.Set("code", "fake-auth-code")
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// token — the token endpoint. Accepts any grant (code is not checked —
// this is a fake) and returns both an access_token (for the userinfo
// path) and an id_token (for the OIDC id_token path), so either
// OAuthProvider config shape works.
func (c config) token(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "bearer",
		"expires_in":   3600,
		"id_token":     c.idToken(),
	})
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
func (c config) idToken() string {
	header := b64(map[string]any{"alg": "none", "typ": "JWT"})
	payload := b64(map[string]any{
		"iss":   c.Issuer,
		"sub":   c.Subject,
		"email": c.Email,
		"aud":   "fakeidp",
		"iat":   0,
		"exp":   9999999999,
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
