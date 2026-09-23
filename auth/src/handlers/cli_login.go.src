package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `cli_login` feature — the console acting as a
// first-party OAuth authorization server for CLIs (w17ctl), via the
// loopback + PKCE flow (the same UX as `claude login`). Staged into a
// bundle only when the activation enables `cli_login` (plugin.yaml maps
// the feature to this file via go_files). The plugin author's standalone
// `go test` always compiles it. See
// docs/specs/plugins/auth-cli-login-and-orgs.md.
//
// The human authenticates through the project's EXISTING surface (password
// SignIn or the `oauth` providers) — cli_login does not re-implement
// human auth; it only mints + redeems the CLI's authorization code. The
// browser (carrying the user's web-session bearer) hits CliAuthorize; the
// CLI's loopback server redeems the code at CliToken with its PKCE
// verifier. The console NEVER inspects or re-signs the bearer client-side —
// it is minted here (IssueToken) and stays opaque to w17ctl.

// defaultCliAuthCodeTTL bounds how long an issued authorization code stays
// redeemable. Seconds, not minutes: the browser→loopback hop is immediate,
// and PKCE already makes a leaked code useless without the verifier, so the
// short TTL + single-use are defense-in-depth (RFC 6749 §10.5 — codes
// SHOULD be short-lived and single-use).
const defaultCliAuthCodeTTL = 60 * time.Second

// pkceMinVerifierLen is RFC 7636 §4.1's minimum code_verifier length (the
// floor of the 43–128 unreserved-charset range). A too-short verifier
// weakens the challenge; we enforce the floor (not the exact charset — the
// hash comparison already rejects a tampered verifier).
const pkceMinVerifierLen = 43

var (
	errCliChallengeMissing = errors.New("cli auth: code_challenge required")
	errCliRedirectUnsafe   = errors.New("cli auth: redirect_uri must be loopback (http://127.0.0.1 / ::1 / localhost)")
	errCliVerifierInvalid  = errors.New("cli auth: code_verifier invalid")
	errCliCodeInvalid      = errors.New("cli auth: authorization code invalid/expired/used")
)

// CliAuthorize mints a single-use authorization code for the
// bearer-authenticated principal, bound to the CLI's PKCE challenge. The
// caller (the browser, carrying the user's web session) is resolved from
// the gateway auth envelope — the same source as WhoAmI / Logout, so a
// direct gRPC call with no threaded principal fails closed. The console
// web then redirects the browser to redirect_uri?code=<code>.
func (h *AuthServiceHandler) CliAuthorize(ctx context.Context, req *pb.CliAuthorizeReq) (*pb.CliAuthorizeResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if req.GetCodeChallenge() == "" {
		return nil, Unauthenticated(errCliChallengeMissing)
	}
	if !isLoopbackRedirect(req.GetRedirectUri()) {
		return nil, Unauthenticated(errCliRedirectUnsafe)
	}
	code, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	if _, err := h.Mutation.CreateCliAuthCode(ctx, &pb.CreateCliAuthCodeReq{
		UserId:        userID,
		CodeHash:      sha256Hex(code),
		CodeChallenge: req.GetCodeChallenge(),
		ExpiresAt:     timestamppb.New(time.Now().Add(defaultCliAuthCodeTTL)),
	}); err != nil {
		return nil, err
	}
	return &pb.CliAuthorizeResp{Code: code, RedirectUri: req.GetRedirectUri()}, nil
}

// CliToken completes the PKCE exchange. It consumes the code single-use
// FIRST (so a wrong verifier still burns the code — no verifier brute-force
// against a live code), then verifies the verifier hashes to the bound
// challenge, then mints the CLI bearer. Unauthenticated — the CLI has no
// token yet; every failure is the same opaque Unauthenticated.
func (h *AuthServiceHandler) CliToken(ctx context.Context, req *pb.CliTokenReq) (*pb.CliTokenResp, error) {
	if len(req.GetCodeVerifier()) < pkceMinVerifierLen {
		return nil, Unauthenticated(errCliVerifierInvalid)
	}
	consumed, err := h.Mutation.ConsumeCliAuthCode(ctx, &pb.ConsumeCliAuthCodeReq{
		CodeHash: sha256Hex(req.GetCode()),
	})
	if err != nil {
		return nil, err
	}
	userID := consumed.GetUserId()
	if userID == "" {
		// Zero rows matched the live-code WHERE → unknown / expired / used.
		return nil, Unauthenticated(errCliCodeInvalid)
	}
	// PKCE S256: the verifier must hash to the challenge the code was bound
	// to at authorize time. Without this, a stolen code alone would mint a
	// token (the whole point of PKCE — RFC 7636).
	if !verifyPKCES256(req.GetCodeVerifier(), consumed.GetCodeChallenge()) {
		return nil, Unauthenticated(errCliVerifierInvalid)
	}
	resp, err := h.Mutation.IssueToken(ctx, &pb.IssueTokenReq{
		UserId:    userID,
		ExpiresAt: h.sessionTokenExpiry(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.CliTokenResp{Token: resp.GetToken().GetToken(), UserId: userID}, nil
}

// verifyPKCES256 reports whether BASE64URL(SHA256(verifier)) equals the
// stored S256 challenge, compared in constant time.
func verifyPKCES256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return hmac.Equal([]byte(want), []byte(challenge))
}

// isLoopbackRedirect reports whether a CLI redirect_uri is a safe loopback
// callback (RFC 8252 §7.3): http scheme, host 127.0.0.1 / ::1 / localhost,
// any port + path. A non-loopback target would let a stolen authorize link
// redirect the code to an attacker-controlled origin.
func isLoopbackRedirect(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}
