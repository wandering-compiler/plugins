package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// cliMock backs the cli_login handlers. It models the CliAuthCode table
// (keyed by code_hash) so CliAuthorize → CliToken can be exercised end to
// end, including the atomic single-use + expiry semantics of the consume
// DQL (mirrored in ConsumeCliAuthCode below).
type cliCode struct {
	userID      string
	challenge   string
	redirectURI string
	expiresAt   time.Time
	consumed    bool
}

type cliMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	codes     map[string]*cliCode // code_hash -> stored code
	issuedFor string              // user_id IssueToken was last called with

	// registered mirrors the AuthClient rows. Keyed on the exact pair the
	// query's WHERE matches, so the mock cannot be looser than the statement
	// — which is the whole property under test.
	registered map[[2]string]bool

	createErr  error
	consumeErr error
	issueErr   error
}

func newCliMock() *cliMock { return &cliMock{codes: map[string]*cliCode{}} }

func (m *cliMock) CreateCliAuthCode(ctx context.Context, in *pb.CreateCliAuthCodeReq, _ ...grpc.CallOption) (*pb.CreateCliAuthCodeResp, error) {
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.codes[in.GetCodeHash()] = &cliCode{
		userID:      in.GetUserId(),
		challenge:   in.GetCodeChallenge(),
		redirectURI: in.GetRedirectUri(),
		expiresAt:   in.GetExpiresAt().AsTime(),
	}
	return &pb.CreateCliAuthCodeResp{Code: &pb.CliAuthCode{Id: "cac-1", UserId: in.GetUserId(), CodeHash: in.GetCodeHash()}}, nil
}

func (m *cliMock) ConsumeCliAuthCode(ctx context.Context, in *pb.ConsumeCliAuthCodeReq, _ ...grpc.CallOption) (*pb.ConsumeCliAuthCodeResp, error) {
	if m.consumeErr != nil {
		return nil, m.consumeErr
	}
	c := m.codes[in.GetCodeHash()]
	// Mirror the atomic DQL WHERE: a live code exists AND is not consumed
	// AND is not expired. Anything else matches zero rows (empty user_id).
	if c == nil || c.consumed || time.Now().After(c.expiresAt) {
		return &pb.ConsumeCliAuthCodeResp{}, nil
	}
	c.consumed = true
	return &pb.ConsumeCliAuthCodeResp{UserId: c.userID, CodeChallenge: c.challenge, RedirectUri: c.redirectURI}, nil
}

func (m *cliMock) GetRegisteredRedirect(ctx context.Context, in *pb.GetRegisteredRedirectReq, _ ...grpc.CallOption) (*pb.GetRegisteredRedirectResp, error) {
	if m.registered[[2]string{in.GetClientId(), in.GetRedirectUri()}] {
		return &pb.GetRegisteredRedirectResp{Client: &pb.AuthClient{
			ClientId: in.GetClientId(), RedirectUri: in.GetRedirectUri(), Enabled: true,
		}}, nil
	}
	return &pb.GetRegisteredRedirectResp{}, nil
}

func (m *cliMock) register(clientID, redirect string) {
	if m.registered == nil {
		m.registered = map[[2]string]bool{}
	}
	m.registered[[2]string{clientID, redirect}] = true
}

func (m *cliMock) RegisterAuthClient(ctx context.Context, in *pb.RegisterAuthClientReq, _ ...grpc.CallOption) (*pb.RegisterAuthClientResp, error) {
	m.register(in.GetClientId(), in.GetRedirectUri())
	return &pb.RegisterAuthClientResp{Client: &pb.AuthClient{
		Id: "cl-1", ClientId: in.GetClientId(), Name: in.GetName(),
		RedirectUri: in.GetRedirectUri(), Enabled: true,
	}}, nil
}

func (m *cliMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	m.issuedFor = in.GetUserId()
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "tok-1", Token: "bearer-for-" + in.GetUserId(), UserId: in.GetUserId()}}, nil
}

// pkceChallengeOf is the challenge a verifier must hash to — the same
// transform CliToken verifies with, written once so a test cannot pass by
// agreeing with its own arithmetic.
func pkceChallengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newCliHandler(m *cliMock) *AuthServiceHandler {
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
}

// cliCtx threads the gateway-authenticated principal the way the gateway
// does (the x-w17-scope-user_id metadata callerUserID reads).
func cliCtx(uid string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(scopeUserIDKey, uid))
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// A valid PKCE verifier (>= the RFC 7636 minimum length).
func validVerifier() string { return strings.Repeat("aZ9-._~", 7) } // 49 chars

func TestCliLogin_EndToEnd(t *testing.T) {
	m := newCliMock()
	h := newCliHandler(m)
	verifier := validVerifier()

	authz, err := h.CliAuthorize(cliCtx("user-1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallenge(verifier),
		RedirectUri:   "http://127.0.0.1:54123/cb",
	})
	if err != nil {
		t.Fatalf("CliAuthorize: %v", err)
	}
	if authz.GetCode() == "" {
		t.Fatal("no code returned")
	}
	if authz.GetRedirectUri() != "http://127.0.0.1:54123/cb" {
		t.Errorf("redirect_uri not echoed: %q", authz.GetRedirectUri())
	}
	// The code is stored ONLY as its hash — a DB read can't redeem it.
	if _, ok := m.codes[authz.GetCode()]; ok {
		t.Error("authorization code stored in plaintext (key should be the hash)")
	}
	if _, ok := m.codes[sha256Hex(authz.GetCode())]; !ok {
		t.Error("authorization code hash not stored")
	}

	tok, err := h.CliToken(context.Background(), &pb.CliTokenReq{
		Code:         authz.GetCode(),
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("CliToken: %v", err)
	}
	if tok.GetUserId() != "user-1" {
		t.Errorf("user_id = %q, want user-1", tok.GetUserId())
	}
	if tok.GetToken() != "bearer-for-user-1" {
		t.Errorf("token = %q", tok.GetToken())
	}
	if m.issuedFor != "user-1" {
		t.Errorf("IssueToken called for %q, want user-1", m.issuedFor)
	}

	// Single-use: redeeming the same code again fails opaquely.
	if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: authz.GetCode(), CodeVerifier: verifier}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("replay should be Unauthenticated, got %v", err)
	}
}

func TestCliAuthorize_Rejections(t *testing.T) {
	ch := pkceChallenge(validVerifier())
	cases := []struct {
		name string
		ctx  context.Context
		req  *pb.CliAuthorizeReq
	}{
		{"no principal", context.Background(), &pb.CliAuthorizeReq{CodeChallenge: ch, RedirectUri: "http://127.0.0.1:1/cb"}},
		{"empty challenge", cliCtx("u"), &pb.CliAuthorizeReq{RedirectUri: "http://127.0.0.1:1/cb"}},
		{"https redirect", cliCtx("u"), &pb.CliAuthorizeReq{CodeChallenge: ch, RedirectUri: "https://evil.example/cb"}},
		{"remote http redirect", cliCtx("u"), &pb.CliAuthorizeReq{CodeChallenge: ch, RedirectUri: "http://evil.example/cb"}},
		{"empty redirect", cliCtx("u"), &pb.CliAuthorizeReq{CodeChallenge: ch}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newCliMock()
			h := newCliHandler(m)
			if _, err := h.CliAuthorize(tc.ctx, tc.req); status.Code(err) != codes.Unauthenticated {
				t.Fatalf("want Unauthenticated, got %v", err)
			}
			if len(m.codes) != 0 {
				t.Error("a code was minted on a rejected authorize")
			}
		})
	}
}

func TestCliToken_Rejections(t *testing.T) {
	verifier := validVerifier()
	ch := pkceChallenge(verifier)

	t.Run("short verifier short-circuits before consume", func(t *testing.T) {
		m := newCliMock()
		m.codes[sha256Hex("c")] = &cliCode{userID: "u", challenge: ch, expiresAt: time.Now().Add(time.Minute)}
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "c", CodeVerifier: "tooshort"}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
		if m.codes[sha256Hex("c")].consumed {
			t.Error("a too-short verifier must not even consume the code")
		}
	})

	t.Run("unknown code", func(t *testing.T) {
		m := newCliMock()
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "nope", CodeVerifier: verifier}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
		if m.issuedFor != "" {
			t.Error("token issued for an unknown code")
		}
	})

	t.Run("wrong verifier still burns the code", func(t *testing.T) {
		m := newCliMock()
		m.codes[sha256Hex("c")] = &cliCode{userID: "u", challenge: ch, expiresAt: time.Now().Add(time.Minute)}
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "c", CodeVerifier: strings.Repeat("bZ9-._~", 7)}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
		if m.issuedFor != "" {
			t.Error("token issued despite a wrong verifier")
		}
		if !m.codes[sha256Hex("c")].consumed {
			t.Error("consume-then-verify: a wrong-verifier attempt should still burn the code")
		}
	})

	t.Run("expired code", func(t *testing.T) {
		m := newCliMock()
		m.codes[sha256Hex("c")] = &cliCode{userID: "u", challenge: ch, expiresAt: time.Now().Add(-time.Second)}
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "c", CodeVerifier: verifier}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
	})
}

// Storage errors propagate as-is (not swallowed into Unauthenticated) so an
// operator sees the real failure rather than an auth denial.
func TestCliLogin_StorageErrorsPropagate(t *testing.T) {
	boom := errors.New("db down")

	t.Run("authorize create error", func(t *testing.T) {
		m := newCliMock()
		m.createErr = boom
		h := newCliHandler(m)
		if _, err := h.CliAuthorize(cliCtx("u"), &pb.CliAuthorizeReq{CodeChallenge: pkceChallenge(validVerifier()), RedirectUri: "http://127.0.0.1:1/cb"}); !errors.Is(err, boom) {
			t.Fatalf("want raw db error, got %v", err)
		}
	})

	t.Run("token consume error", func(t *testing.T) {
		m := newCliMock()
		m.consumeErr = boom
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "c", CodeVerifier: validVerifier()}); !errors.Is(err, boom) {
			t.Fatalf("want raw db error, got %v", err)
		}
	})

	t.Run("token issue error", func(t *testing.T) {
		m := newCliMock()
		m.codes[sha256Hex("c")] = &cliCode{userID: "u", challenge: pkceChallenge(validVerifier()), expiresAt: time.Now().Add(time.Minute)}
		m.issueErr = boom
		h := newCliHandler(m)
		if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{Code: "c", CodeVerifier: validVerifier()}); !errors.Is(err, boom) {
			t.Fatalf("want raw db error, got %v", err)
		}
	})
}

func TestIsLoopbackRedirect(t *testing.T) {
	good := []string{"http://127.0.0.1:8080/cb", "http://localhost:1/x", "http://[::1]:9000/cb", "http://127.0.0.1/"}
	bad := []string{"", "https://127.0.0.1/cb", "http://evil.example/cb", "ftp://127.0.0.1/", "http://127.0.0.1.evil.example/", "://nonsense"}
	for _, g := range good {
		if !isLoopbackRedirect(g) {
			t.Errorf("%q should be a loopback redirect", g)
		}
	}
	for _, b := range bad {
		if isLoopbackRedirect(b) {
			t.Errorf("%q should NOT be a loopback redirect", b)
		}
	}
}

func TestVerifyPKCES256(t *testing.T) {
	v := validVerifier()
	if !verifyPKCES256(v, pkceChallenge(v)) {
		t.Error("matching verifier rejected")
	}
	if verifyPKCES256(v, pkceChallenge("different")) {
		t.Error("mismatched verifier accepted")
	}
	if verifyPKCES256(v, "") {
		t.Error("empty challenge accepted")
	}
}

// --- a consumer: the flow can serve a browser app, and only a registered one --
//
// CliAuthorize refused every non-loopback redirect, which is right for a CLI
// and made the flow unusable for web SSO: a sign-in app on its own origin
// cannot use the loopback exemption. The answer is not a looser check — an
// unregistered non-loopback redirect is exactly the hole the original comment
// warns about — but a registry the operator writes into.
//
// These pin the boundary from both sides, because a gate that refuses
// everything and a gate that allows everything both pass a one-sided test.

func TestCliAuthorize_LoopbackStillNeedsNoRegistration(t *testing.T) {
	m := newCliMock()
	h := newCliHandler(m)
	for _, uri := range []string{
		"http://127.0.0.1:16201/cb",
		"http://localhost:9000/callback",
		"http://[::1]:8080/cb",
	} {
		if _, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
			CodeChallenge: "chal", RedirectUri: uri,
		}); err != nil {
			t.Errorf("loopback %s was refused — the CLI flow must be unchanged: %v", uri, err)
		}
	}
}

func TestCliAuthorize_ARegisteredCallbackIsAccepted(t *testing.T) {
	m := newCliMock()
	m.register("acme-web", "https://app.acme.example/auth/callback")
	h := newCliHandler(m)

	resp, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal",
		ClientId:      "acme-web",
		RedirectUri:   "https://app.acme.example/auth/callback",
	})
	if err != nil {
		t.Fatalf("a registered callback was refused: %v", err)
	}
	if resp.GetCode() == "" {
		t.Error("no code was minted")
	}
}

// The half that matters. Each of these is a way a looser check would let a
// code reach somewhere the operator never vouched for.
func TestCliAuthorize_RefusesEverythingNotRegistered(t *testing.T) {
	m := newCliMock()
	m.register("acme-web", "https://app.acme.example/auth/callback")
	h := newCliHandler(m)

	for _, tc := range []struct {
		what     string
		clientID string
		redirect string
	}{
		{"an origin nobody registered", "acme-web", "https://evil.example/cb"},
		{"a suffix on a registered host — what a PREFIX match would accept",
			"acme-web", "https://app.acme.example.evil.example/auth/callback"},
		{"a different path on a registered origin — what a HOST match would accept",
			"acme-web", "https://app.acme.example/other"},
		{"the right callback under a client that does not have it", "other-web", "https://app.acme.example/auth/callback"},
		{"a registered callback with no client named at all", "", "https://app.acme.example/auth/callback"},
		{"https loopback — not the loopback exemption, and not registered", "acme-web", "https://127.0.0.1:16201/cb"},
		{"empty", "acme-web", ""},
	} {
		if _, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
			CodeChallenge: "chal", ClientId: tc.clientID, RedirectUri: tc.redirect,
		}); err == nil {
			t.Errorf("%s: a code was minted for %q", tc.what, tc.redirect)
		}
	}
}

// A lookup that fails is not a lookup that said yes. This is the gate, so a
// store we cannot reach must refuse — otherwise taking the database down is
// itself the way past it.
func TestCliAuthorize_AFailedRegistryLookupRefuses(t *testing.T) {
	m := &registryDownMock{cliMock: newCliMock()}
	h := newCliHandler(m.cliMock)
	h.Query = m
	if _, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal", ClientId: "acme-web", RedirectUri: "https://app.acme.example/auth/callback",
	}); err == nil {
		t.Error("the registry was unreachable and the redirect was authorised anyway")
	}
}

type registryDownMock struct{ *cliMock }

func (registryDownMock) GetRegisteredRedirect(context.Context, *pb.GetRegisteredRedirectReq, ...grpc.CallOption) (*pb.GetRegisteredRedirectResp, error) {
	return nil, status.Error(codes.Unavailable, "store down")
}

// --- the exchange must name the redirect the code was issued for -----------
//
// RFC 6749 §4.1.3. Without it a client with two registered callbacks could
// have a code minted for one redeemed as though it came from the other — which
// is a gap the loopback-only design never had, because there was only ever one
// kind of target.
func TestCliToken_RefusesAnExchangeNamingADifferentRedirect(t *testing.T) {
	m := newCliMock()
	m.register("acme-web", "https://app.acme.example/cb-a")
	m.register("acme-web", "https://app.acme.example/cb-b")
	h := newCliHandler(m)

	verifier := strings.Repeat("a", 64)
	authorized, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallengeOf(verifier),
		ClientId:      "acme-web",
		RedirectUri:   "https://app.acme.example/cb-a",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{
		Code: authorized.GetCode(), CodeVerifier: verifier,
		RedirectUri: "https://app.acme.example/cb-b", // the OTHER registered one
	}); err == nil {
		t.Error("a code minted for cb-a was redeemed naming cb-b")
	}
}

func TestCliToken_AcceptsTheRedirectTheCodeWasIssuedFor(t *testing.T) {
	m := newCliMock()
	m.register("acme-web", "https://app.acme.example/cb-a")
	h := newCliHandler(m)

	verifier := strings.Repeat("a", 64)
	authorized, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: pkceChallengeOf(verifier),
		ClientId:      "acme-web",
		RedirectUri:   "https://app.acme.example/cb-a",
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp, err := h.CliToken(context.Background(), &pb.CliTokenReq{
		Code: authorized.GetCode(), CodeVerifier: verifier,
		RedirectUri: "https://app.acme.example/cb-a",
	})
	if err != nil {
		t.Fatalf("the matching redirect was refused: %v", err)
	}
	if resp.GetToken() == "" {
		t.Error("no token was minted")
	}
}

// --- registration refuses what the authorize check could never match -------
func TestRegisterClient_RefusesARedirectThatCannotWork(t *testing.T) {
	m := newCliMock()
	h := newCliHandler(m)
	for _, tc := range []struct{ what, uri string }{
		{"plaintext — http is for loopback, which needs no registration", "http://app.example.com/cb"},
		{"not absolute", "/cb"},
		{"no host", "https:///cb"},
		{"a fragment never reaches the server, so it can never match", "https://app.example.com/cb#x"},
	} {
		if _, err := h.RegisterClient(cliCtx("admin"), &pb.RegisterClientReq{
			ClientId: "c", RedirectUri: tc.uri,
		}); err == nil {
			t.Errorf("%s: %q was written down", tc.what, tc.uri)
		}
	}
	if _, err := h.RegisterClient(cliCtx("admin"), &pb.RegisterClientReq{
		ClientId: "c", RedirectUri: "https://app.example.com/cb",
	}); err != nil {
		t.Errorf("a usable registration was refused: %v", err)
	}
}

// The exactness lives in the query's WHERE, and a mock cannot testify about
// it — the mock in this file matches exactly, so a handler-side check is
// unreachable through it and a looser SQL would never show up. Assert the
// statement itself, the way the projection gate does.
func TestGetRegisteredRedirect_MatchesTheWholeStringAndNothingLess(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "proto", "queries", "auth_query.proto"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := string(b)
	i := strings.Index(src, "rpc GetRegisteredRedirect(")
	if i < 0 {
		t.Fatal("GetRegisteredRedirect is gone — the registry lookup has no statement")
	}
	end := strings.Index(src[i:], "\n  }\n")
	dql := src[i : i+end]

	if !strings.Contains(dql, "c.redirect_uri = :redirect_uri") {
		t.Errorf("the redirect is not compared with equality:\n%s", dql)
	}
	// The shapes that would silently widen it. LIKE and a prefix concat both
	// accept `https://app.example.com.evil.example`; a host-only comparison
	// accepts any path on a registered origin.
	for _, bad := range []string{"LIKE", "like ", "ILIKE", "POSITION(", "STARTS_WITH", "||"} {
		if strings.Contains(dql, bad) {
			t.Errorf("the lookup uses %q — a redirect check must be whole-string equality:\n%s", bad, dql)
		}
	}
	if !strings.Contains(dql, "c.enabled = TRUE") {
		t.Errorf("a disabled registration would still authorise a redirect:\n%s", dql)
	}
	if !strings.Contains(dql, "c.client_id = :client_id") {
		t.Errorf("the lookup does not scope to the client, so any client's callback matches:\n%s", dql)
	}
}

// And the handler's own re-check, which exists for the case the statement
// returned something other than what was asked for. Unreachable through the
// exact mock above, so it gets a deliberately loose one.
type looseRegistryMock struct{ *cliMock }

func (looseRegistryMock) GetRegisteredRedirect(_ context.Context, in *pb.GetRegisteredRedirectReq, _ ...grpc.CallOption) (*pb.GetRegisteredRedirectResp, error) {
	// A query edited to match by prefix would answer like this: a row comes
	// back, and it is not the row that was asked for.
	return &pb.GetRegisteredRedirectResp{Client: &pb.AuthClient{
		ClientId: in.GetClientId(), RedirectUri: "https://app.acme.example/auth/callback", Enabled: true,
	}}, nil
}

func TestCliAuthorize_RefusesARowThatIsNotTheOneItAskedFor(t *testing.T) {
	m := looseRegistryMock{cliMock: newCliMock()}
	h := newCliHandler(m.cliMock)
	h.Query = m

	if _, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal",
		ClientId:      "acme-web",
		RedirectUri:   "https://app.acme.example.evil.example/auth/callback",
	}); err == nil {
		t.Error("the lookup returned a different redirect and the handler authorised the one it was asked about")
	}
}

// --- a consumer addendum: state, and https on the authorize path ------------

// state is the client's anti-CSRF value and the server's only job is to hand
// it back. PKCE does not cover what it covers: an attacker who walks a victim
// through a flow with the ATTACKER's code leaves them signed in as the
// attacker, in their own app, with every PKCE check satisfied.
//
// It cannot be smuggled through redirect_uri either — the redirect is matched
// as a whole string against the registry, so a per-request value can never be
// registered. That is what makes it a field rather than a convention.
func TestCliAuthorize_EchoesStateUnchanged(t *testing.T) {
	m := newCliMock()
	m.register("acme-web", "https://app.acme.example/cb")
	h := newCliHandler(m)

	const state = "9f1c-not-guessable"
	resp, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal", ClientId: "acme-web",
		RedirectUri: "https://app.acme.example/cb", State: state,
	})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if resp.GetState() != state {
		t.Errorf("state came back as %q, want %q — the client cannot compare what it does not get", resp.GetState(), state)
	}
	// And the loopback path too: a CLI that starts using state must not have
	// it silently dropped.
	resp, err = h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal", RedirectUri: "http://127.0.0.1:16201/cb", State: state,
	})
	if err != nil {
		t.Fatalf("loopback authorize: %v", err)
	}
	if resp.GetState() != state {
		t.Errorf("state dropped on the loopback path: %q", resp.GetState())
	}
}

// https is required on the authorize path as well as at registration. The
// registration check refuses the mistake when someone makes it; this one holds
// the guarantee for a row that arrived some other way — a migration, a
// restore, a hand on the database.
func TestCliAuthorize_RefusesAPlaintextRegisteredCallback(t *testing.T) {
	m := newCliMock()
	// A row that registration would have refused, present anyway.
	m.register("legacy", "http://app.example.com/cb")
	h := newCliHandler(m)

	if _, err := h.CliAuthorize(cliCtx("u1"), &pb.CliAuthorizeReq{
		CodeChallenge: "chal", ClientId: "legacy", RedirectUri: "http://app.example.com/cb",
	}); err == nil {
		t.Error("a plaintext non-loopback callback was authorised because a row existed for it")
	}
}

func (m *cliMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId()}}, nil
}
