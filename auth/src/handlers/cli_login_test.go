package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// cliMock backs the cli_login handlers. It models the CliAuthCode table
// (keyed by code_hash) so CliAuthorize → CliToken can be exercised end to
// end, including the atomic single-use + expiry semantics of the consume
// DQL (mirrored in ConsumeCliAuthCode below).
type cliCode struct {
	userID    string
	challenge string
	expiresAt time.Time
	consumed  bool
}

type cliMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	codes     map[string]*cliCode // code_hash -> stored code
	issuedFor string              // user_id IssueToken was last called with

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
		userID:    in.GetUserId(),
		challenge: in.GetCodeChallenge(),
		expiresAt: in.GetExpiresAt().AsTime(),
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
	return &pb.ConsumeCliAuthCodeResp{UserId: c.userID, CodeChallenge: c.challenge}, nil
}

func (m *cliMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	if m.issueErr != nil {
		return nil, m.issueErr
	}
	m.issuedFor = in.GetUserId()
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "tok-1", Token: "bearer-for-" + in.GetUserId(), UserId: in.GetUserId()}}, nil
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
