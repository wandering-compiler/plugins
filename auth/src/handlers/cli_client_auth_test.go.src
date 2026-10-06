package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// a consumer — the authorization-code flow was built for CLIs (2026-06-28),
// where a secret cannot be kept and PKCE alone is the right answer (RFC 8252).
// Taking it past loopback to browser and server apps carried that PUBLIC
// client shape onto clients that can keep a secret, leaving the registry's
// write path as the only thing between "anyone may register a callback" and
// "a code is delivered there". A confidential client closes it from the other
// end: a registration is worth nothing without the secret it issued.

type clientAuthMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	storedHash string
	enabled    bool
	lookupErr  error
	notFound   bool

	// what the code carried
	codeClientID    string
	codeRedirectURI string

	askedClientID string
	issued        bool
}

func (m *clientAuthMock) ConsumeCliAuthCode(ctx context.Context, in *pb.ConsumeCliAuthCodeReq, _ ...grpc.CallOption) (*pb.ConsumeCliAuthCodeResp, error) {
	return &pb.ConsumeCliAuthCodeResp{
		UserId:        "u1",
		CodeChallenge: pkceChallengeOf(testVerifier),
		RedirectUri:   m.codeRedirectURI,
		ClientId:      m.codeClientID,
	}, nil
}

func (m *clientAuthMock) GetAuthClientSecret(ctx context.Context, in *pb.GetAuthClientSecretReq, _ ...grpc.CallOption) (*pb.GetAuthClientSecretResp, error) {
	m.askedClientID = in.GetClientId()
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	if m.notFound {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetAuthClientSecretResp{ClientSecret: m.storedHash, Enabled: m.enabled}, nil
}

func (m *clientAuthMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	m.issued = true
	return &pb.IssueTokenResp{Token: &pb.UserToken{Token: "tok"}}, nil
}

const testVerifier = "verifier-that-is-long-enough-for-pkce-rules-0123456789"

func newClientAuthHandler(t *testing.T, m *clientAuthMock, secret string) *AuthServiceHandler {
	t.Helper()
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	if secret != "" {
		hashed, err := h.PasswordHash.Hash(secret)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		m.storedHash = hashed
	}
	return h
}

// The code the registry exists for: a registered client redeems only with its
// own secret.
func TestCliToken_RegisteredClientMustPresentItsSecret(t *testing.T) {
	m := &clientAuthMock{
		enabled:         true,
		codeClientID:    "engine-7",
		codeRedirectURI: "https://engine7.example/cb",
	}
	h := newClientAuthHandler(t, m, "s3cret-value")

	base := func() *pb.CliTokenReq {
		return &pb.CliTokenReq{
			Code:         "code",
			CodeVerifier: testVerifier,
			RedirectUri:  "https://engine7.example/cb",
		}
	}

	// Right secret → token.
	req := base()
	req.ClientSecret = "s3cret-value"
	if _, err := h.CliToken(context.Background(), req); err != nil {
		t.Fatalf("the registered client could not redeem with its own secret: %v", err)
	}
	if m.askedClientID != "engine-7" {
		t.Errorf("verified against client %q, want engine-7", m.askedClientID)
	}

	// Wrong secret → refused, and NO token minted.
	m.issued = false
	req = base()
	req.ClientSecret = "not-the-secret"
	if _, err := h.CliToken(context.Background(), req); err == nil {
		t.Error("a wrong client secret redeemed the code")
	}
	if m.issued {
		t.Error("a token was issued despite failed client authentication")
	}

	// ABSENT secret → refused. This is the shape a caller who never
	// registered would send, and the one the old flow accepted.
	m.issued = false
	if _, err := h.CliToken(context.Background(), base()); err == nil {
		t.Error("a code for a registered client was redeemed with no secret at all")
	}
	if m.issued {
		t.Error("a token was issued with no client authentication")
	}
}

// Loopback keeps the public-client shape on purpose: no registration, no
// secret, PKCE is the binding. Every CLI in the field redeems this way, and
// demanding a secret there would break them for a guarantee they already have.
func TestCliToken_LoopbackStaysAPublicClient(t *testing.T) {
	m := &clientAuthMock{codeRedirectURI: "http://127.0.0.1:8123/cb"} // no client id
	h := newClientAuthHandler(t, m, "")

	if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{
		Code:         "code",
		CodeVerifier: testVerifier,
		RedirectUri:  "http://127.0.0.1:8123/cb",
	}); err != nil {
		t.Fatalf("a loopback redemption was refused: %v", err)
	}
	if m.askedClientID != "" {
		t.Errorf("loopback asked for a client secret (%q) — CLIs have none", m.askedClientID)
	}
}

// Disabled BETWEEN authorize and exchange: the code is live, the client is
// not. The `enabled = TRUE` that ran at authorize says nothing about now.
func TestCliToken_ClientDisabledAfterAuthorizeCannotRedeem(t *testing.T) {
	m := &clientAuthMock{
		enabled:         false,
		codeClientID:    "engine-7",
		codeRedirectURI: "https://engine7.example/cb",
	}
	h := newClientAuthHandler(t, m, "s3cret-value")

	if _, err := h.CliToken(context.Background(), &pb.CliTokenReq{
		Code: "code", CodeVerifier: testVerifier,
		RedirectUri: "https://engine7.example/cb", ClientSecret: "s3cret-value",
	}); err == nil {
		t.Error("a disabled client redeemed a code minted before it was disabled")
	}
}

// Every way client authentication fails looks the same on the wire. Which of
// "no such client" / "disabled" / "wrong secret" happened is what somebody
// probing the registry would want to learn.
func TestCliToken_ClientAuthFailuresAreIndistinguishable(t *testing.T) {
	msgs := map[string]bool{}
	for _, tc := range []struct {
		name string
		m    *clientAuthMock
		sec  string
	}{
		{"no such client", &clientAuthMock{notFound: true, codeClientID: "x", codeRedirectURI: "https://a.example/cb"}, "s"},
		{"disabled", &clientAuthMock{enabled: false, codeClientID: "x", codeRedirectURI: "https://a.example/cb"}, "s3cret-value"},
		{"wrong secret", &clientAuthMock{enabled: true, codeClientID: "x", codeRedirectURI: "https://a.example/cb"}, "s3cret-value"},
	} {
		h := newClientAuthHandler(t, tc.m, "s3cret-value")
		sec := tc.sec
		if tc.name == "wrong secret" {
			sec = "wrong"
		}
		_, err := h.CliToken(context.Background(), &pb.CliTokenReq{
			Code: "code", CodeVerifier: testVerifier,
			RedirectUri: "https://a.example/cb", ClientSecret: sec,
		})
		if err == nil {
			t.Fatalf("%s: redeemed", tc.name)
		}
		msgs[err.Error()] = true
	}
	if len(msgs) != 1 {
		t.Errorf("client-auth failures are distinguishable on the wire: %v", keysOf(msgs))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// RegisterClient hands the secret back ONCE and stores only its hash.
func TestRegisterClient_IssuesASecretAndStoresOnlyItsHash(t *testing.T) {
	m := &registerMock{}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	resp, err := h.RegisterClient(cliCtx("admin"), &pb.RegisterClientReq{
		ClientId:    "engine-7",
		RedirectUri: "https://engine7.example/cb",
	})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if resp.GetClientSecret() == "" {
		t.Fatal("registration returned no secret — the client has nothing to authenticate with")
	}
	if m.storedSecret == resp.GetClientSecret() {
		t.Error("the secret was stored VERBATIM — a database read would hand somebody a working client credential")
	}
	if !strings.HasPrefix(m.storedSecret, "$") {
		t.Errorf("stored secret %q is not a PHC hash", m.storedSecret)
	}
	// And the stored row never carries it back out.
	if resp.GetClient().GetClientSecret() != "" {
		t.Error("the returned AuthClient carries the secret hash — the registry queries must not project it")
	}
}

type registerMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	storedSecret string
}

func (m *registerMock) RegisterAuthClient(ctx context.Context, in *pb.RegisterAuthClientReq, _ ...grpc.CallOption) (*pb.RegisterAuthClientResp, error) {
	m.storedSecret = in.GetClientSecret()
	return &pb.RegisterAuthClientResp{Client: &pb.AuthClient{
		ClientId:    in.GetClientId(),
		RedirectUri: in.GetRedirectUri(),
	}}, nil
}

func (m *clientAuthMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId()}}, nil
}
