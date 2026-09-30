package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// oauthMock satisfies both client interfaces for the OAuth flow + the
// minimal `devices` methods issueSession transits in the standalone binary.
type oauthMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	provider     *pb.OAuthProvider
	identity     *pb.OAuthIdentity // existing identity (nil = first sign-in)
	userByEmail  *pb.User          // existing account by email (nil = none)
	createdUser  *pb.CreateUserReq
	createdIdent *pb.CreateOAuthIdentityReq
}

func (m *oauthMock) GetProviderByName(ctx context.Context, in *pb.GetProviderByNameReq, _ ...grpc.CallOption) (*pb.GetProviderByNameResp, error) {
	return &pb.GetProviderByNameResp{Provider: m.provider}, nil
}
func (m *oauthMock) GetOAuthIdentity(ctx context.Context, in *pb.GetOAuthIdentityReq, _ ...grpc.CallOption) (*pb.GetOAuthIdentityResp, error) {
	return &pb.GetOAuthIdentityResp{Identity: m.identity}, nil
}
func (m *oauthMock) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: m.userByEmail}, nil
}
func (m *oauthMock) CreateUser(ctx context.Context, in *pb.CreateUserReq, _ ...grpc.CallOption) (*pb.CreateUserResp, error) {
	m.createdUser = in
	return &pb.CreateUserResp{User: &pb.User{Id: "u-new", Email: in.GetEmail()}}, nil
}
func (m *oauthMock) CreateOAuthIdentity(ctx context.Context, in *pb.CreateOAuthIdentityReq, _ ...grpc.CallOption) (*pb.CreateOAuthIdentityResp, error) {
	m.createdIdent = in
	return &pb.CreateOAuthIdentityResp{Identity: &pb.OAuthIdentity{Id: "id-1", UserId: in.GetUserId()}}, nil
}

// device-path methods (issueSession override is active in the combined binary)
func (m *oauthMock) GetDeviceByIdentifier(ctx context.Context, in *pb.GetDeviceByIdentifierReq, _ ...grpc.CallOption) (*pb.GetDeviceByIdentifierResp, error) {
	return &pb.GetDeviceByIdentifierResp{}, nil
}
func (m *oauthMock) CreateDevice(ctx context.Context, in *pb.CreateDeviceReq, _ ...grpc.CallOption) (*pb.CreateDeviceResp, error) {
	return &pb.CreateDeviceResp{Device: &pb.Device{Id: "dev-1"}}, nil
}
func (m *oauthMock) TrustDevice(ctx context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	return &pb.TrustDeviceResp{}, nil
}
func (m *oauthMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{Token: &pb.UserToken{Token: "oauth-tok"}}, nil
}

func TestOAuthState_SignVerifyRoundTrip(t *testing.T) {
	state, err := signOAuthState("topsecret", "google", "/dashboard")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := verifyOAuthState("topsecret", "google", state)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != "/dashboard" {
		t.Errorf("redirect_after = %q, want /dashboard", got)
	}
	// Tamper / wrong secret / wrong provider all fail.
	if _, err := verifyOAuthState("wrongkey", "google", state); err == nil {
		t.Error("wrong secret must fail state verification")
	}
	if _, err := verifyOAuthState("topsecret", "github", state); err == nil {
		t.Error("provider mismatch must fail state verification")
	}
	if _, err := verifyOAuthState("topsecret", "google", state+"x"); err == nil {
		t.Error("tampered signature must fail")
	}
}

func TestOAuthAuthorizeURL_BuildsRedirect(t *testing.T) {
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", ClientSecret: "csec",
		AuthorizeUrl: "https://idp.example/authorize", Scopes: "openid email", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	resp, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: "/home"})
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	u := resp.GetAuthorizeUrl()
	for _, want := range []string{
		"https://idp.example/authorize?",
		"client_id=cid",
		"response_type=code",
		"redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Foauth%2Fgoogle%2Fcallback",
		"scope=openid+email",
		"state=",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize url missing %q:\n%s", want, u)
		}
	}
}

func TestOAuthAuthorizeURL_DisabledProvider(t *testing.T) {
	m := &oauthMock{provider: &pb.OAuthProvider{Name: "google", Enabled: false}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google"}); err == nil {
		t.Error("a disabled provider must be rejected")
	}
}

// TestOAuthAuthorizeURL_EmptyClientSecret_Rejected — Q36-auth-2. An
// enabled provider with no client_secret must be rejected, not used to
// sign the state CSRF token with an empty (public) HMAC key — which an
// attacker could recompute to forge any state (login-CSRF / arbitrary
// redirect_after). Guards both the authorize (sign) and callback
// (verify) paths via loadEnabledProvider.
func TestOAuthAuthorizeURL_EmptyClientSecret_Rejected(t *testing.T) {
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", ClientSecret: "", // empty secret
		AuthorizeUrl: "https://idp.example/authorize", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google"}); err == nil {
		t.Fatal("an enabled provider with empty client_secret must be rejected (empty-key state HMAC = forgeable CSRF token)")
	}
}

// Q45-auth-1: an absolute / protocol-relative redirect_after is an open
// redirect (CWE-601) — the authorize side must reject it before signing.
func TestOAuthAuthorizeURL_RejectsUnsafeRedirect(t *testing.T) {
	for _, bad := range []string{"https://evil.com", "//evil.com", "http://x", "javascript:alert(1)", "/\\evil.com", "\\\\evil"} {
		m := &oauthMock{provider: &pb.OAuthProvider{
			Name: "google", ClientId: "cid", ClientSecret: "csec",
			AuthorizeUrl: "https://idp.example/authorize", Enabled: true,
		}}
		h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
		if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: bad}); err == nil {
			t.Errorf("redirect_after %q must be rejected as an open-redirect target", bad)
		}
	}
	// A site-relative path is still accepted.
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", ClientSecret: "csec",
		AuthorizeUrl: "https://idp.example/authorize", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: "/dashboard"}); err != nil {
		t.Errorf("a site-relative redirect_after must be accepted: %v", err)
	}
}

// Q45-auth-1 defense-in-depth: a state signed (by an older build) with an
// unsafe redirect_after must be neutralised at callback — the response must
// not carry an off-origin redirect target.
func TestOAuthCallback_DropsUnsafeRedirect(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-9", "email": "eve@idp.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p9", Name: "google", ClientId: "cid", ClientSecret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	// Sign directly (simulating an old build that didn't validate) with an
	// absolute redirect.
	state, _ := signOAuthState("csec", "google", "https://evil.com")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "auth-code", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.GetRedirectAfter() != "" {
		t.Errorf("unsafe redirect_after must be dropped, got %q", resp.GetRedirectAfter())
	}
}

// TestOAuthCallback_EmptyClientSecret_Rejected — Q36-auth-2 (verify side).
func TestOAuthCallback_EmptyClientSecret_Rejected(t *testing.T) {
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", ClientSecret: "", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	// Even an attacker-forged state signed with the empty key must not be
	// accepted — the provider is refused before verification.
	forged := "eyJ4IjoieSJ9." + oauthStateSig("", "eyJ4IjoieSJ9")
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: forged}); err == nil {
		t.Fatal("callback must reject a provider with empty client_secret (forgeable state)")
	}
}

// fakeIdP stands up a token + userinfo endpoint.
func fakeIdP(t *testing.T, userinfo map[string]any, idToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"access_token": "at-123", "token_type": "bearer"}
		if idToken != "" {
			resp["id_token"] = idToken
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(userinfo)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOAuthCallback_UserinfoPath_CreatesUser(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", ClientSecret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	state, _ := signOAuthState("csec", "google", "/welcome")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "auth-code", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.GetToken() != "oauth-tok" || resp.GetUserId() == "" {
		t.Errorf("callback resp = %+v, want a token + user id", resp)
	}
	if resp.GetRedirectAfter() != "/welcome" {
		t.Errorf("redirect_after = %q, want /welcome", resp.GetRedirectAfter())
	}
	if m.createdUser == nil || m.createdUser.GetEmail() != "alice@idp.com" {
		t.Errorf("expected a user created for alice@idp.com, got %+v", m.createdUser)
	}
	if m.createdIdent == nil || m.createdIdent.GetExternalId() != "ext-1" {
		t.Errorf("expected an identity for ext-1, got %+v", m.createdIdent)
	}
}

func TestOAuthCallback_IDTokenPath(t *testing.T) {
	claims, _ := json.Marshal(map[string]any{"sub": "ext-2", "email": "bob@idp.com"})
	idToken := "h." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	srv := fakeIdP(t, nil, idToken)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "okta", ClientId: "cid", ClientSecret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: "", Enabled: true, // no userinfo → decode id_token
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	state, _ := signOAuthState("csec", "okta", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "okta", Code: "c", State: state})
	if err != nil {
		t.Fatalf("callback (id_token): %v", err)
	}
	if resp.GetToken() == "" {
		t.Error("expected a session token")
	}
	if m.createdIdent.GetExternalId() != "ext-2" || m.createdUser.GetEmail() != "bob@idp.com" {
		t.Errorf("id_token claims not mapped: ident=%+v user=%+v", m.createdIdent, m.createdUser)
	}
}

func TestOAuthCallback_GitHubNumericId(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"id": float64(987654), "email": "dev@gh.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "github", ClientId: "cid", ClientSecret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo",
		SubjectPath: "id", EmailPath: "email", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state, _ := signOAuthState("csec", "github", "")
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "github", Code: "c", State: state}); err != nil {
		t.Fatalf("callback (github): %v", err)
	}
	if m.createdIdent.GetExternalId() != "987654" {
		t.Errorf("github numeric id → external_id = %q, want 987654", m.createdIdent.GetExternalId())
	}
}

func TestOAuthCallback_ExistingIdentity_ReusesUser(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.com"}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", ClientSecret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		identity: &pb.OAuthIdentity{Id: "id-existing", UserId: "u-existing"},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state, _ := signOAuthState("csec", "google", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.GetUserId() != "u-existing" {
		t.Errorf("existing identity must reuse its user, got %q", resp.GetUserId())
	}
	if m.createdUser != nil || m.createdIdent != nil {
		t.Error("existing identity must NOT create a new user/identity")
	}
}

func TestOAuthCallback_BadState_Unauthenticated(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "x", "email": "y@z.c"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientSecret: "csec", TokenUrl: srv.URL + "/token",
		UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: "forged.sig"}); err == nil {
		t.Error("a forged state must fail the callback")
	}
}

// TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting — Q36-auth-1.
// When the IdP does NOT assert `email_verified`, an external identity must
// NOT auto-link to a pre-existing local account with the same email —
// otherwise an attacker who set their IdP profile email to a victim's gets
// a session for the victim's account (account takeover / CWE-287).
func TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting(t *testing.T) {
	// Claims carry the victim's email but NO email_verified.
	srv := fakeIdP(t, map[string]any{"sub": "attacker-ext", "email": "victim@corp.com"}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", ClientId: "cid", ClientSecret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		userByEmail: &pb.User{Id: "victim-123", Email: "victim@corp.com"}, // pre-existing account
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state, _ := signOAuthState("csec", "google", "")
	_, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err == nil {
		t.Fatal("callback must REFUSE linking an unverified email to an existing account (account takeover)")
	}
	if m.createdIdent != nil && m.createdIdent.GetUserId() == "victim-123" {
		t.Errorf("attacker identity was bound to the victim's account: %+v", m.createdIdent)
	}
}

// TestOAuthCallback_VerifiedEmail_LinksToExisting — Q36-auth-1. With
// email_verified=true the auto-link to a pre-existing account is the
// intended behaviour (no new user created).
func TestOAuthCallback_VerifiedEmail_LinksToExisting(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-9", "email": "user@corp.com", "email_verified": true}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", ClientId: "cid", ClientSecret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		// EmailVerifiedAt set: since T3-7 pass #14 (B14-2) the auto-link
		// requires BOTH sides to have verified the address. The IdP side is
		// what this test is about; the local side is a precondition of the
		// scenario rather than its subject, so it belongs in the fixture.
		// Without it this exercises the refusal, not the link.
		userByEmail: &pb.User{Id: "user-77", Email: "user@corp.com", EmailVerifiedAt: timestamppb.Now()},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state, _ := signOAuthState("csec", "google", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatalf("verified email should link to the existing account: %v", err)
	}
	if resp.GetUserId() != "user-77" {
		t.Errorf("user_id = %q, want user-77 (linked to existing)", resp.GetUserId())
	}
	if m.createdUser != nil {
		t.Errorf("expected NO new user (linked to existing), got %+v", m.createdUser)
	}
	if m.createdIdent == nil || m.createdIdent.GetUserId() != "user-77" {
		t.Errorf("identity should bind to existing user-77, got %+v", m.createdIdent)
	}
}
