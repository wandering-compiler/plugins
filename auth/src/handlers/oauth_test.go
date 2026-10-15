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
	"time"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// oauthMock satisfies both client interfaces for the OAuth flow + the
// minimal `devices` methods issueSession transits in the standalone binary.
type oauthMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	issuedHash   string // the token_hash IssueToken was handed
	issuedDevice string // the device IssueToken bound the session to
	issuedReq    *pb.IssueTokenReq

	provider     *pb.OAuthProvider
	identity     *pb.OAuthIdentity // existing identity (nil = first sign-in)
	userByEmail  *pb.User          // existing account by email (nil = none)
	createdUser  *pb.CreateUserReq
	createdIdent *pb.CreateOAuthIdentityReq
	// What an OAuth sign-up must give the account it creates, like SignUp.
	assigned []*pb.AssignRoleToUserReq
	verified []string
	moved    *pb.MoveOAuthProviderSecretReq
	cleared  string

	// loginCodes mirrors OAuthLoginCode: code_hash -> row. Consume is the
	// conditional UPDATE's semantics: one unconsumed match, then none.
	trustedDevice bool
	userDisabled  bool // GetUserById answers with a disabled account

	loginCodes map[string]*pb.CreateOAuthLoginCodeReq
	consumed   map[string]bool
}

func (m *oauthMock) CreateOAuthLoginCode(_ context.Context, in *pb.CreateOAuthLoginCodeReq, _ ...grpc.CallOption) (*pb.CreateOAuthLoginCodeResp, error) {
	if m.loginCodes == nil {
		m.loginCodes, m.consumed = map[string]*pb.CreateOAuthLoginCodeReq{}, map[string]bool{}
	}
	m.loginCodes[in.GetCodeHash()] = in
	return &pb.CreateOAuthLoginCodeResp{Id: "lc-1"}, nil
}

func (m *oauthMock) ConsumeOAuthLoginCode(_ context.Context, in *pb.ConsumeOAuthLoginCodeReq, _ ...grpc.CallOption) (*pb.ConsumeOAuthLoginCodeResp, error) {
	row, ok := m.loginCodes[in.GetCodeHash()]
	if !ok || m.consumed[in.GetCodeHash()] || !row.GetExpiresAt().AsTime().After(time.Now()) {
		return &pb.ConsumeOAuthLoginCodeResp{}, nil
	}
	m.consumed[in.GetCodeHash()] = true
	return &pb.ConsumeOAuthLoginCodeResp{
		UserId: row.UserId, CodeChallenge: row.GetCodeChallenge(),
		ProviderId: row.ProviderId, ExternalId: row.GetExternalId(), Email: row.GetEmail(), EmailVerified: row.GetEmailVerified(),
	}, nil
}

// testState signs a state the way OAuthAuthorizeURL does, bound to the
// challenge of validVerifier() — the browser's verifier in these tests.
func testState(t *testing.T, secret, provider, redirectAfter string) string {
	t.Helper()
	state, _, err := signOAuthState(secret, provider, redirectAfter, challengeDigest(pkceChallengeOf(validVerifier())), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// redeem completes a callback the way the page does: OAuthExchange with the
// callback's code and the browser's verifier.
func redeem(t *testing.T, h *AuthServiceHandler, cb *pb.OAuthCallbackResp) *pb.OAuthExchangeResp {
	t.Helper()
	ex, err := h.OAuthExchange(mintCtx(), &pb.OAuthExchangeReq{Code: cb.GetCode(), CodeVerifier: validVerifier()})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	return ex
}

// stateNonce reads the per-sign-in nonce out of a state, which a test
// needs to build the id_token the provider would return for it.
func stateNonce(t *testing.T, state string) string {
	t.Helper()
	payload, _, _ := strings.Cut(state, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var p oauthStatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.Nonce
}

func (m *oauthMock) ClearOAuthProviderLegacySecret(_ context.Context, in *pb.ClearOAuthProviderLegacySecretReq, _ ...grpc.CallOption) (*pb.ClearOAuthProviderLegacySecretResp, error) {
	m.cleared = in.GetId()
	return &pb.ClearOAuthProviderLegacySecretResp{Id: in.GetId()}, nil
}

func (m *oauthMock) MoveOAuthProviderSecret(_ context.Context, in *pb.MoveOAuthProviderSecretReq, _ ...grpc.CallOption) (*pb.MoveOAuthProviderSecretResp, error) {
	m.moved = in
	return &pb.MoveOAuthProviderSecretResp{Id: in.GetId()}, nil
}

func (m *oauthMock) CountUsers(context.Context, *pb.CountUsersReq, ...grpc.CallOption) (*pb.CountUsersResp, error) {
	return &pb.CountUsersResp{Count: 1}, nil
}
func (m *oauthMock) GetFirstUserRoles(context.Context, *pb.GetFirstUserRolesReq, ...grpc.CallOption) (*pb.GetFirstUserRolesResp, error) {
	return &pb.GetFirstUserRolesResp{RoleIds: []string{"r-first"}}, nil
}
func (m *oauthMock) GetDefaultRoles(context.Context, *pb.GetDefaultRolesReq, ...grpc.CallOption) (*pb.GetDefaultRolesResp, error) {
	return &pb.GetDefaultRolesResp{RoleIds: []string{"r-account"}}, nil
}
func (m *oauthMock) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.assigned = append(m.assigned, in)
	return &pb.AssignRoleToUserResp{}, nil
}
func (m *oauthMock) MarkEmailVerified(_ context.Context, in *pb.MarkEmailVerifiedReq, _ ...grpc.CallOption) (*pb.MarkEmailVerifiedResp, error) {
	m.verified = append(m.verified, in.GetUserId())
	return &pb.MarkEmailVerifiedResp{}, nil
}

func (m *oauthMock) GetProviderByName(ctx context.Context, in *pb.GetProviderByNameReq, _ ...grpc.CallOption) (*pb.GetProviderByNameResp, error) {
	// The storage layer decrypts `secret` into the top-level field.
	return &pb.GetProviderByNameResp{Provider: m.provider, Secret: m.provider.GetSecret()}, nil
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

// device-path methods: the device the exchange binds its session to
func (m *oauthMock) RegisterDevice(_ context.Context, in *pb.RegisterDeviceReq, _ ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	return fakeRegisterDevice(in)
}
func (m *oauthMock) TrustDevice(ctx context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	m.trustedDevice = true
	return &pb.TrustDeviceResp{}, nil
}
func (m *oauthMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	m.issuedHash, m.issuedDevice, m.issuedReq = in.GetTokenHash(), in.GetDeviceId(), in
	return &pb.IssueTokenResp{Token: &pb.UserToken{}}, nil
}

func TestOAuthState_SignVerifyRoundTrip(t *testing.T) {
	ch := challengeDigest(pkceChallengeOf(validVerifier()))
	now := time.Now()
	state, nonce, err := signOAuthState("topsecret", "google", "/dashboard", ch, now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := verifyOAuthState("topsecret", "google", state, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.RedirectAfter != "/dashboard" || got.Challenge != ch || got.Nonce != nonce {
		t.Errorf("state = %+v, want redirect /dashboard, the challenge and the nonce", got)
	}
	// Tamper / wrong secret / wrong provider all fail.
	if _, err := verifyOAuthState("wrongkey", "google", state, now); err == nil {
		t.Error("wrong secret must fail state verification")
	}
	if _, err := verifyOAuthState("topsecret", "github", state, now); err == nil {
		t.Error("provider mismatch must fail state verification")
	}
	if _, err := verifyOAuthState("topsecret", "google", state+"x", now); err == nil {
		t.Error("tampered signature must fail")
	}
}

// A state is not stored, so its expiry is what retires it: a callback
// replayed after oauthStateTTL is refused.
func TestOAuthState_Expires(t *testing.T) {
	now := time.Now()
	state, _, err := signOAuthState("s", "google", "", challengeDigest(pkceChallengeOf(validVerifier())), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOAuthState("s", "google", state, now.Add(oauthStateTTL-time.Second)); err != nil {
		t.Errorf("a state inside its lifetime was refused: %v", err)
	}
	if _, err := verifyOAuthState("s", "google", state, now.Add(oauthStateTTL)); err != errOAuthStateExpired {
		t.Errorf("an expired state: err = %v, want errOAuthStateExpired", err)
	}
}

// A state without a challenge (signed before the challenge was required)
// could only produce a code nobody can redeem; it is refused up front.
func TestOAuthState_WithoutAChallengeIsRefused(t *testing.T) {
	raw, _ := json.Marshal(oauthStatePayload{Nonce: "n", Provider: "google", Expires: time.Now().Add(time.Minute).Unix()})
	payload := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := verifyOAuthState("s", "google", payload+"."+oauthStateSig("s", payload), time.Now()); err == nil {
		t.Error("a state with no code_challenge was accepted")
	}
}

func TestOAuthAuthorizeURL_BuildsRedirect(t *testing.T) {
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", Secret: "csec",
		AuthorizeUrl: "https://idp.example/authorize", Scopes: "openid email", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	resp, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: "/home", CodeChallenge: pkceChallengeOf(validVerifier())})
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
		"code_challenge_method=S256",
		"code_challenge=",
		"nonce=",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize url missing %q:\n%s", want, u)
		}
	}
}

// The client secret lives in the encrypted `secret`, where the admin writes.
// The legacy plaintext column is read only while `secret` is empty, and moved
// (conditioned on still holding what was read); beside a set `secret` it is
// ignored and cleared — letting it win would undo a rotation an operator made
// in the admin before the provider's first sign-in.
func TestOAuthProvider_SecretFromEncryptedColumnOrMovedFromLegacy(t *testing.T) {
	for _, c := range []struct {
		name           string
		secret, legacy string
		want           string
		moves, clears  bool
	}{
		{"encrypted only", "enc", "", "enc", false, false},
		{"legacy only", "", "plain", "plain", true, false},
		{"encrypted wins, plaintext copy cleared", "rotated", "stale", "rotated", false, true},
	} {
		m := &oauthMock{provider: &pb.OAuthProvider{Id: "p1", Name: "google", Secret: c.secret, ClientSecret: c.legacy, Enabled: true}}
		h := &AuthServiceHandler{Query: m, Mutation: m}
		p, err := h.loadEnabledProvider(context.Background(), "google")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if p.GetSecret() != c.want {
			t.Errorf("%s: secret = %q, want %q", c.name, p.GetSecret(), c.want)
		}
		if moved := m.moved != nil; moved != c.moves ||
			(moved && (m.moved.GetId() != "p1" || m.moved.GetSecret() != c.want || m.moved.GetLegacy() != c.legacy)) {
			t.Errorf("%s: move = %+v, want moves=%v", c.name, m.moved, c.moves)
		}
		if cleared := m.cleared == "p1"; cleared != c.clears {
			t.Errorf("%s: cleared = %v, want %v", c.name, cleared, c.clears)
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

// TestOAuthAuthorizeURL_EmptyClientSecret_Rejected — an
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

// An absolute / protocol-relative redirect_after is an open
// redirect (CWE-601) — the authorize side must reject it before signing.
func TestOAuthAuthorizeURL_RejectsUnsafeRedirect(t *testing.T) {
	for _, bad := range []string{"https://evil.com", "//evil.com", "http://x", "javascript:alert(1)", "/\\evil.com", "\\\\evil"} {
		m := &oauthMock{provider: &pb.OAuthProvider{
			Name: "google", ClientId: "cid", Secret: "csec",
			AuthorizeUrl: "https://idp.example/authorize", Enabled: true,
		}}
		h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
		if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: bad, CodeChallenge: pkceChallengeOf(validVerifier())}); err == nil {
			t.Errorf("redirect_after %q must be rejected as an open-redirect target", bad)
		}
	}
	// A site-relative path is still accepted.
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", ClientId: "cid", Secret: "csec",
		AuthorizeUrl: "https://idp.example/authorize", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, OAuthRedirectBase: "https://app.example"}
	if _, err := h.OAuthAuthorizeURL(context.Background(), &pb.OAuthAuthorizeURLReq{Provider: "google", RedirectAfter: "/dashboard", CodeChallenge: pkceChallengeOf(validVerifier())}); err != nil {
		t.Errorf("a site-relative redirect_after must be accepted: %v", err)
	}
}

// Defense in depth: a state signed (by an older build) with an
// unsafe redirect_after must be neutralised at callback — the response must
// not carry an off-origin redirect target.
func TestOAuthCallback_DropsUnsafeRedirect(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-9", "email": "eve@idp.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p9", Name: "google", ClientId: "cid", Secret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	// Sign directly (simulating an old build that didn't validate) with an
	// absolute redirect.
	state := testState(t, "csec", "google", "https://evil.com")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "auth-code", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if resp.GetRedirectAfter() != "" {
		t.Errorf("unsafe redirect_after must be dropped, got %q", resp.GetRedirectAfter())
	}
}

// TestOAuthCallback_EmptyClientSecret_Rejected — the verify side of the same
// empty-client_secret refusal.
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
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	state := testState(t, "csec", "google", "/welcome")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "auth-code", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if m.issuedHash != "" {
		t.Fatal("the callback issued a session; it must hand out only a login code")
	}
	ex := redeem(t, h, resp)
	if ex.GetToken() == "" || m.issuedHash != sha256Hex(ex.GetToken()) || ex.GetUserId() == "" {
		t.Errorf("exchange resp = %+v, want a token + user id", ex)
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
	// The account is a full account: the turnkey default roles, like SignUp's.
	// Holding none, every endpoint would answer 403.
	if len(m.assigned) != 1 || m.assigned[0].GetRoleId() != "r-account" {
		t.Errorf("the OAuth-created account got roles %+v, want the default role", m.assigned)
	}
	// The provider did not assert email_verified, so nothing is recorded.
	if len(m.verified) != 0 {
		t.Errorf("an unasserted address was marked verified: %v", m.verified)
	}
}

// A provider that asserts email_verified vouches for the address the way a
// returned code does; the account it creates records that, so an
// address-proof floor on invitations admits it.
func TestOAuthCallback_AProviderVerifiedAddressIsRecorded(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-2", "email": "bob@idp.com", "email_verified": true}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state := testState(t, "csec", "google", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "auth-code", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	uid := redeem(t, h, resp).GetUserId()
	if len(m.verified) != 1 || m.verified[0] != uid {
		t.Fatalf("the provider-verified address was not recorded for the new account: %v (user %s)", m.verified, uid)
	}
}

func TestOAuthCallback_IDTokenPath(t *testing.T) {
	state := testState(t, "csec", "okta", "")
	claims, _ := json.Marshal(map[string]any{
		"sub": "ext-2", "email": "bob@idp.com",
		"aud": "cid", "exp": time.Now().Add(time.Hour).Unix(), "nonce": oidcNonce("csec", stateNonce(t, state)),
	})
	idToken := "h." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	srv := fakeIdP(t, nil, idToken)
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "okta", ClientId: "cid", Secret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: "", Enabled: true, // no userinfo → decode id_token
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}

	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "okta", Code: "c", State: state})
	if err != nil {
		t.Fatalf("callback (id_token): %v", err)
	}
	if redeem(t, h, resp).GetToken() == "" {
		t.Error("expected a session token")
	}
	if m.createdIdent.GetExternalId() != "ext-2" || m.createdUser.GetEmail() != "bob@idp.com" {
		t.Errorf("id_token claims not mapped: ident=%+v user=%+v", m.createdIdent, m.createdUser)
	}
}

// An id_token is accepted only if it was minted for this client and this
// sign-in, and is still valid.
func TestCheckIDTokenClaims(t *testing.T) {
	now := time.Now()
	future := float64(now.Add(time.Hour).Unix())
	for _, c := range []struct {
		name   string
		claims map[string]any
		ok     bool
	}{
		{"valid", map[string]any{"aud": "cid", "exp": future, "nonce": "n1"}, true},
		{"audience array", map[string]any{"aud": []any{"other", "cid"}, "exp": future, "nonce": "n1"}, true},
		{"another client's token", map[string]any{"aud": "other", "exp": future, "nonce": "n1"}, false},
		{"no audience", map[string]any{"exp": future, "nonce": "n1"}, false},
		{"expired", map[string]any{"aud": "cid", "exp": float64(now.Add(-time.Second).Unix()), "nonce": "n1"}, false},
		{"no expiry", map[string]any{"aud": "cid", "nonce": "n1"}, false},
		{"another sign-in's nonce", map[string]any{"aud": "cid", "exp": future, "nonce": "n2"}, false},
		{"no nonce", map[string]any{"aud": "cid", "exp": future}, false},
		{"another authorized party", map[string]any{"aud": []any{"other", "cid"}, "azp": "other", "exp": future, "nonce": "n1"}, false},
		{"this authorized party", map[string]any{"aud": []any{"other", "cid"}, "azp": "cid", "exp": future, "nonce": "n1"}, true},
	} {
		if err := checkIDTokenClaims(c.claims, "cid", "n1", now); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestOAuthCallback_GitHubNumericId(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"id": float64(987654), "email": "dev@gh.com"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Id: "p1", Name: "github", ClientId: "cid", Secret: "csec",
		TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo",
		SubjectPath: "id", EmailPath: "email", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state := testState(t, "csec", "github", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "github", Code: "c", State: state})
	if err != nil {
		t.Fatalf("callback (github): %v", err)
	}
	redeem(t, h, resp) // the new account and its identity are made by the exchange
	if m.createdIdent.GetExternalId() != "987654" {
		t.Errorf("github numeric id → external_id = %q, want 987654", m.createdIdent.GetExternalId())
	}
}

func TestOAuthCallback_ExistingIdentity_ReusesUser(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-1", "email": "alice@idp.com"}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", Secret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		identity: &pb.OAuthIdentity{Id: "id-existing", UserId: "u-existing"},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state := testState(t, "csec", "google", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	if uid := redeem(t, h, resp).GetUserId(); uid != "u-existing" {
		t.Errorf("existing identity must reuse its user, got %q", uid)
	}
	if m.createdUser != nil || m.createdIdent != nil {
		t.Error("existing identity must NOT create a new user/identity")
	}
}

func TestOAuthCallback_BadState_Unauthenticated(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "x", "email": "y@z.c"}, "")
	m := &oauthMock{provider: &pb.OAuthProvider{
		Name: "google", Secret: "csec", TokenUrl: srv.URL + "/token",
		UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
	}}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: "forged.sig"}); err == nil {
		t.Error("a forged state must fail the callback")
	}
}

// TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting.
// When the IdP does NOT assert `email_verified`, an external identity must
// NOT auto-link to a pre-existing local account with the same email —
// otherwise an attacker who set their IdP profile email to a victim's gets
// a session for the victim's account (account takeover / CWE-287).
func TestOAuthCallback_UnverifiedEmail_RefusesLinkToExisting(t *testing.T) {
	// Claims carry the victim's email but NO email_verified.
	srv := fakeIdP(t, map[string]any{"sub": "attacker-ext", "email": "victim@corp.com"}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		userByEmail: &pb.User{Id: "victim-123", Email: "victim@corp.com"}, // pre-existing account
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state := testState(t, "csec", "google", "")
	_, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err == nil {
		t.Fatal("callback must REFUSE linking an unverified email to an existing account (account takeover)")
	}
	if m.createdIdent != nil && m.createdIdent.GetUserId() == "victim-123" {
		t.Errorf("attacker identity was bound to the victim's account: %+v", m.createdIdent)
	}
}

// TestOAuthCallback_VerifiedEmail_LinksToExisting — with
// email_verified=true the auto-link to a pre-existing account is the
// intended behaviour (no new user created).
func TestOAuthCallback_VerifiedEmail_LinksToExisting(t *testing.T) {
	srv := fakeIdP(t, map[string]any{"sub": "ext-9", "email": "user@corp.com", "email_verified": true}, "")
	m := &oauthMock{
		provider: &pb.OAuthProvider{
			Id: "p1", Name: "google", ClientId: "cid", Secret: "csec",
			TokenUrl: srv.URL + "/token", UserinfoUrl: srv.URL + "/userinfo", Enabled: true,
		},
		// EmailVerifiedAt set: the auto-link
		// requires BOTH sides to have verified the address. The IdP side is
		// what this test is about; the local side is a precondition of the
		// scenario rather than its subject, so it belongs in the fixture.
		// Without it this exercises the refusal, not the link.
		userByEmail: &pb.User{Id: "user-77", Email: "user@corp.com", EmailVerifiedAt: timestamppb.Now()},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
	state := testState(t, "csec", "google", "")
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatalf("verified email should link to the existing account: %v", err)
	}
	if uid := redeem(t, h, resp).GetUserId(); uid != "user-77" {
		t.Errorf("user_id = %q, want user-77 (linked to existing)", uid)
	}
	if m.createdUser != nil {
		t.Errorf("expected NO new user (linked to existing), got %+v", m.createdUser)
	}
	if m.createdIdent == nil || m.createdIdent.GetUserId() != "user-77" {
		t.Errorf("identity should bind to existing user-77, got %+v", m.createdIdent)
	}
}

func (m *oauthMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u := &pb.User{Id: in.GetUserId()}
	if m.userDisabled {
		u.DisabledAt = timestamppb.Now()
	}
	return &pb.GetUserByIdResp{User: u}, nil
}
