package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// oauthStore is an in-memory oauth_server: the rows its statements write,
// with the predicates those statements carry (live, undecided, unspent).
type oauthStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	clients  map[string]*pb.OAuthClientRow // by client_id hash
	auths    map[string]*oauthAuthRow      // by request hash
	grants   map[string]*oauthGrantRow
	refresh  map[string]*oauthRefreshRow // by token hash
	access   []*oauthAccessRow
	sessions map[string]*pb.GetOAuthApprovingSessionResp // by token id
	revoked  map[string]bool                             // device ids
	ended    map[string]bool                             // session token hashes ended by a replay
	users    map[string]*pb.User
	n        int
}

type oauthAuthRow struct {
	req                   *pb.CreateOAuthAuthorizationReq
	id                    string
	decided               pb.OAuthDecision
	userID, orgID, device string
	sessionEnd            *timestamppb.Timestamp
	codeHash              string
	codeExpires           time.Time
	codeConsumed          bool
	sessionHash           string
}

type oauthGrantRow struct {
	req       *pb.CreateOAuthGrantReq
	id        string
	revoked   bool
	reason    pb.RevokeReason
	touched   int
	expiresAt time.Time
}

type oauthRefreshRow struct {
	grantID string
	expires time.Time
	used    bool
}

type oauthAccessRow struct {
	req     *pb.IssueOAuthAccessTokenReq
	revoked bool
}

func newOAuthStore() *oauthStore {
	return &oauthStore{
		clients: map[string]*pb.OAuthClientRow{}, auths: map[string]*oauthAuthRow{}, grants: map[string]*oauthGrantRow{},
		refresh: map[string]*oauthRefreshRow{}, sessions: map[string]*pb.GetOAuthApprovingSessionResp{},
		revoked: map[string]bool{}, ended: map[string]bool{}, users: map[string]*pb.User{"u1": {Id: "u1", Email: "a@example.com"}},
	}
}

func (s *oauthStore) next(prefix string) string { s.n++; return prefix + string(rune('0'+s.n)) }

var errNoRow = status.Error(codes.NotFound, "no rows")

// ListUserOrgs: u1 belongs to org-1 (the package's tests stage every file, so
// the organization hooks of oauth_server_org.go are set).
func (s *oauthStore) ListUserOrgs(_ context.Context, in *pb.ListUserOrgsReq, _ ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	if in.GetUserId() != "u1" {
		return &pb.ListUserOrgsResp{}, nil
	}
	return &pb.ListUserOrgsResp{Orgs: []*pb.UserOrg{{OrgId: "org-1", Slug: "acme", Name: "Acme"}}}, nil
}

func (s *oauthStore) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u, ok := s.users[in.GetUserId()]
	if !ok {
		return nil, errNoRow
	}
	return &pb.GetUserByIdResp{User: u}, nil
}

func (s *oauthStore) GetOAuthClientByHash(_ context.Context, in *pb.GetOAuthClientByHashReq, _ ...grpc.CallOption) (*pb.GetOAuthClientByHashResp, error) {
	c, ok := s.clients[in.GetClientIdHash()]
	if !ok {
		return nil, errNoRow
	}
	return &pb.GetOAuthClientByHashResp{Client: proto.Clone(c).(*pb.OAuthClientRow)}, nil
}

func (s *oauthStore) CreateOAuthClient(_ context.Context, in *pb.CreateOAuthClientReq, _ ...grpc.CallOption) (*pb.CreateOAuthClientResp, error) {
	if _, dup := s.clients[in.GetClientIdHash()]; dup {
		return nil, status.Error(codes.AlreadyExists, "dup")
	}
	id := s.next("c")
	s.clients[in.GetClientIdHash()] = &pb.OAuthClientRow{
		Id: id, ClientId: in.GetClientId(), Kind: in.GetKind(), ClientName: in.GetClientName(), SoftwareId: in.GetSoftwareId(),
		ClientUri: in.GetClientUri(), LogoUri: in.GetLogoUri(), RedirectUris: in.GetRedirectUris(),
		MetadataFetchedAt: in.GetMetadataFetchedAt(),
	}
	return &pb.CreateOAuthClientResp{Id: id, CreatedAt: timestamppb.Now()}, nil
}

func (s *oauthStore) RefreshOAuthClientMetadata(_ context.Context, in *pb.RefreshOAuthClientMetadataReq, _ ...grpc.CallOption) (*pb.RefreshOAuthClientMetadataResp, error) {
	for _, c := range s.clients {
		if c.GetId() == in.GetId() {
			c.ClientName, c.RedirectUris, c.MetadataFetchedAt = in.GetClientName(), in.GetRedirectUris(), timestamppb.Now()
			return &pb.RefreshOAuthClientMetadataResp{Id: c.GetId()}, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) CreateOAuthAuthorization(_ context.Context, in *pb.CreateOAuthAuthorizationReq, _ ...grpc.CallOption) (*pb.CreateOAuthAuthorizationResp, error) {
	id := s.next("a")
	s.auths[in.GetRequestHash()] = &oauthAuthRow{req: in, id: id}
	return &pb.CreateOAuthAuthorizationResp{Id: id}, nil
}

func (s *oauthStore) clientByRow(id string) *pb.OAuthClientRow {
	for _, c := range s.clients {
		if c.GetId() == id {
			return c
		}
	}
	return nil
}

func (s *oauthStore) GetPendingOAuthAuthorization(_ context.Context, in *pb.GetPendingOAuthAuthorizationReq, _ ...grpc.CallOption) (*pb.GetPendingOAuthAuthorizationResp, error) {
	a, ok := s.auths[in.GetRequestHash()]
	if !ok || a.decided != 0 || !a.req.GetExpiresAt().AsTime().After(time.Now()) {
		return nil, errNoRow
	}
	return &pb.GetPendingOAuthAuthorizationResp{
		Id: a.id, Kind: a.req.GetKind(), RedirectUri: a.req.GetRedirectUri(), Scope: a.req.GetScope(),
		Resource: a.req.GetResource(), ExpiresAt: a.req.GetExpiresAt(), Client: s.clientByRow(a.req.GetClientRowId()),
	}, nil
}

func (s *oauthStore) GetOAuthApprovingSession(_ context.Context, in *pb.GetOAuthApprovingSessionReq, _ ...grpc.CallOption) (*pb.GetOAuthApprovingSessionResp, error) {
	got, ok := s.sessions[in.GetTokenId()]
	if !ok {
		return nil, errNoRow
	}
	return got, nil
}

func (s *oauthStore) DecideOAuthAuthorization(_ context.Context, in *pb.DecideOAuthAuthorizationReq, _ ...grpc.CallOption) (*pb.DecideOAuthAuthorizationResp, error) {
	a, ok := s.auths[in.GetRequestHash()]
	if !ok || a.decided != 0 || !a.req.GetExpiresAt().AsTime().After(time.Now()) {
		return nil, errNoRow
	}
	a.decided, a.userID, a.orgID, a.device, a.sessionEnd = in.GetDecision(), in.GetUserId(), in.GetOrgId(), in.GetApprovedByDeviceId(), in.GetSessionExpiresAt()
	a.codeHash = in.GetCodeHash()
	if in.GetCodeExpiresAt() != nil {
		a.codeExpires = in.GetCodeExpiresAt().AsTime()
	}
	return &pb.DecideOAuthAuthorizationResp{Id: a.id, RedirectUri: a.req.GetRedirectUri(), State: a.req.GetState(), Issuer: a.req.GetIssuer()}, nil
}

func (s *oauthStore) ConsumeOAuthCode(_ context.Context, in *pb.ConsumeOAuthCodeReq, _ ...grpc.CallOption) (*pb.ConsumeOAuthCodeResp, error) {
	for _, a := range s.auths {
		if a.codeHash == in.GetCodeHash() && a.codeHash != "" && !a.codeConsumed && time.Now().Before(a.codeExpires) &&
			a.decided == pb.OAuthDecision_OAUTH_DECISION_APPROVED {
			a.codeConsumed = true
			return &pb.ConsumeOAuthCodeResp{
				Id: a.id, ClientRowId: a.req.GetClientRowId(), Kind: a.req.GetKind(), RedirectUri: a.req.GetRedirectUri(),
				CodeChallenge: a.req.GetCodeChallenge(), Scope: a.req.GetScope(), Resource: a.req.GetResource(),
				UserId: a.userID, OrgId: a.orgID, ApprovedByDeviceId: a.device, SessionExpiresAt: a.sessionEnd,
			}, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) GetOAuthDeviceRevocation(_ context.Context, in *pb.GetOAuthDeviceRevocationReq, _ ...grpc.CallOption) (*pb.GetOAuthDeviceRevocationResp, error) {
	resp := &pb.GetOAuthDeviceRevocationResp{DeviceId: in.GetDeviceId()}
	if s.revoked[in.GetDeviceId()] {
		resp.RevokedAt = timestamppb.Now()
	}
	return resp, nil
}

func (s *oauthStore) CreateOAuthGrant(_ context.Context, in *pb.CreateOAuthGrantReq, _ ...grpc.CallOption) (*pb.CreateOAuthGrantResp, error) {
	id := s.next("g")
	s.grants[id] = &oauthGrantRow{req: in, id: id, expiresAt: in.GetExpiresAt().AsTime()}
	return &pb.CreateOAuthGrantResp{Id: id, UserId: in.GetUserId(), CreatedAt: timestamppb.Now()}, nil
}

func (s *oauthStore) IssueOAuthAccessToken(_ context.Context, in *pb.IssueOAuthAccessTokenReq, _ ...grpc.CallOption) (*pb.IssueOAuthAccessTokenResp, error) {
	s.access = append(s.access, &oauthAccessRow{req: in})
	return &pb.IssueOAuthAccessTokenResp{Id: s.next("t")}, nil
}

func (s *oauthStore) CreateOAuthRefreshToken(_ context.Context, in *pb.CreateOAuthRefreshTokenReq, _ ...grpc.CallOption) (*pb.CreateOAuthRefreshTokenResp, error) {
	s.refresh[in.GetTokenHash()] = &oauthRefreshRow{grantID: in.GetGrantId(), expires: in.GetExpiresAt().AsTime()}
	return &pb.CreateOAuthRefreshTokenResp{Id: s.next("r")}, nil
}

func (s *oauthStore) UseOAuthRefreshToken(_ context.Context, in *pb.UseOAuthRefreshTokenReq, _ ...grpc.CallOption) (*pb.UseOAuthRefreshTokenResp, error) {
	r, ok := s.refresh[in.GetTokenHash()]
	if !ok || r.used || !time.Now().Before(r.expires) {
		return nil, errNoRow
	}
	r.used = true
	return &pb.UseOAuthRefreshTokenResp{Id: "r", GrantId: r.grantID}, nil
}

func (s *oauthStore) GetOAuthRefreshToken(_ context.Context, in *pb.GetOAuthRefreshTokenReq, _ ...grpc.CallOption) (*pb.GetOAuthRefreshTokenResp, error) {
	r, ok := s.refresh[in.GetTokenHash()]
	if !ok {
		return nil, errNoRow
	}
	resp := &pb.GetOAuthRefreshTokenResp{Id: "r", GrantId: r.grantID, ExpiresAt: timestamppb.New(r.expires)}
	if r.used {
		resp.UsedAt = timestamppb.Now()
	}
	return resp, nil
}

func (s *oauthStore) GetOAuthGrant(_ context.Context, in *pb.GetOAuthGrantReq, _ ...grpc.CallOption) (*pb.GetOAuthGrantResp, error) {
	g, ok := s.grants[in.GetId()]
	if !ok {
		return nil, errNoRow
	}
	c := s.clientByRow(g.req.GetClientRowId())
	resp := &pb.GetOAuthGrantResp{
		Id: g.id, UserId: g.req.GetUserId(), OrgId: g.req.GetOrgId(), ClientRowId: g.req.GetClientRowId(),
		ClientId: c.GetClientId(), Resource: g.req.GetResource(), Scope: g.req.GetScope(),
		ApprovedByDeviceId: g.req.GetApprovedByDeviceId(), ExpiresAt: timestamppb.New(g.expiresAt),
		ClientDisabledAt: c.GetDisabledAt(),
	}
	if g.revoked {
		resp.RevokedAt = timestamppb.Now()
	}
	return resp, nil
}

func (s *oauthStore) GetOAuthGrantLastToken(_ context.Context, in *pb.GetOAuthGrantLastTokenReq, _ ...grpc.CallOption) (*pb.GetOAuthGrantLastTokenResp, error) {
	for i := len(s.access) - 1; i >= 0; i-- {
		if a := s.access[i]; a.req.GetGrantId() == in.GetGrantId() {
			resp := &pb.GetOAuthGrantLastTokenResp{TokenId: "t"}
			if a.revoked {
				resp.RevokedAt = timestamppb.Now()
			}
			return resp, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) GetOAuthAccessTokenGrant(_ context.Context, in *pb.GetOAuthAccessTokenGrantReq, _ ...grpc.CallOption) (*pb.GetOAuthAccessTokenGrantResp, error) {
	for _, a := range s.access {
		if a.req.GetTokenHash() == in.GetTokenHash() {
			return &pb.GetOAuthAccessTokenGrantResp{GrantId: a.req.GetGrantId()}, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) TouchOAuthGrant(_ context.Context, in *pb.TouchOAuthGrantReq, _ ...grpc.CallOption) (*pb.TouchOAuthGrantResp, error) {
	g, ok := s.grants[in.GetId()]
	if !ok || g.revoked {
		return nil, errNoRow
	}
	g.touched++
	return &pb.TouchOAuthGrantResp{Id: g.id}, nil
}

func (s *oauthStore) GetOAuthCodeUse(_ context.Context, in *pb.GetOAuthCodeUseReq, _ ...grpc.CallOption) (*pb.GetOAuthCodeUseResp, error) {
	for _, a := range s.auths {
		if a.codeHash != "" && a.codeHash == in.GetCodeHash() {
			resp := &pb.GetOAuthCodeUseResp{Id: a.id, SessionTokenHash: a.sessionHash}
			if a.codeConsumed {
				resp.CodeConsumedAt = timestamppb.Now()
			}
			return resp, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) LinkOAuthSession(_ context.Context, in *pb.LinkOAuthSessionReq, _ ...grpc.CallOption) (*pb.LinkOAuthSessionResp, error) {
	for _, a := range s.auths {
		if a.id == in.GetId() && a.sessionHash == "" {
			a.sessionHash = in.GetSessionTokenHash()
			return &pb.LinkOAuthSessionResp{Id: a.id}, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) RevokeOAuthCodeSession(_ context.Context, in *pb.RevokeOAuthCodeSessionReq, _ ...grpc.CallOption) (*pb.RevokeOAuthCodeSessionResp, error) {
	if s.ended[in.GetTokenHash()] {
		return nil, errNoRow
	}
	s.ended[in.GetTokenHash()] = true
	return &pb.RevokeOAuthCodeSessionResp{TokenId: "t-" + in.GetTokenHash()[:4], UserId: "u1"}, nil
}

func (s *oauthStore) GetOAuthGrantByAuthorization(_ context.Context, in *pb.GetOAuthGrantByAuthorizationReq, _ ...grpc.CallOption) (*pb.GetOAuthGrantByAuthorizationResp, error) {
	for _, g := range s.grants {
		if g.req.GetAuthorizationId() == in.GetAuthorizationId() {
			return &pb.GetOAuthGrantByAuthorizationResp{Id: g.id}, nil
		}
	}
	return nil, errNoRow
}

func (s *oauthStore) RevokeOAuthGrant(_ context.Context, in *pb.RevokeOAuthGrantReq, _ ...grpc.CallOption) (*pb.RevokeOAuthGrantResp, error) {
	if g, ok := s.grants[in.GetId()]; ok && !g.revoked {
		g.revoked, g.reason = true, in.GetReason()
	}
	for _, a := range s.access {
		if a.req.GetGrantId() == in.GetId() {
			a.revoked = true
		}
	}
	return &pb.RevokeOAuthGrantResp{}, nil
}

func (s *oauthStore) ListUserOAuthGrants(_ context.Context, in *pb.ListUserOAuthGrantsReq, _ ...grpc.CallOption) (*pb.ListUserOAuthGrantsResp, error) {
	resp := &pb.ListUserOAuthGrantsResp{}
	for _, g := range s.grants {
		if g.req.GetUserId() == in.GetUserId() && !g.revoked {
			resp.Grants = append(resp.Grants, &pb.OAuthGrantRow{Id: g.id, Resource: g.req.GetResource()})
		}
	}
	return resp, nil
}

// --- fixtures ---------------------------------------------------------------

const (
	testResource      = "https://mcp.example.com/mcp"
	testIssuer        = "https://auth.example.com"
	oauthTestVerifier = "a-pkce-verifier-that-is-long-enough-for-rfc-7636-xyz"
	claudeCB          = "https://claude.ai/api/mcp/auth_callback"
)

func oauthHandler() (*AuthServiceHandler, *oauthStore) {
	s := newOAuthStore()
	s.sessions["sess-1"] = &pb.GetOAuthApprovingSessionResp{TokenId: "sess-1", DeviceId: "dev-1"}
	return &AuthServiceHandler{Query: s, Mutation: s, OAuthDynamicRegistration: true}, s
}

func register(t *testing.T, h *AuthServiceHandler, redirects ...string) string {
	t.Helper()
	resp, err := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: redirects, ClientName: "Claude"})
	if err != nil || resp.GetOauthError() != "" {
		t.Fatalf("register: %v %v", err, resp)
	}
	return resp.GetClientId()
}

func beginReq(clientID, redirect string, resources ...string) *pb.BeginOAuthAuthorizationReq {
	return &pb.BeginOAuthAuthorizationReq{
		ResponseType: "code", ClientId: clientID, RedirectUri: redirect, State: "st-1",
		CodeChallenge: s256Challenge(oauthTestVerifier), CodeChallengeMethod: "S256",
		Resources: resources, Issuer: testIssuer,
	}
}

// approve runs the browser half: begin, then the user approves; it returns
// the code the redirect carries.
func approve(t *testing.T, h *AuthServiceHandler, clientID, redirect string, resources ...string) string {
	t.Helper()
	b, err := h.BeginOAuthAuthorization(context.Background(), beginReq(clientID, redirect, resources...))
	if err != nil || b.GetOauthError() != "" {
		t.Fatalf("begin: %v %v", err, b)
	}
	a, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId(), OrgId: "org-1"})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	u, _ := url.Parse(a.GetRedirectUrl())
	if u.Query().Get("state") != "st-1" || u.Query().Get("iss") != testIssuer {
		t.Fatalf("approve redirect = %s", a.GetRedirectUrl())
	}
	return u.Query().Get("code")
}

func exchange(h *AuthServiceHandler, clientID, code string) *pb.ExchangeOAuthTokenResp {
	resp, err := h.ExchangeOAuthToken(context.Background(), &pb.ExchangeOAuthTokenReq{
		GrantType: "authorization_code", ClientId: clientID, Code: code, CodeVerifier: oauthTestVerifier, RedirectUri: claudeCB,
	})
	if err != nil {
		panic(err)
	}
	return resp
}

func refreshWith(h *AuthServiceHandler, clientID, token string) *pb.ExchangeOAuthTokenResp {
	resp, err := h.ExchangeOAuthToken(context.Background(), &pb.ExchangeOAuthTokenReq{GrantType: "refresh_token", ClientId: clientID, RefreshToken: token})
	if err != nil {
		panic(err)
	}
	return resp
}

// --- the flow -----------------------------------------------------------

// The whole MCP flow: a registered client, the user's approval, the code
// exchanged for an mcp_only access token for the resource and a refresh
// token, both bound to the grant.
func TestOAuthServer_MCPFlow(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	code := approve(t, h, cid, claudeCB, testResource)
	tok := exchange(h, cid, code)
	if tok.GetOauthError() != "" || !strings.HasPrefix(tok.GetAccessToken(), mcpAccessTokenPrefix) ||
		!strings.HasPrefix(tok.GetRefreshToken(), mcpRefreshTokenPrefix) || tok.GetTokenType() != "Bearer" || tok.GetScope() != "mcp" {
		t.Fatalf("token response = %v", tok)
	}
	if tok.GetExpiresIn() < 3590 || tok.GetExpiresIn() > 3600 {
		t.Errorf("expires_in = %d, want the 1 h default", tok.GetExpiresIn())
	}
	if len(s.access) != 1 {
		t.Fatalf("access tokens = %d", len(s.access))
	}
	a := s.access[0].req
	if a.GetResource() != testResource || a.GetUserId() != "u1" || a.GetApprovedByDeviceId() != "dev-1" || a.GetTokenHash() != sha256Hex(tok.GetAccessToken()) {
		t.Errorf("access row = %v", a)
	}
	if len(s.grants) != 1 {
		t.Fatalf("grants = %d", len(s.grants))
	}
	// The code is single-use; presented again, it ends what it bought
	// (OAuth 2.1 §4.1.3).
	if again := exchange(h, cid, code); again.GetOauthError() != oauthInvalidGrant {
		t.Errorf("a spent code redeemed again: %v", again)
	}
	for _, g := range s.grants {
		if !g.revoked {
			t.Error("a replayed code left its grant live")
		}
	}
	if !s.access[0].revoked {
		t.Error("a replayed code left its access token live")
	}
}

// A replayed w17ctl login code ends the session the first redemption minted:
// a session-kind code buys no grant row, so the link on its authorization is
// what the replay follows.
func TestOAuthServer_ReplayedSessionCodeEndsTheSession(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	code := approve(t, h, cid, claudeCB, testResource)
	var auth *oauthAuthRow
	for _, a := range s.auths {
		auth = a
	}
	// What issueSessionGrant records in the exchange's transaction.
	auth.codeConsumed = true
	if _, err := s.LinkOAuthSession(context.Background(), &pb.LinkOAuthSessionReq{Id: auth.id, SessionTokenHash: sha256Hex("w17ctl-session")}); err != nil {
		t.Fatal(err)
	}
	if again := exchange(h, cid, code); again.GetOauthError() != oauthInvalidGrant {
		t.Fatalf("a spent code redeemed again: %v", again)
	}
	if !s.ended[sha256Hex("w17ctl-session")] {
		t.Error("a replayed session code left its session live")
	}
	if _, err := s.LinkOAuthSession(context.Background(), &pb.LinkOAuthSessionReq{Id: auth.id, SessionTokenHash: "other"}); err == nil {
		t.Error("an authorization took a second session")
	}
}

// A wrong verifier burns the code: it cannot be guessed at.
func TestOAuthServer_WrongVerifierBurnsTheCode(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB)
	code := approve(t, h, cid, claudeCB, testResource)
	bad, _ := h.ExchangeOAuthToken(context.Background(), &pb.ExchangeOAuthTokenReq{
		GrantType: "authorization_code", ClientId: cid, Code: code, CodeVerifier: strings.Repeat("x", 50),
	})
	if bad.GetOauthError() != oauthInvalidGrant {
		t.Fatalf("wrong verifier: %v", bad)
	}
	if good := exchange(h, cid, code); good.GetOauthError() != oauthInvalidGrant {
		t.Errorf("the code survived a wrong verifier: %v", good)
	}
}

// A code is redeemed by the client it was issued to, at its redirect, for
// its resource.
func TestOAuthServer_CodeIsBoundToClientRedirectAndResource(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB)
	other := register(t, h, "https://evil.example/cb")
	for name, req := range map[string]func(code string) *pb.ExchangeOAuthTokenReq{
		"another client": func(c string) *pb.ExchangeOAuthTokenReq {
			return &pb.ExchangeOAuthTokenReq{GrantType: "authorization_code", ClientId: other, Code: c, CodeVerifier: oauthTestVerifier}
		},
		"another redirect": func(c string) *pb.ExchangeOAuthTokenReq {
			return &pb.ExchangeOAuthTokenReq{GrantType: "authorization_code", ClientId: cid, Code: c, CodeVerifier: oauthTestVerifier, RedirectUri: "https://claude.ai/other"}
		},
		"another resource": func(c string) *pb.ExchangeOAuthTokenReq {
			return &pb.ExchangeOAuthTokenReq{GrantType: "authorization_code", ClientId: cid, Code: c, CodeVerifier: oauthTestVerifier, Resources: []string{"https://other.example/mcp"}}
		},
	} {
		code := approve(t, h, cid, claudeCB, testResource)
		resp, err := h.ExchangeOAuthToken(context.Background(), req(code))
		if err != nil || resp.GetOauthError() == "" || resp.GetAccessToken() != "" {
			t.Errorf("%s: %v %v", name, err, resp)
		}
	}
}

// The refresh token rotates; a used one presented again ends the grant and
// its access tokens.
func TestOAuthServer_RefreshRotatesAndReuseEndsTheGrant(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	first := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	second := refreshWith(h, cid, first.GetRefreshToken())
	if second.GetOauthError() != "" || second.GetRefreshToken() == first.GetRefreshToken() || second.GetAccessToken() == "" {
		t.Fatalf("refresh: %v", second)
	}
	if len(s.access) != 2 {
		t.Fatalf("access tokens after a refresh = %d", len(s.access))
	}
	reuse := refreshWith(h, cid, first.GetRefreshToken())
	if reuse.GetOauthError() != oauthInvalidGrant {
		t.Fatalf("reuse: %v", reuse)
	}
	for _, g := range s.grants {
		if !g.revoked || g.reason != pb.RevokeReason_REVOKE_REASON_REFRESH_REUSED {
			t.Errorf("grant after reuse = %+v", g)
		}
	}
	for _, a := range s.access {
		if !a.revoked {
			t.Error("an access token outlived the reused grant")
		}
	}
	if after := refreshWith(h, cid, second.GetRefreshToken()); after.GetOauthError() != oauthInvalidGrant {
		t.Errorf("the legitimate holder's newer token still refreshes a revoked grant: %v", after)
	}
}

// Every revocation that reached the grant's newest access token (sign out
// everywhere, a password change, a disabled account) ends the grant at the
// next refresh; so does the approving device's revocation.
func TestOAuthServer_RevocationsReachTheGrant(t *testing.T) {
	for name, revoke := range map[string]func(s *oauthStore){
		"the user's tokens revoked": func(s *oauthStore) { s.access[len(s.access)-1].revoked = true },
		"the approving device":      func(s *oauthStore) { s.revoked["dev-1"] = true },
		"the account disabled": func(s *oauthStore) {
			s.users["u1"].DisabledAt = timestamppb.Now()
		},
	} {
		h, s := oauthHandler()
		cid := register(t, h, claudeCB)
		first := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
		revoke(s)
		if r := refreshWith(h, cid, first.GetRefreshToken()); r.GetOauthError() != oauthInvalidGrant {
			t.Errorf("%s: refresh = %v", name, r)
		}
		for _, g := range s.grants {
			if !g.revoked {
				t.Errorf("%s: the grant was not revoked", name)
			}
		}
	}
}

// A refresh token works for the client it was issued to only.
func TestOAuthServer_RefreshByAnotherClient(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB)
	other := register(t, h, "https://other.example/cb")
	first := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	if r := refreshWith(h, other, first.GetRefreshToken()); r.GetOauthError() != oauthInvalidGrant {
		t.Errorf("another client refreshed: %v", r)
	}
}

// --- the authorization endpoint ----------------------------------------

func TestBeginOAuthAuthorization_Refusals(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB, "http://127.0.0.1/callback")
	h.OAuthResources = testResource
	cases := []struct {
		name       string
		req        *pb.BeginOAuthAuthorizationReq
		code       string
		noRedirect bool
	}{
		{"unknown client", beginReq("w17c_nope", claudeCB, testResource), oauthInvalidClient, true},
		{"unregistered redirect", beginReq(cid, "https://claude.ai/evil", testResource), oauthInvalidRequest, true},
		{"token response", func() *pb.BeginOAuthAuthorizationReq {
			r := beginReq(cid, claudeCB, testResource)
			r.ResponseType = "token"
			return r
		}(), oauthUnsupportedResponseType, false},
		{"no PKCE", func() *pb.BeginOAuthAuthorizationReq {
			r := beginReq(cid, claudeCB, testResource)
			r.CodeChallenge, r.CodeChallengeMethod = "", ""
			return r
		}(), oauthInvalidRequest, false},
		{"plain PKCE", func() *pb.BeginOAuthAuthorizationReq {
			r := beginReq(cid, claudeCB, testResource)
			r.CodeChallengeMethod = "plain"
			return r
		}(), oauthInvalidRequest, false},
		{"another scope", func() *pb.BeginOAuthAuthorizationReq {
			r := beginReq(cid, claudeCB, testResource)
			r.Scope = "admin"
			return r
		}(), oauthInvalidScope, false},
		{"no resource on the web", beginReq(cid, claudeCB), oauthInvalidTarget, false},
		{"two resources", beginReq(cid, claudeCB, testResource, "https://b.example/mcp"), oauthInvalidTarget, false},
		{"a resource not served here", beginReq(cid, claudeCB, "https://other.example/mcp"), oauthInvalidTarget, false},
		{"a fragment resource", beginReq(cid, claudeCB, testResource+"#x"), oauthInvalidTarget, false},
	}
	for _, c := range cases {
		resp, err := h.BeginOAuthAuthorization(context.Background(), c.req)
		if err != nil || resp.GetOauthError() != c.code || resp.GetNoRedirect() != c.noRedirect || resp.GetRequestId() != "" {
			t.Errorf("%s: %v %v", c.name, err, resp)
		}
	}
	// No resource on a loopback redirect is a session grant — for w17ctl
	// only; any other client is told a resource is required.
	r := beginReq(cid, "http://127.0.0.1:49152/callback")
	if resp, _ := h.BeginOAuthAuthorization(context.Background(), r); resp.GetOauthError() != oauthInvalidTarget {
		t.Errorf("a session grant offered to a client that is not w17ctl: %v", resp)
	}
	w, err := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: []string{"http://127.0.0.1/callback"}, ClientName: "w17ctl", SoftwareId: "w17ctl"})
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(w.GetClientId(), "http://127.0.0.1:49152/callback")); resp.GetRequestId() == "" {
		t.Errorf("w17ctl's session grant refused: %v", resp)
	}
	// A resource is compared normalised: host case, default port, trailing
	// slash.
	h.OAuthResources = testResource
	if resp, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, "http://127.0.0.1:49152/callback", "https://MCP.example.com:443/mcp/")); resp.GetRequestId() == "" {
		t.Errorf("a differently spelled resource refused: %v", resp)
	}
}

// --- the consent page ----------------------------------------------------

func TestConsent_ShowsTheRequestAndNeedsASession(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB)
	b, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, claudeCB, testResource))
	got, err := h.GetOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.GetOAuthAuthorizationReq{RequestId: b.GetRequestId()})
	if err != nil || len(got.GetOrgs()) != 1 || got.GetOrgs()[0].GetSlug() != "acme" || got.GetClientName() != "Claude" || got.GetRedirectHost() != "claude.ai" || got.GetResource() != testResource ||
		got.GetKind() != pb.OAuthGrantKind_OAUTH_GRANT_KIND_MCP {
		t.Fatalf("consent = %v %v", err, got)
	}
	// An API or MCP token is not a session: it may not approve.
	if _, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", ""), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("approve without a session: %v", err)
	}
	// An unknown request id.
	if _, err := h.GetOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.GetOAuthAuthorizationReq{RequestId: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown request: %v", err)
	}
}

// A request is decided once; a denial tells the client access_denied.
func TestConsent_DecidedOnce(t *testing.T) {
	h, _ := oauthHandler()
	cid := register(t, h, claudeCB)
	b, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, claudeCB, testResource))
	d, err := h.DenyOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.DenyOAuthAuthorizationReq{RequestId: b.GetRequestId()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(d.GetRedirectUrl())
	if u.Query().Get("error") != "access_denied" || u.Query().Get("state") != "st-1" || u.Query().Get("code") != "" {
		t.Errorf("deny redirect = %s", d.GetRedirectUrl())
	}
	if _, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId()}); status.Code(err) != codes.NotFound {
		t.Errorf("approve after deny: %v", err)
	}
}

// With organizations the user names one of theirs; the grant and its tokens
// carry it.
func TestConsent_OrganizationIsChosenAndChecked(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	b, _ := h.BeginOAuthAuthorization(context.Background(), beginReq(cid, claudeCB, testResource))
	if _, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId(), OrgId: "org-2"}); err == nil {
		t.Fatal("another organization was accepted")
	}
	a, err := h.ApproveOAuthAuthorization(sessionCallerCtx("u1", "sess-1"), &pb.ApproveOAuthAuthorizationReq{RequestId: b.GetRequestId(), OrgId: "org-1"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(a.GetRedirectUrl())
	exchange(h, cid, u.Query().Get("code"))
	if len(s.access) != 1 || s.access[0].req.GetOrgId() != "org-1" {
		t.Errorf("the token does not carry the organization: %v", s.access)
	}
}

// --- connected apps ------------------------------------------------------

func TestConnectedApps_RevokeOwnOnly(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	list, err := h.ListMyOAuthGrants(sessionCallerCtx("u1", "sess-1"), &pb.ListMyOAuthGrantsReq{})
	if err != nil || len(list.GetGrants()) != 1 {
		t.Fatalf("list = %v %v", err, list)
	}
	id := list.GetGrants()[0].GetId()
	if _, err := h.RevokeMyOAuthGrant(sessionCallerCtx("u2", "sess-2"), &pb.RevokeMyOAuthGrantReq{GrantId: id}); status.Code(err) != codes.NotFound {
		t.Errorf("another user revoked it: %v", err)
	}
	if _, err := h.RevokeMyOAuthGrant(sessionCallerCtx("u1", "sess-1"), &pb.RevokeMyOAuthGrantReq{GrantId: id}); err != nil {
		t.Fatal(err)
	}
	if !s.grants[id].revoked || !s.access[0].revoked {
		t.Error("the grant or its token outlived the revocation")
	}
}

// The revocation endpoint ends the grant behind an access or a refresh
// token, and says nothing about an unknown token or another client's.
func TestRevokeOAuthToken(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	tok := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	if _, err := h.RevokeOAuthToken(context.Background(), &pb.RevokeOAuthTokenReq{Token: "unknown"}); err != nil {
		t.Errorf("unknown token: %v", err)
	}
	if _, err := h.RevokeOAuthToken(context.Background(), &pb.RevokeOAuthTokenReq{Token: tok.GetAccessToken(), ClientId: "w17c_other"}); err != nil {
		t.Fatal(err)
	}
	for _, g := range s.grants {
		if g.revoked {
			t.Fatal("another client revoked the grant")
		}
	}
	if _, err := h.RevokeOAuthToken(context.Background(), &pb.RevokeOAuthTokenReq{Token: tok.GetRefreshToken(), TokenTypeHint: "refresh_token", ClientId: cid}); err != nil {
		t.Fatal(err)
	}
	for _, g := range s.grants {
		if !g.revoked {
			t.Error("the grant outlived its refresh token's revocation")
		}
	}
}

// --- clients -------------------------------------------------------------

func TestRegisterOAuthClient_Rules(t *testing.T) {
	h, _ := oauthHandler()
	h.OAuthRedirectHosts = "claude.ai"
	for name, uris := range map[string][]string{
		"none":        nil,
		"http":        {"http://claude.ai/cb"},
		"javascript":  {"javascript:alert(1)"},
		"file":        {"file:///etc/passwd"},
		"fragment":    {"https://claude.ai/cb#x"},
		"other host":  {"https://evil.example/cb"},
		"credentials": {"https://u:p@claude.ai/cb"},
	} {
		resp, err := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: uris})
		if err != nil || resp.GetOauthError() == "" || resp.GetClientId() != "" {
			t.Errorf("%s: %v %v", name, err, resp)
		}
	}
	if resp, _ := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: []string{"http://localhost:1234/cb"}}); resp.GetClientId() == "" {
		t.Errorf("loopback refused under a host allowlist: %v", resp)
	}
	// A native app's private-use scheme (RFC 8252 §7.1) — Cursor's.
	if resp, _ := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: []string{"cursor://anysphere.cursor-mcp/oauth/callback"}}); resp.GetClientId() == "" {
		t.Errorf("a private-use scheme refused: %v", resp)
	}
	if got := (&AuthServiceHandler{}).redirectHost("cursor://anysphere.cursor-mcp/oauth/callback"); got != "the cursor app on this device" {
		t.Errorf("redirectHost = %q", got)
	}
	h.OAuthDynamicRegistration = false
	if resp, _ := h.RegisterOAuthClient(context.Background(), &pb.RegisterOAuthClientReq{RedirectUris: []string{claudeCB}}); resp.GetOauthError() == "" {
		t.Error("registration while closed")
	}
}

// A metadata-document client is read once, kept a day, and must name
// itself.
func TestResolveOAuthClient_CIMD(t *testing.T) {
	h, s := oauthHandler()
	const cimd = "https://claude.ai/oauth/claude-code-client-metadata"
	fetches := 0
	doc := map[string]any{"client_id": cimd, "client_name": "Claude Code", "redirect_uris": []string{"http://localhost/callback"}}
	defer func(f func(context.Context, string) ([]byte, error)) { fetchClientMetadata = f }(fetchClientMetadata)
	fetchClientMetadata = func(_ context.Context, u string) ([]byte, error) {
		fetches++
		if u != cimd {
			return nil, errors.New("unexpected URL")
		}
		return json.Marshal(doc)
	}
	c, err := h.resolveOAuthClient(context.Background(), cimd, "")
	if err != nil || c.GetClientName() != "Claude Code" || c.GetKind() != pb.OAuthClientKind_OAUTH_CLIENT_KIND_CIMD {
		t.Fatalf("first: %v %v", err, c)
	}
	if _, err := h.resolveOAuthClient(context.Background(), cimd, ""); err != nil || fetches != 1 {
		t.Errorf("second read: %v, fetches %d (want 1: kept a day)", err, fetches)
	}
	// A day later the document is read again; if it does not answer the
	// known client keeps working for a while.
	for _, row := range s.clients {
		row.MetadataFetchedAt = timestamppb.New(time.Now().Add(-25 * time.Hour))
	}
	fetchClientMetadata = func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
	if _, err := h.resolveOAuthClient(context.Background(), cimd, ""); err != nil {
		t.Errorf("stale client while the host is down: %v", err)
	}
	// A document naming another client is refused.
	const other = "https://evil.example/client.json"
	fetchClientMetadata = func(context.Context, string) ([]byte, error) { return json.Marshal(doc) }
	if _, err := h.resolveOAuthClient(context.Background(), other, ""); err == nil {
		t.Error("a document naming another client_id was accepted")
	}
	// An unknown document that cannot be read is invalid_client, not a
	// failure.
	fetchClientMetadata = func(context.Context, string) ([]byte, error) { return nil, errors.New("down") }
	_, err = h.resolveOAuthClient(context.Background(), "https://new.example/client.json", "")
	if oe, ok := asOAuthError(err); !ok || oe.code != oauthInvalidClient {
		t.Errorf("unreadable new document: %v", err)
	}
}

func TestRedirectRegistered(t *testing.T) {
	reg := claudeCB + "\nhttp://127.0.0.1/callback"
	for uri, want := range map[string]bool{
		claudeCB:       true,
		claudeCB + "/": false,
		"https://claude.ai.evil/api/mcp/auth_callback": false,
		"http://127.0.0.1:5555/callback":               true,
		"http://127.0.0.1:5555/other":                  false,
		"http://localhost:5555/callback":               false,
		"":                                             false,
	} {
		if got := redirectRegistered(reg, uri); got != want {
			t.Errorf("%q: %v, want %v", uri, got, want)
		}
	}
}

// --- Authenticate --------------------------------------------------------

// An MCP token works on the resource it was issued for only.
func TestCheckMCPToken_Resource(t *testing.T) {
	p := &authPrincipal{mcpOnly: true, oauthResource: testResource}
	if err := checkMCPToken(p, testResource); err != nil {
		t.Errorf("own resource: %v", err)
	}
	for _, served := range []string{"", "https://other.example/mcp"} {
		if err := checkMCPToken(p, served); err == nil {
			t.Errorf("served %q accepted a token for %s", served, testResource)
		}
	}
	if err := checkMCPToken(&authPrincipal{mcpOnly: true}, testResource); err == nil {
		t.Error("a protected resource accepted an mcp_only token issued for none")
	}
	if err := checkMCPToken(&authPrincipal{mcpOnly: true}, ""); err != nil {
		t.Errorf("a surface naming no resource refused a token for none: %v", err)
	}
	if err := checkMCPToken(&authPrincipal{oauthResource: testResource}, testResource); err == nil {
		t.Error("a token that is not mcp_only passed")
	}
}

func TestCheckOAuthServerConfig(t *testing.T) {
	for _, h := range []*AuthServiceHandler{
		{OAuthRedirectHosts: "https://claude.ai"},
		{OAuthRedirectHosts: "claude.ai/x"},
		{OAuthResources: "mcp.example.com"},
		{OAuthResources: "http://mcp.example.com/mcp"},
	} {
		if err := checkOAuthServerConfig(h); err == nil {
			t.Errorf("accepted %+v", h)
		}
	}
	if err := checkOAuthServerConfig(&AuthServiceHandler{OAuthRedirectHosts: "claude.ai, cursor.com", OAuthResources: testResource + " http://localhost:8081/mcp"}); err != nil {
		t.Error(err)
	}
}

// A refresh that fails on the store spends nothing: the client's retry is
// not a reuse, and the grant stays.
func TestOAuthServer_RefreshFailureIsNotAReuse(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	first := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	flaky := &flakyRefreshStore{oauthStore: s, failures: 1}
	h.Query, h.Mutation = flaky, flaky
	if _, err := h.ExchangeOAuthToken(context.Background(), &pb.ExchangeOAuthTokenReq{GrantType: "refresh_token", ClientId: cid, RefreshToken: first.GetRefreshToken()}); status.Code(err) != codes.Unavailable {
		t.Fatalf("the failing refresh: %v", err)
	}
	// Without a coordinator the test store cannot roll back; restore the
	// spend as the transaction would have.
	for _, r := range s.refresh {
		r.used = false
	}
	if r := refreshWith(h, cid, first.GetRefreshToken()); r.GetOauthError() != "" || r.GetAccessToken() == "" {
		t.Fatalf("the retry: %v", r)
	}
	for _, g := range s.grants {
		if g.revoked {
			t.Error("a store failure ended the grant")
		}
	}
}

// flakyRefreshStore fails the account read of a refresh once.
type flakyRefreshStore struct {
	*oauthStore
	failures int
}

func (f *flakyRefreshStore) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, o ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	if f.failures > 0 {
		f.failures--
		return nil, status.Error(codes.Unavailable, "db down")
	}
	return f.oauthStore.GetUserById(ctx, in, o...)
}

// A grant revoked while a refresh runs yields no token: the refresh holds
// the live row first.
func TestOAuthServer_RefreshOfARevokedGrantMintsNothing(t *testing.T) {
	h, s := oauthHandler()
	cid := register(t, h, claudeCB)
	first := exchange(h, cid, approve(t, h, cid, claudeCB, testResource))
	for _, g := range s.grants {
		g.revoked = true
	}
	n := len(s.access)
	if r := refreshWith(h, cid, first.GetRefreshToken()); r.GetOauthError() != oauthInvalidGrant || len(s.access) != n {
		t.Errorf("refresh of a revoked grant: %v, %d new tokens", r, len(s.access)-n)
	}
}
