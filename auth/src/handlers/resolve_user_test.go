package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// resolveUserMock is one account and the session-realm roles it holds, and
// the role catalogue the ceiling reads.
type resolveUserMock struct {
	roleCatalogueMock

	user      *pb.User
	grants    []*pb.RoleGrant // the account's session-realm roles
	realmsAsk []pb.TokenType
}

func (m *resolveUserMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	if m.user == nil || in.GetUserId() != m.user.GetId() {
		return nil, status.Error(codes.NotFound, "AuthQuery.GetUserById: not found")
	}
	return &pb.GetUserByIdResp{User: m.user}, nil
}

func (m *resolveUserMock) GetUserRoleGrants(_ context.Context, _ *pb.GetUserRoleGrantsReq, _ ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{Grants: m.grants}, nil
}

func (m *resolveUserMock) GetUserRolePermissionsByRealm(_ context.Context, in *pb.GetUserRolePermissionsByRealmReq, _ ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	m.realmsAsk = append(m.realmsAsk, in.GetTokenType())
	if in.GetTokenType() != pb.TokenType_TOKEN_TYPE_SESSION {
		return &pb.GetUserRolePermissionsByRealmResp{}, nil
	}
	return &pb.GetUserRolePermissionsByRealmResp{Grants: m.grants}, nil
}

// noFeatureSeams runs the test with no decorator or narrower staged but the
// ones it installs, restoring the package's afterwards.
func noFeatureSeams(t *testing.T, decorators ...scopeDecorator) {
	t.Helper()
	prevDec, prevNarrow, prevEnrich := scopeDecorators, grantNarrowers, authRespEnrichers
	t.Cleanup(func() { scopeDecorators, grantNarrowers, authRespEnrichers = prevDec, prevNarrow, prevEnrich })
	scopeDecorators, grantNarrowers, authRespEnrichers = decorators, nil, nil
}

// A person is answered with what their session would hold — a wildcard role
// expanded from the deployed lock, as Authenticate expands it — and only the
// session realm is read: an API or MCP token's roles need the token.
func TestResolveUser_AnswersWhatTheirSessionHolds(t *testing.T) {
	noFeatureSeams(t)
	m := &resolveUserMock{
		user:   &pb.User{Id: "u1", Email: "u1@example.com"},
		grants: []*pb.RoleGrant{{RoleId: "r-admin", AllPermissions: true}},
	}
	lock := &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3}}
	h := &AuthServiceHandler{Query: m, Lock: lock}

	who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u1"})
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if who.GetUserId() != "u1" || who.GetScopes()["user_id"] != "u1" {
		t.Errorf("answered user %q, scopes %v; want u1 in both", who.GetUserId(), who.GetScopes())
	}
	if got := len(who.GetPermissionIds()); got != 3 {
		t.Errorf("permission_ids = %v, want the whole lock (3)", who.GetPermissionIds())
	}
	if !who.GetActedFor() {
		t.Error("the answer does not say it was resolved without a credential (acted_for)")
	}
	if who.GetSessionTokenId() != "" || who.GetDeviceId() != "" {
		t.Errorf("answered a session %q / device %q for a person who presented none", who.GetSessionTokenId(), who.GetDeviceId())
	}
	for _, realm := range m.realmsAsk {
		if realm != pb.TokenType_TOKEN_TYPE_SESSION {
			t.Errorf("read the %v realm's roles; only the session's count", realm)
		}
	}
}

// The organization is the one the request's headers select. An incoming
// `w17-org` — whatever the caller's caller forwarded — is not read.
func TestResolveUser_TheOrganizationComesFromTheRequest(t *testing.T) {
	var sawHeader, sawIncoming string
	noFeatureSeams(t, func(ctx context.Context, _ *AuthServiceHandler, _ string, headers, scopes, _ map[string]string) error {
		sawHeader, sawIncoming = orgSlugFromHeaders(headers), orgSlugFromContext(ctx)
		scopes["org_id"] = "org-" + sawHeader
		return nil
	})
	m := &resolveUserMock{user: &pb.User{Id: "u1"}}
	h := &AuthServiceHandler{Query: m, Lock: &acllock.Lock{Version: 1}}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(principal.OrgScopeHeader, "forwarded", "x-request-id", "r1"))
	who, err := h.ResolveUser(ctx, &pb.ResolveUserReq{UserId: "u1", Headers: map[string]string{principal.OrgScopeHeader: "acme"}})
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if sawHeader != "acme" || who.GetScopes()["org_id"] != "org-acme" {
		t.Errorf("selector %q, org scope %q; want acme / org-acme", sawHeader, who.GetScopes()["org_id"])
	}
	if sawIncoming != "" {
		t.Errorf("the incoming w17-org %q reached the decorator", sawIncoming)
	}
}

func TestResolveUser_Refuses(t *testing.T) {
	noFeatureSeams(t)
	m := &resolveUserMock{user: &pb.User{Id: "u-off", DisabledAt: timestamppb.Now()}}
	h := &AuthServiceHandler{Query: m, Lock: &acllock.Lock{Version: 1}}

	for _, c := range []struct {
		name string
		id   string
		want codes.Code
	}{
		{"nobody named", "", codes.InvalidArgument},
		{"an unknown person", "u-ghost", codes.NotFound},
	} {
		if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: c.id}); status.Code(err) != c.want {
			t.Errorf("%s: code = %v, want %v (err=%v)", c.name, status.Code(err), c.want, err)
		}
	}
	if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "u-off"}); err == nil {
		t.Error("a disabled account was answered")
	}
}

// The case it exists for: code acting for a person stamps their answer as the
// envelope (principal.ActAs) and the role ceiling judges what they hold. With
// a bare user id stamped instead, they held nothing and could grant no role
// that carries a permission.
func TestResolveUser_TheCeilingJudgesThePersonActedFor(t *testing.T) {
	noFeatureSeams(t)
	m := &resolveUserMock{
		user:   &pb.User{Id: "adviser"},
		grants: []*pb.RoleGrant{{RoleId: "r-worker", PermissionIds: []int32{1, 2}}},
	}
	m.roleCatalogueMock = *newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-worker": {1, 2}, "r-viewer": {1}}
	h := &AuthServiceHandler{Query: m, Lock: &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3}}}

	who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: "adviser"})
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	acting := withEnvelope(t, who)
	if _, err := h.checkMayGrantRole(acting, "r-viewer"); err != nil {
		t.Errorf("a role inside what the person holds was refused: %v", err)
	}
	if _, err := h.checkMayGrantRole(acting, "r-admin"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a role above what the person holds: code = %v, want PermissionDenied", status.Code(err))
	}

	bare := withEnvelope(t, &pb.AuthResp{UserId: "adviser"})
	if _, err := h.checkMayGrantRole(bare, "r-viewer"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("control: a bare user id granted a role that carries a permission (code %v)", status.Code(err))
	}
}

// withEnvelope is the incoming side of principal.ActAs: the whole AuthResp as
// the x-w17-user envelope.
func withEnvelope(t *testing.T, who *pb.AuthResp) context.Context {
	t.Helper()
	raw, err := proto.Marshal(who)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(userMetadataKey, base64.StdEncoding.EncodeToString(raw)))
}

// Under an organization's lock the ceiling re-reads the caller's grants in
// the realm their envelope names: a session's roles for a session, the token
// realms' otherwise. ResolveUser names no session token — there is none — so
// without acted_for the person was read as a token, held none of their
// session's roles there, and could hand out nothing (live: product-roles-proof,
// an organization's member refused the member role she holds).
func TestResolveUser_UnderTheOrganizationsLockThePersonIsTheirSession(t *testing.T) {
	member := &pb.RoleGrant{RoleId: "r-member", PermissionIds: []int32{1}}
	s := &callerGrantsStore{
		org: []*pb.RoleGrant{member},
		byRealm: map[pb.TokenType][]*pb.RoleGrant{
			pb.TokenType_TOKEN_TYPE_SESSION: {member},
			pb.TokenType_TOKEN_TYPE_API:     nil,
			pb.TokenType_TOKEN_TYPE_MCP:     nil,
		},
	}
	h := &AuthServiceHandler{Query: s}
	held := map[int32]bool{1: true}
	locked := func(who *pb.AuthResp) context.Context {
		return context.WithValue(inOrg(withEnvelope(t, who), "org-1"), orgLockKey{}, "org-1")
	}

	got, err := heldUnderOrgLock(locked(&pb.AuthResp{UserId: "u1", PermissionIds: []int32{1}, ActedFor: true}), h, held)
	if err != nil || !got[1] {
		t.Errorf("acted for: held %v (%v); want the member role's permission kept", got, err)
	}
	got, _ = heldUnderOrgLock(locked(&pb.AuthResp{UserId: "u1", PermissionIds: []int32{1}}), h, held)
	if got[1] {
		t.Errorf("control: an envelope naming neither a session nor acted_for kept a session-realm role (%v)", got)
	}
}
