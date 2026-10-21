package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// kindsMock is orgMock plus the per-grant kinds ListUserRoleKinds answers.
type kindsMock struct {
	orgMock
	roleKinds map[string][]*pb.UserRoleKind // key "user|org"
}

func (m *kindsMock) ListUserRoleKinds(_ context.Context, in *pb.ListUserRoleKindsReq, _ ...grpc.CallOption) (*pb.ListUserRoleKindsResp, error) {
	return &pb.ListUserRoleKindsResp{Roles: m.roleKinds[in.GetUserId()+"|"+in.GetOrgId()]}, nil
}

// u1 is staff of acme and a client of acme and of beta; u2 is a client of
// nothing.
func kindsHandler() *AuthServiceHandler {
	m := &kindsMock{orgMock: orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"u1": {
			{OrgId: "org-acme", Slug: "acme", MembershipKind: "staff"},
			{OrgId: "org-acme", Slug: "acme", MembershipKind: "client"},
			{OrgId: "org-beta", Slug: "beta", MembershipKind: "client"},
		},
		"u2": {{OrgId: "org-acme", Slug: "acme", MembershipKind: "staff"}},
	}}}
	m.roleKinds = map[string][]*pb.UserRoleKind{
		"u1|org-acme": {
			{RoleId: "r-staff", MembershipKind: "staff"},
			{RoleId: "r-client", MembershipKind: "client"},
			{RoleId: "r-any", MembershipKind: ""},
		},
	}
	return &AuthServiceHandler{Query: m}
}

func admits(kinds string) map[string]string {
	return map[string]string{membershipKindsHeader: kinds}
}

func wantNotAdmitted(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied (403 before any handler)", err)
	}
}

func TestResolveOrgScopeByKind(t *testing.T) {
	h := kindsHandler()

	t.Run("the slug resolves through an admitted membership", func(t *testing.T) {
		sc, lb := map[string]string{}, map[string]string{}
		hd := admits("client")
		hd[orgScopeMetadataKey] = "beta"
		if err := resolveOrgScope(context.Background(), h, "u1", hd, sc, lb); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-beta" || lb["org_id"] != "org-beta" {
			t.Errorf("scopes %v labels %v, want org-beta", sc, lb)
		}
	})

	t.Run("a membership of another kind in the named org is 403, not 'not a member'", func(t *testing.T) {
		hd := admits("partner")
		hd[orgScopeMetadataKey] = "acme"
		wantNotAdmitted(t, resolveOrgScope(context.Background(), h, "u1", hd, map[string]string{}, map[string]string{}))
	})

	t.Run("no selector: the one admitted organization", func(t *testing.T) {
		sc := map[string]string{}
		if err := resolveOrgScope(context.Background(), h, "u1", admits("staff"), sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-acme" {
			t.Errorf("org_id = %q, want org-acme — u1's only staff membership", sc["org_id"])
		}
	})

	t.Run("no selector and several admitted: ambiguous, no scope", func(t *testing.T) {
		sc := map[string]string{}
		if err := resolveOrgScope(context.Background(), h, "u1", admits("client"), sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := sc["org_id"]; ok {
			t.Errorf("stamped %q though u1 is a client of two organizations", sc["org_id"])
		}
	})

	t.Run("no admitted membership at all is 403", func(t *testing.T) {
		wantNotAdmitted(t, resolveOrgScope(context.Background(), h, "u2", admits("client"), map[string]string{}, map[string]string{}))
	})

	t.Run("a gateway that names no kinds resolves as before", func(t *testing.T) {
		m := &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{"u1|acme": {OrgId: "org-acme"}}}
		sc := map[string]string{}
		hd := map[string]string{orgScopeMetadataKey: "acme"}
		if err := resolveOrgScope(context.Background(), &AuthServiceHandler{Query: m}, "u1", hd, sc, map[string]string{}); err != nil {
			t.Fatal(err)
		}
		if sc["org_id"] != "org-acme" {
			t.Errorf("org_id = %q", sc["org_id"])
		}
	})
}

func TestNarrowGrantsToAdmittedKinds(t *testing.T) {
	h := kindsHandler()
	grants := func() []*pb.RoleGrant {
		return []*pb.RoleGrant{{RoleId: "r-staff"}, {RoleId: "r-client"}, {RoleId: "r-any"}, {RoleId: "r-realm"}}
	}
	ids := func(gs []*pb.RoleGrant) map[string]bool {
		out := map[string]bool{}
		for _, g := range gs {
			out[g.GetRoleId()] = true
		}
		return out
	}

	p := &authPrincipal{userID: "u1", grants: grants()}
	ctx := context.WithValue(context.Background(), authHeadersKey{}, admits("client"))
	if err := narrowGrantsToAdmittedKinds(ctx, h, p, map[string]string{"org_id": "org-acme"}); err != nil {
		t.Fatal(err)
	}
	got := ids(p.grants)
	// The client's role counts; the staff role does not — u1 is staff of the
	// same organization, but came through the client's gateway. A grant of no
	// kind and a realm-wide one belong to no membership and stay.
	if got["r-staff"] || !got["r-client"] || !got["r-any"] || !got["r-realm"] {
		t.Errorf("survivors = %v, want r-client r-any r-realm", got)
	}

	p = &authPrincipal{userID: "u1", grants: grants()}
	if err := narrowGrantsToAdmittedKinds(context.Background(), h, p, map[string]string{"org_id": "org-acme"}); err != nil {
		t.Fatal(err)
	}
	if len(p.grants) != 4 {
		t.Errorf("a gateway naming no kinds narrowed the grants to %v", ids(p.grants))
	}
}

// Ownership is root authority its staff exercise: through an audience that
// admits only some kinds, it does not widen.
func TestOwnershipDoesNotWidenThroughAKindFilter(t *testing.T) {
	q := &ownsMock{owner: true}
	p := &authPrincipal{userID: "u1", realm: pb.TokenType_TOKEN_TYPE_SESSION}
	ctx := context.WithValue(context.Background(), authHeadersKey{}, admits("client"))
	if err := narrowGrantsToActiveOrg(ctx, &AuthServiceHandler{Query: q}, p, map[string]string{"org_id": "org-acme"}); err != nil {
		t.Fatal(err)
	}
	for _, g := range p.grants {
		if g.GetAllPermissions() {
			t.Fatal("an owner reached the client's surface with the owner's wildcard")
		}
	}
}

// ownsMock answers the queries narrowGrantsToActiveOrg makes.
type ownsMock struct {
	pb.AuthQueryClient
	owner bool
}

func (m *ownsMock) GetUserOrgPermissions(context.Context, *pb.GetUserOrgPermissionsReq, ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	return &pb.GetUserOrgPermissionsResp{}, nil
}

func (m *ownsMock) GetUserOwnsOrg(context.Context, *pb.GetUserOwnsOrgReq, ...grpc.CallOption) (*pb.GetUserOwnsOrgResp, error) {
	return &pb.GetUserOwnsOrgResp{Owner: m.owner}, nil
}

// The refusal survives Authenticate's folding of decorator errors into the
// opaque Unauthenticated: an admitted credential at the wrong door is 403.
func TestNotAdmittedSurvivesTheDecoratorFold(t *testing.T) {
	prev := scopeDecorators
	defer func() { scopeDecorators = prev }()
	scopeDecorators = []scopeDecorator{func(ctx context.Context, _ *AuthServiceHandler, _ string, _, _, _ map[string]string) error {
		return membershipNotAdmitted(ctx)
	}}
	err := runScopeDecorators(context.Background(), nil, "u1", nil, map[string]string{}, map[string]string{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v (%s), want PermissionDenied", err, status.Code(err))
	}
}
