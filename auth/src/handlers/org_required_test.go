package handlers

import (
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// A request naming no organization from a member of several is narrowed to
// the realm-wide roles — and, so the gateway can answer "name one"
// (ORGANIZATION_REQUIRED) instead of "no access" (MISSING_PERMISSION), says
// what it set aside: the permissions of the roles held inside organizations.
// These are the four answers the gateway tells apart, at the half that decides
// them here.

// memoCtx is a request context the way principalResp builds it: a memo the
// decorators and narrowers share.
func memoCtx(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestMemoKey{}, map[string]any{})
}

func twoOrgHandler() *AuthServiceHandler {
	return &AuthServiceHandler{Query: &orgMock{
		orgsByUser: map[string][]*pb.UserOrg{
			"multi": {{OrgId: "org-a", Slug: "a"}, {OrgId: "org-b", Slug: "b"}},
			"one":   {{OrgId: "org-a", Slug: "a"}},
		},
		bySlug: map[string]*pb.GetUserOrgBySlugResp{"multi|a": {OrgId: "org-a"}},
	}}
}

func TestResolveOrgScope_MarksTheUnnamedOrganization(t *testing.T) {
	for _, c := range []struct {
		name    string
		user    string
		slug    string
		headers map[string]string
		noSole  bool
		want    bool
	}{
		{"a member of two, naming none", "multi", "", nil, false, true},
		{"a member of two, naming one", "multi", "a", nil, false, false},
		{"a member of one, inferred", "one", "", nil, false, false},
		{"a member of one where nothing is inferred", "one", "", nil, true, true},
		// No membership: nothing set aside, nothing to name. The narrower
		// finds no org-held role, so the mark alone says nothing.
		{"a member of none", "nobody", "", nil, false, true},
		// An audience that takes no selector: naming one would be refused,
		// so there is nothing to tell the caller to do.
		{"an audience without DEFAULT", "multi", "", map[string]string{tenantFromHeader: tenantFromHost}, false, false},
		{"an audience with DEFAULT", "multi", "", map[string]string{tenantFromHeader: tenantFromHost + "," + tenantFromDefault}, false, true},
	} {
		h := twoOrgHandler()
		h.NoOrgFromSoleMembership = c.noSole
		ctx := memoCtx(ctxWithOrg(c.slug))
		if err := resolveOrgScope(ctx, h, c.user, c.headers, map[string]string{}, map[string]string{}); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if _, got := orgUnnamed(ctx); got != c.want {
			t.Errorf("%s: marked unnamed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNarrowGrants_SaysWhatAnUnnamedOrganizationSetAside(t *testing.T) {
	unnamed := func() context.Context {
		ctx := memoCtx(context.Background())
		requestMemoOf(ctx)[orgUnnamedMemo] = orgUnnamedMark{anyOrg: true}
		return ctx
	}
	for _, c := range []struct {
		name  string
		ctx   context.Context
		org   string
		prin  *authPrincipal
		realm []*pb.RoleGrant
		inOrg []*pb.RoleGrant
		want  string
	}{
		{"two organizations, none named", unnamed(), "", sessionPrincipal(grant("realm", 1), grant("operator", 9, 5, 9)), []*pb.RoleGrant{grant("realm", 1)}, nil, "5,9"},
		{"an organization's wildcard set aside", unnamed(), "", sessionPrincipal(&pb.RoleGrant{RoleId: "owner", AllPermissions: true}), nil, nil, "*"},
		{"only realm-wide roles", unnamed(), "", sessionPrincipal(grant("realm", 1)), []*pb.RoleGrant{grant("realm", 1)}, nil, ""},
		// Not marked: the resolution did not find a request that could have
		// named one (an admin plane, an audience taking no selector).
		{"not marked", memoCtx(context.Background()), "", sessionPrincipal(grant("operator", 9)), nil, nil, ""},
		{"an organization named", unnamed(), "org-a", sessionPrincipal(grant("operator", 9)), nil, []*pb.RoleGrant{grant("operator", 9)}, ""},
	} {
		m := &permMock{realmGrants: c.realm, orgGrants: c.inOrg}
		h := &AuthServiceHandler{Query: m}
		scopes := map[string]string{}
		if c.org != "" {
			scopes["org_id"] = c.org
		}
		if err := narrowGrantsToActiveOrg(c.ctx, h, c.prin, scopes); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := scopes[orgPermissionsScope]; got != c.want {
			t.Errorf("%s: org_permissions %q, want %q", c.name, got, c.want)
		}
		// The hint adds no permission: what the request holds is still the
		// realm-wide set alone.
		for _, id := range c.prin.effectivePermissions(h.Lock) {
			if id == 5 || id == 9 {
				if c.org == "" {
					t.Errorf("%s: the set-aside permission %d survived the narrowing", c.name, id)
				}
			}
		}
	}
}

// A product is told ITS codes held inside organizations — never the identity's
// ids, which mean nothing against its lock.
func TestAnswerProductRoles_SaysWhatAnUnnamedOrganizationSetAside(t *testing.T) {
	h, m := prodHandler(t)
	m.grants = append(m.grants,
		&pb.ProductRoleGrantRow{Id: "g-2", UserId: "alice", OrgId: "org-b", Product: "alpha", RoleKey: "viewer"},
		&pb.ProductRoleGrantRow{Id: "g-3", UserId: "alice", Product: "alpha", RoleKey: "auditor"}, // realm-wide
	)
	run := func(orgID string, mark bool) *pb.AuthResp {
		t.Helper()
		ctx := context.WithValue(privateCallerCtx("alpha"), authHeadersKey{}, map[string]string{productHeader: "alpha"})
		ctx = memoCtx(ctx)
		if mark {
			requestMemoOf(ctx)[orgUnnamedMemo] = orgUnnamedMark{anyOrg: true}
		}
		resp := &pb.AuthResp{Scopes: map[string]string{"user_id": "alice", orgPermissionsScope: "1,2"}}
		if orgID != "" {
			resp.Scopes["org_id"] = orgID
		}
		if err := answerProductRoles(ctx, h, &authPrincipal{userID: "alice"}, resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := run("", true)
	if got, want := resp.GetScopes()[orgProductRolesScope], "notes.NoteMutation.CreateNote,notes.NoteMutation.DeleteNote,notes.NoteQuery.GetNote,notes.NoteQuery.ListNotes"; got != want {
		t.Errorf("org_product_roles = %q, want admin's and viewer's codes %q", got, want)
	}
	if _, ok := resp.GetScopes()[orgPermissionsScope]; ok {
		t.Error("the identity's own ids reached the product's answer")
	}
	if resp := run("", false); resp.GetScopes()[orgProductRolesScope] != "" {
		t.Errorf("unmarked request answered a hint: %q", resp.GetScopes()[orgProductRolesScope])
	}
	if resp := run("org-a", true); resp.GetScopes()[orgProductRolesScope] != "" {
		t.Errorf("a request in an organization answered a hint: %q", resp.GetScopes()[orgProductRolesScope])
	}
}

// The selector arrives on the AuthReq headers too, and a named organization
// is never marked unnamed whichever channel carried it.
func TestResolveOrgScope_SelectorInHeadersIsNamed(t *testing.T) {
	h := twoOrgHandler()
	ctx := memoCtx(metadata.NewIncomingContext(context.Background(), metadata.MD{}))
	if err := resolveOrgScope(ctx, h, "multi", map[string]string{orgScopeMetadataKey: "a"}, map[string]string{}, map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if _, marked := orgUnnamed(ctx); marked {
		t.Error("a request naming its organization in the headers was marked unnamed")
	}
}

// permByOrgMock answers each organization's grants by its id.
type permByOrgMock struct {
	permMock
	byOrg map[string][]*pb.RoleGrant
}

func (m *permByOrgMock) GetUserOrgPermissions(_ context.Context, in *pb.GetUserOrgPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	return &pb.GetUserOrgPermissionsResp{Grants: m.byOrg[in.GetOrgId()]}, nil
}

// On an audience admitting only some membership kinds, a role held in an
// organization it does not admit is no "name it and you have it": naming that
// organization would be refused. The hint counts the admitted ones only.
func TestNarrowGrants_OnlyAdmittedOrganizationsCount(t *testing.T) {
	ctx := memoCtx(context.Background())
	requestMemoOf(ctx)[orgUnnamedMemo] = orgUnnamedMark{orgs: map[string]bool{"org-a": true}}
	h := &AuthServiceHandler{Query: &permByOrgMock{byOrg: map[string][]*pb.RoleGrant{
		"org-a": {grant("staff", 9)},
		"org-b": {grant("client", 5)},
	}}}
	scopes := map[string]string{}
	if err := narrowGrantsToActiveOrg(ctx, h, sessionPrincipal(grant("staff", 9), grant("client", 5)), scopes); err != nil {
		t.Fatal(err)
	}
	if got := scopes[orgPermissionsScope]; got != "9" {
		t.Errorf("org_permissions %q, want only the admitted organization's 9", got)
	}
}

func TestAnswerProductRoles_OnlyAdmittedOrganizationsCount(t *testing.T) {
	h, m := prodHandler(t)
	m.grants = append(m.grants,
		&pb.ProductRoleGrantRow{Id: "g-2", UserId: "alice", OrgId: "org-b", Product: "alpha", RoleKey: "viewer"},
	)
	hint := func(orgs ...string) string {
		t.Helper()
		ctx := context.WithValue(privateCallerCtx("alpha"), authHeadersKey{}, map[string]string{productHeader: "alpha"})
		ctx = memoCtx(ctx)
		mark := orgUnnamedMark{orgs: map[string]bool{}}
		for _, o := range orgs {
			mark.orgs[o] = true
		}
		requestMemoOf(ctx)[orgUnnamedMemo] = mark
		resp := &pb.AuthResp{Scopes: map[string]string{"user_id": "alice"}}
		if err := answerProductRoles(ctx, h, &authPrincipal{userID: "alice"}, resp); err != nil {
			t.Fatal(err)
		}
		return resp.GetScopes()[orgProductRolesScope]
	}
	viewer := hint("org-b")
	if viewer == "" || strings.Contains(viewer, "notes.NoteMutation.CreateNote") {
		t.Errorf("org-b admitted only: %q, want viewer's codes without admin's", viewer)
	}
	if both := hint("org-a", "org-b"); !strings.Contains(both, "notes.NoteMutation.CreateNote") {
		t.Errorf("both admitted: %q, want admin's codes too", both)
	}
	if none := hint("org-c"); none != "" {
		t.Errorf("no admitted organization holds a role: %q", none)
	}
}

// Listing one's own organizations needs no organization: a member of two
// whose role carrying ListMyOrgs is held inside them (no realm-wide grant of
// it) keeps it on a request naming none — not refused, and not told to name
// the organization it is asking for. w17ctl lists naming none, and a release
// of it from before ORGANIZATION_REQUIRED retries only on PERMISSION_DENIED.
// It keeps nothing else, and nothing its roles do not carry.
func TestNarrowGrants_ListingOnesOrganizationsNeedsNone(t *testing.T) {
	lock := &acllock.Lock{Permissions: map[string]int{"auth.AuthService.ListMyOrgs": 6, "auth.AuthService.WhoAmI": 1, "notes.Note.Get": 9}}
	for _, c := range []struct {
		name string
		prin *authPrincipal
		want []int32
	}{
		{"an organization's role carries it", sessionPrincipal(grant("member", 6, 9)), []int32{6}},
		{"an organization's wildcard", sessionPrincipal(&pb.RoleGrant{RoleId: "owner", AllPermissions: true}), []int32{6}},
		{"no role carries it", sessionPrincipal(grant("member", 9)), nil},
	} {
		ctx := memoCtx(context.Background())
		requestMemoOf(ctx)[orgUnnamedMemo] = orgUnnamedMark{anyOrg: true}
		h := &AuthServiceHandler{Query: &permMock{}, Lock: lock}
		scopes := map[string]string{}
		if err := narrowGrantsToActiveOrg(ctx, h, c.prin, scopes); err != nil {
			t.Fatal(err)
		}
		got := c.prin.effectivePermissions(lock)
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: holds %v, want %v", c.name, got, c.want)
		}
	}
	// Naming an organization changes nothing: its roles apply as they are.
	ctx := memoCtx(context.Background())
	prin := sessionPrincipal(grant("member", 9))
	h := &AuthServiceHandler{Query: &permMock{orgGrants: []*pb.RoleGrant{grant("member", 9)}}, Lock: lock}
	if err := narrowGrantsToActiveOrg(ctx, h, prin, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatal(err)
	}
	if got := prin.effectivePermissions(lock); !slices.Equal(got, []int32{9}) {
		t.Errorf("named organization: holds %v, want [9]", got)
	}
}
