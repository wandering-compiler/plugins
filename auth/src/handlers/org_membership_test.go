package handlers

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// orgMock backs the org_membership query surface (ListUserOrgs +
// GetUserOrgBySlug). Embeds both client interfaces so the un-overridden
// methods satisfy the type.
type orgMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	orgsByUser map[string][]*pb.UserOrg            // ListUserOrgs
	bySlug     map[string]*pb.GetUserOrgBySlugResp // key "user|slug"; absent = not a member

	listErr   error
	bySlugErr error

	listCalls int // ListUserOrgs calls
}

func (m *orgMock) ListUserOrgs(ctx context.Context, in *pb.ListUserOrgsReq, _ ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	m.listCalls++
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &pb.ListUserOrgsResp{Orgs: m.orgsByUser[in.GetUserId()]}, nil
}

func (m *orgMock) GetUserOrgBySlug(ctx context.Context, in *pb.GetUserOrgBySlugReq, _ ...grpc.CallOption) (*pb.GetUserOrgBySlugResp, error) {
	if m.bySlugErr != nil {
		return nil, m.bySlugErr
	}
	if r := m.bySlug[in.GetUserId()+"|"+in.GetSlug()]; r != nil {
		return r, nil
	}
	// Not a member: what a generated single-row read answers for no row —
	// NotFound, not an empty response. The fake used to answer empty, which
	// is why resolveOrgScope's `return err` on NotFound never showed here.
	return nil, status.Error(codes.NotFound, "no rows")
}

// ctxWithOrg sets only the active-org selector (resolveOrgScope takes the
// principal as an arg, so it needs no user metadata).
func ctxWithOrg(slug string) context.Context {
	if slug == "" {
		return context.Background()
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(orgScopeMetadataKey, slug))
}

// orgAuthedCtx threads the gateway-resolved principal (for ListMyOrgs).
func orgAuthedCtx(uid string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(scopeUserIDKey, uid))
}

func TestResolveOrgScope(t *testing.T) {
	m := &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{
		"u1|acme": {OrgId: "org-acme", Role: "member"},
	}}
	h := &AuthServiceHandler{Query: m}

	t.Run("no header and no memberships stamps nothing", func(t *testing.T) {
		sc, lb := map[string]string{}, map[string]string{}
		if err := resolveOrgScope(ctxWithOrg(""), h, "u1", nil, sc, lb); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := sc["org_id"]; ok {
			t.Error("a caller with no orgs has nothing to stamp")
		}
		if _, ok := lb["org_id"]; ok {
			t.Error("no org means no broadcast label either")
		}
	})

	t.Run("member stamps org_id", func(t *testing.T) {
		sc, lb := map[string]string{}, map[string]string{}
		if err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, sc, lb); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sc["org_id"] != "org-acme" {
			t.Errorf("org_id = %q, want org-acme", sc["org_id"])
		}
		// The BROADCAST key travels with the row key. Without it the org's
		// events go out unlabelled, and an unlabelled event reaches every
		// authenticated client — per-org data, every-org event stream.
		if lb["org_id"] != "org-acme" {
			t.Errorf("labels[org_id] = %q, want org-acme", lb["org_id"])
		}
	})

	t.Run("non-member fails closed and stamps nothing", func(t *testing.T) {
		sc, lb := map[string]string{}, map[string]string{}
		err := resolveOrgScope(ctxWithOrg("acme"), h, "u-other", nil, sc, lb)
		if !errors.Is(err, errOrgNotMember) {
			t.Fatalf("want errOrgNotMember, got %v", err)
		}
		if _, ok := sc["org_id"]; ok {
			t.Error("a non-member request must not stamp an org scope")
		}
		// The mirror hazard: a label stamped for an org the caller does not
		// belong to would route THEIR events into that org's stream.
		if _, ok := lb["org_id"]; ok {
			t.Error("a non-member request must not stamp a broadcast label")
		}
	})

	t.Run("query error propagates (not membership rejection)", func(t *testing.T) {
		boom := errors.New("db down")
		m2 := &orgMock{bySlugErr: boom}
		h2 := &AuthServiceHandler{Query: m2}
		err := resolveOrgScope(ctxWithOrg("acme"), h2, "u1", nil, map[string]string{}, map[string]string{})
		if !errors.Is(err, boom) {
			t.Fatalf("want raw db error, got %v", err)
		}
	})
}

// The single-org inference. Without it, a one-org install fails every request
// that omits the header on any scoped model — which is every w17ctl command
// except `init`, the only one that sends it. It cannot widen access: one
// membership row means one reachable org whether or not the header is present,
// and the id still comes from OrgMembership rather than from the request.
func TestResolveOrgScope_SoleOrgInference(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"solo": {{OrgId: "org-solo", Slug: "solo", Role: "owner"}},
	}}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg(""), h, "solo", nil, sc, lb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc["org_id"] != "org-solo" {
		t.Errorf("org_id = %q, want org-solo (the caller's only org)", sc["org_id"])
	}
	if lb["org_id"] != "org-solo" {
		t.Errorf("labels[org_id] = %q, want org-solo — the inferred org labels events too", lb["org_id"])
	}
}

// Several orgs is genuinely ambiguous — picking one would decide which org a
// write lands in. Stamping nothing makes the scoped model answer
// PermissionDenied, and the caller resends with the header.
func TestResolveOrgScope_MultipleOrgsStayAmbiguous(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"multi": {
			{OrgId: "org-a", Slug: "a", Role: "owner"},
			{OrgId: "org-b", Slug: "b", Role: "member"},
		},
	}}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg(""), h, "multi", nil, sc, lb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, ok := sc["org_id"]; ok {
		t.Errorf("stamped %q — guessing between two orgs decides where a write lands", got)
	}
	if got, ok := lb["org_id"]; ok {
		t.Errorf("labelled %q — guessing would also decide which org hears the event", got)
	}
}

// A lookup failure must not turn every header-less request into an auth
// failure: login and `org list` legitimately carry no org context. The caller
// gets no scope, so a scoped model still refuses.
func TestResolveOrgScope_InferenceLookupErrorIsNotFatal(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{listErr: errors.New("db down")}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg(""), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("a failed org lookup must not fail Authenticate: %v", err)
	}
	if _, ok := sc["org_id"]; ok {
		t.Error("a failed lookup must not stamp a scope")
	}
	if _, ok := lb["org_id"]; ok {
		t.Error("a failed lookup must not stamp a label")
	}
}

// An explicit header still wins over inference — the caller picking an org
// they belong to must not be second-guessed by the sole-org shortcut.
func TestResolveOrgScope_HeaderWinsOverInference(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{
		orgsByUser: map[string][]*pb.UserOrg{"u1": {{OrgId: "org-sole", Slug: "sole"}}},
		bySlug:     map[string]*pb.GetUserOrgBySlugResp{"u1|acme": {OrgId: "org-acme"}},
	}}
	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sc["org_id"] != "org-acme" {
		t.Errorf("org_id = %q, want org-acme (the explicitly selected org)", sc["org_id"])
	}
	if lb["org_id"] != "org-acme" {
		t.Errorf("labels[org_id] = %q, want org-acme", lb["org_id"])
	}
}

func TestListMyOrgs(t *testing.T) {
	orgs := []*pb.UserOrg{
		{OrgId: "o1", Slug: "jana", Name: "Jana (personal)", Kind: "private", Role: "owner"},
		{OrgId: "o2", Slug: "acme", Name: "Acme s.r.o.", Kind: "company", Role: "member"},
	}
	m := &orgMock{orgsByUser: map[string][]*pb.UserOrg{"u1": orgs}}
	h := &AuthServiceHandler{Query: m}

	t.Run("returns the caller's orgs", func(t *testing.T) {
		resp, err := h.ListMyOrgs(orgAuthedCtx("u1"), &pb.ListMyOrgsReq{})
		if err != nil {
			t.Fatalf("ListMyOrgs: %v", err)
		}
		if len(resp.GetOrgs()) != 2 {
			t.Fatalf("orgs len = %d, want 2", len(resp.GetOrgs()))
		}
		if resp.GetOrgs()[1].GetSlug() != "acme" || resp.GetOrgs()[1].GetKind() != "company" {
			t.Errorf("unexpected org content: %+v", resp.GetOrgs()[1])
		}
	})

	t.Run("no principal is Unauthenticated", func(t *testing.T) {
		if _, err := h.ListMyOrgs(context.Background(), &pb.ListMyOrgsReq{}); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("want Unauthenticated, got %v", err)
		}
	})

	t.Run("query error propagates", func(t *testing.T) {
		boom := errors.New("db down")
		h2 := &AuthServiceHandler{Query: &orgMock{listErr: boom}}
		if _, err := h2.ListMyOrgs(orgAuthedCtx("u1"), &pb.ListMyOrgsReq{}); !errors.Is(err, boom) {
			t.Fatalf("want raw db error, got %v", err)
		}
	})
}

// --- grant narrowing to the active organization -----------------------------

// permMock backs the two permission queries the narrower picks between.
// Recording WHICH one was called is half the point: reaching for the
// unscoped answer when no org resolved is the leak this exists to close,
// and a test that only inspected the returned ids could not tell the two
// apart whenever the sets happen to coincide.
type permMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	orgGrants   []*pb.RoleGrant
	realmGrants []*pb.RoleGrant
	err         error

	sawOrgID    string
	calledOrg   bool
	calledRealm bool
}

func (m *permMock) GetUserOrgPermissions(ctx context.Context, in *pb.GetUserOrgPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	m.calledOrg = true
	m.sawOrgID = in.GetOrgId()
	if m.err != nil {
		return nil, m.err
	}
	return &pb.GetUserOrgPermissionsResp{Grants: m.orgGrants}, nil
}

func (m *permMock) GetUserRealmWidePermissions(ctx context.Context, in *pb.GetUserRealmWidePermissionsReq, _ ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	m.calledRealm = true
	if m.err != nil {
		return nil, m.err
	}
	return &pb.GetUserRealmWidePermissionsResp{Grants: m.realmGrants}, nil
}

func grant(role string, perms ...int32) *pb.RoleGrant {
	return &pb.RoleGrant{RoleId: role, PermissionIds: perms}
}

func sessionPrincipal(grants ...*pb.RoleGrant) *authPrincipal {
	return &authPrincipal{userID: "u1", realm: pb.TokenType_TOKEN_TYPE_SESSION, grants: grants}
}

func TestNarrowGrants_ActiveOrg(t *testing.T) {
	// Incoming grants are the union across every org; company B's role must
	// not survive into company A.
	m := &permMock{orgGrants: []*pb.RoleGrant{grant("role-a", 1, 2)}}
	h := &AuthServiceHandler{Query: m}
	p := sessionPrincipal(grant("role-a", 1, 2), grant("role-b", 7))

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if !m.calledOrg || m.sawOrgID != "org-a" {
		t.Errorf("the active org was not passed to the scoped query: calledOrg=%v orgID=%q", m.calledOrg, m.sawOrgID)
	}
	if got := p.effectivePermissions(h.Lock); !reflect.DeepEqual(got, []int32{1, 2}) {
		t.Errorf("permissions from another organization survived: got %v, want [1 2]", got)
	}
}

// THE soundness property this whole change exists for.
//
// Permission 5 is granted by role-x on the incoming (realm) side and by
// role-y on the org side. No SINGLE role grants it under both axes, so it
// must not survive — and under the old set-intersection it did, because the
// two sets both contained the bare id 5 and nothing recorded where it came
// from. That is the hole that made api_token + org_membership refuse to be
// enabled together.
// Inside an organization a credential is told what it holds realm-wide
// (realm_permissions): `*` for a realm-wide wildcard, otherwise the ids its
// realm-wide roles grant — another plugin's backoffice method acts realm-wide
// on it. An organization's own roles, a realm-wide role this credential does
// not carry (another token realm's) and a request in no organization mark
// nothing. The mark adds no permission.
func TestNarrowGrants_MarksTheRealmPermissions(t *testing.T) {
	wild := func(role string) *pb.RoleGrant { return &pb.RoleGrant{RoleId: role, AllPermissions: true} }
	for _, c := range []struct {
		name  string
		org   string
		prin  *authPrincipal
		realm []*pb.RoleGrant
		inOrg []*pb.RoleGrant
		want  string
	}{
		{"the backoffice's wildcard, a member of the organization", "org-a", sessionPrincipal(wild("platform-admin"), wild("tenant-admin")), []*pb.RoleGrant{wild("platform-admin")}, []*pb.RoleGrant{wild("platform-admin"), wild("tenant-admin")}, "*"},
		{"the backoffice's listed role", "org-a", sessionPrincipal(grant("backoffice", 12, 7, 12), grant("member", 3)), []*pb.RoleGrant{grant("backoffice", 7, 12)}, []*pb.RoleGrant{grant("backoffice", 7, 12), grant("member", 3)}, "7,12"},
		{"the organization's own wildcard", "org-a", sessionPrincipal(wild("tenant-admin")), nil, []*pb.RoleGrant{wild("tenant-admin")}, ""},
		{"a realm-wide role this credential does not carry", "org-a", sessionPrincipal(wild("tenant-admin")), []*pb.RoleGrant{wild("api-admin")}, []*pb.RoleGrant{wild("tenant-admin")}, ""},
		{"no organization", "", sessionPrincipal(wild("platform-admin")), []*pb.RoleGrant{wild("platform-admin")}, nil, ""},
	} {
		m := &permMock{orgGrants: c.inOrg, realmGrants: c.realm}
		h := &AuthServiceHandler{Query: m}
		scopes := map[string]string{}
		if c.org != "" {
			scopes["org_id"] = c.org
		}
		if err := narrowGrantsToActiveOrg(context.Background(), h, c.prin, scopes); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := scopes[realmPermissionsScope]; got != c.want {
			t.Errorf("%s: realm_permissions %q, want %q", c.name, got, c.want)
		}
	}
}

func TestNarrowGrants_APermissionTwoDifferentRolesGrantDoesNotSurvive(t *testing.T) {
	m := &permMock{orgGrants: []*pb.RoleGrant{grant("role-y", 5)}}
	h := &AuthServiceHandler{Query: m}
	p := sessionPrincipal(grant("role-x", 5))

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if got := p.effectivePermissions(h.Lock); len(got) != 0 {
		t.Errorf("a permission assembled from two roles that each fail one axis survived: got %v, want none", got)
	}
}

func TestNarrowGrants_NoActiveOrg(t *testing.T) {
	// Member of several orgs, no W17-Org header. Only realm-wide grants may
	// count; falling back to the incoming set is exactly the cross-tenant leak.
	m := &permMock{realmGrants: []*pb.RoleGrant{grant("role-w", 1)}}
	h := &AuthServiceHandler{Query: m}
	p := sessionPrincipal(grant("role-w", 1), grant("role-scoped", 5, 9))

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if !m.calledRealm {
		t.Error("no active org — the realm-wide query must be the one that runs")
	}
	if m.calledOrg {
		t.Error("the org-scoped query ran without an org")
	}
	if got := p.effectivePermissions(h.Lock); !reflect.DeepEqual(got, []int32{1}) {
		t.Errorf("org-scoped grants leaked without an active org: got %v, want [1]", got)
	}
}

// A wildcard is a ROLE like any other and has to pass the org axis. A
// superadmin of company B holds nothing in company A.
func TestNarrowGrants_WildcardRoleMustPassTheOrgAxis(t *testing.T) {
	m := &permMock{orgGrants: []*pb.RoleGrant{grant("role-a", 3)}}
	h := &AuthServiceHandler{Query: m, Lock: wildcardLock()}
	p := sessionPrincipal(grant("role-a", 3), &pb.RoleGrant{RoleId: "role-super", AllPermissions: true})

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if got := p.effectivePermissions(h.Lock); !reflect.DeepEqual(got, []int32{3}) {
		t.Errorf("a superadmin role from another org expanded here: got %v, want [3]", got)
	}
}

// Whoever created an organization holds in it exactly what their roles say.
// Organization ownership once appended a synthetic wildcard here — over the
// WHOLE deployed permission lock, not just the organization — for a principal
// named by Organization.owner_id, a column nothing wrote. A session principal
// with no role in the active organization, whatever their relation to it,
// must come out of the narrowing holding nothing, for a session and for an
// API token alike.
func TestNarrowGrants_NoRoleMeansNothingWhoeverCreatedTheOrg(t *testing.T) {
	for name, realm := range map[string]pb.TokenType{
		"session":   pb.TokenType_TOKEN_TYPE_SESSION,
		"api token": pb.TokenType_TOKEN_TYPE_API,
	} {
		t.Run(name, func(t *testing.T) {
			m := &permMock{} // no role grants in the org, none realm-wide
			h := &AuthServiceHandler{Query: m, Lock: wildcardLock()}
			p := &authPrincipal{userID: "u-creator", realm: realm}

			if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
				t.Fatalf("narrow: %v", err)
			}
			if len(p.grants) != 0 {
				t.Errorf("a principal with no role in the organization was granted %v", p.grants)
			}
			if got := p.effectivePermissions(h.Lock); len(got) != 0 {
				t.Errorf("a principal with no role in the organization holds %v, want nothing", got)
			}
		})
	}
}

func TestNarrowGrants_QueryErrorFailsClosed(t *testing.T) {
	m := &permMock{err: errors.New("boom")}
	h := &AuthServiceHandler{Query: m}
	p := sessionPrincipal(grant("role-a", 1))

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err == nil {
		t.Fatal("a failed permission lookup must propagate, not silently keep the wider set")
	}
}

// --- the selector arrives on the AuthReq header map -------------------------

// The active-org selector must resolve from AuthReq.Headers, because on a
// public gRPC surface that is the ONLY channel carrying it: the rpc
// gateway sanitizes the incoming metadata, hands it over as
// AuthReq.Headers, then calls Authenticate with the raw incoming context —
// which has no OUTGOING metadata and no forwarding interceptor. Reading
// only the context made org selection a REST-only feature, and the single
// deployment with organizations has one-org users, so the sole-org inference
// supplied the right answer and the gap never showed.
func TestResolveOrgScope_SlugFromHeadersWithoutMetadata(t *testing.T) {
	m := &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{
		"u1|acme": {OrgId: "org-acme"},
	}}
	h := &AuthServiceHandler{Query: m}
	scopes, labels := map[string]string{}, map[string]string{}

	// context.Background() deliberately: no gRPC metadata at all.
	err := resolveOrgScope(context.Background(), h, "u1",
		map[string]string{"w17-org": "acme"}, scopes, labels)
	if err != nil {
		t.Fatalf("resolveOrgScope: %v", err)
	}
	if scopes["org_id"] != "org-acme" {
		t.Errorf("the header-borne selector did not resolve: scopes=%v", scopes)
	}
	if labels["org_id"] != "org-acme" {
		t.Errorf("the event audience key was not stamped: labels=%v", labels)
	}
}

// REST lowercases HTTP header names, gRPC metadata keys are lowercase by
// protocol — but a hand-built caller need not be, and getting this wrong
// degrades silently to the single-org inference.
func TestResolveOrgScope_HeaderLookupIsCaseInsensitive(t *testing.T) {
	m := &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{
		"u1|acme": {OrgId: "org-acme"},
	}}
	h := &AuthServiceHandler{Query: m}
	scopes := map[string]string{}

	if err := resolveOrgScope(context.Background(), h, "u1",
		map[string]string{"W17-Org": "acme"}, scopes, map[string]string{}); err != nil {
		t.Fatalf("resolveOrgScope: %v", err)
	}
	if scopes["org_id"] != "org-acme" {
		t.Errorf("a differently-cased header key was missed: scopes=%v", scopes)
	}
}

// The decoy for both tests above: with the selector on NEITHER channel the
// resolver must fall through to the inference, not invent an org. Without
// this a resolver that ignored its inputs entirely and always stamped
// would pass them.
func TestResolveOrgScope_NoSelectorFallsBackToInference(t *testing.T) {
	m := &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"u1": {{OrgId: "org-only"}, {OrgId: "org-second"}},
	}}
	h := &AuthServiceHandler{Query: m}
	scopes := map[string]string{}

	if err := resolveOrgScope(context.Background(), h, "u1", nil, scopes, map[string]string{}); err != nil {
		t.Fatalf("resolveOrgScope: %v", err)
	}
	if _, ok := scopes["org_id"]; ok {
		t.Errorf("two orgs and no selector is ambiguous — nothing may be stamped: scopes=%v", scopes)
	}
}

// Live membership is the only way to select an organization. Ownership
// (Organization.owner_id) used to be a second one, read when the membership
// lookup found nothing, so the person named there could act in an
// organization they were no member of. Without a membership row — never
// added, or ended by MarkOrgMembershipRemoved — the organization's creator is
// refused like anybody else and nothing is stamped; and the refusal is the
// answer itself, one lookup, with no second claim consulted.
func TestResolveOrgScope_WithoutAMembershipNobodySelectsTheOrg(t *testing.T) {
	m := &orgMock{
		// Deliberately empty: u-creator made acme but is a member of nothing.
		bySlug: map[string]*pb.GetUserOrgBySlugResp{},
		orgsByUser: map[string][]*pb.UserOrg{
			"u-creator": nil,
		},
	}
	h := &AuthServiceHandler{Query: m}

	sc, lb := map[string]string{}, map[string]string{}
	err := resolveOrgScope(ctxWithOrg("acme"), h, "u-creator", nil, sc, lb)
	if !errors.Is(err, errOrgNotMember) {
		t.Fatalf("want errOrgNotMember for a principal with no membership, got %v", err)
	}
	if len(sc) != 0 || len(lb) != 0 {
		t.Fatalf("a refused scope must stamp nothing, got scopes=%v labels=%v", sc, lb)
	}
}

// The slug is stamped alongside the id, from the same resolution.
//
// It exists so a consumer can RENDER an organization without a second lookup —
// the console writes it into a project's lock, where a bare UUID tells a
// reviewer nothing about which organization a project just moved to. Verified
// by construction: the org was resolved BY this slug, so the pair cannot
// disagree.
func TestResolveOrgScope_StampsTheSlugWithTheID(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{bySlug: map[string]*pb.GetUserOrgBySlugResp{
		"u1|acme": {OrgId: "org-acme", Role: "member"},
	}}}

	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("resolveOrgScope: %v", err)
	}
	if sc["org_id"] != "org-acme" {
		t.Fatalf("org_id = %q", sc["org_id"])
	}
	if sc["org_slug"] != "acme" {
		t.Fatalf("org_slug = %q, want the slug the org was resolved by", sc["org_slug"])
	}
	// A scope, not a label: an audience keyed by a display name is the same
	// audience keyed by its id, and two keys for one audience drift apart.
	if _, labelled := lb["org_slug"]; labelled {
		t.Error("the slug became an event-audience key — org_id already is one")
	}
}

// The single-org inference stamps it too; it reads the slug off the membership
// row rather than from anything the caller said.
func TestResolveOrgScope_SoleOrgInferenceAlsoStampsTheSlug(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"u1": {{OrgId: "org-solo", Slug: "solo"}},
	}}}

	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg(""), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("resolveOrgScope: %v", err)
	}
	if sc["org_id"] != "org-solo" || sc["org_slug"] != "solo" {
		t.Fatalf("scopes = %v, want both id and slug for the sole org", sc)
	}
}

// On the admin plane no organization is selected — not from the header, not
// by inferring the caller's only one — so only realm-wide roles survive the
// narrowing (TestNarrowGrants_NoActiveOrg) and a role scoped to one
// organization grants nothing in the console that spans them all.
func TestResolveOrgScope_TheAdminPlaneSelectsNoOrganization(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{
		orgsByUser: map[string][]*pb.UserOrg{"solo": {{OrgId: "org-solo", Slug: "solo", Role: "owner"}}},
		bySlug:     map[string]*pb.GetUserOrgBySlugResp{"solo|solo": {OrgId: "org-solo"}},
	}}
	// "inferred" sends no selector at all, so only the sole-org inference
	// could pick one; the other two name the org on each channel it arrives on.
	cases := map[string]struct {
		ctx     context.Context
		headers map[string]string
	}{
		"inferred":      {ctxWithOrg(""), nil},
		"named header":  {ctxWithOrg(""), map[string]string{orgScopeMetadataKey: "solo"}},
		"named context": {ctxWithOrg("solo"), nil},
	}
	for name, c := range cases {
		sc, lb := map[string]string{}, map[string]string{}
		if err := resolveOrgScope(context.WithValue(c.ctx, adminPlaneKey{}, true), h, "solo", c.headers, sc, lb); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sc["org_id"] != "" || lb["org_id"] != "" {
			t.Errorf("%s: the admin plane selected organization %q", name, sc["org_id"])
		}
		// Control: without the mark the same request DOES select the org, so
		// the assertion above is not passing for an unrelated reason.
		sc, lb = map[string]string{}, map[string]string{}
		if err := resolveOrgScope(c.ctx, h, "solo", c.headers, sc, lb); err != nil {
			t.Fatalf("%s (app plane): %v", name, err)
		}
		if sc["org_id"] != "org-solo" {
			t.Errorf("%s (app plane): org_id = %q, want org-solo", name, sc["org_id"])
		}
	}
}

// AuthenticateAdmin is what marks the admin plane, and Authenticate must not:
// the resolveOrgScope test above sets the mark by hand, so without this one a
// handler that forgot it would pass every test.
func TestAuthenticateAdmin_MarksTheAdminPlaneAndAuthenticateDoesNot(t *testing.T) {
	prevResolve, prevDec, prevNarrow := resolvePrincipal, scopeDecorators, grantNarrowers
	t.Cleanup(func() { resolvePrincipal, scopeDecorators, grantNarrowers = prevResolve, prevDec, prevNarrow })
	resolvePrincipal = func(context.Context, *AuthServiceHandler, string) (*authPrincipal, error) {
		return &authPrincipal{userID: "u1", deviceThumbprint: testJKT}, nil
	}
	var seen []bool
	scopeDecorators = []scopeDecorator{func(ctx context.Context, _ *AuthServiceHandler, _ string, _, _, _ map[string]string) error {
		seen = append(seen, onAdminPlane(ctx))
		return nil
	}}
	grantNarrowers = []grantNarrower{func(ctx context.Context, _ *AuthServiceHandler, _ *authPrincipal, _ map[string]string) error {
		seen = append(seen, onAdminPlane(ctx))
		return nil
	}}
	h := &AuthServiceHandler{HeaderName: "Authorization"}
	req := boundAuthReq("tok", testJKT)

	if _, err := h.AuthenticateAdmin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !seen[0] || !seen[1] {
		t.Fatalf("AuthenticateAdmin: decorator/narrower saw admin plane = %v, want [true true]", seen)
	}
	seen = nil
	if _, err := h.Authenticate(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] || seen[1] {
		t.Fatalf("Authenticate: decorator/narrower saw admin plane = %v, want [false false]", seen)
	}
}

// An organization has no owner, and no statement reads one. owner_id was
// root authority nobody wrote; with the field reserved a query naming it would
// fail at generation, and this says so where a reader of the tests looks —
// along with the two business answers that still carry an `owner` flag for
// old clients, which no statement may fill.
func TestOrganizationHasNoOwner(t *testing.T) {
	if fd := (&pb.Organization{}).ProtoReflect().Descriptor().Fields().ByName("owner_id"); fd != nil {
		t.Fatalf("Organization still declares %s", fd.FullName())
	}
	for rel, src := range authProtos(t) {
		for name, body := range rpcBodies(dqlText(src)) {
			// owner_id anywhere, or an `owner` column computed beside an
			// Organization (the old `(o.owner_id = m.user_id) AS owner`); the
			// device and session lists' `owner` is an account's address.
			if strings.Contains(body, "owner_id") || (strings.Contains(body, "@module.Organization") && strings.Contains(body, " AS owner")) {
				t.Errorf("%s: %s reads organization ownership:\n%s", rel, name, body)
			}
		}
	}
}

// UserOrg.owner and OrgMember.owner stay on the wire for old clients and are
// always false: ListMyOrgs and ListOrgMembers fill nothing into them.
func TestOwnerFlagsAreAlwaysFalse(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{orgsByUser: map[string][]*pb.UserOrg{
		"u1": {{OrgId: "org-acme", Slug: "acme", Role: "org-admin"}},
	}}}
	resp, err := h.ListMyOrgs(orgAuthedCtx("u1"), &pb.ListMyOrgsReq{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range resp.GetOrgs() {
		if o.GetOwner() {
			t.Errorf("ListMyOrgs answered owner=true for %s", o.GetSlug())
		}
	}
	members, err := (&AuthServiceHandler{Query: memberListQuery{}}).ListOrgMembers(
		metadata.NewIncomingContext(context.Background(), metadata.Pairs(scopeUserIDKey, "u1", "x-w17-scope-org_id", "org-1")),
		&pb.ListOrgMembersReq{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members.GetMembers() {
		if m.GetOwner() {
			t.Errorf("ListOrgMembers answered owner=true for %s", m.GetUserId())
		}
	}
}
