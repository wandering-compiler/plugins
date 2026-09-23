package handlers

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// orgMock backs the org_membership query surface (ListUserOrgs +
// GetUserOrgBySlug). Embeds both client interfaces so the un-overridden
// methods satisfy the type.
type orgMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	orgsByUser map[string][]*pb.UserOrg            // ListUserOrgs
	bySlug     map[string]*pb.GetUserOrgBySlugResp // key "user|slug"; absent = not a member
	owned      map[string]string                   // key "user|slug" -> org id; absent = not the owner

	listErr   error
	bySlugErr error
	ownedErr  error
}

func (m *orgMock) ListUserOrgs(ctx context.Context, in *pb.ListUserOrgsReq, _ ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
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
	return &pb.GetUserOrgBySlugResp{}, nil // empty org_id = not a member
}

// GetOwnedOrgBySlug is the ownership fallback resolveOrgScope reaches for when
// the membership lookup comes back empty. Kept as a SEPARATE map from bySlug so
// a test can express the state that matters — owner, no membership row — which
// is unreachable if both answers come from one fixture.
func (m *orgMock) GetOwnedOrgBySlug(ctx context.Context, in *pb.GetOwnedOrgBySlugReq, _ ...grpc.CallOption) (*pb.GetOwnedOrgBySlugResp, error) {
	if m.ownedErr != nil {
		return nil, m.ownedErr
	}
	return &pb.GetOwnedOrgBySlugResp{OrgId: m.owned[in.GetUserId()+"|"+in.GetSlug()]}, nil
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
		{OrgId: "o1", Slug: "jiri", Name: "Jiri (osobní)", Kind: "private", Role: "owner"},
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
	owner       bool
	err         error

	sawOrgID     string
	calledOrg    bool
	calledRealm  bool
	calledOwning bool
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

func (m *permMock) GetUserOwnsOrg(ctx context.Context, in *pb.GetUserOwnsOrgReq, _ ...grpc.CallOption) (*pb.GetUserOwnsOrgResp, error) {
	m.calledOwning = true
	if m.err != nil {
		return nil, m.err
	}
	return &pb.GetUserOwnsOrgResp{Owner: m.owner}, nil
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
	if m.calledRealm {
		t.Error("an active org was resolved — the realm-wide query must not run")
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

// Ownership WIDENS — the one exception to "a narrower only subtracts" — and
// it is what makes an owner able to act without seeded role grants.
func TestNarrowGrants_OwnershipWidensASession(t *testing.T) {
	m := &permMock{owner: true} // no role grants at all
	h := &AuthServiceHandler{Query: m, Lock: wildcardLock()}
	p := sessionPrincipal()

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if got := p.effectivePermissions(h.Lock); len(got) == 0 {
		t.Error("an owner holding no role received nothing — ownership is still inert")
	}
}

// ...but NOT an API token. Its ceiling stays the holder's api-realm roles,
// so a stolen CI token is not an owner login even when its minter owns the
// company.
func TestNarrowGrants_OwnershipDoesNotWidenAnApiToken(t *testing.T) {
	m := &permMock{owner: true}
	h := &AuthServiceHandler{Query: m, Lock: wildcardLock()}
	p := &authPrincipal{userID: "u1", realm: pb.TokenType_TOKEN_TYPE_API}

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatalf("narrow: %v", err)
	}
	if got := p.effectivePermissions(h.Lock); len(got) != 0 {
		t.Errorf("ownership widened an API token: got %v", got)
	}
	if m.calledOwning {
		t.Error("the ownership probe ran for an API token — it cannot apply, so it should not be asked")
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
// deployment with organizations has one-org users, so inferSoleOrgScope
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

// An OWNER with no membership row can still scope into the org they own.
//
// This is the state D13-3 makes reachable: DeleteOrgMembership removes the row
// and nothing anywhere adds one back, so without the ownership fallback the
// owner of an organization is locked out of it permanently — and the refusal
// they get is the opaque Unauthenticated every other auth failure returns, so
// nothing on the way out says "your membership is gone".
func TestResolveOrgScope_OwnerWithoutMembership(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{
		// Deliberately empty: u1 is a member of nothing.
		bySlug: map[string]*pb.GetUserOrgBySlugResp{},
		owned:  map[string]string{"u1|acme": "org-acme"},
	}}

	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("owner must resolve their own org: %v", err)
	}
	if sc["org_id"] != "org-acme" {
		t.Fatalf("scope org_id = %q, want org-acme", sc["org_id"])
	}
	// stampOrg owns both keys; an owner whose rows are scoped but whose events
	// are not would be the same one-surface-over leak the label exists to fix.
	if lb["org_id"] != "org-acme" {
		t.Fatalf("label org_id = %q, want org-acme", lb["org_id"])
	}
}

// The decoy for the test above: ownership admits the OWNER, not everyone the
// membership lookup turned away. Without this, a fallback that stamped any org
// it could find a row for would pass the owner test and leak every org.
func TestResolveOrgScope_NonMemberNonOwnerStillRefused(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{
		bySlug: map[string]*pb.GetUserOrgBySlugResp{},
		owned:  map[string]string{"u1|acme": "org-acme"}, // u1 owns acme; u2 owns nothing
	}}

	sc, lb := map[string]string{}, map[string]string{}
	err := resolveOrgScope(ctxWithOrg("acme"), h, "u2", nil, sc, lb)
	if !errors.Is(err, errOrgNotMember) {
		t.Fatalf("want errOrgNotMember for a non-member non-owner, got %v", err)
	}
	if len(sc) != 0 || len(lb) != 0 {
		t.Fatalf("a refused scope must stamp nothing, got scopes=%v labels=%v", sc, lb)
	}
}

// A failing ownership lookup must not become "not a member". The distinction
// matters because the two produce the same opaque refusal to the caller but
// mean opposite things to whoever reads the logs, and because swallowing it
// would make a database outage look like a revoked membership.
func TestResolveOrgScope_OwnershipLookupErrorPropagates(t *testing.T) {
	boom := errors.New("db down")
	h := &AuthServiceHandler{Query: &orgMock{
		bySlug:   map[string]*pb.GetUserOrgBySlugResp{},
		ownedErr: boom,
	}}

	err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, map[string]string{}, map[string]string{})
	if !errors.Is(err, boom) {
		t.Fatalf("want the raw db error, got %v", err)
	}
}

// Membership stays the primary path: when the membership lookup answers, the
// ownership query is not consulted at all. Asserted because the fallback sits
// on the hot path of every org-scoped request, and a version that always ran
// both would pass every other test here while doubling the query count.
func TestResolveOrgScope_MembershipShortCircuitsTheOwnershipLookup(t *testing.T) {
	h := &AuthServiceHandler{Query: &orgMock{
		bySlug: map[string]*pb.GetUserOrgBySlugResp{
			"u1|acme": {OrgId: "org-acme", Role: "member"},
		},
		ownedErr: errors.New("ownership lookup must not run for a member"),
	}}

	sc, lb := map[string]string{}, map[string]string{}
	if err := resolveOrgScope(ctxWithOrg("acme"), h, "u1", nil, sc, lb); err != nil {
		t.Fatalf("member must resolve without the fallback: %v", err)
	}
	if sc["org_id"] != "org-acme" {
		t.Fatalf("scope org_id = %q, want org-acme", sc["org_id"])
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
