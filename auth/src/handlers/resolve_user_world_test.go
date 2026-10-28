package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"slices"
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

// The shape ResolveUser exists for, as a world the real organization
// decorator and narrower run over: a firm whose advisers invite its clients
// from a product, through the identity's own method on its private surface.
// The product names the adviser; the identity answers what the adviser holds
// in the firm and acts as them, and every check that reads the envelope — the
// role ceiling above all — judges the adviser, nothing more and nothing less.

// worldGrant is one role a user holds: in an organization (org) or
// realm-wide (org ""), in one realm.
type worldGrant struct {
	user, role, org string
	realm           pb.TokenType
}

// worldRole is a role of the catalogue: what it carries, or everything.
type worldRole struct {
	perms []int32
	all   bool
}

type worldOrg struct{ id, slug string }

// world is the store every query of ResolveUser, Authenticate, the
// organization decorator, the narrower and the role ceiling reads.
type world struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	users   map[string]*pb.User
	orgs    []worldOrg
	members map[string][]string // user → org ids
	roles   map[string]worldRole
	grants  []worldGrant
}

func (world) keepsCallerGrants() {}

func (w *world) roleGrant(role string) *pb.RoleGrant {
	r := w.roles[role]
	return &pb.RoleGrant{RoleId: role, PermissionIds: r.perms, AllPermissions: r.all}
}

func (w *world) grantsWhere(keep func(worldGrant) bool) []*pb.RoleGrant {
	var out []*pb.RoleGrant
	for _, g := range w.grants {
		if keep(g) {
			out = append(out, w.roleGrant(g.role))
		}
	}
	return out
}

func (w *world) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u := w.users[in.GetUserId()]
	if u == nil {
		return nil, status.Error(codes.NotFound, "AuthQuery.GetUserById: not found")
	}
	return &pb.GetUserByIdResp{User: u}, nil
}

func (w *world) GetUserRolePermissionsByRealm(_ context.Context, in *pb.GetUserRolePermissionsByRealmReq, _ ...grpc.CallOption) (*pb.GetUserRolePermissionsByRealmResp, error) {
	return &pb.GetUserRolePermissionsByRealmResp{Grants: w.grantsWhere(func(g worldGrant) bool {
		return g.user == in.GetUserId() && g.realm == in.GetTokenType()
	})}, nil
}

func (w *world) GetUserRoleGrants(_ context.Context, in *pb.GetUserRoleGrantsReq, _ ...grpc.CallOption) (*pb.GetUserRoleGrantsResp, error) {
	return &pb.GetUserRoleGrantsResp{Grants: w.grantsWhere(func(g worldGrant) bool { return g.user == in.GetUserId() })}, nil
}

func (w *world) slugOf(orgID string) string {
	for _, o := range w.orgs {
		if o.id == orgID {
			return o.slug
		}
	}
	return ""
}

func (w *world) ListUserOrgs(_ context.Context, in *pb.ListUserOrgsReq, _ ...grpc.CallOption) (*pb.ListUserOrgsResp, error) {
	var out []*pb.UserOrg
	for _, id := range w.members[in.GetUserId()] {
		out = append(out, &pb.UserOrg{OrgId: id, Slug: w.slugOf(id)})
	}
	return &pb.ListUserOrgsResp{Orgs: out}, nil
}

func (w *world) GetUserOrgBySlug(_ context.Context, in *pb.GetUserOrgBySlugReq, _ ...grpc.CallOption) (*pb.GetUserOrgBySlugResp, error) {
	for _, id := range w.members[in.GetUserId()] {
		if w.slugOf(id) == in.GetSlug() {
			return &pb.GetUserOrgBySlugResp{OrgId: id}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

// GetUserOrgPermissions: the roles that count in an organization — its own
// and the realm-wide ones.
func (w *world) GetUserOrgPermissions(_ context.Context, in *pb.GetUserOrgPermissionsReq, _ ...grpc.CallOption) (*pb.GetUserOrgPermissionsResp, error) {
	return &pb.GetUserOrgPermissionsResp{Grants: w.grantsWhere(func(g worldGrant) bool {
		return g.user == in.GetUserId() && (g.org == in.GetOrgId() || g.org == "")
	})}, nil
}

func (w *world) GetUserRealmWidePermissions(_ context.Context, in *pb.GetUserRealmWidePermissionsReq, _ ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	return &pb.GetUserRealmWidePermissionsResp{Grants: w.grantsWhere(func(g worldGrant) bool {
		return g.user == in.GetUserId() && g.org == ""
	})}, nil
}

func (w *world) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	out := &pb.ListRoleGrantsResp{}
	for _, id := range slices.Sorted(func(yield func(string) bool) {
		for id := range w.roles {
			if !yield(id) {
				return
			}
		}
	}) {
		out.Grants = append(out.Grants, w.roleGrant(id))
	}
	return out, nil
}

const (
	firmID  = "org-firm"
	otherID = "org-other"

	adviser  = "u-adviser"  // staff of the firm; owner of another organization; an API token's role
	owner    = "u-owner"    // the firm's owner (a wildcard role there)
	outsider = "u-outsider" // no membership in the firm; a realm-wide support role
	machine  = "u-machine"  // a machine account: API-realm roles only
	disabled = "u-disabled" // the firm's staff, disabled
)

const session, apiRealm = pb.TokenType_TOKEN_TYPE_SESSION, pb.TokenType_TOKEN_TYPE_API

func newFirmWorld() *world {
	return &world{
		users: map[string]*pb.User{
			adviser:  {Id: adviser},
			owner:    {Id: owner},
			outsider: {Id: outsider},
			machine:  {Id: machine},
			disabled: {Id: disabled, DisabledAt: timestamppb.Now()},
		},
		orgs: []worldOrg{{firmID, "firm"}, {otherID, "other"}},
		members: map[string][]string{
			adviser:  {firmID, otherID},
			owner:    {firmID},
			machine:  {firmID},
			disabled: {firmID},
		},
		roles: map[string]worldRole{
			"client":      {perms: []int32{1}},
			"staff":       {perms: []int32{1, 2, 3}},
			"firm-admin":  {perms: []int32{1, 2, 3, 5}},
			"owner":       {all: true},
			"support":     {perms: []int32{4}},
			"integration": {perms: []int32{9}},
		},
		grants: []worldGrant{
			{adviser, "staff", firmID, session},
			{adviser, "owner", otherID, session},       // a wildcard ELSEWHERE
			{adviser, "integration", firmID, apiRealm}, // a token's role, not the person's session
			{owner, "owner", firmID, session},
			{outsider, "support", "", session},
			{machine, "integration", firmID, apiRealm},
			{disabled, "staff", firmID, session},
		},
	}
}

func firmLock(n int) *acllock.Lock {
	perms := map[string]int{}
	for i := 1; i <= n; i++ {
		perms[fmt.Sprintf("p%d", i)] = i
	}
	return &acllock.Lock{Permissions: perms}
}

// withOrgSeams stages exactly the organization decorator and narrower — the
// axes ResolveUser must apply as Authenticate does — and nothing that reads
// a store this world does not keep.
func withOrgSeams(t *testing.T) {
	t.Helper()
	prevSources := orgGrantSources
	t.Cleanup(func() { orgGrantSources = prevSources })
	noFeatureSeams(t, resolveOrgScope)
	grantNarrowers = []grantNarrower{narrowGrantsToActiveOrg}
	orgGrantSources = nil
}

func orgHeaders(slug string) map[string]string {
	if slug == "" {
		return nil
	}
	return map[string]string{principal.OrgScopeHeader: slug}
}

// actingAs is what the identity's own method does: resolve the person in the
// organization, stamp the answer (principal.ActAs's incoming side), and — for
// a grant that runs under the organization's lock — mark the lock.
func actingAs(t *testing.T, h *AuthServiceHandler, user, org string, locked bool) (context.Context, *pb.AuthResp) {
	t.Helper()
	who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: user, Headers: orgHeaders(org)})
	if err != nil {
		t.Fatalf("ResolveUser(%s in %q): %v", user, org, err)
	}
	raw, err := proto.Marshal(who)
	if err != nil {
		t.Fatal(err)
	}
	md := metadata.Pairs(userMetadataKey, base64.StdEncoding.EncodeToString(raw))
	for k, v := range who.GetScopes() {
		md.Set(principal.ScopeKey(k), v)
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if locked && who.GetScopes()["org_id"] != "" {
		ctx = context.WithValue(ctx, orgLockKey{}, who.GetScopes()["org_id"])
	}
	return ctx, who
}

func sortedIDs32(ids []int32) []int32 {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

// Parity: for every person and organization, ResolveUser answers what
// Authenticate answers for that person's session asking in that organization
// — the same permissions, scopes and labels, or a refusal both times. A
// difference is a second resolver, and the day they differ the ceiling sits
// somewhere the access checks do not.
func TestResolveUser_AnswersWhatAuthenticateAnswersForTheirSession(t *testing.T) {
	withOrgSeams(t)
	w := newFirmWorld()
	h := &AuthServiceHandler{Query: w, Mutation: &touchRecorder{}, Lock: firmLock(9), HeaderName: "Authorization", Scheme: "Bearer"}

	prevRes := resolvePrincipal
	t.Cleanup(func() { resolvePrincipal = prevRes })
	resolvePrincipal = func(ctx context.Context, h *AuthServiceHandler, token string) (*authPrincipal, error) {
		grants, err := callerRealmGrants(ctx, h, token, true)
		if err != nil {
			return nil, err
		}
		return &authPrincipal{userID: token, tokenID: "tok-" + token, realm: session, grants: grants, deviceThumbprint: testJKT, user: w.users[token]}, nil
	}

	for _, user := range []string{adviser, owner, outsider, machine} {
		for _, org := range []string{"", "firm", "other", "nowhere"} {
			name := user + " in " + org
			headers := map[string]string{"authorization": "DPoP " + user, dpopJKTKey: testJKT}
			for k, v := range orgHeaders(org) {
				headers[k] = v
			}
			authn, authnErr := h.Authenticate(context.Background(), &pb.AuthReq{Headers: headers})
			resolved, resolveErr := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: user, Headers: orgHeaders(org)})
			if (authnErr == nil) != (resolveErr == nil) {
				t.Errorf("%s: Authenticate err=%v, ResolveUser err=%v — one refused, the other answered", name, authnErr, resolveErr)
				continue
			}
			if authnErr != nil {
				continue
			}
			if !reflect.DeepEqual(sortedIDs32(authn.GetPermissionIds()), sortedIDs32(resolved.GetPermissionIds())) {
				t.Errorf("%s: permissions Authenticate %v, ResolveUser %v", name, sortedIDs32(authn.GetPermissionIds()), sortedIDs32(resolved.GetPermissionIds()))
			}
			if !reflect.DeepEqual(authn.GetScopes(), resolved.GetScopes()) || !reflect.DeepEqual(authn.GetLabels(), resolved.GetLabels()) {
				t.Errorf("%s: scopes/labels Authenticate %v/%v, ResolveUser %v/%v", name, authn.GetScopes(), authn.GetLabels(), resolved.GetScopes(), resolved.GetLabels())
			}
			if authn.GetActedFor() {
				t.Errorf("%s: Authenticate answered acted_for — only ResolveUser may", name)
			}
			if !resolved.GetActedFor() || resolved.GetSessionTokenId() != "" || resolved.GetDeviceId() != "" {
				t.Errorf("%s: ResolveUser answered acted_for=%v session=%q device=%q", name, resolved.GetActedFor(), resolved.GetSessionTokenId(), resolved.GetDeviceId())
			}
		}
	}
}

// What a person holds in the firm, and no more: their roles there and
// realm-wide, of their session's realm. A wildcard they hold in ANOTHER
// organization, an API token's role, and the organization they name but do
// not belong to give them nothing here.
func TestResolveUser_HoldsTheirSessionRolesInTheOrganizationAlone(t *testing.T) {
	withOrgSeams(t)
	w := newFirmWorld()
	h := &AuthServiceHandler{Query: w, Lock: firmLock(9)}

	for _, c := range []struct {
		name, user, org string
		want            []int32 // nil = refused
	}{
		{"staff in the firm", adviser, "firm", []int32{1, 2, 3}},
		{"the same person in the organization they own", adviser, "other", []int32{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"the firm's owner", owner, "firm", []int32{1, 2, 3, 4, 5, 6, 7, 8, 9}},
		{"a realm-wide role, no organization", outsider, "", []int32{4}},
		{"an organization they do not belong to", outsider, "firm", nil},
		{"an organization nobody has", adviser, "nowhere", nil},
		{"a machine account's session (it has none)", machine, "firm", []int32{}},
	} {
		who, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: c.user, Headers: orgHeaders(c.org)})
		if c.want == nil {
			if err == nil {
				t.Errorf("%s: answered %v, want a refusal", c.name, who.GetPermissionIds())
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := sortedIDs32(who.GetPermissionIds()); !slices.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: holds %v, want %v", c.name, got, c.want)
		}
		if c.org == "firm" && who.GetScopes()["org_id"] != firmID {
			t.Errorf("%s: org scope %q, want %q", c.name, who.GetScopes()["org_id"], firmID)
		}
	}
}

// The role ceiling, judging the person the identity acts for, in the request
// and again under the organization's lock (where an invitation and a role
// change re-read the caller's grants). A role is handed out only by someone
// holding everything it grants: the adviser hands out the client's and their
// own, not one carrying a permission they lack, not the owner's wildcard, not
// a role their API token holds. The owner hands out every one.
func TestResolveUser_TheCeilingJudgesThePersonInAndOutOfTheLock(t *testing.T) {
	withOrgSeams(t)
	w := newFirmWorld()
	h := &AuthServiceHandler{Query: w, Lock: firmLock(9)}

	for _, c := range []struct {
		user string
		may  map[string]bool
	}{
		{adviser, map[string]bool{"client": true, "staff": true, "firm-admin": false, "owner": false, "integration": false, "support": false}},
		{owner, map[string]bool{"client": true, "staff": true, "firm-admin": true, "owner": true, "integration": true, "support": true}},
	} {
		for _, locked := range []bool{false, true} {
			ctx, _ := actingAs(t, h, c.user, "firm", locked)
			for role, may := range c.may {
				_, err := h.checkMayGrantRole(ctx, role)
				if may && err != nil {
					t.Errorf("%s (locked %v) may hand out %s: refused %v", c.user, locked, role, err)
				}
				if !may && status.Code(err) != codes.PermissionDenied {
					t.Errorf("%s (locked %v) may NOT hand out %s: got %v", c.user, locked, role, err)
				}
			}
		}
	}

	// A grant of theirs taken while the request waited for the lock: under
	// the lock the ceiling judges what they hold now.
	ctx, _ := actingAs(t, h, adviser, "firm", true)
	w.grants = slices.DeleteFunc(w.grants, func(g worldGrant) bool { return g.user == adviser && g.role == "staff" })
	if _, err := h.checkMayGrantRole(ctx, "client"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("the adviser lost the staff role while waiting and still handed out the client's: %v", err)
	}
}

// The incoming request is the caller's, not the person's: whatever principal
// or organization it carries — an envelope holding everything, a scope, a
// selector — ResolveUser answers the person it names, from the store.
func TestResolveUser_IgnoresThePrincipalTheRequestCarries(t *testing.T) {
	withOrgSeams(t)
	w := newFirmWorld()
	h := &AuthServiceHandler{Query: w, Lock: firmLock(9)}

	forged, err := proto.Marshal(&pb.AuthResp{UserId: owner, PermissionIds: []int32{1, 2, 3, 4, 5, 6, 7, 8, 9}, ActedFor: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		userMetadataKey, base64.StdEncoding.EncodeToString(forged),
		principal.ScopeKey("org_id"), otherID,
		principal.ScopeKey("user_id"), owner,
		principal.OrgScopeHeader, "other",
	))
	who, err := h.ResolveUser(ctx, &pb.ResolveUserReq{UserId: adviser, Headers: orgHeaders("firm")})
	if err != nil {
		t.Fatalf("ResolveUser: %v", err)
	}
	if got := sortedIDs32(who.GetPermissionIds()); !slices.Equal(got, []int32{1, 2, 3}) {
		t.Errorf("holds %v, want the adviser's staff role in the firm [1 2 3]", got)
	}
	if who.GetUserId() != adviser || who.GetScopes()["user_id"] != adviser || who.GetScopes()["org_id"] != firmID {
		t.Errorf("answered user %q scopes %v, want the adviser in the firm", who.GetUserId(), who.GetScopes())
	}

	// With no organization named, the incoming selector does not pick one:
	// the adviser belongs to two, so none is chosen and nothing org-scoped
	// counts.
	who, err = h.ResolveUser(ctx, &pb.ResolveUserReq{UserId: adviser})
	if err != nil {
		t.Fatalf("ResolveUser, no organization: %v", err)
	}
	if who.GetScopes()["org_id"] != "" || len(who.GetPermissionIds()) != 0 {
		t.Errorf("no organization named: scopes %v, permissions %v — the forwarded selector chose one", who.GetScopes(), who.GetPermissionIds())
	}
}

// A disabled account is acted for by nobody, in any organization.
func TestResolveUser_ADisabledAccountIsRefusedEverywhere(t *testing.T) {
	withOrgSeams(t)
	h := &AuthServiceHandler{Query: newFirmWorld(), Lock: firmLock(9)}
	for _, org := range []string{"", "firm"} {
		if _, err := h.ResolveUser(context.Background(), &pb.ResolveUserReq{UserId: disabled, Headers: orgHeaders(org)}); err == nil {
			t.Errorf("a disabled account was answered in %q", org)
		}
	}
}

// The firm's invitations through the acting path. The owner's invitation to
// the wildcard role is recorded as that, and is accepted after the lock grew
// by the methods a release added; the adviser's to the client's role is
// recorded as what it carried. A role that stopped being a wildcard, or grew
// past the list, refuses its pending invitations.
func TestResolveUser_InvitationsMadeActingForAPersonOutliveTheLockGrowing(t *testing.T) {
	withOrgSeams(t)
	w := newFirmWorld()
	h := &AuthServiceHandler{Query: w, Lock: firmLock(9)}

	ownerCtx, _ := actingAs(t, h, owner, "firm", true)
	ownerSnap, err := h.checkMayGrantRole(ownerCtx, "owner")
	if err != nil || ownerSnap != "owner:*" {
		t.Fatalf("the owner inviting an owner: snapshot %q, %v; want owner:*", ownerSnap, err)
	}
	adviserCtx, _ := actingAs(t, h, adviser, "firm", true)
	clientSnap, err := h.checkMayGrantRole(adviserCtx, "client")
	if err != nil || clientSnap != "client:1" {
		t.Fatalf("the adviser inviting a client: snapshot %q, %v; want client:1", clientSnap, err)
	}

	h.Lock = firmLock(40) // a release added methods
	for snap, role := range map[string]string{ownerSnap: "owner", clientSnap: "client"} {
		if err := h.checkRoleWithinSnapshot(context.Background(), role, snap); err != nil {
			t.Errorf("%s after the lock grew: %v", snap, err)
		}
	}

	w.roles["client"] = worldRole{perms: []int32{1, 7}}
	if err := h.checkRoleWithinSnapshot(context.Background(), "client", clientSnap); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("the client's role grew past its invitation: %v, want FailedPrecondition", err)
	}
	w.roles["owner"] = worldRole{perms: []int32{1}}
	if err := h.checkRoleWithinSnapshot(context.Background(), "owner", ownerSnap); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("the owner's role stopped granting everything: %v, want FailedPrecondition", err)
	}
	if err := h.checkRoleWithinSnapshot(context.Background(), "client", ownerSnap); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a wildcard snapshot of another role accepted for the client's: %v", err)
	}
}
