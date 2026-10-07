package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// withHeldPermissions adds the gateway's x-w17-user envelope to ctx — the
// permission set Authenticate resolved for the request, which is what the role
// ceiling reads. Keeps whatever scopes ctx already carries.
func withHeldPermissions(ctx context.Context, userID string, held ...int32) context.Context {
	raw, err := proto.Marshal(&pb.AuthResp{UserId: userID, PermissionIds: held})
	if err != nil {
		panic(err)
	}
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set(userMetadataKey, base64.StdEncoding.EncodeToString(raw))
	return metadata.NewIncomingContext(ctx, md)
}

func TestRoleWithinCeiling(t *testing.T) {
	held := map[int32]bool{1: true, 2: true, 3: true}
	lock := &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3}}
	wider := &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}}

	cases := []struct {
		name string
		g    *pb.RoleGrant
		lock *acllock.Lock
		want bool
	}{
		{"a role you hold everything of", &pb.RoleGrant{PermissionIds: []int32{1, 3}}, lock, true},
		{"a role that carries nothing", &pb.RoleGrant{}, lock, true},
		{"one permission you lack", &pb.RoleGrant{PermissionIds: []int32{1, 4}}, lock, false},
		{"a wildcard over a catalogue you hold whole", &pb.RoleGrant{AllPermissions: true}, lock, true},
		{"a wildcard over a catalogue you do not", &pb.RoleGrant{AllPermissions: true}, wider, false},
		// The case the empty expansion would get backwards: nil is a subset of
		// everything, so without the explicit refusal the most powerful role
		// would be grantable by anyone.
		{"a wildcard with no lock to expand", &pb.RoleGrant{AllPermissions: true}, nil, false},
		// A domain with no endpoint catalogue: its lock exists and allocates
		// nothing, so "everything" is nothing — known, and within anyone's
		// ceiling. It used to read as unexpandable, and an invitation to such a
		// role could never be accepted (reported by a consumer, 2026-10-06).
		{"a wildcard over an empty catalogue", &pb.RoleGrant{AllPermissions: true}, &acllock.Lock{Version: 1}, true},
	}
	for _, c := range cases {
		carried := expandRoleGrant(c.g, c.lock)
		if got := carried != nil && allHeld(carried, held); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The reported hole: anyone who may invite could invite at org-admin. Refused
// BEFORE anything is written — the catalogue mock has no mutation client, so a
// write would panic rather than pass.
func TestInviteToOrg_RefusesARoleAboveTheInviter(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}}
	h := &AuthServiceHandler{Query: m}

	ctx := withHeldPermissions(whoAmICtx("u1", "org-1"), "u1", 1, 2)
	_, err := h.InviteToOrg(ctx, &pb.InviteToOrgReq{Email: "x@example.com", Role: "org-admin"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

// Control, and the half of the rule that is not "a role you hold": a role the
// inviter does NOT hold passes when they hold everything it carries. A ceiling
// that refused every role but the inviter's own would pass the test above.
func TestCheckMayGrantRole_ARoleYouDoNotHoldButCover(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-viewer": {1}}
	h := &AuthServiceHandler{Query: m}

	ctx := withHeldPermissions(context.Background(), "u1", 1, 2)
	if _, err := h.checkMayGrantRole(ctx, "r-viewer"); err != nil {
		t.Errorf("a role inside the ceiling was refused: %v", err)
	}
	if _, err := h.checkMayGrantRole(ctx, "r-admin"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a role above the ceiling: code = %v, want PermissionDenied", status.Code(err))
	}
}

// The picker offers what the invitation accepts — the same function decides
// both, and this holds it to that.
func TestListAssignableRoles_OffersOnlyRolesWithinTheCeiling(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-worker": {1, 2}, "r-viewer": {1}}
	h := &AuthServiceHandler{Query: m}

	resp, err := h.ListAssignableRoles(withHeldPermissions(context.Background(), "u1", 1, 2), &pb.ListAssignableRolesReq{})
	if err != nil {
		t.Fatalf("ListAssignableRoles: %v", err)
	}
	got := map[string]bool{}
	for _, r := range resp.GetRoles() {
		got[r.GetName()] = true
	}
	if got["org-admin"] {
		t.Error("org-admin was offered to someone who does not hold all of it")
	}
	if !got["org-worker"] || !got["org-viewer"] {
		t.Errorf("offered %v, want org-worker and org-viewer", got)
	}
}

// No resolved permissions — a call past the gateway — must refuse, not read as
// "nothing to exceed".
func TestCheckMayGrantRole_NoEnvelopeFailsClosed(t *testing.T) {
	h := &AuthServiceHandler{Query: newRoleCatalogue()}
	if _, err := h.checkMayGrantRole(whoAmICtx("u1", "org-1"), "r-viewer"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
}

// The sharpest instance: a bot's token acts with its role, so a role above the
// operator is a credential for what the operator may not do. On this console:
// an org-admin, who may not push, minting a ci-push bot that can.
func TestCreateBot_RefusesARoleAboveTheOperator(t *testing.T) {
	m := &botAdminMock{
		apiRoles:  []*pb.ApiRealmRole{{Id: "role-ci"}},
		rolePerms: map[string][]int32{"role-ci": {7, 50}},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m}

	ctx := withHeldPermissions(whoAmICtx("admin-1", "org-1"), "admin-1", 7)
	_, err := h.CreateBot(ctx, &pb.CreateBotReq{Email: "ci@example.com", RoleId: "role-ci"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if m.created {
		t.Error("the bot was created before the ceiling was checked")
	}
}

func TestListBotRoles_OffersOnlyRolesWithinTheCeiling(t *testing.T) {
	m := &botAdminMock{
		apiRoles:  []*pb.ApiRealmRole{{Id: "role-ci"}, {Id: "role-fetch"}},
		rolePerms: map[string][]int32{"role-ci": {7, 50}, "role-fetch": {7}},
	}
	h := &AuthServiceHandler{Query: m}

	resp, err := h.ListBotRoles(withHeldPermissions(whoAmICtx("admin-1", "org-1"), "admin-1", 7), &pb.ListBotRolesReq{})
	if err != nil {
		t.Fatalf("ListBotRoles: %v", err)
	}
	if len(resp.GetRoles()) != 1 || resp.GetRoles()[0].GetId() != "role-fetch" {
		t.Errorf("offered %v, want only role-fetch", resp.GetRoles())
	}
}

// The snapshot is what the ceiling checked, in one canonical spelling — sorted,
// so the same role always reads the same.
func TestCheckMayGrantRole_ReturnsTheSnapshotItChecked(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-viewer": {3, 1}}
	h := &AuthServiceHandler{Query: m}

	snap, err := h.checkMayGrantRole(withHeldPermissions(context.Background(), "u1", 1, 2, 3), "r-viewer")
	if err != nil {
		t.Fatalf("checkMayGrantRole: %v", err)
	}
	if snap != "r-viewer:1,3" {
		t.Errorf("snapshot = %q, want r-viewer:1,3", snap)
	}
}

// Accept writes the grant LATER than the ceiling was checked, against a live
// catalogue. Same role, or narrower, is what the inviter covered; wider, a
// different role under the name, or no snapshot at all is not.
func TestCheckRoleWithinSnapshot(t *testing.T) {
	m := newRoleCatalogue()
	m.rolePerms = map[string][]int32{"r-viewer": {1, 2}}
	h := &AuthServiceHandler{Query: m}
	ctx := context.Background()

	cases := []struct {
		name     string
		roleID   string
		snapshot string
		ok       bool
	}{
		{"unchanged", "r-viewer", "r-viewer:1,2", true},
		{"narrowed since", "r-viewer", "r-viewer:1,2,3", true},
		{"widened since", "r-viewer", "r-viewer:1", false},
		{"another role under the name", "r-viewer", "r-admin:1,2", false},
		{"made before the ceiling existed", "r-viewer", "", false},
		{"malformed", "r-viewer", "r-viewer:1,x", false},
	}
	for _, c := range cases {
		err := h.checkRoleWithinSnapshot(ctx, c.roleID, c.snapshot)
		if c.ok && err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
		if !c.ok && status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", c.name, status.Code(err))
		}
	}
}

// Through the accept path, asserted on the writes: a role widened after the
// invitation was sent grants nothing — no membership, no role.
func TestAcceptOrgInvite_RefusesARoleWidenedSinceTheInvitation(t *testing.T) {
	withRealSeams(t)
	for name, m := range map[string]*inviteTokenMock{
		"widened": {pendingEmail: "", accountEmail: "a@example.com", snapshot: "role-1:1", livePerms: []int32{1, 2}},
		"legacy":  {pendingEmail: "", accountEmail: "a@example.com", legacy: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := &AuthServiceHandler{Query: m, Mutation: m}
			_, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "secret"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition (err=%v)", status.Code(err), err)
			}
			if m.addedMembership || m.assignedOrg != "" {
				t.Error("the grant was written for a role the inviter never covered")
			}
		})
	}
}

// The snapshot an invitation stores for a wildcard role in an empty-catalogue
// domain is accepted against the same role at acceptance.
func TestRoleSnapshot_AWildcardOverAnEmptyCatalogueRoundTrips(t *testing.T) {
	carried := expandRoleGrant(&pb.RoleGrant{AllPermissions: true}, &acllock.Lock{Version: 1})
	if carried == nil {
		t.Fatal("a wildcard over an empty catalogue expanded to nil (unexpandable)")
	}
	snap := encodeRoleSnapshot("r-tenant-admin", carried)
	_, snapPerms, ok := decodeRoleSnapshot(snap)
	if !ok {
		t.Fatalf("decode %q failed", snap)
	}
	if !allHeld(carried, snapPerms) {
		t.Fatalf("the role no longer fits its own snapshot %q", snap)
	}
}
