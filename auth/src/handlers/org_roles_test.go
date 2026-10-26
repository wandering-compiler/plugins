package handlers

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// org_roles: an organization's own roles, composed from the lock's
// permissions under the role ceiling.

// orgRolesMock is one organization's catalogue — two shared roles, a bot's
// role and one custom role — with the writes recorded.
type orgRolesMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	rows      []*pb.OrgRoleRow
	rolePerms map[string][]int32
	grants    int64               // CountRoleGrants
	scoped    []*pb.OrgScopedRole // ListOrgScopedRoles: every organization's
	askedOrg  string

	created  *pb.CreateRoleReq
	claimed  *pb.ClaimRoleForOrgReq
	labelled *pb.UpdateOrgRoleLabelReq
	added    []int32
	removed  []int32
	deleted  string
}

func newOrgRoles() (*AuthServiceHandler, *orgRolesMock) {
	m := &orgRolesMock{
		rows: []*pb.OrgRoleRow{
			{Id: "r-admin", Name: "org-admin"},
			{Id: "r-viewer", Name: "org-viewer"},
			{Id: "r-ci", Name: "ci-push", TokenType: pb.TokenType_TOKEN_TYPE_API},
			{Id: "r-dev", Name: "developer-a1b2c3", DisplayName: "Developer", Custom: true},
		},
		rolePerms: map[string][]int32{"r-admin": {1, 2, 3, 4}, "r-viewer": {1}, "r-ci": {5}, "r-dev": {1, 2}},
	}
	lock := &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}}
	return &AuthServiceHandler{Query: m, Mutation: m, Lock: lock}, m
}

func (m *orgRolesMock) ListOrgRoleRows(_ context.Context, in *pb.ListOrgRoleRowsReq, _ ...grpc.CallOption) (*pb.ListOrgRoleRowsResp, error) {
	m.askedOrg = in.GetOrgId()
	return &pb.ListOrgRoleRowsResp{Roles: m.rows}, nil
}

func (m *orgRolesMock) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	out := &pb.ListRoleGrantsResp{}
	for _, r := range m.rows {
		out.Grants = append(out.Grants, &pb.RoleGrant{RoleId: r.GetId(), PermissionIds: m.rolePerms[r.GetId()]})
	}
	return out, nil
}

func (m *orgRolesMock) ListRoles(context.Context, *pb.ListRolesReq, ...grpc.CallOption) (*pb.ListRolesResp, error) {
	return &pb.ListRolesResp{}, nil
}

func (m *orgRolesMock) CountRoleGrants(context.Context, *pb.CountRoleGrantsReq, ...grpc.CallOption) (*pb.CountRoleGrantsResp, error) {
	return &pb.CountRoleGrantsResp{Count: m.grants}, nil
}

func (m *orgRolesMock) CreateRole(_ context.Context, in *pb.CreateRoleReq, _ ...grpc.CallOption) (*pb.CreateRoleResp, error) {
	m.created = in
	return &pb.CreateRoleResp{Role: &pb.Role{Id: "r-new", Name: in.GetName()}}, nil
}

func (m *orgRolesMock) ClaimRoleForOrg(_ context.Context, in *pb.ClaimRoleForOrgReq, _ ...grpc.CallOption) (*pb.ClaimRoleForOrgResp, error) {
	m.claimed = in
	return &pb.ClaimRoleForOrgResp{RoleId: in.GetRoleId()}, nil
}

func (m *orgRolesMock) UpdateOrgRoleLabel(_ context.Context, in *pb.UpdateOrgRoleLabelReq, _ ...grpc.CallOption) (*pb.UpdateOrgRoleLabelResp, error) {
	m.labelled = in
	return &pb.UpdateOrgRoleLabelResp{RoleId: in.GetRoleId()}, nil
}

func (m *orgRolesMock) AddPermissionToRole(_ context.Context, in *pb.AddPermissionToRoleReq, _ ...grpc.CallOption) (*pb.AddPermissionToRoleResp, error) {
	m.added = append(m.added, in.GetPermissionId())
	return &pb.AddPermissionToRoleResp{}, nil
}

func (m *orgRolesMock) RemovePermissionFromRole(_ context.Context, in *pb.RemovePermissionFromRoleReq, _ ...grpc.CallOption) (*pb.RemovePermissionFromRoleResp, error) {
	m.removed = append(m.removed, in.GetPermissionId())
	return &pb.RemovePermissionFromRoleResp{}, nil
}

func (m *orgRolesMock) DeleteRole(_ context.Context, in *pb.DeleteRoleReq, _ ...grpc.CallOption) (*pb.DeleteRoleResp, error) {
	m.deleted = in.GetRoleId()
	return &pb.DeleteRoleResp{RoleId: in.GetRoleId()}, nil
}

func (m *orgRolesMock) wrote() bool {
	return m.created != nil || m.claimed != nil || m.labelled != nil || len(m.added)+len(m.removed) > 0 || m.deleted != ""
}

func orgCaller(held ...int32) context.Context {
	return withHeldPermissions(ctxWithCallerInOrg("u1", "org-1"), "u1", held...)
}

// The catalogue every org-role grant reads is the organization's — asked for
// by its id — and a bot's role in it is offered to nobody and refused by name.
func TestOrgRoleCatalogue_IsTheOrganizationsAndHoldsNoBotRole(t *testing.T) {
	h, m := newOrgRoles()
	ctx := orgCaller(1, 2, 3, 4, 5)
	resp, err := h.ListAssignableRoles(ctx, &pb.ListAssignableRolesReq{})
	if err != nil {
		t.Fatal(err)
	}
	if m.askedOrg != "org-1" {
		t.Errorf("catalogue asked for org %q, want org-1", m.askedOrg)
	}
	names := map[string]string{}
	for _, r := range resp.GetRoles() {
		names[r.GetName()] = r.GetDisplayName()
	}
	if _, ok := names["ci-push"]; ok || len(names) != 3 || names["developer-a1b2c3"] != "Developer" {
		t.Errorf("offered %v", names)
	}
	if _, err := h.roleIDByName(ctx, "org-1", "ci-push"); detailOf(t, err).GetCode() != CodeRoleIsForBots {
		t.Errorf("a bot's role by name: %v", err)
	}
	if id, err := h.roleIDByName(ctx, "org-1", "developer-a1b2c3"); err != nil || id != "r-dev" {
		t.Errorf("custom role by name: %q %v", id, err)
	}
}

// ListOrgRoles shows what each role carries and whether the caller covers it.
func TestListOrgRoles_CarriesPermissionsAndTheCeiling(t *testing.T) {
	h, _ := newOrgRoles()
	resp, err := h.ListOrgRoles(orgCaller(1, 2), &pb.ListOrgRolesReq{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*pb.OrgRole{}
	for _, r := range resp.GetRoles() {
		got[r.GetId()] = r
	}
	if _, ok := got["r-ci"]; ok || len(got) != 3 {
		t.Fatalf("roles = %v", resp.GetRoles())
	}
	if r := got["r-dev"]; !r.GetCustom() || !r.GetGrantable() || len(r.GetPermissionIds()) != 2 {
		t.Errorf("r-dev = %v", r)
	}
	if r := got["r-admin"]; r.GetCustom() || r.GetGrantable() {
		t.Errorf("r-admin = %v", r)
	}
}

// A new role carries only allocated permissions the author holds, at least
// one; it is created, claimed for the organization and given each permission.
func TestCreateOrgRole(t *testing.T) {
	refusals := []struct {
		name  string
		perms []int32
		code  string
	}{
		{"none", nil, CodeOrgRoleNoPermissions},
		{"not in the lock", []int32{1, 99}, CodeOrgRoleUnknownPermission},
		{"not held", []int32{1, 3}, CodeRoleAboveCaller},
	}
	for _, c := range refusals {
		h, m := newOrgRoles()
		_, err := h.CreateOrgRole(orgCaller(1, 2), &pb.CreateOrgRoleReq{DisplayName: "Dev", PermissionIds: c.perms})
		if detailOf(t, err).GetCode() != c.code {
			t.Errorf("%s: %v", c.name, err)
		}
		if m.wrote() {
			t.Errorf("%s: a refusal wrote", c.name)
		}
	}
	h, m := newOrgRoles()
	if _, err := h.CreateOrgRole(orgCaller(1, 2), &pb.CreateOrgRoleReq{DisplayName: " "}); detailOf(t, err).GetCode() != CodeOrgRoleNoName {
		t.Errorf("blank name: %v", err)
	}
	resp, err := h.CreateOrgRole(orgCaller(1, 2), &pb.CreateOrgRoleReq{DisplayName: "Front-end Dev ✓", PermissionIds: []int32{2, 1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^front-end-dev-[0-9a-f]{6}$`).MatchString(resp.GetName()) || m.created.GetName() != resp.GetName() {
		t.Errorf("name = %q", resp.GetName())
	}
	if m.claimed.GetOrgId() != "org-1" || m.claimed.GetRoleId() != "r-new" || m.claimed.GetDisplayName() != "Front-end Dev ✓" {
		t.Errorf("claimed = %v", m.claimed)
	}
	if len(m.added) != 2 || m.added[0] != 1 || m.added[1] != 2 {
		t.Errorf("added = %v", m.added)
	}
}

// An update applies the difference; only the organization's own role, and
// only by someone who covers it as it is.
func TestUpdateOrgRole(t *testing.T) {
	h, m := newOrgRoles()
	if _, err := h.UpdateOrgRole(orgCaller(1, 2, 3, 4), &pb.UpdateOrgRoleReq{RoleId: "r-admin", DisplayName: "x", PermissionIds: []int32{1}}); detailOf(t, err).GetCode() != CodeOrgRoleNotOwn {
		t.Errorf("a shared role: %v", err)
	}
	if _, err := h.UpdateOrgRole(orgCaller(1, 3), &pb.UpdateOrgRoleReq{RoleId: "r-dev", DisplayName: "x", PermissionIds: []int32{1}}); detailOf(t, err).GetCode() != CodeRoleAboveCaller {
		t.Errorf("a role above the caller: %v", err)
	}
	if m.wrote() {
		t.Fatal("a refusal wrote")
	}
	if _, err := h.UpdateOrgRole(orgCaller(1, 2, 3), &pb.UpdateOrgRoleReq{RoleId: "r-dev", DisplayName: "Developer", Description: "d", PermissionIds: []int32{1, 3}}); err != nil {
		t.Fatal(err)
	}
	if m.labelled.GetOrgId() != "org-1" || m.labelled.GetDescription() != "d" {
		t.Errorf("labelled = %v", m.labelled)
	}
	if len(m.added) != 1 || m.added[0] != 3 || len(m.removed) != 1 || m.removed[0] != 2 {
		t.Errorf("added = %v, removed = %v", m.added, m.removed)
	}
}

// A role still held is not deleted.
func TestDeleteOrgRole(t *testing.T) {
	h, m := newOrgRoles()
	m.grants = 2
	if _, err := h.DeleteOrgRole(orgCaller(1, 2), &pb.DeleteOrgRoleReq{RoleId: "r-dev"}); detailOf(t, err).GetCode() != CodeOrgRoleInUse || m.deleted != "" {
		t.Errorf("held: %v", err)
	}
	m.grants = 0
	if _, err := h.DeleteOrgRole(orgCaller(1, 2), &pb.DeleteOrgRoleReq{RoleId: "r-dev"}); err != nil || m.deleted != "r-dev" {
		t.Errorf("free: %v", err)
	}
	if _, err := h.DeleteOrgRole(orgCaller(1, 2), &pb.DeleteOrgRoleReq{RoleId: "r-viewer"}); status.Code(err) != codes.NotFound {
		t.Errorf("a shared role: %v", err)
	}
}

// --- the last superadmin -----------------------------------------------

type superadminMock struct {
	*membershipRoleMock
	others     int64    // other members' direct wildcard grants (CountOtherOrgSuperadmins)
	teamOthers int64    // other members' wildcard team roles (CountOtherOrgTeamSuperadmins)
	teamRoles  []string // what u2 holds in org-1 through a team
}

func (m *superadminMock) GetUserTeamRoleGrants(_ context.Context, in *pb.GetUserTeamRoleGrantsReq, _ ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	if in.GetUserId() != "u2" || in.GetOrgId() != "org-1" || len(m.teamRoles) == 0 {
		return noTeamRoles()
	}
	out := &pb.GetUserTeamRoleGrantsResp{}
	for _, id := range m.teamRoles {
		out.Grants = append(out.Grants, &pb.RoleGrant{RoleId: id, AllPermissions: id == "r-super"})
	}
	return out, nil
}

func (m *superadminMock) CountOtherOrgTeamSuperadmins(context.Context, *pb.CountOtherOrgTeamSuperadminsReq, ...grpc.CallOption) (*pb.CountOtherOrgTeamSuperadminsResp, error) {
	return &pb.CountOtherOrgTeamSuperadminsResp{Count: m.teamOthers}, nil
}

func (m *superadminMock) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	return &pb.ListRoleGrantsResp{Grants: []*pb.RoleGrant{
		{RoleId: "r-super", AllPermissions: true},
		{RoleId: "r-admin", PermissionIds: []int32{1}},
	}}, nil
}

func (m *superadminMock) CountOtherOrgSuperadmins(context.Context, *pb.CountOtherOrgSuperadminsReq, ...grpc.CallOption) (*pb.CountOtherOrgSuperadminsResp, error) {
	return &pb.CountOtherOrgSuperadminsResp{Count: m.others}, nil
}

// An organization keeps a superadmin: the last one is neither removed nor
// moved to a lesser role — unless another member is one, or the new role is a
// wildcard too. Nobody is exempt: organization ownership once counted as a
// superadmin here and let the last one leave; it grants nothing now.
func TestRefuseLastSuperadmin(t *testing.T) {
	_, mm := newMembershipRoleHandler("r-super")
	m := &superadminMock{membershipRoleMock: mm}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	mem := &pb.OrgMembership{Id: "mem-1", UserId: "u2", OrgId: "org-1"}
	ctx := context.Background()

	if err := h.refuseLastSuperadmin(ctx, mem, ""); detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Errorf("removal: %v", err)
	}
	if err := h.refuseLastSuperadmin(ctx, mem, "r-admin"); detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Errorf("demotion: %v", err)
	}
	if err := h.refuseLastSuperadmin(ctx, mem, "r-super"); err != nil {
		t.Errorf("to another wildcard: %v", err)
	}
	m.others = 1
	if err := h.refuseLastSuperadmin(ctx, mem, ""); err != nil {
		t.Errorf("another superadmin: %v", err)
	}
	m.others = 0
	mm.memberOrgRoles = []string{"r-admin"}
	if err := h.refuseLastSuperadmin(ctx, mem, ""); err != nil {
		t.Errorf("not a superadmin: %v", err)
	}
}

// The last superadmin cannot demote or remove THEMSELVES — the case an
// organization's creator is in: they made it, hold its only wildcard role, and
// with ownership gone nothing else keeps it administered. Through the
// business methods, so the refusal is shown to come before either write.
func TestLastSuperadmin_CannotDemoteOrRemoveThemselves(t *testing.T) {
	_, mm := newMembershipRoleHandler("r-super")
	m := &superadminMock{membershipRoleMock: mm}
	mm.all = append(mm.all, &pb.Role{Id: "r-super", Name: "org-super"})
	mm.orgScoped = append(mm.orgScoped, &pb.OrgScopedRole{Id: "r-super", Name: "org-super"})
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: wildcardLock()}
	// u2 is the member of mem-1 and the caller, holding everything the lock has.
	self := inOrg(withHeldPermissions(context.Background(), "u2", 1, 2, 3), "org-1")

	_, err := h.UpdateOrgMembershipRole(self, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-admin"})
	if status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Fatalf("self-demotion of the last superadmin: %v", err)
	}
	_, err = h.RemoveOrgMembership(self, &pb.RemoveOrgMembershipReq{Id: "mem-1"})
	if status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Fatalf("self-removal of the last superadmin: %v", err)
	}
	if mm.updated != nil || mm.deleted != nil {
		t.Fatalf("a refused request wrote: updated=%v deleted=%v", mm.updated, mm.deleted)
	}

	// Control: with another superadmin in the organization, both go through.
	m.others = 1
	if _, err := h.UpdateOrgMembershipRole(self, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-admin"}); err != nil {
		t.Fatalf("self-demotion beside another superadmin: %v", err)
	}
}

// A wildcard role held through a TEAM makes a superadmin on both sides of the
// rule, as checkMayManageMembership already counts team roles for the ceiling.
func TestRefuseLastSuperadmin_TeamHeldWildcards(t *testing.T) {
	ctx := context.Background()
	mem := &pb.OrgMembership{Id: "mem-1", UserId: "u2", OrgId: "org-1"}

	// The member: a superadmin only through a team. Removing them ends the
	// team membership too, so it is refused; a role change leaves the team's
	// wildcard in place, so it is not.
	_, mm := newMembershipRoleHandler("r-admin")
	m := &superadminMock{membershipRoleMock: mm, teamRoles: []string{"r-super"}}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if err := h.refuseLastSuperadmin(ctx, mem, ""); detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Errorf("removing the last superadmin, a superadmin through a team: %v", err)
	}
	if err := h.refuseLastSuperadmin(ctx, mem, "r-admin"); err != nil {
		t.Errorf("a role change keeps the team's wildcard: %v", err)
	}

	// The others: the member is the last DIRECT superadmin, and another member
	// holds a wildcard through a team — the organization keeps a superadmin.
	_, mm = newMembershipRoleHandler("r-super")
	m = &superadminMock{membershipRoleMock: mm, teamOthers: 1}
	h = &AuthServiceHandler{Query: m, Mutation: m}
	if err := h.refuseLastSuperadmin(ctx, mem, ""); err != nil {
		t.Errorf("another member is a superadmin through a team: %v", err)
	}
	m.teamOthers = 0
	if err := h.refuseLastSuperadmin(ctx, mem, ""); detailOf(t, err).GetCode() != CodeLastSuperadmin {
		t.Errorf("control, nobody else: %v", err)
	}
}

// Who counts as "another superadmin" is decided in SQL, so the statements
// are what is asserted: a grant counts only when it, its role, the membership
// (and, through a team, the team, its role grant and the team membership) are
// live, and the account is neither disabled nor erased. A disabled superadmin
// holds no working credential; counting one let the last ACTIVE superadmin
// leave. **Unit (statement) only** — no database runs here.
func TestOtherSuperadminCounts_OnlyActiveLiveAccounts(t *testing.T) {
	q := authProtos(t)["queries/auth_query.proto"]
	for marker, want := range map[string][]string{
		"rpc CountOtherOrgSuperadmins(": {
			"ur.revoked_at IS NULL", "r.deleted_at IS NULL", "r.all_permissions = TRUE",
			"m.removed_at IS NULL", "ur.user_id <> :user_id",
			"JOIN @module.User u ON u.id = ur.user_id",
			"?feature(user_admin) u.disabled_at IS NULL", "?feature(user_admin) u.erased_at IS NULL",
		},
		"rpc CountOtherOrgTeamSuperadmins(": {
			"tm.removed_at IS NULL", "t.deleted_at IS NULL", "tr.revoked_at IS NULL",
			"r.deleted_at IS NULL", "r.all_permissions = TRUE", "m.removed_at IS NULL",
			"m.created_at <= tm.created_at", "tm.user_id <> :user_id",
			"JOIN @module.User u ON u.id = tm.user_id",
			"?feature(user_admin) u.disabled_at IS NULL", "?feature(user_admin) u.erased_at IS NULL",
		},
	} {
		body := dqlText(methodDQL(t, q, marker))
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("%s does not say %q:\n%s", marker, w, body)
			}
		}
	}
}

// Another organization's custom role, named here, is the typo answer — not
// "realm-wide", which would say some other company has a role by that name.
func TestRoleIDByName_AnotherOrganizationsRoleIsUnknown(t *testing.T) {
	h, m := newOrgRoles()
	m.scoped = []*pb.OrgScopedRole{{Id: "r-x", Name: "their-role-abc123"}}
	if _, err := h.roleIDByName(orgCaller(), "org-1", "their-role-abc123"); detailOf(t, err).GetCode() != CodeUnknownOrgRole {
		t.Errorf("another organization's role: %v", err)
	}
}

func (m *orgRolesMock) ListOrgScopedRoles(context.Context, *pb.ListOrgScopedRolesReq, ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: m.scoped}, nil
}
