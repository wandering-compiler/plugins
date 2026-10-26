package handlers

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// teams: groups of an organization's members that hold roles.

// The other features' fakes meet teams through the seams it appends to (this
// package compiles every feature at once): none of them has a team, so a
// member holds no team role and the cascades end nothing.

func noTeamRoles() (*pb.GetUserTeamRoleGrantsResp, error) {
	return nil, status.Error(codes.NotFound, "no team role")
}

func (m *permMock) GetUserTeamRoleGrants(context.Context, *pb.GetUserTeamRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	return noTeamRoles()
}

func (o *orgTables) GetUserTeamRoleGrants(context.Context, *pb.GetUserTeamRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	return noTeamRoles()
}

func (o *orgTables) EndUserTeamMemberships(context.Context, *pb.EndUserTeamMembershipsReq, ...grpc.CallOption) (*pb.EndUserTeamMembershipsResp, error) {
	return &pb.EndUserTeamMembershipsResp{}, nil
}

func (o *orgTables) EndTeamsOfOrg(context.Context, *pb.EndTeamsOfOrgReq, ...grpc.CallOption) (*pb.EndTeamsOfOrgResp, error) {
	return &pb.EndTeamsOfOrgResp{}, nil
}

func (m *membershipRoleMock) GetUserTeamRoleGrants(context.Context, *pb.GetUserTeamRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	return noTeamRoles()
}

func (m *membershipRoleMock) EndUserTeamMemberships(context.Context, *pb.EndUserTeamMembershipsReq, ...grpc.CallOption) (*pb.EndUserTeamMembershipsResp, error) {
	return &pb.EndUserTeamMembershipsResp{}, nil
}

func (o *orgTables) CountOtherOrgTeamSuperadmins(context.Context, *pb.CountOtherOrgTeamSuperadminsReq, ...grpc.CallOption) (*pb.CountOtherOrgTeamSuperadminsResp, error) {
	return &pb.CountOtherOrgTeamSuperadminsResp{}, nil
}

func (m *membershipRoleMock) CountOtherOrgTeamSuperadmins(context.Context, *pb.CountOtherOrgTeamSuperadminsReq, ...grpc.CallOption) (*pb.CountOtherOrgTeamSuperadminsResp, error) {
	return &pb.CountOtherOrgTeamSuperadminsResp{}, nil
}

func (m *botAdminMock) GetUserTeamRoleGrants(context.Context, *pb.GetUserTeamRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	return noTeamRoles()
}

func (m *orgRolesMock) CountTeamRoleGrants(context.Context, *pb.CountTeamRoleGrantsReq, ...grpc.CallOption) (*pb.CountTeamRoleGrantsResp, error) {
	return &pb.CountTeamRoleGrantsResp{}, nil
}

// --- the grants -------------------------------------------------------------

// teamPermMock answers the narrower's queries plus a member's team roles in
// one organization.
type teamPermMock struct {
	*permMock
	teamOrg    string
	teamGrants []*pb.RoleGrant
	askedTeams bool
}

func (m *teamPermMock) GetUserTeamRoleGrants(_ context.Context, in *pb.GetUserTeamRoleGrantsReq, _ ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	m.askedTeams = true
	if in.GetOrgId() != m.teamOrg || len(m.teamGrants) == 0 {
		return nil, status.Error(codes.NotFound, "no team role")
	}
	return &pb.GetUserTeamRoleGrantsResp{Grants: m.teamGrants}, nil
}

// A team's role counts for a session acting in the team's organization — on
// top of what the member holds directly there.
func TestTeamGrants_CountForASessionInTheTeamsOrganization(t *testing.T) {
	m := &teamPermMock{permMock: &permMock{orgGrants: []*pb.RoleGrant{grant("role-a", 1)}}, teamOrg: "org-a", teamGrants: []*pb.RoleGrant{grant("role-team", 7)}}
	h := &AuthServiceHandler{Query: m}
	p := sessionPrincipal(grant("role-a", 1))

	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatal(err)
	}
	got := p.effectivePermissions(h.Lock)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if !reflect.DeepEqual(got, []int32{1, 7}) {
		t.Errorf("permissions = %v, want [1 7]", got)
	}
}

// ...and nowhere else: not in another organization, not without one, and not
// for an API token, whose ceiling stays its holder's api-realm roles.
func TestTeamGrants_CountNowhereElse(t *testing.T) {
	cases := []struct {
		name   string
		p      *authPrincipal
		scopes map[string]string
		asked  bool
	}{
		{"another organization", sessionPrincipal(), map[string]string{"org_id": "org-b"}, true},
		{"no organization", sessionPrincipal(), map[string]string{}, false},
		{"an API token", &authPrincipal{userID: "u1", realm: pb.TokenType_TOKEN_TYPE_API}, map[string]string{"org_id": "org-a"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &teamPermMock{permMock: &permMock{}, teamOrg: "org-a", teamGrants: []*pb.RoleGrant{grant("role-team", 7)}}
			h := &AuthServiceHandler{Query: m}
			if err := narrowGrantsToActiveOrg(context.Background(), h, c.p, c.scopes); err != nil {
				t.Fatal(err)
			}
			if got := c.p.effectivePermissions(h.Lock); len(got) != 0 {
				t.Errorf("a team's role counted: %v", got)
			}
			if m.askedTeams != c.asked {
				t.Errorf("teams asked = %v, want %v", m.askedTeams, c.asked)
			}
		})
	}
}

// A team's wildcard role is a superadmin in the team's organization: it
// expands from the lock like any other wildcard.
func TestTeamGrants_AWildcardExpandsFromTheLock(t *testing.T) {
	m := &teamPermMock{permMock: &permMock{}, teamOrg: "org-a", teamGrants: []*pb.RoleGrant{{RoleId: "role-super", AllPermissions: true}}}
	h := &AuthServiceHandler{Query: m, Lock: wildcardLock()}
	p := sessionPrincipal()
	if err := narrowGrantsToActiveOrg(context.Background(), h, p, map[string]string{"org_id": "org-a"}); err != nil {
		t.Fatal(err)
	}
	if got := p.effectivePermissions(h.Lock); len(got) == 0 {
		t.Error("a team's wildcard role granted nothing")
	}
}

// A failing team query fails the request closed, like the org query.
func TestTeamGrants_QueryErrorFailsClosed(t *testing.T) {
	m := &failingTeamPerm{permMock: &permMock{}}
	h := &AuthServiceHandler{Query: m}
	if err := narrowGrantsToActiveOrg(context.Background(), h, sessionPrincipal(), map[string]string{"org_id": "org-a"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want the query's error", err)
	}
}

type failingTeamPerm struct{ *permMock }

func (m *failingTeamPerm) GetUserTeamRoleGrants(context.Context, *pb.GetUserTeamRoleGrantsReq, ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}

// --- the endpoints ----------------------------------------------------------

type teamRow struct {
	org, name string
	deleted   bool
}

type teamMemberRow struct {
	team, user string
	ended      bool
}

type teamRoleRow struct {
	team, role string
	ended      bool
}

// teamStore is org-1's (and org-2's) teams, members and roles, with the
// organization's role catalogue: org-admin carries 1–4, org-worker 1–2,
// org-viewer 1, a bot's role 5.
type teamStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	teams   map[string]*teamRow
	members []*teamMemberRow
	roles   []*teamRoleRow
	// orgMembers — org-1's live members, true for a machine account.
	orgMembers map[string]bool
}

func newTeams() (*AuthServiceHandler, *teamStore) {
	s := &teamStore{
		teams: map[string]*teamRow{
			"t-dev":   {org: "org-1", name: "Developers"},
			"t-admin": {org: "org-1", name: "Admins"},
			"t-other": {org: "org-2", name: "Theirs"},
		},
		members: []*teamMemberRow{{team: "t-dev", user: "u2"}},
		roles: []*teamRoleRow{
			{team: "t-dev", role: "r-worker"},
			{team: "t-admin", role: "r-admin"},
		},
		orgMembers: map[string]bool{"u1": false, "u2": false, "u3": false, "bot": true},
	}
	lock := &acllock.Lock{Permissions: map[string]int{"a": 1, "b": 2, "c": 3, "d": 4, "e": 5}}
	return &AuthServiceHandler{Query: s, Mutation: s, Lock: lock}, s
}

var teamRolePerms = map[string][]int32{"r-admin": {1, 2, 3, 4}, "r-worker": {1, 2}, "r-viewer": {1}, "r-ci": {5}}

func (s *teamStore) ListOrgRoleRows(context.Context, *pb.ListOrgRoleRowsReq, ...grpc.CallOption) (*pb.ListOrgRoleRowsResp, error) {
	return &pb.ListOrgRoleRowsResp{Roles: []*pb.OrgRoleRow{
		{Id: "r-admin", Name: "org-admin"},
		{Id: "r-worker", Name: "org-worker"},
		{Id: "r-viewer", Name: "org-viewer"},
		{Id: "r-ci", Name: "ci-push", TokenType: pb.TokenType_TOKEN_TYPE_API},
	}}, nil
}

func (s *teamStore) ListRoleGrants(context.Context, *pb.ListRoleGrantsReq, ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	out := &pb.ListRoleGrantsResp{}
	for id, perms := range teamRolePerms {
		out.Grants = append(out.Grants, &pb.RoleGrant{RoleId: id, PermissionIds: perms})
	}
	return out, nil
}

func (s *teamStore) GetTeam(_ context.Context, in *pb.GetTeamReq, _ ...grpc.CallOption) (*pb.GetTeamResp, error) {
	t := s.teams[in.GetId()]
	if t == nil || t.deleted {
		return nil, status.Error(codes.NotFound, "no team")
	}
	return &pb.GetTeamResp{Id: in.GetId(), OrgId: t.org, Name: t.name}, nil
}

func (s *teamStore) ListTeamsByOrg(_ context.Context, in *pb.ListTeamsByOrgReq, _ ...grpc.CallOption) (*pb.ListTeamsByOrgResp, error) {
	out := &pb.ListTeamsByOrgResp{}
	for id, t := range s.teams {
		if t.org == in.GetOrgId() && !t.deleted {
			out.Teams = append(out.Teams, &pb.TeamRow{Id: id, Name: t.name})
		}
	}
	sort.Slice(out.Teams, func(i, j int) bool { return out.Teams[i].GetName() < out.Teams[j].GetName() })
	return out, nil
}

func (s *teamStore) ListTeamMembersByOrg(_ context.Context, in *pb.ListTeamMembersByOrgReq, _ ...grpc.CallOption) (*pb.ListTeamMembersByOrgResp, error) {
	out := &pb.ListTeamMembersByOrgResp{}
	for _, m := range s.members {
		if !m.ended && s.teams[m.team].org == in.GetOrgId() {
			out.Members = append(out.Members, &pb.TeamMemberRow{TeamId: m.team, UserId: m.user, Email: m.user + "@example.com"})
		}
	}
	return out, nil
}

func (s *teamStore) ListTeamRolesByOrg(_ context.Context, in *pb.ListTeamRolesByOrgReq, _ ...grpc.CallOption) (*pb.ListTeamRolesByOrgResp, error) {
	out := &pb.ListTeamRolesByOrgResp{}
	for _, r := range s.roles {
		if !r.ended && s.teams[r.team].org == in.GetOrgId() {
			out.Roles = append(out.Roles, &pb.TeamRoleRow{TeamId: r.team, RoleId: r.role})
		}
	}
	return out, nil
}

func (s *teamStore) ListTeamRoleIds(_ context.Context, in *pb.ListTeamRoleIdsReq, _ ...grpc.CallOption) (*pb.ListTeamRoleIdsResp, error) {
	out := &pb.ListTeamRoleIdsResp{}
	for _, r := range s.roles {
		if !r.ended && r.team == in.GetTeamId() {
			out.RoleIds = append(out.RoleIds, r.role)
		}
	}
	return out, nil
}

func (s *teamStore) GetOrgMemberAccount(_ context.Context, in *pb.GetOrgMemberAccountReq, _ ...grpc.CallOption) (*pb.GetOrgMemberAccountResp, error) {
	bot, ok := s.orgMembers[in.GetUserId()]
	if !ok || in.GetOrgId() != "org-1" {
		return nil, status.Error(codes.NotFound, "not a member")
	}
	u := &pb.User{Id: in.GetUserId()}
	if bot {
		u.Kind = pb.AccountKind_BOT
	}
	return &pb.GetOrgMemberAccountResp{User: u}, nil
}

func (s *teamStore) CreateTeam(_ context.Context, in *pb.CreateTeamReq, _ ...grpc.CallOption) (*pb.CreateTeamResp, error) {
	for _, t := range s.teams {
		if t.org == in.GetOrgId() && t.name == in.GetName() && !t.deleted {
			return nil, status.Error(codes.AlreadyExists, "duplicate")
		}
	}
	s.teams["t-new"] = &teamRow{org: in.GetOrgId(), name: in.GetName()}
	return &pb.CreateTeamResp{TeamId: "t-new"}, nil
}

func (s *teamStore) UpdateTeam(_ context.Context, in *pb.UpdateTeamReq, _ ...grpc.CallOption) (*pb.UpdateTeamResp, error) {
	t := s.teams[in.GetId()]
	if t == nil || t.org != in.GetOrgId() || t.deleted {
		return nil, status.Error(codes.NotFound, "no team")
	}
	t.name = in.GetName()
	return &pb.UpdateTeamResp{TeamId: in.GetId()}, nil
}

func (s *teamStore) DeleteTeam(_ context.Context, in *pb.DeleteTeamReq, _ ...grpc.CallOption) (*pb.DeleteTeamResp, error) {
	t := s.teams[in.GetId()]
	if t == nil || t.org != in.GetOrgId() || t.deleted {
		return nil, status.Error(codes.NotFound, "no team")
	}
	t.deleted = true
	return &pb.DeleteTeamResp{TeamId: in.GetId()}, nil
}

func (s *teamStore) AddTeamMember(_ context.Context, in *pb.AddTeamMemberReq, _ ...grpc.CallOption) (*pb.AddTeamMemberResp, error) {
	for _, m := range s.members {
		if m.team == in.GetTeamId() && m.user == in.GetUserId() && !m.ended {
			return nil, status.Error(codes.AlreadyExists, "duplicate")
		}
	}
	s.members = append(s.members, &teamMemberRow{team: in.GetTeamId(), user: in.GetUserId()})
	return &pb.AddTeamMemberResp{MemberId: "m-new"}, nil
}

func (s *teamStore) RemoveTeamMember(_ context.Context, in *pb.RemoveTeamMemberReq, _ ...grpc.CallOption) (*pb.RemoveTeamMemberResp, error) {
	for _, m := range s.members {
		if m.team == in.GetTeamId() && m.user == in.GetUserId() && !m.ended {
			m.ended = true
			return &pb.RemoveTeamMemberResp{MemberId: "m"}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "not a member")
}

func (s *teamStore) GrantTeamRole(_ context.Context, in *pb.GrantTeamRoleReq, _ ...grpc.CallOption) (*pb.GrantTeamRoleResp, error) {
	s.roles = append(s.roles, &teamRoleRow{team: in.GetTeamId(), role: in.GetRoleId()})
	return &pb.GrantTeamRoleResp{TeamRoleId: "tr-new"}, nil
}

func (s *teamStore) RevokeTeamRole(_ context.Context, in *pb.RevokeTeamRoleReq, _ ...grpc.CallOption) (*pb.RevokeTeamRoleResp, error) {
	for _, r := range s.roles {
		if r.team == in.GetTeamId() && r.role == in.GetRoleId() && !r.ended {
			r.ended = true
			return &pb.RevokeTeamRoleResp{TeamRoleId: "tr"}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "not held")
}

func (s *teamStore) liveRoles(team string) []string {
	var out []string
	for _, r := range s.roles {
		if r.team == team && !r.ended {
			out = append(out, r.role)
		}
	}
	sort.Strings(out)
	return out
}

func (s *teamStore) liveMembers(team string) []string {
	var out []string
	for _, m := range s.members {
		if m.team == team && !m.ended {
			out = append(out, m.user)
		}
	}
	sort.Strings(out)
	return out
}

// An org-worker: holds 1 and 2, so covers org-worker and org-viewer, not
// org-admin.
func workerCaller() context.Context { return orgCaller(1, 2) }

func TestListOrgTeams_AssemblesTeamsAndTheCeiling(t *testing.T) {
	h, _ := newTeams()
	resp, err := h.ListOrgTeams(workerCaller(), &pb.ListOrgTeamsReq{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*pb.OrgTeam{}
	for _, team := range resp.GetTeams() {
		got[team.GetName()] = team
	}
	if len(got) != 2 || got["Theirs"] != nil {
		t.Fatalf("teams = %v, want org-1's two", resp.GetTeams())
	}
	dev := got["Developers"]
	if len(dev.GetMembers()) != 1 || dev.GetMembers()[0].GetUserId() != "u2" || !reflect.DeepEqual(dev.GetRoleIds(), []string{"r-worker"}) || !dev.GetManageable() {
		t.Errorf("Developers = %v", dev)
	}
	if got["Admins"].GetManageable() {
		t.Error("a team holding org-admin is manageable by an org-worker")
	}
}

func TestCreateOrgTeam_NameIsRequiredAndUnique(t *testing.T) {
	h, _ := newTeams()
	if _, err := h.CreateOrgTeam(workerCaller(), &pb.CreateOrgTeamReq{Name: "  "}); detailOf(t, err).GetCode() != CodeTeamNoName {
		t.Errorf("blank name: %v", err)
	}
	if _, err := h.CreateOrgTeam(workerCaller(), &pb.CreateOrgTeamReq{Name: "Developers"}); detailOf(t, err).GetCode() != CodeTeamNameTaken {
		t.Errorf("taken name: %v", err)
	}
	resp, err := h.CreateOrgTeam(workerCaller(), &pb.CreateOrgTeamReq{Name: " QA "})
	if err != nil || resp.GetTeamId() != "t-new" {
		t.Fatalf("create: %v %v", resp, err)
	}
}

// Another organization's team is no team at all, for every call.
func TestTeams_AnotherOrganizationsTeamIsNotFound(t *testing.T) {
	h, s := newTeams()
	ctx := orgCaller(1, 2, 3, 4)
	calls := map[string]error{}
	_, calls["update"] = h.UpdateOrgTeam(ctx, &pb.UpdateOrgTeamReq{TeamId: "t-other", Name: "Mine"})
	_, calls["delete"] = h.DeleteOrgTeam(ctx, &pb.DeleteOrgTeamReq{TeamId: "t-other"})
	_, calls["add"] = h.AddOrgTeamMember(ctx, &pb.AddOrgTeamMemberReq{TeamId: "t-other", UserId: "u3"})
	_, calls["remove"] = h.RemoveOrgTeamMember(ctx, &pb.RemoveOrgTeamMemberReq{TeamId: "t-other", UserId: "u3"})
	_, calls["roles"] = h.SetOrgTeamRoles(ctx, &pb.SetOrgTeamRolesReq{TeamId: "t-other", RoleIds: []string{"r-viewer"}})
	for name, err := range calls {
		if status.Code(err) != codes.NotFound || detailOf(t, err).GetCode() != CodeTeamNotFound {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s.teams["t-other"].name != "Theirs" || s.teams["t-other"].deleted {
		t.Error("another organization's team was changed")
	}
}

// Adding a member gives them the team's roles: the caller covers them, and
// only a person of the organization joins.
func TestAddOrgTeamMember(t *testing.T) {
	cases := []struct {
		name, team, user, code string
	}{
		{"not in the organization", "t-dev", "stranger", CodeTeamMemberNotInOrg},
		{"a machine account", "t-dev", "bot", CodeTeamMemberIsBot},
		{"a team above the caller", "t-admin", "u3", CodeTeamAboveCaller},
		{"already in it", "t-dev", "u2", CodeTeamMemberAlready},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, s := newTeams()
			before := len(s.members)
			_, err := h.AddOrgTeamMember(workerCaller(), &pb.AddOrgTeamMemberReq{TeamId: c.team, UserId: c.user})
			if detailOf(t, err).GetCode() != c.code {
				t.Errorf("err = %v, want %s", err, c.code)
			}
			if len(s.members) != before {
				t.Error("a member was written anyway")
			}
		})
	}
	h, s := newTeams()
	if _, err := h.AddOrgTeamMember(workerCaller(), &pb.AddOrgTeamMemberReq{TeamId: "t-dev", UserId: "u3"}); err != nil {
		t.Fatal(err)
	}
	if got := s.liveMembers("t-dev"); !reflect.DeepEqual(got, []string{"u2", "u3"}) {
		t.Errorf("members = %v", got)
	}
}

// Removing a member and deleting a team take the team's roles away: the
// caller covers them.
func TestRemovingFromATeamNeedsTheCeiling(t *testing.T) {
	h, s := newTeams()
	s.members = append(s.members, &teamMemberRow{team: "t-admin", user: "u3"})
	if _, err := h.RemoveOrgTeamMember(workerCaller(), &pb.RemoveOrgTeamMemberReq{TeamId: "t-admin", UserId: "u3"}); detailOf(t, err).GetCode() != CodeTeamAboveCaller {
		t.Errorf("remove from a team above the caller: %v", err)
	}
	if _, err := h.DeleteOrgTeam(workerCaller(), &pb.DeleteOrgTeamReq{TeamId: "t-admin"}); detailOf(t, err).GetCode() != CodeTeamAboveCaller {
		t.Errorf("delete a team above the caller: %v", err)
	}
	if got := s.liveMembers("t-admin"); len(got) != 1 || s.teams["t-admin"].deleted {
		t.Error("the team above the caller was changed")
	}
	if _, err := h.RemoveOrgTeamMember(workerCaller(), &pb.RemoveOrgTeamMemberReq{TeamId: "t-dev", UserId: "u2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DeleteOrgTeam(workerCaller(), &pb.DeleteOrgTeamReq{TeamId: "t-dev"}); err != nil {
		t.Fatal(err)
	}
	if len(s.liveMembers("t-dev")) != 0 || !s.teams["t-dev"].deleted {
		t.Error("the team within the ceiling was not changed")
	}
}

// A team's roles are org-scoped session roles of the organization's
// catalogue, and the caller covers every role the change gives or takes.
func TestSetOrgTeamRoles(t *testing.T) {
	cases := []struct {
		name  string
		team  string
		roles []string
		code  string
	}{
		{"a bot's role", "t-dev", []string{"r-ci"}, CodeTeamRoleNotAvailable},
		{"an unknown role", "t-dev", []string{"r-nope"}, CodeTeamRoleNotAvailable},
		{"giving a role above the caller", "t-dev", []string{"r-worker", "r-admin"}, CodeRoleAboveCaller},
		{"taking a role above the caller", "t-admin", []string{"r-viewer"}, CodeRoleAboveCaller},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, s := newTeams()
			before := s.liveRoles(c.team)
			_, err := h.SetOrgTeamRoles(workerCaller(), &pb.SetOrgTeamRolesReq{TeamId: c.team, RoleIds: c.roles})
			if detailOf(t, err).GetCode() != c.code {
				t.Errorf("err = %v, want %s", err, c.code)
			}
			if got := s.liveRoles(c.team); !reflect.DeepEqual(got, before) {
				t.Errorf("roles changed to %v", got)
			}
		})
	}
	h, s := newTeams()
	resp, err := h.SetOrgTeamRoles(workerCaller(), &pb.SetOrgTeamRolesReq{TeamId: "t-dev", RoleIds: []string{"r-viewer", "r-viewer", ""}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.liveRoles("t-dev"); !reflect.DeepEqual(got, []string{"r-viewer"}) || !reflect.DeepEqual(resp.GetRoleIds(), got) {
		t.Errorf("roles = %v, answered %v", got, resp.GetRoleIds())
	}
	// An org-admin's team keeps org-admin while an org-worker who does not
	// cover it changes nothing else: a kept role is not asked about.
	s.roles = append(s.roles, &teamRoleRow{team: "t-admin", role: "r-viewer"})
	if _, err := h.SetOrgTeamRoles(workerCaller(), &pb.SetOrgTeamRolesReq{TeamId: "t-admin", RoleIds: []string{"r-admin", "r-viewer"}}); err != nil {
		t.Errorf("an unchanged set was refused: %v", err)
	}
}

// --- the organization's side -------------------------------------------------

// teamMembershipMock is a membership mock whose member is in a team.
type teamMembershipMock struct {
	*membershipRoleMock
	teamRoles []string
	ended     *pb.EndUserTeamMembershipsReq
}

func (m *teamMembershipMock) GetUserTeamRoleGrants(_ context.Context, in *pb.GetUserTeamRoleGrantsReq, _ ...grpc.CallOption) (*pb.GetUserTeamRoleGrantsResp, error) {
	if in.GetUserId() != "u2" || in.GetOrgId() != "org-1" || len(m.teamRoles) == 0 {
		return nil, status.Error(codes.NotFound, "no team role")
	}
	out := &pb.GetUserTeamRoleGrantsResp{}
	for _, id := range m.teamRoles {
		out.Grants = append(out.Grants, &pb.RoleGrant{RoleId: id, PermissionIds: m.rolePerms[id]})
	}
	return out, nil
}

func (m *teamMembershipMock) EndUserTeamMemberships(_ context.Context, in *pb.EndUserTeamMembershipsReq, _ ...grpc.CallOption) (*pb.EndUserTeamMembershipsResp, error) {
	m.ended = in
	return &pb.EndUserTeamMembershipsResp{}, nil
}

// Removing someone from the organization takes their team roles too: the
// caller covers those, and the team memberships end with the membership.
func TestRemoveOrgMembership_TeamRoles(t *testing.T) {
	ctx := inOrg(withHeldPermissions(context.Background(), "u1", 1, 2), "org-1")

	base, inner := newMembershipRoleHandler("r-viewer")
	m := &teamMembershipMock{membershipRoleMock: inner, teamRoles: []string{"r-admin"}}
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: base.Lock}
	_, err := h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"})
	if detailOf(t, err).GetCode() != CodeMemberAboveCaller {
		t.Fatalf("removing a member of an org-admin team: %v", err)
	}
	if inner.deleted != nil || m.ended != nil {
		t.Fatal("the removal was written anyway")
	}

	m.teamRoles = []string{"r-worker"}
	if _, err := h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"}); err != nil {
		t.Fatal(err)
	}
	if m.ended.GetUserId() != "u2" || m.ended.GetOrgId() != "org-1" || m.ended.GetRemovedBy() != "u1" {
		t.Errorf("team memberships ended with %v", m.ended)
	}
}

// teamRoleCountMock counts a role a team holds.
type teamRoleCountMock struct {
	*orgRolesMock
	teamHolders int64
}

func (m *teamRoleCountMock) CountTeamRoleGrants(context.Context, *pb.CountTeamRoleGrantsReq, ...grpc.CallOption) (*pb.CountTeamRoleGrantsResp, error) {
	return &pb.CountTeamRoleGrantsResp{Count: m.teamHolders}, nil
}

// A role a team holds is in use.
func TestDeleteOrgRole_ARoleATeamHoldsIsInUse(t *testing.T) {
	base, inner := newOrgRoles()
	m := &teamRoleCountMock{orgRolesMock: inner, teamHolders: 1}
	h := &AuthServiceHandler{Query: m, Mutation: m, Lock: base.Lock}
	_, err := h.DeleteOrgRole(orgCaller(1, 2, 3, 4, 5), &pb.DeleteOrgRoleReq{RoleId: "r-dev"})
	if detailOf(t, err).GetCode() != CodeOrgRoleInUse {
		t.Fatalf("err = %v", err)
	}
	if inner.deleted != "" {
		t.Error("the role was deleted anyway")
	}
}
