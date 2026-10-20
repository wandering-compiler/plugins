package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// bot_roles: a machine account holds any combination of the API-realm roles.

// botRolesMock records every grant and revoke SetBotRoles writes.
type botRolesMock struct {
	*botAdminMock
	assigns []*pb.AssignRoleToUserReq
	revokes []*pb.RevokeRoleFromUserReq
}

func (m *botRolesMock) AssignRoleToUser(_ context.Context, in *pb.AssignRoleToUserReq, _ ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.assigns = append(m.assigns, in)
	return &pb.AssignRoleToUserResp{}, nil
}

func (m *botRolesMock) RevokeRoleFromUser(_ context.Context, in *pb.RevokeRoleFromUserReq, _ ...grpc.CallOption) (*pb.RevokeRoleFromUserResp, error) {
	m.revokes = append(m.revokes, in)
	return &pb.RevokeRoleFromUserResp{}, nil
}

func newBotRoles(held ...string) (*AuthServiceHandler, *botRolesMock) {
	m := &botRolesMock{botAdminMock: &botAdminMock{
		apiRoles: []*pb.ApiRealmRole{{Id: "ci-push"}, {Id: "deploy-fetch"}},
		botsOrg:  "org-1",
		botRoles: held,
	}}
	return &AuthServiceHandler{Query: m, Mutation: m}, m
}

// The set is replaced: a role kept is not re-granted, a role dropped is
// revoked, a new one granted — all in the caller's organization.
func TestSetBotRoles_ReplacesTheSetInTheCallersOrganization(t *testing.T) {
	h, m := newBotRoles("ci-push")
	resp, err := h.SetBotRoles(ctxWithCallerInOrg("admin-1", "org-1"), &pb.SetBotRolesReq{UserId: "bot-1", RoleIds: []string{"ci-push", "deploy-fetch", "deploy-fetch"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetRoleIds(); len(got) != 2 || got[0] != "ci-push" || got[1] != "deploy-fetch" {
		t.Errorf("role_ids = %v", got)
	}
	if len(m.revokes) != 0 || len(m.assigns) != 1 || m.assigns[0].GetRoleId() != "deploy-fetch" || m.assigns[0].GetOrgId() != "org-1" {
		t.Errorf("assigns = %v, revokes = %v", m.assigns, m.revokes)
	}

	h, m = newBotRoles("ci-push", "deploy-fetch")
	if _, err := h.SetBotRoles(ctxWithCallerInOrg("admin-1", "org-1"), &pb.SetBotRolesReq{UserId: "bot-1", RoleIds: []string{"deploy-fetch"}}); err != nil {
		t.Fatal(err)
	}
	if len(m.assigns) != 0 || len(m.revokes) != 1 || m.revokes[0].GetRoleId() != "ci-push" || m.revokes[0].GetOrgId() != "org-1" {
		t.Errorf("assigns = %v, revokes = %v", m.assigns, m.revokes)
	}
}

// Every refusal comes before anything is written: no role at all, a person's
// role, a role above the caller, a bot of another organization.
func TestSetBotRoles_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		req   *pb.SetBotRolesReq
		setup func(m *botRolesMock)
		code  codes.Code
	}{
		{"no role", &pb.SetBotRolesReq{UserId: "bot-1"}, nil, codes.InvalidArgument},
		{"a session role", &pb.SetBotRolesReq{UserId: "bot-1", RoleIds: []string{"org-admin"}}, nil, codes.InvalidArgument},
		{"above the caller", &pb.SetBotRolesReq{UserId: "bot-1", RoleIds: []string{"deploy-fetch"}},
			func(m *botRolesMock) { m.rolePerms = map[string][]int32{"deploy-fetch": {7}} }, codes.PermissionDenied},
		{"another organization's bot", &pb.SetBotRolesReq{UserId: "bot-1", RoleIds: []string{"ci-push"}},
			func(m *botRolesMock) { m.botsOrg = "org-2" }, codes.PermissionDenied},
	}
	for _, c := range cases {
		h, m := newBotRoles("ci-push")
		if c.setup != nil {
			c.setup(m)
		}
		_, err := h.SetBotRoles(ctxWithCallerInOrg("admin-1", "org-1"), c.req)
		if status.Code(err) != c.code {
			t.Errorf("%s: code = %v, want %v (%v)", c.name, status.Code(err), c.code, err)
		}
		if len(m.assigns)+len(m.revokes) != 0 {
			t.Errorf("%s: a refusal wrote grants", c.name)
		}
	}
}

// The directory says which roles each bot holds.
func TestListBots_CarriesTheRolesEachBotHolds(t *testing.T) {
	h, m := newBotRoles("ci-push", "deploy-fetch")
	m.members = []*pb.User{{Id: "bot-1", Email: "ci@example.com", Kind: pb.AccountKind_BOT, TenantId: "tenant-1"}}
	resp, err := h.ListBots(ctxWithCallerInOrg("admin-1", "org-1"), &pb.ListBotsReq{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetBots()) != 1 || len(resp.GetBots()[0].GetRoleIds()) != 2 {
		t.Errorf("bots = %v", resp.GetBots())
	}
}
