package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// membershipRoleMock is the role catalogue plus one membership — mem-1, held
// by u2 in org-1 — and the two mutations a change or a removal calls,
// recording whether either was reached: every refusal has to come BEFORE
// anything is written.
type membershipRoleMock struct {
	*roleCatalogueMock
	memberOrgRoles []string // what u2 holds INSIDE org-1

	updated *pb.UpdateOrgMembershipReq
	deleted *pb.DeleteOrgMembershipReq
}

func (m *membershipRoleMock) GetOrgMembership(_ context.Context, in *pb.GetOrgMembershipReq, _ ...grpc.CallOption) (*pb.OrgMembership, error) {
	if in.GetId() != "mem-1" {
		return nil, status.Error(codes.NotFound, "no such membership")
	}
	return &pb.OrgMembership{Id: "mem-1", UserId: "u2", OrgId: "org-1", Role: "org-viewer"}, nil
}

func (m *membershipRoleMock) ListUserOrgGrants(_ context.Context, in *pb.ListUserOrgGrantsReq, _ ...grpc.CallOption) (*pb.ListUserOrgGrantsResp, error) {
	if in.GetUserId() != "u2" || in.GetOrgId() != "org-1" {
		return &pb.ListUserOrgGrantsResp{}, nil
	}
	return &pb.ListUserOrgGrantsResp{RoleIds: m.memberOrgRoles}, nil
}

func (m *membershipRoleMock) UpdateOrgMembership(_ context.Context, in *pb.UpdateOrgMembershipReq, _ ...grpc.CallOption) (*pb.UpdateOrgMembershipResp, error) {
	m.updated = in
	return &pb.UpdateOrgMembershipResp{MembershipId: in.GetId()}, nil
}

func (m *membershipRoleMock) DeleteOrgMembership(_ context.Context, in *pb.DeleteOrgMembershipReq, _ ...grpc.CallOption) (*pb.DeleteOrgMembershipResp, error) {
	m.deleted = in
	return &pb.DeleteOrgMembershipResp{MembershipId: in.GetId()}, nil
}

func newMembershipRoleHandler(memberHolds ...string) (*AuthServiceHandler, *membershipRoleMock) {
	m := &membershipRoleMock{roleCatalogueMock: newRoleCatalogue(), memberOrgRoles: memberHolds}
	m.rolePerms = map[string][]int32{"r-admin": {1, 2, 3}, "r-worker": {1, 2}, "r-viewer": {1}}
	return &AuthServiceHandler{Query: m, Mutation: m}, m
}

// inOrg puts the caller in an active organization, the way Authenticate's
// org scope stamps it.
func inOrg(ctx context.Context, orgID string) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	md = md.Copy()
	md.Set("x-w17-scope-org_id", orgID)
	return metadata.NewIncomingContext(ctx, md)
}

func detailOf(t *testing.T, err error) *w17pb.ErrorDetail {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed
		}
	}
	t.Fatalf("no ErrorDetail on %v", err)
	return nil
}

// The reported hole: whoever could edit a membership could make anyone —
// themselves included — org-admin, holding none of what it grants. Refused,
// and nothing is written.
func TestUpdateOrgMembershipRole_RefusesARoleAboveTheCaller(t *testing.T) {
	h, m := newMembershipRoleHandler("r-viewer")
	ctx := withHeldPermissions(context.Background(), "u1", 1, 2)

	_, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-admin"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if m.updated != nil {
		t.Fatalf("the grant was written anyway: %v", m.updated)
	}
}

// Control: a role inside the ceiling — one the caller does not hold but
// covers — goes through, and the mutation is handed the role CHECKED, by id.
func TestUpdateOrgMembershipRole_GrantsTheCheckedRoleByID(t *testing.T) {
	h, m := newMembershipRoleHandler("r-viewer")
	ctx := inOrg(withHeldPermissions(context.Background(), "u1", 1, 2), "org-1")

	resp, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-worker"})
	if err != nil {
		t.Fatalf("a role inside the ceiling was refused: %v", err)
	}
	if m.updated.GetId() != "mem-1" || m.updated.GetRoleId() != "r-worker" || resp.GetMembershipId() != "mem-1" {
		t.Errorf("mutation got %v, answered %v", m.updated, resp)
	}
}

// The other half of the ceiling: a change and a removal both revoke what the
// member holds in the organization, so a caller who could only hand out
// org-worker cannot demote or remove an org-admin.
func TestMembership_TheMemberAboveTheCallerIsNotTheirsToChange(t *testing.T) {
	ctx := withHeldPermissions(context.Background(), "u1", 1, 2)

	h, m := newMembershipRoleHandler("r-admin")
	_, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-viewer"})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeMemberAboveCaller {
		t.Fatalf("demoting an org-admin: %v", err)
	}
	if m.updated != nil {
		t.Fatalf("the demotion was written anyway: %v", m.updated)
	}

	h, m = newMembershipRoleHandler("r-admin")
	_, err = h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeMemberAboveCaller {
		t.Fatalf("removing an org-admin: %v", err)
	}
	if m.deleted != nil {
		t.Fatalf("the removal was written anyway: %v", m.deleted)
	}

	// Control: a member the caller covers is theirs to remove.
	h, m = newMembershipRoleHandler("r-viewer")
	if _, err := h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"}); err != nil || m.deleted.GetId() != "mem-1" {
		t.Fatalf("removing a covered member: err=%v deleted=%v", err, m.deleted)
	}
}

// The ceiling is checked against the permissions resolved for the caller's
// ACTIVE organization — so a membership in another one is refused, whatever
// the caller holds where they are. An owner of org-2 holds everything there
// and nothing here.
func TestMembership_AnotherOrganizationsMemberIsRefused(t *testing.T) {
	ctx := inOrg(withHeldPermissions(context.Background(), "u1", 1, 2, 3), "org-2")

	h, m := newMembershipRoleHandler("r-viewer")
	_, err := h.UpdateOrgMembershipRole(ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: "org-admin"})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeMembershipInOtherOrg {
		t.Fatalf("changing a role in another org: %v", err)
	}
	_, err = h.RemoveOrgMembership(ctx, &pb.RemoveOrgMembershipReq{Id: "mem-1"})
	if status.Code(err) != codes.PermissionDenied || detailOf(t, err).GetCode() != CodeMembershipInOtherOrg {
		t.Fatalf("removing a member of another org: %v", err)
	}
	if m.updated != nil || m.deleted != nil {
		t.Fatalf("written anyway: update=%v delete=%v", m.updated, m.deleted)
	}
}

// A role name that is not org-assignable is refused on the `role` field, with
// a code per cause and the value in the sentence; a call with no principal (a
// direct gRPC call past the admin) fails closed rather than reading as
// "nothing to exceed".
func TestUpdateOrgMembershipRole_OtherRefusals(t *testing.T) {
	cases := []struct {
		name       string
		ctx        context.Context
		role       string
		want       codes.Code
		detailCode string
		message    string
	}{
		{"a role nobody has", withHeldPermissions(context.Background(), "u1", 1, 2, 3), "org-admni",
			codes.InvalidArgument, CodeUnknownOrgRole, "There is no organization role named org-admni."},
		{"a realm role", withHeldPermissions(context.Background(), "u1", 1, 2, 3), "account",
			codes.InvalidArgument, CodeRoleNotOrgScoped, "account is a realm-wide role. An organization membership can only carry an organization-scoped role."},
		{"no principal on the call", context.Background(), "org-viewer", codes.PermissionDenied, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, m := newMembershipRoleHandler()
			_, err := h.UpdateOrgMembershipRole(tc.ctx, &pb.UpdateOrgMembershipRoleReq{Id: "mem-1", Role: tc.role})
			if status.Code(err) != tc.want {
				t.Fatalf("code = %v, want %v (err=%v)", status.Code(err), tc.want, err)
			}
			if tc.detailCode != "" {
				d := detailOf(t, err)
				if d.GetCode() != tc.detailCode || d.GetField() != "role" || d.GetMessage() != tc.message {
					t.Errorf("detail = %v", d)
				}
			}
			if m.updated != nil {
				t.Fatalf("the grant was written anyway: %v", m.updated)
			}
		})
	}
}
