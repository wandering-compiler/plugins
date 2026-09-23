package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// signupRolesQueryMock stubs the three rbac queries resolveSignupRoleIDs
// calls; any other method nil-panics (the test never makes one).
type signupRolesQueryMock struct {
	pb.AuthQueryClient
	count      int64
	firstRoles []string
	defRoles   []string
}

func (m *signupRolesQueryMock) CountUsers(ctx context.Context, in *pb.CountUsersReq, opts ...grpc.CallOption) (*pb.CountUsersResp, error) {
	return &pb.CountUsersResp{Count: m.count}, nil
}
func (m *signupRolesQueryMock) GetFirstUserRoles(ctx context.Context, in *pb.GetFirstUserRolesReq, opts ...grpc.CallOption) (*pb.GetFirstUserRolesResp, error) {
	return &pb.GetFirstUserRolesResp{RoleIds: m.firstRoles}, nil
}
func (m *signupRolesQueryMock) GetDefaultRoles(ctx context.Context, in *pb.GetDefaultRolesReq, opts ...grpc.CallOption) (*pb.GetDefaultRolesResp, error) {
	return &pb.GetDefaultRolesResp{RoleIds: m.defRoles}, nil
}

// signupRolesMutationMock records AssignRoleToUser calls.
type signupRolesMutationMock struct {
	pb.AuthMutationClient
	assigned []string // role_ids assigned, in order
}

func (m *signupRolesMutationMock) AssignRoleToUser(ctx context.Context, in *pb.AssignRoleToUserReq, opts ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	m.assigned = append(m.assigned, in.GetRoleId())
	return &pb.AssignRoleToUserResp{}, nil
}

// assignFor drives the split resolve→assign path the same way SignUp does:
// resolve the role ids from committed state, then link them to the user.
func assignFor(t *testing.T, h *AuthServiceHandler, userID string) {
	t.Helper()
	roleIDs, err := resolveSignupRoleIDs(context.Background(), h)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := assignSignupRoleIDs(context.Background(), h, userID, roleIDs); err != nil {
		t.Fatalf("assign: %v", err)
	}
}

func TestAssignSignupRoles_FirstUserGetsBootstrapRoles(t *testing.T) {
	// count == 0: no committed user yet ⇒ the signup in flight is the first
	// (resolve runs BEFORE the create tx commits — see resolveSignupRoleIDs).
	q := &signupRolesQueryMock{count: 0, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	assignFor(t, h, "u1")
	if len(mut.assigned) != 1 || mut.assigned[0] != "role-admin" {
		t.Errorf("assigned = %v, want [role-admin] (first user → first_user roles)", mut.assigned)
	}
}

func TestAssignSignupRoles_LaterUserGetsDefaultRoles(t *testing.T) {
	q := &signupRolesQueryMock{count: 5, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	assignFor(t, h, "u2")
	if len(mut.assigned) != 1 || mut.assigned[0] != "role-member" {
		t.Errorf("assigned = %v, want [role-member] (later user → default roles)", mut.assigned)
	}
}
