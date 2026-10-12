package handlers

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
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
	assigned  []string // role_ids assigned, in order
	claimed   string   // user holding the bootstrap claim ("" = free)
	claimResp *pb.ClaimBootstrapAdminResp
	claimErr  error
}

// ClaimBootstrapAdmin mirrors the UPSERT … DO NOTHING on the constant key:
// the first caller writes, every later one conflicts and writes nothing.
func (m *signupRolesMutationMock) ClaimBootstrapAdmin(_ context.Context, in *pb.ClaimBootstrapAdminReq, _ ...grpc.CallOption) (*pb.ClaimBootstrapAdminResp, error) {
	if in.GetSlot() != bootstrapSlot {
		return nil, errors.New("unexpected slot " + in.GetSlot())
	}
	if m.claimErr != nil || m.claimResp != nil {
		return m.claimResp, m.claimErr
	}
	if m.claimed != "" {
		return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(0)}, nil
	}
	m.claimed = in.GetUserId()
	return &pb.ClaimBootstrapAdminResp{Written: proto.Int32(1)}, nil
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

// Two sign-ups that both read "no users yet" — the race the committed count
// cannot settle. Only the one that wins the bootstrap claim gets the
// first_user roles; the other gets the default roles.
func TestAssignSignupRoles_ConcurrentFirstSignUpsGetOneBootstrapAdmin(t *testing.T) {
	q := &signupRolesQueryMock{count: 0, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	a, err := resolveSignupRoleIDs(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := resolveSignupRoleIDs(context.Background(), h) // read before either commits
	if err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(context.Background(), h, "u1", a); err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(context.Background(), h, "u2", b); err != nil {
		t.Fatal(err)
	}
	if len(mut.assigned) != 2 || mut.assigned[0] != "role-admin" || mut.assigned[1] != "role-member" {
		t.Errorf("assigned = %v, want [role-admin role-member]: one bootstrap admin, then a default account", mut.assigned)
	}
	if mut.claimed != "u1" {
		t.Errorf("claim held by %q, want u1", mut.claimed)
	}
}

// A deployment whose claim is taken does not hand out first_user roles
// again, even when the user table is empty (every account deleted).
func TestAssignSignupRoles_ATakenClaimIsNotReopened(t *testing.T) {
	q := &signupRolesQueryMock{count: 0, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{claimed: "u-gone"}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	assignFor(t, h, "u3")
	if len(mut.assigned) != 1 || mut.assigned[0] != "role-member" {
		t.Errorf("assigned = %v, want [role-member]", mut.assigned)
	}
}

// A claim answer without `written` must not read as a win: the first_user
// roles are the privileged branch, so an absent count falls back to defaults.
func TestAssignSignupRoles_AnAbsentWrittenCountFailsClosed(t *testing.T) {
	q := &signupRolesQueryMock{count: 0, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{claimResp: &pb.ClaimBootstrapAdminResp{}}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	assignFor(t, h, "u1")
	if len(mut.assigned) != 1 || mut.assigned[0] != "role-member" {
		t.Errorf("assigned = %v, want [role-member]", mut.assigned)
	}
}

// A failed claim fails the sign-up: no role is linked, and the caller rolls
// the transaction back, which leaves the claim free.
func TestAssignSignupRoles_AFailedClaimAssignsNothing(t *testing.T) {
	q := &signupRolesQueryMock{count: 0, firstRoles: []string{"role-admin"}, defRoles: []string{"role-member"}}
	mut := &signupRolesMutationMock{claimErr: errors.New("db down")}
	h := &AuthServiceHandler{Query: q, Mutation: mut}
	roles, err := resolveSignupRoleIDs(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	if err := assignSignupRoleIDs(context.Background(), h, "u1", roles); err == nil {
		t.Fatal("assign succeeded with a failed claim")
	}
	if len(mut.assigned) != 0 {
		t.Errorf("assigned = %v, want none", mut.assigned)
	}
}

// The claim key is written to BootstrapClaim.slot, and storage validates the
// value against the column's declared type before the write. The fakes in this
// package validate nothing, so a key the column refuses passed every test here
// while the first sign-up of every rbac project failed. Hold the constant to
// the declaration itself.
func TestBootstrapSlot_FitsItsColumn(t *testing.T) {
	src, err := os.ReadFile("../../proto/types/models.proto")
	if err != nil {
		t.Fatal(err)
	}
	decl := regexp.MustCompile(`(?s)message BootstrapClaim \{.*?string slot\s*=\s*\d+\s*\[\(w17\.field\) = \{ type: (\w+), max_len: (\d+)`).FindSubmatch(src)
	if decl == nil {
		t.Fatal("BootstrapClaim.slot declaration not found in models.proto")
	}
	if string(decl[1]) != "SLUG" {
		t.Fatalf("BootstrapClaim.slot is %s; this test checks the SLUG rule only", decl[1])
	}
	maxLen, _ := strconv.Atoi(string(decl[2]))
	if !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(bootstrapSlot) || len(bootstrapSlot) > maxLen {
		t.Fatalf("bootstrapSlot %q is not a SLUG of at most %d characters", bootstrapSlot, maxLen)
	}
}
