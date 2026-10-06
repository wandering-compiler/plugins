package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// roleCatalogueMock serves BOTH role queries, and deliberately serves them
// DIFFERENT contents: ListRoles holds the whole catalogue (realm roles
// included), ListOrgScopedRoles only the org-assignable ones. That is the real
// shape — `org_scoped` is a feature-gated column the shared query cannot even
// name — and it is what lets these tests tell the two apart. A mock that
// returned the same rows from both would pass no matter which one the code
// under test called, which is exactly how the drift this covers survived.
type roleCatalogueMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	all       []*pb.Role          // ListRoles
	orgScoped []*pb.OrgScopedRole // ListOrgScopedRoles
	rolePerms map[string][]int32  // ListRoleGrants; a role absent here carries nothing

	listRolesCalls int
}

func (m *roleCatalogueMock) ListRoles(ctx context.Context, in *pb.ListRolesReq, _ ...grpc.CallOption) (*pb.ListRolesResp, error) {
	m.listRolesCalls++
	return &pb.ListRolesResp{Roles: m.all}, nil
}

func (m *roleCatalogueMock) ListRoleGrants(ctx context.Context, _ *pb.ListRoleGrantsReq, _ ...grpc.CallOption) (*pb.ListRoleGrantsResp, error) {
	out := &pb.ListRoleGrantsResp{}
	for _, r := range m.all {
		out.Grants = append(out.Grants, &pb.RoleGrant{RoleId: r.GetId(), PermissionIds: m.rolePerms[r.GetId()]})
	}
	return out, nil
}

func (m *roleCatalogueMock) ListOrgScopedRoles(ctx context.Context, in *pb.ListOrgScopedRolesReq, _ ...grpc.CallOption) (*pb.ListOrgScopedRolesResp, error) {
	return &pb.ListOrgScopedRolesResp{Roles: m.orgScoped}, nil
}

// newRoleCatalogue builds the console's own shape: three org-scoped roles plus
// `account`, the REALM default that reaches every organization and is
// therefore not an org admin's to hand out.
func newRoleCatalogue() *roleCatalogueMock {
	return &roleCatalogueMock{
		all: []*pb.Role{
			{Id: "r-admin", Name: "org-admin"},
			{Id: "r-worker", Name: "org-worker"},
			{Id: "r-viewer", Name: "org-viewer"},
			{Id: "r-account", Name: "account"},
		},
		orgScoped: []*pb.OrgScopedRole{
			{Id: "r-admin", Name: "org-admin"},
			{Id: "r-worker", Name: "org-worker"},
			{Id: "r-viewer", Name: "org-viewer"},
		},
	}
}

func TestRoleIDByName_RefusesARealmRole(t *testing.T) {
	m := newRoleCatalogue()
	h := &AuthServiceHandler{Query: m}

	// `account` is in the catalogue and resolvable by name. It is refused
	// anyway, because an invitation grants a role INSIDE one organization and
	// a realm role is not scoped to one. Before this, roleIDByName read
	// ListRoles and happily returned "r-account" — the picker refused to
	// offer it and the API accepted it, which is the worst pairing of the two.
	id, err := h.roleIDByName(context.Background(), "account")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("realm role must be refused with InvalidArgument, got %v", err)
	}

	// ⚠️ This used to assert `listRolesCalls == 0` — the validator must not
	// consult the unrestricted catalogue AT ALL — against a refactor that
	// filtered ListRoles in Go and would reintroduce the original bug.
	//
	// It reads that catalogue now, and the reason the guard can be narrowed is
	// that reading it and RESOLVING from it are different acts. a consumer got the
	// same message for "no such role" and "exists but realm-wide", and went
	// hunting for a row that was there; telling those apart needs the full
	// catalogue, and the answer is only ever WHICH ERROR — never an id.
	//
	// So the invariant is stated as what it always was: no id comes out of the
	// unrestricted catalogue. That fails for the original defect (which returned
	// "r-account") exactly as the call-count did, and does not fail for a
	// message that merely knows more.
	if id != "" {
		t.Fatalf("an id came back for a realm role (%q) — only org-scoped roles may resolve", id)
	}
	// And the message has to say which of the two it is, or the distinction
	// exists in the code and not for the reader.
	if !strings.Contains(err.Error(), "realm-wide") {
		t.Errorf("the refusal does not distinguish a realm role from a typo: %v", err)
	}
}

// The other half of the pair: a name in NEITHER catalogue is a typo, and must
// not be described as a scoping problem.
//
// Both directions, because one message for two causes is what sent a consumer
// looking for a row that was there — and a single test would pass for an
// implementation that answered "realm-wide" to everything.
func TestRoleIDByName_AnUnknownNameIsATypoNotAScopingProblem(t *testing.T) {
	m := newRoleCatalogue()
	h := &AuthServiceHandler{Query: m}

	id, err := h.roleIDByName(context.Background(), "org-adminn")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an unknown role must be refused with InvalidArgument, got %v", err)
	}
	if id != "" {
		t.Fatalf("an id came back for a name in no catalogue: %q", id)
	}
	if strings.Contains(err.Error(), "realm-wide") {
		t.Errorf("a typo was reported as a scoping problem: %v", err)
	}
	if !strings.Contains(err.Error(), "no role by that name") {
		t.Errorf("the refusal does not read as a typo: %v", err)
	}
}

func TestRoleIDByName_AcceptsAnOrgScopedRole(t *testing.T) {
	h := &AuthServiceHandler{Query: newRoleCatalogue()}

	id, err := h.roleIDByName(context.Background(), "org-worker")
	if err != nil {
		t.Fatalf("org-scoped role must resolve: %v", err)
	}
	if id != "r-worker" {
		t.Fatalf("want r-worker, got %q", id)
	}
}

// The two surfaces must agree by construction. This asserts the property
// directly rather than trusting the comment that used to claim it: every name
// the picker OFFERS must be a name the validator ACCEPTS, and the one name it
// does not offer must be refused.
func TestAssignableRolesAndValidatorCannotDisagree(t *testing.T) {
	h := &AuthServiceHandler{Query: newRoleCatalogue()}
	ctx := withHeldPermissions(context.Background(), "u1")

	offered, err := h.ListAssignableRoles(ctx, &pb.ListAssignableRolesReq{})
	if err != nil {
		t.Fatalf("ListAssignableRoles: %v", err)
	}
	if len(offered.GetRoles()) == 0 {
		t.Fatal("picker offered nothing — an empty list passes every 'offered implies accepted' check vacuously")
	}
	for _, r := range offered.GetRoles() {
		if _, err := h.roleIDByName(ctx, r.GetName()); err != nil {
			t.Fatalf("picker offers %q but the validator refuses it: %v", r.GetName(), err)
		}
	}

	// And the decoy: a role that exists, is resolvable, and is NOT offered.
	// Without this the test would pass for a validator that accepts
	// everything.
	for _, r := range offered.GetRoles() {
		if r.GetName() == "account" {
			t.Fatal("fixture no longer holds a realm role the picker excludes — the decoy is gone")
		}
	}
	if _, err := h.roleIDByName(ctx, "account"); err == nil {
		t.Fatal("validator accepts a role the picker does not offer")
	}
}
