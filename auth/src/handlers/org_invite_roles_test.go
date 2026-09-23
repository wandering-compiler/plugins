package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
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

	listRolesCalls int
}

func (m *roleCatalogueMock) ListRoles(ctx context.Context, in *pb.ListRolesReq, _ ...grpc.CallOption) (*pb.ListRolesResp, error) {
	m.listRolesCalls++
	return &pb.ListRolesResp{Roles: m.all}, nil
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
	if _, err := h.roleIDByName(context.Background(), "account"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("realm role must be refused with InvalidArgument, got %v", err)
	}

	// The point is not merely "it errors" — it is that the validator never
	// consults the unrestricted catalogue at all. A future refactor that
	// filters ListRoles in Go would pass the assertion above and reintroduce
	// the bug the moment the filter reads a field the query cannot populate,
	// which is precisely what happened to the picker.
	if m.listRolesCalls != 0 {
		t.Fatalf("validator must not read the unrestricted catalogue, called it %d time(s)", m.listRolesCalls)
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
	ctx := context.Background()

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
