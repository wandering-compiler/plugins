package handlers

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// realmRolesMock adds who holds which realm-wide roles to prodMock.
type realmRolesMock struct {
	*prodMock
	realm map[string][]*pb.RoleGrant // user → realm-wide grants
}

func (m *realmRolesMock) GetUserRealmWidePermissions(_ context.Context, in *pb.GetUserRealmWidePermissionsReq, _ ...grpc.CallOption) (*pb.GetUserRealmWidePermissionsResp, error) {
	return &pb.GetUserRealmWidePermissionsResp{Grants: m.realm[in.GetUserId()]}, nil
}

// A backoffice method called from inside an organization — named, or the
// caller's only one inferred — is the backoffice's when the caller holds it
// through a realm-wide role: an operator who is also a member of one
// organization. One who holds it only inside an organization is refused as
// before.
func TestBackofficeCallFromInsideAnOrg_HeldRealmWide(t *testing.T) {
	h, pm := prodHandler(t)
	m := &realmRolesMock{prodMock: pm, realm: map[string][]*pb.RoleGrant{
		"ops":     {{RoleId: "backoffice", AllPermissions: true}},
		"granter": {{RoleId: "product-granter", PermissionIds: []int32{1}}}, // AssignProductRole
		"lister":  {{RoleId: "product-lister", PermissionIds: []int32{3}}},  // ListProductRoleGrants only
	}}
	h.Query, h.Mutation = m, m
	for _, c := range []struct {
		name   string
		caller string
		ok     bool
	}{
		{"an operator with a realm-wide wildcard", "ops", true},
		{"a caller holding exactly this method realm-wide", "granter", true},
		{"a caller holding another backoffice method realm-wide", "lister", false},
		{"a member holding it only inside the organization", "alice", false},
	} {
		pm.written = nil
		target := "given-by-" + c.caller
		_, err := h.AssignProductRole(whoAmICtx(c.caller, "org-a"), &pb.ProductRoleReq{UserId: target, Product: "alpha", RoleKey: "auditor"})
		switch {
		case c.ok && (err != nil || !slices.Equal(pm.written, []string{target + "//alpha:auditor"})):
			t.Errorf("%s, acting in org-a: err %v, wrote %v; want the realm-wide grant", c.name, err, pm.written)
		case !c.ok && status.Code(err) != codes.PermissionDenied:
			t.Errorf("%s, acting in org-a: err %v, want PermissionDenied", c.name, err)
		}
	}
}

// Every backoffice refusal inside an organization asks heldRealmWide first:
// one that does not refuses the operator who is a member somewhere.
func TestRealmOnlyRefusals_AskWhetherTheCallIsHeldRealmWide(t *testing.T) {
	refusal := regexp.MustCompile(`(?s)func \(h \*AuthServiceHandler\) (refuse[A-Za-z]*InsideOrg)\(ctx context\.Context, method string\) error \{(.*?)\n\}`)
	asks := regexp.MustCompile(`h\.heldRealmWide\(ctx, method\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range refusal.FindAllSubmatch(b, -1) {
			found++
			if !asks.Match(m[2]) {
				t.Errorf("%s (%s) refuses inside an organization without asking heldRealmWide", m[1], f)
			}
		}
	}
	if found < 5 {
		t.Fatalf("found %d backoffice refusals, want the five (packages, hosts, sign-up policies, product roles, plans): the pattern no longer matches", found)
	}
}
