package handlers

import (
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Managing a member — a role change, a removal, a kind change — is refused
// when they hold, through the products' roles granted in the organization, a
// permission the caller does not hold there: a removal ends those grants.
// Their realm-wide grants are not the organization's and do not count.
func TestManagingAMember_TheirProductRolesAreWithinTheCaller(t *testing.T) {
	h, m := prodHandler(t)
	m.grants = append(m.grants,
		&pb.ProductRoleGrantRow{Id: "g-2", UserId: "bob", OrgId: "org-a", Product: "alpha", RoleKey: "viewer"},
		&pb.ProductRoleGrantRow{Id: "g-3", UserId: "bob", Product: "alpha", RoleKey: "admin"}, // realm-wide
		&pb.ProductRoleGrantRow{Id: "g-4", UserId: "dave", OrgId: "org-a", Product: "alpha", RoleKey: "viewer"},
	)
	if err := checkMemberProductRolesWithinCaller(whoAmICtx("dave", "org-a"), h, "bob", "org-a"); err != nil {
		t.Errorf("dave (viewer in org-a) managing bob (viewer there, admin realm-wide): %v", err)
	}
	if err := checkMemberProductRolesWithinCaller(whoAmICtx("dave", "org-a"), h, "alice", "org-a"); refusalCodeOf(err) != CodeMemberAboveCaller {
		t.Errorf("dave (viewer in org-a) managing alice (admin there): %v, want %s", err, CodeMemberAboveCaller)
	}
}
