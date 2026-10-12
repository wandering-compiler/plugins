package handlers

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// declaredMaxLen reads the max_len a proto file declares for message.field.
func declaredMaxLen(t *testing.T, file, message, field string) int {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?s)message ` + message + ` \{.*?string ` + field + `\s*=\s*\d+\s*\[\(w17\.field\) = \{[^}]*?max_len: (\d+)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("%s.%s with a max_len not found in %s", message, field, file)
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// An accepted invitation copies the invite's Role.name into the membership,
// and the admin's role edit writes the chosen role's name there too. A
// membership column narrower than a role name let an invitation be made for a
// role it could never be accepted into. The fakes here check no widths, so
// the declarations are compared directly.
func TestOrgMembershipRole_HoldsAnyRoleName(t *testing.T) {
	const models = "../../proto/types/models.proto"
	roleName := declaredMaxLen(t, models, "Role", "name")
	for _, c := range []struct{ file, message, field string }{
		{models, "OrgMembership", "role"},
		{models, "OrgInvite", "role"},
		{"../../proto/mutations/auth_mutation.proto", "AddOrgMembershipReq", "role"},
		{"../../proto/business/auth_service.proto", "UpdateOrgMembershipRoleReq", "role"},
		{"../../proto/business/auth_service.proto", "InviteToOrgReq", "role"},
	} {
		if got := declaredMaxLen(t, c.file, c.message, c.field); got < roleName {
			t.Errorf("%s.%s max_len %d is narrower than Role.name (%d)", c.message, c.field, got, roleName)
		}
	}
}
