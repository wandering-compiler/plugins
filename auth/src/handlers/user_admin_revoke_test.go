package handlers

import (
	"strings"
	"testing"
)

// DisableUsers is one statement set: mark the accounts disabled, and revoke
// every UserToken they hold — sessions, device-bound sessions, CLI sessions,
// API and bot tokens alike — with reason USER_DISABLED. The revoke filters on
// the owner and on `revoked_at IS NULL` (an earlier revocation stands) and
// nothing else; a token_type or device_id condition there would leave a class
// alive. Both legs bind the same id set, so they cannot disagree about whom
// they hit. Nothing is deleted.
//
// Whatever mints after the commit is refused by the resolvers' disabled gate
// (TestResolvePrincipal_ADisabledAccountIsRefused) and by every mint path's
// own account check; a live test is what shows the two legs commit together.
func TestDisableUsers_RevokesEveryTokenClassWithTheDisable(t *testing.T) {
	body := mutationRPCBody(t, "DisableUsers")
	disable := strings.Index(body, `name: "disable"`)
	main := strings.Index(body, `name: "main"`)
	if disable < 0 || main < disable {
		t.Fatalf("DisableUsers lacks the disable leg ahead of the token leg:\n%s", body)
	}
	if !strings.Contains(body[disable:main], `"UPDATE @module.User SET disabled_at = NOW(), "`) ||
		!strings.Contains(body[disable:main], `"WHERE id IN (:ids) AND disabled_at IS NULL"`) {
		t.Errorf("the disable leg does not stamp disabled_at on the id set:\n%s", body)
	}
	tokenLeg := body[main:]
	if end := strings.Index(tokenLeg, "}"); end > 0 {
		tokenLeg = tokenLeg[:end]
	}
	if !strings.Contains(tokenLeg, `"UPDATE @module.UserToken SET revoked_at = NOW(), revoke_reason = 8 "`) ||
		!strings.Contains(tokenLeg, `"WHERE user_id IN (:ids) AND revoked_at IS NULL"`) {
		t.Errorf("the token leg is not a revocation of every token of the id set:\n%s", tokenLeg)
	}
	if strings.Contains(tokenLeg, "DELETE") {
		t.Errorf("the token leg deletes:\n%s", tokenLeg)
	}
	for _, narrowing := range []string{"token_type", "device_id", "expires_at"} {
		if strings.Contains(tokenLeg, narrowing) {
			t.Errorf("the token revoke is narrowed by %q, so some class survives a disable:\n%s", narrowing, tokenLeg)
		}
	}
	if n := strings.Count(tokenLeg, " AND "); n != 1 {
		t.Errorf("the token revoke has %d conjuncts besides the owner, want only `revoked_at IS NULL`:\n%s", n, tokenLeg)
	}
	if n := strings.Count(body, "dql:"); n != 2 {
		t.Errorf("DisableUsers has %d statements, want the two legs of one unit of work", n)
	}
}
