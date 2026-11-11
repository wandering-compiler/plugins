package handlers

import "context"

// orgMembershipStaged is set by org_membership.go's init: this build has
// organizations.
//
// It exists for the one check that must hold ACROSS features. Machine accounts
// are org-scoped through a seam (botOrgs) that service_account_org.go installs
// when both service_account and org_membership are staged. A seam that is
// simply absent reads as "a realm without organizations", which is the
// realm-wide behaviour — so a build that had org_membership and somehow missed
// that file would list and mint machine accounts across organizations, and
// compile cleanly doing it. With this mark the handler refuses instead.
//
// In no feature's go_files, so it is staged in every build: both features read
// or write it.
var orgMembershipStaged bool

// serviceAccountStaged is set by service_account.go's init: this build has
// machine accounts, and so possibly their bearer tokens (device/bot-bearer).
// Without it, Authenticate refuses a proofless request with the bot-bearer
// prefix before the lookup like any other — no row of such a build can pass,
// so it costs no query. In no feature's go_files, like orgMembershipStaged.
var serviceAccountStaged bool

// The two below are here, in no feature's go_files, for the reason the marks
// above are: features that are staged independently of each other call them
// (org_invite, org_signup, oauth_server, membership_kinds) and one installs them
// (org_suspension).

// orgEntryCheck refuses a way INTO an organization — accepting an invitation,
// registering on its host, an OAuth grant consented for it — that the
// organization's state forbids (org_suspension). Nil when no feature checks.
var orgEntryCheck func(ctx context.Context, h *AuthServiceHandler, orgID string) error

// checkOrgEntry runs orgEntryCheck when a feature installed one.
func checkOrgEntry(ctx context.Context, h *AuthServiceHandler, orgID string) error {
	if orgEntryCheck == nil {
		return nil
	}
	return orgEntryCheck(ctx, h, orgID)
}

// orgInferredKey is the request memo's mark that the organization was
// inferred — the caller's only one — rather than named by the request.
const orgInferredKey = "org_inferred"

// markOrgInferred records that the stamped organization is the caller's only
// one, chosen for them: a check that would refuse it (a suspended one) drops it
// instead, and the request goes on in no organization.
func markOrgInferred(ctx context.Context) {
	if m := requestMemoOf(ctx); m != nil {
		m[orgInferredKey] = true
	}
}

// orgWasInferred reports markOrgInferred for this request.
func orgWasInferred(ctx context.Context) bool {
	v, _ := requestMemoOf(ctx)[orgInferredKey].(bool)
	return v
}
