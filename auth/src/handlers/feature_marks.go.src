package handlers

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
