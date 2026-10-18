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

// serviceAccountStaged is set by service_account.go's init: this build has
// machine accounts, and so possibly their bearer tokens (device/bot-bearer).
// Without it, Authenticate refuses a proofless request with the bot-bearer
// prefix before the lookup like any other — no row of such a build can pass,
// so it costs no query. In no feature's go_files, like orgMembershipStaged.
var serviceAccountStaged bool
