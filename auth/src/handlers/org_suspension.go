package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/auth/gen"
	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_suspension` feature: the realm's operators
// can suspend a whole organization (an incident, a leak), and while it is
// suspended nothing acts in it.
//
// The stamp is Organization.suspended_at, set and cleared by
// AuthMutation.SuspendOrganizations / ResumeOrganizations. The check is one
// read per request, here: after every scope decorator has settled which
// organization the request acts in (scopeChecks), the organization's stamp is
// read, and a suspended one refuses the request ORG_SUSPENDED. One place,
// whichever way the organization was chosen — the W17-Org selector, the
// caller's only organization, an audience's kinds, an OAuth token's consent —
// and whoever the principal is: a person's session, an API token, a machine
// account's bearer token. So a suspended organization's members, its CI and
// its deployments (deploy-fetch) are all refused, and the same session works
// in the member's other organizations.
//
// Nothing is revoked or deleted. Resuming clears the stamp and every session
// and token works again as it did.
//
// A request that acts in no organization (signing in, listing one's own
// organizations, the admin plane) is not checked: it touches no
// organization's rows.
//
// Staged only with `org_suspension`, so a project without it pays no read.

var errOrgSuspended = errors.New("org_suspension: the organization is suspended")

// The file is staged only with the feature, so in a bundle the constant is
// always true. It is asked anyway because a standalone build (`go test`)
// compiles every feature's file: there it keeps the read out of every other
// feature's tests, whose fakes do not answer it, and this file's tests install
// the check themselves.
func init() {
	if gen.FeatureOrgSuspension {
		scopeChecks = append(scopeChecks, refuseSuspendedOrg)
	}
}

// refuseSuspendedOrg refuses a request resolved to a suspended organization.
// A failed read refuses too: a request that cannot be shown to act in a live
// organization is not let through, and the outage is reported as one
// (AUTH_UNAVAILABLE), not as a suspension.
func refuseSuspendedOrg(ctx context.Context, h *AuthServiceHandler, _ string, _, scopes, _ map[string]string) error {
	orgID := scopes["org_id"]
	if orgID == "" {
		return nil
	}
	resp, err := h.Query.GetOrgSuspension(ctx, &pb.GetOrgSuspensionReq{OrgId: orgID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// The decorators selected it from a live membership a moment
			// ago; a row gone since is not a suspension, and the
			// organization's own readers refuse what follows.
			return nil
		}
		return Unauthenticated(err)
	}
	if resp.GetSuspendedAt() != nil {
		return DeniedOrgSuspended(errOrgSuspended)
	}
	return nil
}
