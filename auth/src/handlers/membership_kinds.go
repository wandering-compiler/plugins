package handlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `membership_kinds` feature: memberships of several
// KINDS (`staff`, `client`, …) — the auth half of audience surfaces
// (`w17/audience.proto` in the SDK). A domain publishing several audiences
// serves each from its own gateway, and that gateway names the kinds it admits
// in every Authenticate (x-w17-membership-kinds, which only a gateway writes).
// Staged only with the feature; it requires org_membership.
//
// A membership has ONE kind: a person is an organization's staff or its
// client, and may be staff of one organization and client of another. Every
// read that takes one membership per (user, organization) stays true.
//
// What it changes, all of it subtractive:
//
//   - the organization a request acts in is resolved among the memberships
//     of an admitted kind only, and a caller holding none is refused 403
//     before any handler — a client calling the staff surface reaches no
//     endpoint of it;
//   - ownership does not widen there (see narrowGrantsToActiveOrg);
//   - an invitation's kind is held to what the inviter's audiences may
//     invite (membership_kinds_invite.go).
//
// A gateway that names no kinds — every gateway of a domain without
// audiences — admits every membership, and nothing about it changes.

var errMembershipNotAdmitted = errors.New("membership_kinds: none of the caller's memberships is of a kind this audience admits")

func init() {
	orgScopeByKind = resolveOrgScopeByKind
	configChecks = append(configChecks, parseAudienceTable)
}

// membershipNotAdmitted is the 403 for a caller the audience does not admit.
func membershipNotAdmitted(ctx context.Context) error {
	return &notAdmittedError{err: refusal(ctx, codes.PermissionDenied, errMembershipNotAdmitted.Error(),
		CodeMembershipNotAdmitted, "", MsgMembershipNotAdmitted, nil)}
}

// admittedOrgs is the caller's memberships of an admitted kind (every one when
// kinds is empty), and all of them.
func admittedOrgs(ctx context.Context, h *AuthServiceHandler, userID string, kinds []string) (admitted, all []*pb.UserOrg, err error) {
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return nil, nil, err
	}
	all = resp.GetOrgs()
	for _, o := range all {
		if len(kinds) == 0 || slices.Contains(kinds, o.GetMembershipKind()) {
			admitted = append(admitted, o)
		}
	}
	return admitted, all, nil
}

func orgByID(list []*pb.UserOrg, id string) *pb.UserOrg {
	for _, o := range list {
		if o.GetOrgId() == id {
			return o
		}
	}
	return nil
}

func orgBySlug(list []*pb.UserOrg, slug string) *pb.UserOrg {
	for _, o := range list {
		if o.GetSlug() == slug {
			return o
		}
	}
	return nil
}

// resolveOrgScopeByKind is resolveOrgScope through a gateway that admits only
// some kinds (resolveOrgScope calls it only then). The same order — an OAuth
// token's organization, then the `W17-Org` selector, then the caller's sole
// organization — over the memberships the audience admits. A membership of
// another kind in the named organization is 403, not "not a member".
func resolveOrgScopeByKind(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error {
	admitted, all, err := admittedOrgs(ctx, h, userID, kindsFromHeaders(headers))
	if err != nil {
		return err
	}
	// An OAuth access token acts in the organization chosen on the consent
	// page: held to an admitted kind here, then resolved as on any gateway
	// (oauthOrgScope), so its checks are the one copy.
	if orgID := oauthTokenOrg(ctx); orgID != "" {
		if oauthOrgScope == nil {
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		if orgByID(admitted, orgID) == nil {
			if orgByID(all, orgID) != nil {
				return membershipNotAdmitted(ctx)
			}
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		return oauthOrgScope(ctx, h, userID, orgID, headers, scopes, labels)
	}

	slug := orgSlugFromHeaders(headers)
	if slug == "" {
		slug = orgSlugFromContext(ctx)
	}
	if slug != "" {
		if o := orgBySlug(admitted, slug); o != nil {
			stampOrg(scopes, labels, o.GetOrgId(), o.GetSlug())
			return nil
		}
		if orgBySlug(all, slug) != nil {
			return membershipNotAdmitted(ctx)
		}
		return UnauthenticatedOrgNotMember(errOrgNotMember)
	}

	switch len(admitted) {
	case 1:
		stampOrg(scopes, labels, admitted[0].GetOrgId(), admitted[0].GetSlug())
	case 0:
		// The audience is for members of an admitted kind, and this caller
		// is a member of nothing it admits.
		return membershipNotAdmitted(ctx)
	}
	// Several admitted organizations and no selector: ambiguous, as in
	// resolveOrgScope — no scope, which a scoped model refuses.
	return nil
}

// audienceURLsNeeded is set by the oauth_server combination
// (oauth_server_kinds.go): only the consent page reads the audiences' MCP
// URLs, so only then is an unset one a boot error.
var audienceURLsNeeded bool

// parseAudienceTable reads w17_audiences once, at boot. A table that does not
// parse, or — with the consent page — names an MCP URL variable the deploy
// did not set, refuses to boot: either would quietly turn the consent page's
// filter off.
func parseAudienceTable(h *AuthServiceHandler) error {
	h.audiences = nil
	if strings.TrimSpace(h.Audiences) == "" {
		return nil
	}
	urls := map[string]string{}
	for _, raw := range strings.Split(h.Audiences, ";") {
		parts := strings.Split(raw, ":")
		if len(parts) != 4 || parts[0] == "" {
			return fmt.Errorf("auth plugin: w17_audiences entry %q is not <audience>:<kinds>:<URL variable>:<invites> — the table is generated; regenerate instead of editing it", raw)
		}
		e := audienceEntry{name: parts[0], kinds: splitKinds(parts[1]), invites: splitKinds(parts[3])}
		if v := parts[2]; v != "" {
			e.url = strings.TrimRight(os.Getenv(v), "/")
			if e.url == "" && !audienceURLsNeeded {
				h.audiences = append(h.audiences, e)
				continue
			}
			if e.url == "" {
				return fmt.Errorf("auth plugin: %s is unset — the public URL of the %s audience's MCP surface, the same value its gateway reads; without it the consent page cannot tell which organizations that audience admits", v, e.name)
			}
			if prev, dup := urls[e.url]; dup {
				return fmt.Errorf("auth plugin: audiences %s and %s publish MCP at one URL (%s) — each audience's MCP surface needs its own", prev, e.name, e.url)
			}
			urls[e.url] = e.name
		}
		h.audiences = append(h.audiences, e)
	}
	return nil
}

func splitKinds(s string) []string {
	var out []string
	for _, k := range strings.Split(s, "|") {
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}
