package handlers

import (
	"context"
	"errors"
	"slices"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `membership_kinds` feature: one identity, several
// memberships of several KINDS (`staff`, `client`, …) — the auth half of
// audience surfaces (`w17/audience.proto` in the SDK). A domain publishing several audiences serves each from its own
// gateway, and that gateway names the kinds it admits in every Authenticate
// (x-w17-membership-kinds, which only a gateway writes). Staged only with the
// feature; it requires org_membership.
//
// What it changes, all of it subtractive:
//
//   - the organization a request acts in is resolved among the memberships
//     of an admitted kind only, and a caller holding none is refused 403
//     before any handler — a client calling the staff surface reaches no
//     endpoint of it;
//   - the roles that count are the ones that came with an admitted
//     membership (UserRole.membership_kind), so a person who is staff and
//     client of one organization holds the client roles on the client's
//     surface;
//   - ownership does not widen there (see narrowGrantsToActiveOrg).
//
// A gateway that names no kinds — every gateway of a domain without
// audiences — admits every membership, and nothing about it changes.

var errMembershipNotAdmitted = errors.New("membership_kinds: none of the caller's memberships is of a kind this audience admits")

func init() {
	orgScopeByKind = resolveOrgScopeByKind
	grantNarrowers = append(grantNarrowers, narrowGrantsToAdmittedKinds)
}

// membershipNotAdmitted is the 403 for a caller the audience does not admit.
func membershipNotAdmitted(ctx context.Context) error {
	return &notAdmittedError{err: refusal(ctx, codes.PermissionDenied, errMembershipNotAdmitted.Error(),
		CodeMembershipNotAdmitted, "", MsgMembershipNotAdmitted, nil)}
}

// admittedOrgs is the caller's memberships of an admitted kind (every one when
// kinds is empty), one entry per organization.
func admittedOrgs(ctx context.Context, h *AuthServiceHandler, userID string, kinds []string) (admitted, all []*pb.UserOrg, err error) {
	resp, err := h.Query.ListUserOrgs(ctx, &pb.ListUserOrgsReq{UserId: userID})
	if err != nil {
		return nil, nil, err
	}
	all = resp.GetOrgs()
	seen := map[string]bool{}
	for _, o := range all {
		if len(kinds) > 0 && !slices.Contains(kinds, o.GetMembershipKind()) {
			continue
		}
		if seen[o.GetOrgId()] {
			continue
		}
		seen[o.GetOrgId()] = true
		admitted = append(admitted, o)
	}
	return admitted, all, nil
}

// resolveOrgScopeByKind is resolveOrgScope for an activation with membership
// kinds. The same order — an OAuth token's organization, then the `W17-Org`
// selector, then the caller's sole organization — over the memberships the
// audience admits.
func resolveOrgScopeByKind(ctx context.Context, h *AuthServiceHandler, userID string, headers, scopes, labels map[string]string) error {
	kinds := kindsFromHeaders(headers)
	admitted, all, err := admittedOrgs(ctx, h, userID, kinds)
	if err != nil {
		if len(kinds) == 0 {
			// As inferSoleOrgScope: an unrelated lookup failure leaves the
			// request unscoped, which a scoped model refuses.
			return nil
		}
		return err
	}
	byID := func(list []*pb.UserOrg, id string) *pb.UserOrg {
		for _, o := range list {
			if o.GetOrgId() == id {
				return o
			}
		}
		return nil
	}
	bySlug := func(list []*pb.UserOrg, slug string) *pb.UserOrg {
		for _, o := range list {
			if o.GetSlug() == slug {
				return o
			}
		}
		return nil
	}

	// An OAuth access token acts in the organization chosen on the consent
	// page — while the user still holds an admitted membership of it.
	if orgID := oauthTokenOrg(ctx); orgID != "" {
		o := byID(admitted, orgID)
		if o == nil {
			if byID(all, orgID) != nil {
				return membershipNotAdmitted(ctx)
			}
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		if named := orgSlugFromHeaders(headers); named != "" && named != o.GetSlug() {
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		stampOrg(scopes, labels, o.GetOrgId(), o.GetSlug())
		return nil
	}

	slug := orgSlugFromHeaders(headers)
	if slug == "" {
		slug = orgSlugFromContext(ctx)
	}
	if slug != "" {
		if o := bySlug(admitted, slug); o != nil {
			stampOrg(scopes, labels, o.GetOrgId(), o.GetSlug())
			return nil
		}
		if len(kinds) > 0 {
			if bySlug(all, slug) != nil {
				return membershipNotAdmitted(ctx)
			}
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		// No audience filter: the owner fallback resolveOrgScope has, for the
		// same reason (an owner whose membership row is gone).
		owned, oerr := h.Query.GetOwnedOrgBySlug(ctx, &pb.GetOwnedOrgBySlugReq{UserId: userID, Slug: slug})
		if notFoundOK(oerr) != nil {
			return oerr
		}
		if owned.GetOrgId() == "" {
			return UnauthenticatedOrgNotMember(errOrgNotMember)
		}
		stampOrg(scopes, labels, owned.GetOrgId(), slug)
		return nil
	}

	switch {
	case len(admitted) == 1:
		stampOrg(scopes, labels, admitted[0].GetOrgId(), admitted[0].GetSlug())
	case len(admitted) == 0 && len(kinds) > 0:
		// The audience is for members of an admitted kind, and this caller
		// is a member of nothing it admits.
		return membershipNotAdmitted(ctx)
	}
	// Several admitted organizations and no selector: ambiguous, as in
	// resolveOrgScope — no scope, which a scoped model refuses.
	return nil
}

// narrowGrantsToAdmittedKinds drops the roles the caller holds in the active
// organization through a membership of a kind the audience does not admit.
// A grant of no kind (an admin's binding, from before the feature) counts on
// every audience, and so do realm-wide grants: they belong to no membership.
func narrowGrantsToAdmittedKinds(ctx context.Context, h *AuthServiceHandler, p *authPrincipal, scopes map[string]string) error {
	kinds := admittedKinds(ctx)
	orgID := scopes["org_id"]
	if len(kinds) == 0 || orgID == "" {
		return nil
	}
	resp, err := h.Query.ListUserRoleKinds(ctx, &pb.ListUserRoleKindsReq{UserId: p.userID, OrgId: orgID})
	if err != nil {
		return err
	}
	// A role may be granted more than once (once per kind); it counts when
	// ANY of its grants is admitted.
	admittedRole := map[string]bool{}
	inOrg := map[string]bool{}
	for _, r := range resp.GetRoles() {
		inOrg[r.GetRoleId()] = true
		if r.GetMembershipKind() == "" || slices.Contains(kinds, r.GetMembershipKind()) {
			admittedRole[r.GetRoleId()] = true
		}
	}
	survivors := make([]*pb.RoleGrant, 0, len(p.grants))
	for _, g := range p.grants {
		if id := g.GetRoleId(); inOrg[id] && !admittedRole[id] {
			continue
		}
		survivors = append(survivors, g)
	}
	p.grants = survivors
	return nil
}
