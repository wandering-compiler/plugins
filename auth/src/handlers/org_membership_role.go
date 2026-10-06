package handlers

import (
	"context"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// Changing or removing a member, and the role catalogue every org-role grant
// reads.
//
// Staged with `org_membership`: the role lookup used to live in org_invite.go,
// staged only with `org_invite`, while changing a membership's role — an
// org_membership operation — is a grant just as much as an invitation is.
//
// The role ceiling holds BOTH ways here. A role change and a removal each
// revoke every role the member holds in the organization, so the caller must
// cover those (whoever could only hand out org-viewer must not be able to strip
// an org-admin), and a role change grants one, so the caller must cover that
// too. Covering is the one test the ceiling already has: hold every permission
// the role carries.

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// by `make plugin-msgids-sync` (see errors.go).
//
//w17:msgid
const (
	MsgUnknownOrgRole       = "There is no organization role named {role}."
	MsgRoleNotOrgScoped     = "{role} is a realm-wide role. An organization membership can only carry an organization-scoped role."
	MsgMembershipInOtherOrg = "This membership belongs to another organization."
	MsgMemberAboveCaller    = "This member holds a role with permissions you do not have, so you cannot change or remove their membership."
)

// The codes a client branches on for the same refusals.
const (
	CodeUnknownOrgRole       = "UNKNOWN_ORG_ROLE"
	CodeRoleNotOrgScoped     = "ROLE_NOT_ORG_SCOPED"
	CodeMembershipInOtherOrg = "MEMBERSHIP_IN_ANOTHER_ORG"
	CodeMemberAboveCaller    = "MEMBER_ABOVE_CALLER"
)

// UpdateOrgMembershipRole changes a member's role, under the role ceiling.
//
// The admin's OrgMemberships page edits through this, not through
// AuthMutation.UpdateOrgMembership directly. That mutation moves the member's
// org grant to the role it names, and as a storage method it can check
// nothing about the CALLER — so whoever could edit a membership could hand
// anyone, themselves included, any org role, org-admin among them. An
// invitation and a bot were already held to the ceiling; this was the one
// grant path that was not.
//
// The mutation still does the work — its row lock, the grant it revokes and
// writes, the OrgMembershipUpdated event — so the rule sits in front of it
// rather than beside it. It is handed the role by ID, the role checked here:
// a lookup by name there would let a rename between the two grant another.
func (h *AuthServiceHandler) UpdateOrgMembershipRole(ctx context.Context, req *pb.UpdateOrgMembershipRoleReq) (*pb.UpdateOrgMembershipRoleResp, error) {
	if err := h.checkMayManageMembership(ctx, req.GetId()); err != nil {
		return nil, err
	}
	roleID, err := h.roleIDByName(ctx, req.GetRole())
	if err != nil {
		return nil, err
	}
	// The snapshot is for a grant written LATER (an invitation's acceptance);
	// this one is written now, by the call below.
	if _, err := h.checkMayGrantRole(ctx, roleID); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.UpdateOrgMembership(ctx, &pb.UpdateOrgMembershipReq{Id: req.GetId(), RoleId: roleID})
	if err != nil {
		return nil, err
	}
	return &pb.UpdateOrgMembershipRoleResp{MembershipId: resp.GetMembershipId()}, nil
}

// RemoveOrgMembership removes a member, under the role ceiling: the removal
// revokes every role they hold in the organization, so the caller must cover
// them. AuthMutation.DeleteOrgMembership does the work.
func (h *AuthServiceHandler) RemoveOrgMembership(ctx context.Context, req *pb.RemoveOrgMembershipReq) (*pb.RemoveOrgMembershipResp, error) {
	if err := h.checkMayManageMembership(ctx, req.GetId()); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.DeleteOrgMembership(ctx, &pb.DeleteOrgMembershipReq{Id: req.GetId()})
	if err != nil {
		return nil, err
	}
	return &pb.RemoveOrgMembershipResp{MembershipId: resp.GetMembershipId()}, nil
}

// checkMayManageMembership is what a change or a removal of one membership
// requires of the caller, before either writes anything:
//
//   - the membership is in the organization the caller acts in, when they act
//     in one. Their permissions were resolved FOR that organization (an owner
//     holds every permission in their own org, and only there), so a ceiling
//     checked there says nothing about another. A caller with no active
//     organization acts on realm-wide grants, which reach every organization.
//   - the caller covers every role the member holds in that organization —
//     exactly the grants the change or removal revokes. Realm-wide grants stay
//     with the member and are not asked about.
func (h *AuthServiceHandler) checkMayManageMembership(ctx context.Context, membershipID string) error {
	m, err := h.Query.GetOrgMembership(ctx, &pb.GetOrgMembershipReq{Id: membershipID})
	if err != nil {
		return err
	}
	if active, ok := principal.Scope(ctx, "org_id"); ok && active != "" && active != m.GetOrgId() {
		return refusal(ctx, codes.PermissionDenied,
			"membership "+membershipID+" is in organization "+m.GetOrgId()+", not the caller's active "+active,
			CodeMembershipInOtherOrg, "", MsgMembershipInOtherOrg, nil)
	}
	held, err := h.Query.ListUserOrgGrants(ctx, &pb.ListUserOrgGrantsReq{UserId: m.GetUserId(), OrgId: m.GetOrgId()})
	if err != nil {
		return err
	}
	if len(held.GetRoleIds()) == 0 {
		return nil
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return err
	}
	for _, roleID := range held.GetRoleIds() {
		if !grantable[roleID] {
			return refusal(ctx, codes.PermissionDenied,
				"the member of "+membershipID+" holds role "+roleID+", which the caller does not cover",
				CodeMemberAboveCaller, "", MsgMemberAboveCaller, nil)
		}
	}
	return nil
}

// Two refusals for the two reasons a role name is not org-assignable, a typo
// and a realm role, which a caller fixes in completely different ways.
//
// ⚠️ They used to be one, and the adjective carried the whole distinction — "no
// ORG-ASSIGNABLE role by that name exists". A realm role exists and is still
// refused, and calling that "does not exist" sent the reader hunting for a typo
// that was not there: a consumer measured three states, got one message, and
// went looking for a row that WAS there (member-management-audit-findings, from
// #71/#72). Each now carries its own code, and both name the `role` field.

// assignableRoles is the ONE catalogue every org-role grant reads — an
// invitation, its acceptance, a membership's role change: the roles an org
// admin may hand out, which is the org-scoped ones.
//
// It is a function rather than a rule each caller applies because the two
// callers already drifted. The picker moved to ListOrgScopedRoles while
// roleIDByName kept reading ListRoles, so for a day the list a caller was
// OFFERED and the list that would be ACCEPTED disagreed: an org admin could
// invite at a realm role over the API by naming it, and only the UI knew not
// to. The picker's comment claimed the two could not disagree, which is why
// nothing caught it — a comment is not a check. They cannot disagree now
// because there is only one of them.
func (h *AuthServiceHandler) assignableRoles(ctx context.Context) ([]*pb.OrgScopedRole, error) {
	resp, err := h.Query.ListOrgScopedRoles(ctx, &pb.ListOrgScopedRolesReq{})
	if err != nil {
		return nil, err
	}
	return resp.GetRoles(), nil
}

// roleIDByName resolves an assignable Role.name to its id.
//
// Validated when the invitation is CREATED rather than when it is
// accepted: a typo is then the inviter's error at the moment they make it,
// instead of a failure the invitee walks into days later with no way to
// tell what is wrong or who to ask.
//
// It runs AGAIN at accept, against the same catalogue. That is not
// belt-and-braces: a role can be retired or unscoped between the two
// moments, and the accept is where the grant is actually written.
//
// Its refusals name the `role` field and the value — the request field every
// caller of this names `role`, invitation and membership change alike.
func (h *AuthServiceHandler) roleIDByName(ctx context.Context, name string) (string, error) {
	roles, err := h.assignableRoles(ctx)
	if err != nil {
		return "", err
	}
	for _, r := range roles {
		if r.GetName() == name {
			return r.GetId(), nil
		}
	}
	// Not org-assignable — and the two reasons for that are a typo and a realm
	// role, which a caller fixes in completely different ways. The full catalogue
	// tells them apart; `org_membership` requires `rbac`, so ListRoles is always here.
	if all, lerr := h.Query.ListRoles(ctx, &pb.ListRolesReq{}); lerr == nil {
		for _, r := range all.GetRoles() {
			if r.GetName() == name {
				return "", refusal(ctx, codes.InvalidArgument,
					"role "+name+" exists but is realm-wide, and an organization membership may only carry an organization-scoped role",
					CodeRoleNotOrgScoped, "role", MsgRoleNotOrgScoped, map[string]string{"role": name})
			}
		}
	}
	// A catalogue lookup that could not answer must not invent the distinction:
	// the typo message is the one that holds for both.
	return "", refusal(ctx, codes.InvalidArgument,
		"no role by that name exists in this project's role catalogue: "+name,
		CodeUnknownOrgRole, "role", MsgUnknownOrgRole, map[string]string{"role": name})
}
