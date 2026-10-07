package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file exists only when BOTH `service_account` and `org_membership` are on
// (plugin.yaml, `go_files_combined`): it is what organizations add to machine
// accounts. service_account.go alone serves a realm WITHOUT organizations — one
// organization, the owner of the software — and cannot name the membership
// calls, which do not exist there.
func init() {
	botOrgs = &botOrgScope{
		active:   activeOrgID,
		enroll:   enrollBotInOrg,
		accounts: orgMemberAccounts,
		isMember: isOrgMember,
	}
}

// enrollBotInOrg makes the new machine account a member of the organization and
// grants its role there.
//
// MEMBERSHIP FIRST, and it is not decoration.
//
// An org-scoped role granted with no organization lands as `org_id NULL`, which
// the org axis counts only for roles declared realm-wide — so the grant applies
// NOWHERE and the bot authenticates with an empty permission set. And without a
// membership there is no organization for the console to infer, so an
// unattended caller with no `W17-Org` header has no scope either. Both were
// live: a token minted through the UI pushed nothing and reported "no
// permissions resolved for this principal" (2026-09-20).
func enrollBotInOrg(txCtx context.Context, h *AuthServiceHandler, userID, roleID, orgID string) error {
	if _, err := h.Mutation.AddOrgMembership(txCtx, &pb.AddOrgMembershipReq{
		UserId: userID, OrgId: orgID, Role: "member",
	}); err != nil {
		return err
	}
	// Granted INSIDE that organization, for the same reason.
	_, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{
		UserId: userID, RoleId: roleID, OrgId: orgID,
	})
	return err
}

// orgMemberAccounts lists the members of the caller's organization; ListBots
// keeps the machine accounts among them.
func orgMemberAccounts(ctx context.Context, h *AuthServiceHandler) ([]*pb.User, error) {
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, errSelectOrgForBots
	}
	resp, err := h.Query.ListOrgMemberAccounts(ctx, &pb.ListOrgMemberAccountsReq{OrgId: orgID})
	if err != nil {
		return nil, err
	}
	return resp.GetAccounts(), nil
}

// isOrgMember reports whether userID belongs to the caller's organization.
func isOrgMember(ctx context.Context, h *AuthServiceHandler, userID string) (bool, error) {
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return false, errSelectOrgForToken
	}
	resp, err := h.Query.GetOrgMember(ctx, &pb.GetOrgMemberReq{UserId: userID, OrgId: orgID})
	if err != nil {
		return false, err
	}
	return resp.GetUserId() != "", nil
}
