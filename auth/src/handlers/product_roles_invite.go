package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What product_roles adds to org_invite, staged only when both are on: an
// invitation names the products' roles accepting gives in the organization.
// They are held to the inviter — each covered by a role the inviter holds
// there — and to the organization's plan when the invitation is made, and to
// the catalogue and the plan again at acceptance, which writes the grants in
// its own transaction: a role a product deploy retired, or the plan took,
// since refuses the acceptance and leaves the invitation unspent for the
// inviter to replace.

func init() {
	inviteProductRoles = &inviteProductRoleHooks{
		check:  checkInviteProductRoles,
		verify: verifyInviteProductRoles,
		grant:  grantInviteProductRoles,
		summary: func(row *pb.OrgInvite, out *pb.OrgInviteSummary) {
			out.ProductRoles = decodeProductRoleRefs(row.GetProductRoles())
		},
		mine: func(row *pb.PendingInviteRow, out *pb.MyInvite) {
			out.ProductRoles = decodeProductRoleRefs(row.GetProductRoles())
		},
	}
}

func checkInviteProductRoles(ctx context.Context, h *AuthServiceHandler, inviterID, orgID string, req *pb.InviteToOrgReq) (func(*pb.CreateOrgInviteReq), error) {
	roles, err := h.orgProductRoleRefs(ctx, orgID, inviterID, req.GetProductRoles())
	if err != nil {
		return nil, err
	}
	return func(create *pb.CreateOrgInviteReq) { create.ProductRoles = roles }, nil
}

// verifyInviteProductRoles holds the invitation's roles to the catalogue and
// the organization's plan as they are at acceptance.
func verifyInviteProductRoles(txCtx context.Context, h *AuthServiceHandler, orgID string, claimed *pb.ConsumeOrgInviteByTokenResp) error {
	refs := decodeProductRoleRefs(claimed.GetProductRoles())
	if len(refs) == 0 {
		return nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	for _, r := range refs {
		if err := h.checkOrgProductRole(txCtx, c, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return err
		}
		if err := h.checkProductRoleInPlan(txCtx, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return err
		}
	}
	return nil
}

// grantInviteProductRoles writes the verified roles for the new member, whose
// membership the acceptance wrote in this transaction; the inviter is the
// giver.
func grantInviteProductRoles(txCtx context.Context, h *AuthServiceHandler, userID, orgID string, claimed *pb.ConsumeOrgInviteByTokenResp, resp *pb.AcceptOrgInviteResp) error {
	refs := decodeProductRoleRefs(claimed.GetProductRoles())
	for _, r := range refs {
		if err := h.writeProductRoleGrant(txCtx, claimed.GetInvitedBy(), userID, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return err
		}
	}
	resp.ProductRoles = refs
	return nil
}
