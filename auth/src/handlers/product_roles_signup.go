package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What product_roles adds to org_signup, staged only when both are on: an
// open policy names the products' roles a registration is given in the
// organization, held to the catalogue and the organization's plan when the
// backoffice sets it. A registration gives the roles of the policy live when
// it joins, each the catalogue and the plan still carry — a role either left
// since is not given, and the registration goes through without it: the
// person registering cannot replace the policy, the backoffice can.

func init() {
	signupPolicyProductRoles = &signupPolicyProductRoleHooks{
		check: checkSignUpPolicyProductRoles,
		info: func(row *pb.OrgSignUpPolicyRow, out *pb.OrgSignUpPolicyInfo) {
			out.ProductRoles = decodeProductRoleRefs(row.GetProductRoles())
		},
		grant: grantSignUpProductRoles,
	}
}

func checkSignUpPolicyProductRoles(ctx context.Context, h *AuthServiceHandler, req *pb.SetOrgSignUpPolicyReq) (func(*pb.SetOrgSignUpPolicyRowReq), error) {
	roles, err := h.orgProductRoleRefs(ctx, req.GetOrgId(), "", req.GetProductRoles())
	if err != nil {
		return nil, err
	}
	return func(row *pb.SetOrgSignUpPolicyRowReq) { row.ProductRoles = roles }, nil
}

func grantSignUpProductRoles(txCtx context.Context, h *AuthServiceHandler, userID string, j *orgJoin) error {
	policies, err := h.Query.ListOrgSignUpPolicyRows(txCtx, &pb.ListOrgSignUpPolicyRowsReq{OrgId: j.orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	var refs []*pb.ProductRoleRef
	for _, p := range policies.GetPolicies() {
		if p.GetKind() == j.kind && p.GetOpen() {
			refs = decodeProductRoleRefs(p.GetProductRoles())
		}
	}
	if len(refs) == 0 {
		return nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	for _, r := range refs {
		err := h.checkOrgProductRole(txCtx, c, j.orgID, r.GetProduct(), r.GetRoleKey())
		if err == nil {
			err = h.checkProductRoleInPlan(txCtx, j.orgID, r.GetProduct(), r.GetRoleKey())
		}
		if leftProductRole(err) {
			continue
		}
		if err != nil {
			return err
		}
		// The membership was written in this transaction (writeSignUpJoin).
		if err := h.writeProductRoleGrant(txCtx, "", userID, j.orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return err
		}
	}
	return nil
}

// leftProductRole reports a refusal saying the role left the catalogue or
// the plan — what a registration passes over rather than fails on.
func leftProductRole(err error) bool {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return false
	}
	for _, d := range st.Details() {
		if ed, ok := d.(interface{ GetCode() string }); ok {
			switch ed.GetCode() {
			case CodeProductUnknown, CodeProductRoleUnknown, CodeProductRoleRealmHeld, CodeProductRoleNotInPlan:
				return true
			}
		}
	}
	return false
}
