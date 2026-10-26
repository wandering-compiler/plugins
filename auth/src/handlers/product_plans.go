package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `product_plans` feature: an organization's plan
// across the products (product_roles) — the roles of each product its
// members may hold, a line per role or ('' role) a whole product. The
// backoffice gives and takes the lines, realm-wide.
//
// A product role held in an organization counts only when the plan carries
// it, on every request — so taking a line applies on the next one — and
// nobody hands out a role the plan does not carry. An organization with no
// line for a product holds nothing there. Realm-wide roles are not bounded.

func init() {
	productRoleBounds = append(productRoleBounds, boundByProductPlan)
}

// boundByProductPlan is product_plans' productRoleBound: the organization's
// lines for product, read once per request (the memo).
func boundByProductPlan(ctx context.Context, h *AuthServiceHandler, orgID, product string) (func(string) bool, error) {
	lines, err := orgProductPlan(ctx, h, orgID)
	if err != nil {
		return nil, err
	}
	whole, roles := false, map[string]bool{}
	for _, l := range lines {
		if l.GetProduct() != product {
			continue
		}
		if l.GetRoleKey() == "" {
			whole = true
		}
		roles[l.GetRoleKey()] = true
	}
	return func(role string) bool { return whole || roles[role] }, nil
}

func orgProductPlan(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.OrgProductAllowanceRow, error) {
	key := "product_plans:" + orgID
	if m := requestMemoOf(ctx); m != nil {
		if v, ok := m[key].([]*pb.OrgProductAllowanceRow); ok {
			return v, nil
		}
	}
	resp, err := h.Query.ListOrgProductAllowanceRows(ctx, &pb.ListOrgProductAllowanceRowsReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	if m := requestMemoOf(ctx); m != nil {
		m[key] = resp.GetLines()
	}
	return resp.GetLines(), nil
}

// refusePlansInsideOrg holds the backoffice's plan calls to the realm, and to
// the callers the endpoint ACL lets make them.
func (h *AuthServiceHandler) refusePlansInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" {
		return refusal(ctx, codes.PermissionDenied, "product_plans: an organization's plan is set realm-wide, not from inside an organization",
			CodeProductPlansRealmOnly, "", MsgProductPlansRealmOnly, nil)
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "product_plans: the backoffice's plan methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// checkPlanLine refuses a product or a role the catalogue does not name.
func (h *AuthServiceHandler) checkPlanLine(ctx context.Context, product, role string) error {
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	if role == "" {
		if _, ok := c.byProduct[product]; !ok {
			return refusal(ctx, codes.InvalidArgument, "product_plans: no such product", CodeProductUnknown, "product", MsgProductUnknown, nil)
		}
		return nil
	}
	_, err = c.role(ctx, product, role)
	return err
}

// AllowOrgProduct adds a line to an organization's plan. One it already
// carries changes nothing.
func (h *AuthServiceHandler) AllowOrgProduct(ctx context.Context, req *pb.OrgProductPlanLineReq) (*pb.OrgProductPlanChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "AllowOrgProduct"); err != nil {
		return nil, err
	}
	if err := h.checkPlanLine(ctx, req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	lines, err := orgProductPlan(ctx, h, req.GetOrgId())
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if l.GetProduct() == req.GetProduct() && l.GetRoleKey() == req.GetRoleKey() {
			return &pb.OrgProductPlanChangeResp{}, nil
		}
	}
	if _, err := h.Mutation.AllowOrgProductRow(ctx, &pb.AllowOrgProductRowReq{
		OrgId: req.GetOrgId(), Product: req.GetProduct(), RoleKey: req.GetRoleKey(), AllowedBy: caller,
	}); err != nil && !isUniqueConflict(err) {
		return nil, err
	}
	return &pb.OrgProductPlanChangeResp{}, nil
}

// DisallowOrgProduct takes a line from an organization's plan; its members
// lose what only that line carried on their next request. A line it does not
// carry changes nothing. A product or role the products no longer declare
// may still be taken.
func (h *AuthServiceHandler) DisallowOrgProduct(ctx context.Context, req *pb.OrgProductPlanLineReq) (*pb.OrgProductPlanChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "DisallowOrgProduct"); err != nil {
		return nil, err
	}
	lines, err := orgProductPlan(ctx, h, req.GetOrgId())
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if l.GetProduct() != req.GetProduct() || l.GetRoleKey() != req.GetRoleKey() {
			continue
		}
		if _, err := h.Mutation.EndOrgProductAllowanceRow(ctx, &pb.EndOrgProductAllowanceRowReq{Id: l.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	return &pb.OrgProductPlanChangeResp{}, nil
}

// ListOrgProductPlan is the backoffice's view of one organization's plan.
func (h *AuthServiceHandler) ListOrgProductPlan(ctx context.Context, req *pb.ListOrgProductPlanReq) (*pb.OrgProductPlanResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "ListOrgProductPlan"); err != nil {
		return nil, err
	}
	return orgProductPlanResp(ctx, h, req.GetOrgId())
}

// ListMyOrgProductPlan is the active organization's own plan.
func (h *AuthServiceHandler) ListMyOrgProductPlan(ctx context.Context, req *pb.ListMyOrgProductPlanReq) (*pb.OrgProductPlanResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	return orgProductPlanResp(ctx, h, orgID)
}

func orgProductPlanResp(ctx context.Context, h *AuthServiceHandler, orgID string) (*pb.OrgProductPlanResp, error) {
	lines, err := orgProductPlan(ctx, h, orgID)
	if err != nil {
		return nil, err
	}
	out := &pb.OrgProductPlanResp{}
	for _, l := range lines {
		out.Lines = append(out.Lines, &pb.OrgProductPlanLine{Product: l.GetProduct(), RoleKey: l.GetRoleKey(), AllowedAt: l.GetAllowedAt()})
	}
	return out, nil
}
