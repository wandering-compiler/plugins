package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `named_product_plans` feature: a plan across the
// products (product_plans) defined once in the backoffice — its lines, a role
// of a product or a whole product — and given to organizations.
//
// An organization on a plan holds what the plan's lines carry AND its own
// lines: its own add to the plan, never take from it. The bound reads the
// plan's lines on every request, so editing a plan changes every organization
// on it on its next one. At most one plan per organization; a plan
// organizations are on cannot be deleted. Realm-wide only, under the endpoint
// ACL, as an organization's own lines are. Nothing is deleted.

func init() {
	productPlanLineSources = append(productPlanLineSources, namedPlanLines)
	productPlanRespDecorators = append(productPlanRespDecorators, withNamedPlan)
}

// namedPlanLines is the bound's source: the lines of the plan orgID is on,
// read once per request (the memo).
func namedPlanLines(ctx context.Context, h *AuthServiceHandler, orgID string) ([]productPlanLine, error) {
	key := "named_product_plans:" + orgID
	if m := requestMemoOf(ctx); m != nil {
		if v, ok := m[key].([]productPlanLine); ok {
			return v, nil
		}
	}
	resp, err := h.Query.ListOrgNamedPlanLineRows(ctx, &pb.ListOrgNamedPlanLineRowsReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	out := make([]productPlanLine, 0, len(resp.GetLines()))
	for _, l := range resp.GetLines() {
		out = append(out, productPlanLine{product: l.GetProduct(), roleKey: l.GetRoleKey()})
	}
	if m := requestMemoOf(ctx); m != nil {
		m[key] = out
	}
	return out, nil
}

// withNamedPlan adds the plan orgID is on, and its lines, to what the
// backoffice and the organization read of its plan.
func withNamedPlan(ctx context.Context, h *AuthServiceHandler, orgID string, resp *pb.OrgProductPlanResp) error {
	current, err := orgPlanAssignment(ctx, h, orgID)
	if err != nil || current == nil {
		return err
	}
	plan, err := liveProductPlan(ctx, h, current.GetPlanId())
	if err != nil {
		return err
	}
	resp.PlanId = current.GetPlanId()
	if plan != nil {
		resp.PlanName = plan.GetName()
	}
	lines, err := planLineRows(ctx, h, current.GetPlanId())
	if err != nil {
		return err
	}
	for _, l := range lines {
		resp.PlanLines = append(resp.PlanLines, &pb.OrgProductPlanLine{Product: l.GetProduct(), RoleKey: l.GetRoleKey(), AllowedAt: l.GetAddedAt()})
	}
	return nil
}

func orgPlanAssignment(ctx context.Context, h *AuthServiceHandler, orgID string) (*pb.OrgProductPlanAssignmentRow, error) {
	resp, err := h.Query.ListOrgProductPlanAssignmentRows(ctx, &pb.ListOrgProductPlanAssignmentRowsReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	if len(resp.GetAssignments()) == 0 {
		return nil, nil
	}
	return resp.GetAssignments()[0], nil
}

func planLineRows(ctx context.Context, h *AuthServiceHandler, planID string) ([]*pb.ProductPlanLineRow, error) {
	resp, err := h.Query.ListProductPlanLineRows(ctx, &pb.ListProductPlanLineRowsReq{PlanId: planID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return resp.GetLines(), nil
}

func livePlans(ctx context.Context, h *AuthServiceHandler) ([]*pb.ProductPlanRow, error) {
	resp, err := h.Query.ListProductPlanRows(ctx, &pb.ListProductPlanRowsReq{})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return resp.GetPlans(), nil
}

// liveProductPlan is the live plan of the id; nil when there is none.
func liveProductPlan(ctx context.Context, h *AuthServiceHandler, planID string) (*pb.ProductPlanRow, error) {
	plans, err := livePlans(ctx, h)
	if err != nil {
		return nil, err
	}
	for _, p := range plans {
		if p.GetId() == planID {
			return p, nil
		}
	}
	return nil, nil
}

// requirePlan is liveProductPlan refusing an unknown plan.
func requirePlan(ctx context.Context, h *AuthServiceHandler, planID string) (*pb.ProductPlanRow, error) {
	plan, err := liveProductPlan(ctx, h, planID)
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, refusal(ctx, codes.NotFound, "named_product_plans: no such plan", CodeProductPlanUnknown, "plan_id", MsgProductPlanUnknown, nil)
	}
	return plan, nil
}

func planView(ctx context.Context, h *AuthServiceHandler, plan *pb.ProductPlanRow) (*pb.ProductPlanView, error) {
	lines, err := planLineRows(ctx, h, plan.GetId())
	if err != nil {
		return nil, err
	}
	on, err := h.Query.ListProductPlanAssignmentRows(ctx, &pb.ListProductPlanAssignmentRowsReq{PlanId: plan.GetId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	v := &pb.ProductPlanView{Id: plan.GetId(), Name: plan.GetName(), CreatedAt: plan.GetCreatedAt()}
	for _, l := range lines {
		v.Lines = append(v.Lines, &pb.OrgProductPlanLine{Product: l.GetProduct(), RoleKey: l.GetRoleKey(), AllowedAt: l.GetAddedAt()})
	}
	for _, a := range on.GetAssignments() {
		v.OrgIds = append(v.OrgIds, a.GetOrgId())
	}
	return v, nil
}

// ListProductPlans is the backoffice's list of the named plans: each with its
// lines and the organizations on it.
func (h *AuthServiceHandler) ListProductPlans(ctx context.Context, _ *pb.ListProductPlansReq) (*pb.ProductPlansResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "ListProductPlans"); err != nil {
		return nil, err
	}
	plans, err := livePlans(ctx, h)
	if err != nil {
		return nil, err
	}
	out := &pb.ProductPlansResp{}
	for _, p := range plans {
		v, err := planView(ctx, h, p)
		if err != nil {
			return nil, err
		}
		out.Plans = append(out.Plans, v)
	}
	return out, nil
}

// CreateProductPlan defines a plan, with no lines yet. A live plan of the
// name is refused.
func (h *AuthServiceHandler) CreateProductPlan(ctx context.Context, req *pb.CreateProductPlanReq) (*pb.ProductPlanView, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "CreateProductPlan"); err != nil {
		return nil, err
	}
	nameTaken := func() error {
		return refusal(ctx, codes.AlreadyExists, "named_product_plans: a live plan has this name", CodeProductPlanNameTaken, "name", MsgProductPlanNameTaken, nil)
	}
	plans, err := livePlans(ctx, h)
	if err != nil {
		return nil, err
	}
	for _, p := range plans {
		if p.GetName() == req.GetName() {
			return nil, nameTaken()
		}
	}
	ins, err := h.Mutation.InsertProductPlanRow(ctx, &pb.InsertProductPlanRowReq{Name: req.GetName(), CreatedBy: caller})
	if isUniqueConflict(err) {
		return nil, nameTaken()
	}
	if err != nil {
		return nil, err
	}
	plan, err := liveProductPlan(ctx, h, ins.GetId())
	if err != nil {
		return nil, err
	}
	if plan == nil {
		plan = &pb.ProductPlanRow{Id: ins.GetId(), Name: req.GetName()}
	}
	return planView(ctx, h, plan)
}

// DeleteProductPlan ends a plan and its lines. One organizations are on is
// refused: move them first, so nobody loses roles as a side effect.
func (h *AuthServiceHandler) DeleteProductPlan(ctx context.Context, req *pb.DeleteProductPlanReq) (*pb.ProductPlanChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "DeleteProductPlan"); err != nil {
		return nil, err
	}
	if _, err := requirePlan(ctx, h, req.GetPlanId()); err != nil {
		return nil, err
	}
	on, err := h.Query.ListProductPlanAssignmentRows(ctx, &pb.ListProductPlanAssignmentRowsReq{PlanId: req.GetPlanId()})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	if len(on.GetAssignments()) > 0 {
		return nil, refusal(ctx, codes.FailedPrecondition, "named_product_plans: organizations are on the plan", CodeProductPlanInUse, "plan_id", MsgProductPlanInUse, nil)
	}
	lines, err := planLineRows(ctx, h, req.GetPlanId())
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if _, err := h.Mutation.EndProductPlanLineRow(ctx, &pb.EndProductPlanLineRowReq{Id: l.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	if _, err := h.Mutation.EndProductPlanRow(ctx, &pb.EndProductPlanRowReq{Id: req.GetPlanId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return &pb.ProductPlanChangeResp{}, nil
}

// AddProductPlanLine adds a line to a plan: the organizations on it hold it on
// their next request. A line it already carries changes nothing. An identity
// role must be one no single organization owns: a plan is for many.
func (h *AuthServiceHandler) AddProductPlanLine(ctx context.Context, req *pb.ProductPlanLineReq) (*pb.ProductPlanChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "AddProductPlanLine"); err != nil {
		return nil, err
	}
	if _, err := requirePlan(ctx, h, req.GetPlanId()); err != nil {
		return nil, err
	}
	if err := h.checkPlanLine(ctx, "", req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	lines, err := planLineRows(ctx, h, req.GetPlanId())
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if l.GetProduct() == req.GetProduct() && l.GetRoleKey() == req.GetRoleKey() {
			return &pb.ProductPlanChangeResp{}, nil
		}
	}
	if _, err := h.Mutation.AddProductPlanLineRow(ctx, &pb.AddProductPlanLineRowReq{
		PlanId: req.GetPlanId(), Product: req.GetProduct(), RoleKey: req.GetRoleKey(), AddedBy: caller,
	}); err != nil && !isUniqueConflict(err) {
		return nil, err
	}
	return &pb.ProductPlanChangeResp{}, nil
}

// RemoveProductPlanLine takes a line from a plan: the organizations on it lose
// what only that line carried (and none of their own lines) on their next
// request. A line it does not carry changes nothing.
func (h *AuthServiceHandler) RemoveProductPlanLine(ctx context.Context, req *pb.ProductPlanLineReq) (*pb.ProductPlanChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "RemoveProductPlanLine"); err != nil {
		return nil, err
	}
	if _, err := requirePlan(ctx, h, req.GetPlanId()); err != nil {
		return nil, err
	}
	lines, err := planLineRows(ctx, h, req.GetPlanId())
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if l.GetProduct() != req.GetProduct() || l.GetRoleKey() != req.GetRoleKey() {
			continue
		}
		if _, err := h.Mutation.EndProductPlanLineRow(ctx, &pb.EndProductPlanLineRowReq{Id: l.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	return &pb.ProductPlanChangeResp{}, nil
}

// SetOrgProductPlan puts an organization on a plan, or (an empty plan_id)
// takes it off its plan. Its own lines are untouched either way. The plan it
// is already on changes nothing.
func (h *AuthServiceHandler) SetOrgProductPlan(ctx context.Context, req *pb.SetOrgProductPlanReq) (*pb.ProductPlanChangeResp, error) {
	if resp, done, err := underOrgLock(ctx, h, req.GetOrgId(), req, h.SetOrgProductPlan); done {
		return resp, err
	}
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refusePlansInsideOrg(ctx, "SetOrgProductPlan"); err != nil {
		return nil, err
	}
	if req.GetPlanId() != "" {
		if _, err := requirePlan(ctx, h, req.GetPlanId()); err != nil {
			return nil, err
		}
	}
	current, err := orgPlanAssignment(ctx, h, req.GetOrgId())
	if err != nil {
		return nil, err
	}
	if current != nil && current.GetPlanId() == req.GetPlanId() {
		return &pb.ProductPlanChangeResp{}, nil
	}
	if current != nil {
		if _, err := h.Mutation.EndOrgProductPlanAssignmentRow(ctx, &pb.EndOrgProductPlanAssignmentRowReq{Id: current.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	if req.GetPlanId() == "" {
		return &pb.ProductPlanChangeResp{}, nil
	}
	if _, err := h.Mutation.AssignOrgProductPlanRow(ctx, &pb.AssignOrgProductPlanRowReq{
		OrgId: req.GetOrgId(), PlanId: req.GetPlanId(), AssignedBy: caller,
	}); err != nil {
		return nil, err
	}
	return &pb.ProductPlanChangeResp{}, nil
}
