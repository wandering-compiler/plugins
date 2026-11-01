package handlers

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// namedPlanTables are named_product_plans' three tables, live rows only (an
// ended row is dropped, as the storage's `ended_at IS NULL` reads skip it).
type namedPlanTables struct {
	plans   []*pb.ProductPlanRow
	lines   map[string][]*pb.ProductPlanLineRow // plan id → its lines
	assigns []*pb.OrgProductPlanAssignmentRow
}

func (m *prodMock) ListProductPlanRows(context.Context, *pb.ListProductPlanRowsReq, ...grpc.CallOption) (*pb.ListProductPlanRowsResp, error) {
	return &pb.ListProductPlanRowsResp{Plans: m.named.plans}, nil
}

func (m *prodMock) ListProductPlanLineRows(_ context.Context, in *pb.ListProductPlanLineRowsReq, _ ...grpc.CallOption) (*pb.ListProductPlanLineRowsResp, error) {
	return &pb.ListProductPlanLineRowsResp{Lines: m.named.lines[in.GetPlanId()]}, nil
}

func (m *prodMock) assignedWhere(keep func(*pb.OrgProductPlanAssignmentRow) bool) []*pb.OrgProductPlanAssignmentRow {
	var out []*pb.OrgProductPlanAssignmentRow
	for _, a := range m.named.assigns {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func (m *prodMock) ListOrgProductPlanAssignmentRows(_ context.Context, in *pb.ListOrgProductPlanAssignmentRowsReq, _ ...grpc.CallOption) (*pb.ListOrgProductPlanAssignmentRowsResp, error) {
	return &pb.ListOrgProductPlanAssignmentRowsResp{Assignments: m.assignedWhere(func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetOrgId() == in.GetOrgId() })}, nil
}

func (m *prodMock) ListProductPlanAssignmentRows(_ context.Context, in *pb.ListProductPlanAssignmentRowsReq, _ ...grpc.CallOption) (*pb.ListProductPlanAssignmentRowsResp, error) {
	return &pb.ListProductPlanAssignmentRowsResp{Assignments: m.assignedWhere(func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetPlanId() == in.GetPlanId() })}, nil
}

// ListOrgNamedPlanLineRows is the storage's join: the lines of the plan the
// organization is on.
func (m *prodMock) ListOrgNamedPlanLineRows(_ context.Context, in *pb.ListOrgNamedPlanLineRowsReq, _ ...grpc.CallOption) (*pb.ListOrgNamedPlanLineRowsResp, error) {
	out := &pb.ListOrgNamedPlanLineRowsResp{}
	for _, a := range m.assignedWhere(func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetOrgId() == in.GetOrgId() }) {
		out.Lines = append(out.Lines, m.named.lines[a.GetPlanId()]...)
	}
	return out, nil
}

func (m *prodMock) InsertProductPlanRow(_ context.Context, in *pb.InsertProductPlanRowReq, _ ...grpc.CallOption) (*pb.InsertProductPlanRowResp, error) {
	for _, p := range m.named.plans {
		if p.GetName() == in.GetName() {
			return nil, status.Error(codes.InvalidArgument, "UNIQUE_VIOLATION")
		}
	}
	id := m.next()
	m.named.plans = append(m.named.plans, &pb.ProductPlanRow{Id: id, Name: in.GetName()})
	m.written = append(m.written, "named:"+in.GetName())
	return &pb.InsertProductPlanRowResp{Id: id}, nil
}

func (m *prodMock) EndProductPlanRow(_ context.Context, in *pb.EndProductPlanRowReq, _ ...grpc.CallOption) (*pb.EndProductPlanRowResp, error) {
	m.named.plans = slices.DeleteFunc(m.named.plans, func(p *pb.ProductPlanRow) bool { return p.GetId() == in.GetId() })
	m.ended = append(m.ended, in.GetId())
	return &pb.EndProductPlanRowResp{Id: in.GetId()}, nil
}

func (m *prodMock) AddProductPlanLineRow(_ context.Context, in *pb.AddProductPlanLineRowReq, _ ...grpc.CallOption) (*pb.AddProductPlanLineRowResp, error) {
	if m.named.lines == nil {
		m.named.lines = map[string][]*pb.ProductPlanLineRow{}
	}
	id := m.next()
	m.named.lines[in.GetPlanId()] = append(m.named.lines[in.GetPlanId()], &pb.ProductPlanLineRow{Id: id, Product: in.GetProduct(), RoleKey: in.GetRoleKey()})
	m.written = append(m.written, "named-line:"+in.GetProduct()+":"+in.GetRoleKey())
	return &pb.AddProductPlanLineRowResp{Id: id}, nil
}

func (m *prodMock) EndProductPlanLineRow(_ context.Context, in *pb.EndProductPlanLineRowReq, _ ...grpc.CallOption) (*pb.EndProductPlanLineRowResp, error) {
	for plan, lines := range m.named.lines {
		m.named.lines[plan] = slices.DeleteFunc(lines, func(l *pb.ProductPlanLineRow) bool { return l.GetId() == in.GetId() })
	}
	m.ended = append(m.ended, in.GetId())
	return &pb.EndProductPlanLineRowResp{Id: in.GetId()}, nil
}

func (m *prodMock) AssignOrgProductPlanRow(_ context.Context, in *pb.AssignOrgProductPlanRowReq, _ ...grpc.CallOption) (*pb.AssignOrgProductPlanRowResp, error) {
	if len(m.assignedWhere(func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetOrgId() == in.GetOrgId() })) > 0 {
		return nil, status.Error(codes.InvalidArgument, "UNIQUE_VIOLATION")
	}
	id := m.next()
	m.named.assigns = append(m.named.assigns, &pb.OrgProductPlanAssignmentRow{Id: id, OrgId: in.GetOrgId(), PlanId: in.GetPlanId()})
	m.written = append(m.written, "assign:"+in.GetOrgId()+"/"+in.GetPlanId())
	return &pb.AssignOrgProductPlanRowResp{Id: id}, nil
}

func (m *prodMock) EndOrgProductPlanAssignmentRow(_ context.Context, in *pb.EndOrgProductPlanAssignmentRowReq, _ ...grpc.CallOption) (*pb.EndOrgProductPlanAssignmentRowResp, error) {
	m.named.assigns = slices.DeleteFunc(m.named.assigns, func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetId() == in.GetId() })
	m.ended = append(m.ended, in.GetId())
	return &pb.EndOrgProductPlanAssignmentRowResp{Id: in.GetId()}, nil
}

// namedPlanHandler is prodHandler with the named plans' methods in the lock.
func namedPlanHandler(t *testing.T) (*AuthServiceHandler, *prodMock) {
	t.Helper()
	h, m := prodHandler(t)
	for i, method := range []string{"LIST_PRODUCT_PLANS", "CREATE_PRODUCT_PLAN", "DELETE_PRODUCT_PLAN", "ADD_PRODUCT_PLAN_LINE", "REMOVE_PRODUCT_PLAN_LINE", "SET_ORG_PRODUCT_PLAN"} {
		h.Lock.Permissions["AUTH_AUTH_SERVICE_"+method] = 100 + i
	}
	return h, m
}

// holds is the permission codes a person holds in a product, in an organization.
func holds(t *testing.T, h *AuthServiceHandler, user, org, product string) []string {
	t.Helper()
	resp, err := answer(t, h, user, org, product)
	if err != nil {
		t.Fatalf("answer %s in %s for %s: %v", user, org, product, err)
	}
	got := slices.Clone(resp.GetProductRoles())
	slices.Sort(got)
	return got
}

// A plan is the backoffice's, realm-wide: defined, given to organizations,
// edited once for all of them. An organization on it holds the plan's lines
// besides its own, never instead of them.
func TestNamedProductPlans(t *testing.T) {
	h, m := namedPlanHandler(t)
	ops := whoAmICtx("ops", "")
	m.grants = append(m.grants, &pb.ProductRoleGrantRow{Id: "g-2", UserId: "carol", OrgId: "org-b", Product: "beta", RoleKey: "viewer"})

	if _, err := h.CreateProductPlan(whoAmICtx("alice", "org-a"), &pb.CreateProductPlanReq{Name: "pro"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("from inside an organization: err = %v, want PermissionDenied", err)
	}
	pro, err := h.CreateProductPlan(ops, &pb.CreateProductPlanReq{Name: "pro"})
	if err != nil || pro.GetName() != "pro" {
		t.Fatalf("CreateProductPlan: %v, %v", pro, err)
	}
	if _, err := h.CreateProductPlan(ops, &pb.CreateProductPlanReq{Name: "pro"}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("a second live plan of the name: err = %v, want AlreadyExists", err)
	}
	if _, err := h.AddProductPlanLine(ops, &pb.ProductPlanLineReq{PlanId: pro.GetId(), Product: "gamma"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an unknown product: err = %v, want InvalidArgument", err)
	}
	if _, err := h.AddProductPlanLine(ops, &pb.ProductPlanLineReq{PlanId: "no-such", Product: "beta"}); status.Code(err) != codes.NotFound {
		t.Errorf("an unknown plan: err = %v, want NotFound", err)
	}
	line := &pb.ProductPlanLineReq{PlanId: pro.GetId(), Product: "beta", RoleKey: "viewer"}
	if _, err := h.AddProductPlanLine(ops, line); err != nil {
		t.Fatalf("AddProductPlanLine: %v", err)
	}

	// carol holds beta's viewer in org-b, which carries nothing yet: not counted.
	if got := holds(t, h, "carol", "org-b", "beta"); len(got) != 0 {
		t.Fatalf("before the plan: carol holds %v, want nothing", got)
	}
	if _, err := h.SetOrgProductPlan(ops, &pb.SetOrgProductPlanReq{OrgId: "org-b", PlanId: pro.GetId()}); err != nil {
		t.Fatalf("SetOrgProductPlan: %v", err)
	}
	if got := holds(t, h, "carol", "org-b", "beta"); !slices.Equal(got, []string{"notes.NoteQuery.ListNotes"}) {
		t.Errorf("on the plan: carol holds %v, want beta viewer's ListNotes", got)
	}

	// org-a: its own line (the whole of alpha) and the plan, both.
	if _, err := h.SetOrgProductPlan(ops, &pb.SetOrgProductPlanReq{OrgId: "org-a", PlanId: pro.GetId()}); err != nil {
		t.Fatalf("SetOrgProductPlan org-a: %v", err)
	}
	if got := holds(t, h, "alice", "org-a", "alpha"); !slices.Equal(got, alphaAdmin) {
		t.Errorf("org-a's own line under the plan: alice holds %v in alpha, want alpha admin's codes", got)
	}
	plan, err := h.ListOrgProductPlan(ops, &pb.ListOrgProductPlanReq{OrgId: "org-a"})
	if err != nil || plan.GetPlanName() != "pro" || len(plan.GetLines()) != 1 || len(plan.GetPlanLines()) != 1 {
		t.Errorf("org-a's plan: %v (err %v), want its own line and pro's", plan, err)
	}

	// One edit, every organization on the plan, on the next request.
	if _, err := h.RemoveProductPlanLine(ops, line); err != nil {
		t.Fatalf("RemoveProductPlanLine: %v", err)
	}
	if got := holds(t, h, "carol", "org-b", "beta"); len(got) != 0 {
		t.Errorf("the line taken from the plan: carol holds %v, want nothing", got)
	}
	if got := holds(t, h, "alice", "org-a", "alpha"); !slices.Equal(got, alphaAdmin) {
		t.Errorf("a plan's edit takes nothing of an organization's own: alice holds %v, want alpha admin's codes", got)
	}

	// A plan organizations are on is not deleted from under them.
	if _, err := h.DeleteProductPlan(ops, &pb.DeleteProductPlanReq{PlanId: pro.GetId()}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("deleting a plan in use: err = %v, want FailedPrecondition", err)
	}
	for _, org := range []string{"org-a", "org-b"} {
		if _, err := h.SetOrgProductPlan(ops, &pb.SetOrgProductPlanReq{OrgId: org}); err != nil {
			t.Fatalf("taking %s off: %v", org, err)
		}
	}
	if _, err := h.DeleteProductPlan(ops, &pb.DeleteProductPlanReq{PlanId: pro.GetId()}); err != nil {
		t.Errorf("deleting an unused plan: %v", err)
	}
	if plans, err := h.ListProductPlans(ops, &pb.ListProductPlansReq{}); err != nil || len(plans.GetPlans()) != 0 {
		t.Errorf("after the delete: %v (err %v), want none", plans.GetPlans(), err)
	}
}

// Moving an organization between plans leaves one live assignment; the plan it
// is already on changes nothing.
func TestSetOrgProductPlan_MovesBetweenPlans(t *testing.T) {
	h, m := namedPlanHandler(t)
	ops := whoAmICtx("ops", "")
	basic, _ := h.CreateProductPlan(ops, &pb.CreateProductPlanReq{Name: "basic"})
	pro, _ := h.CreateProductPlan(ops, &pb.CreateProductPlanReq{Name: "pro"})
	for _, id := range []string{basic.GetId(), pro.GetId(), pro.GetId()} {
		if _, err := h.SetOrgProductPlan(ops, &pb.SetOrgProductPlanReq{OrgId: "org-b", PlanId: id}); err != nil {
			t.Fatalf("SetOrgProductPlan %s: %v", id, err)
		}
	}
	on := m.assignedWhere(func(a *pb.OrgProductPlanAssignmentRow) bool { return a.GetOrgId() == "org-b" })
	if len(on) != 1 || on[0].GetPlanId() != pro.GetId() {
		t.Errorf("org-b's assignments: %v, want one, on pro", on)
	}
	if n := slices.Index(m.written, "assign:org-b/"+pro.GetId()); n < 0 || slices.Index(m.written[n+1:], "assign:org-b/"+pro.GetId()) >= 0 {
		t.Errorf("pro assigned more than once: %v", m.written)
	}
}
