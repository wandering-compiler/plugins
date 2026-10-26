package handlers

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// prodMock keeps product role grants, organization memberships and plan
// lines in memory.
type prodMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	grants  []*pb.ProductRoleGrantRow
	members map[string]bool // "user/org"
	plan    []*pb.OrgProductAllowanceRow
	planOrg map[string]string // line id → org
	written []string
	ended   []string
	seq     int
}

func (m *prodMock) next() string { m.seq++; return fmt.Sprintf("id-%d", m.seq) }

func (m *prodMock) live(keep func(*pb.ProductRoleGrantRow) bool) *pb.ProductRoleGrantRowsResp {
	out := &pb.ProductRoleGrantRowsResp{}
	for _, g := range m.grants {
		if keep(g) {
			out.Grants = append(out.Grants, g)
		}
	}
	return out
}

func (m *prodMock) ListProductRolesOfUser(_ context.Context, in *pb.ListProductRolesOfUserReq, _ ...grpc.CallOption) (*pb.ProductRoleGrantRowsResp, error) {
	return m.live(func(g *pb.ProductRoleGrantRow) bool {
		return g.GetUserId() == in.GetUserId() && g.GetProduct() == in.GetProduct()
	}), nil
}

func (m *prodMock) ListOrgProductRoleGrantRows(_ context.Context, in *pb.ListOrgProductRoleGrantRowsReq, _ ...grpc.CallOption) (*pb.ProductRoleGrantRowsResp, error) {
	return m.live(func(g *pb.ProductRoleGrantRow) bool { return g.GetOrgId() == in.GetOrgId() }), nil
}

func (m *prodMock) ListUserProductRoleGrantRows(_ context.Context, in *pb.ListUserProductRoleGrantRowsReq, _ ...grpc.CallOption) (*pb.ProductRoleGrantRowsResp, error) {
	return m.live(func(g *pb.ProductRoleGrantRow) bool { return g.GetUserId() == in.GetUserId() }), nil
}

func (m *prodMock) ListRealmProductRoleGrantRows(_ context.Context, _ *pb.ListRealmProductRoleGrantRowsReq, _ ...grpc.CallOption) (*pb.ProductRoleGrantRowsResp, error) {
	return m.live(func(g *pb.ProductRoleGrantRow) bool { return g.GetOrgId() == "" }), nil
}

func (m *prodMock) GetOrgMember(_ context.Context, in *pb.GetOrgMemberReq, _ ...grpc.CallOption) (*pb.GetOrgMemberResp, error) {
	if m.members[in.GetUserId()+"/"+in.GetOrgId()] {
		return &pb.GetOrgMemberResp{UserId: in.GetUserId()}, nil
	}
	return nil, status.Error(codes.NotFound, "no member")
}

func (m *prodMock) GrantProductRoleRow(_ context.Context, in *pb.GrantProductRoleRowReq, _ ...grpc.CallOption) (*pb.GrantProductRoleRowResp, error) {
	id := m.next()
	m.grants = append(m.grants, &pb.ProductRoleGrantRow{Id: id, UserId: in.GetUserId(), OrgId: in.GetOrgId(), Product: in.GetProduct(), RoleKey: in.GetRoleKey(), GrantedBy: in.GetGrantedBy()})
	m.written = append(m.written, in.GetUserId()+"/"+in.GetOrgId()+"/"+in.GetProduct()+":"+in.GetRoleKey())
	return &pb.GrantProductRoleRowResp{Id: id}, nil
}

func (m *prodMock) EndProductRoleGrantRow(_ context.Context, in *pb.EndProductRoleGrantRowReq, _ ...grpc.CallOption) (*pb.EndProductRoleGrantRowResp, error) {
	m.grants = slices.DeleteFunc(m.grants, func(g *pb.ProductRoleGrantRow) bool { return g.GetId() == in.GetId() })
	m.ended = append(m.ended, in.GetId())
	return &pb.EndProductRoleGrantRowResp{Id: in.GetId()}, nil
}

func (m *prodMock) EndUserProductRoleGrantsInOrg(_ context.Context, in *pb.EndUserProductRoleGrantsInOrgReq, _ ...grpc.CallOption) (*pb.EndUserProductRoleGrantsInOrgResp, error) {
	m.grants = slices.DeleteFunc(m.grants, func(g *pb.ProductRoleGrantRow) bool {
		return g.GetUserId() == in.GetUserId() && g.GetOrgId() == in.GetOrgId()
	})
	return &pb.EndUserProductRoleGrantsInOrgResp{}, nil
}

func (m *prodMock) EndProductRoleGrantsOfOrg(_ context.Context, in *pb.EndProductRoleGrantsOfOrgReq, _ ...grpc.CallOption) (*pb.EndProductRoleGrantsOfOrgResp, error) {
	m.grants = slices.DeleteFunc(m.grants, func(g *pb.ProductRoleGrantRow) bool { return g.GetOrgId() == in.GetOrgId() })
	return &pb.EndProductRoleGrantsOfOrgResp{}, nil
}

func (m *prodMock) ListOrgProductAllowanceRows(_ context.Context, in *pb.ListOrgProductAllowanceRowsReq, _ ...grpc.CallOption) (*pb.ListOrgProductAllowanceRowsResp, error) {
	out := &pb.ListOrgProductAllowanceRowsResp{}
	for _, l := range m.plan {
		if m.planOrg[l.GetId()] == in.GetOrgId() {
			out.Lines = append(out.Lines, l)
		}
	}
	return out, nil
}

func (m *prodMock) AllowOrgProductRow(_ context.Context, in *pb.AllowOrgProductRowReq, _ ...grpc.CallOption) (*pb.AllowOrgProductRowResp, error) {
	id := m.next()
	m.plan = append(m.plan, &pb.OrgProductAllowanceRow{Id: id, Product: in.GetProduct(), RoleKey: in.GetRoleKey()})
	m.planOrg[id] = in.GetOrgId()
	m.written = append(m.written, "plan:"+in.GetOrgId()+"/"+in.GetProduct()+":"+in.GetRoleKey())
	return &pb.AllowOrgProductRowResp{Id: id}, nil
}

func (m *prodMock) EndOrgProductAllowanceRow(_ context.Context, in *pb.EndOrgProductAllowanceRowReq, _ ...grpc.CallOption) (*pb.EndOrgProductAllowanceRowResp, error) {
	m.plan = slices.DeleteFunc(m.plan, func(l *pb.OrgProductAllowanceRow) bool { return l.GetId() == in.GetId() })
	m.ended = append(m.ended, in.GetId())
	return &pb.EndOrgProductAllowanceRowResp{Id: in.GetId()}, nil
}

const testProductRoles = `{"roles":[
 {"product":"alpha","key":"viewer","name":"Viewer","org_scoped":true,"covers":["viewer"]},
 {"product":"alpha","key":"editor","name":"Editor","org_scoped":true,"covers":["editor","viewer"]},
 {"product":"alpha","key":"admin","name":"Admin","org_scoped":true,"covers":["admin","editor","viewer"]},
 {"product":"alpha","key":"auditor","name":"Auditor","org_scoped":false},
 {"product":"beta","key":"viewer","name":"Viewer","org_scoped":true}]}`

// prodHandler: alice holds alpha's admin in org-a, whose plan carries the
// whole of alpha; bob and alice are org-a's members, carol is org-b's.
func prodHandler(t *testing.T) (*AuthServiceHandler, *prodMock) {
	t.Helper()
	m := &prodMock{
		members: map[string]bool{"alice/org-a": true, "bob/org-a": true, "carol/org-b": true},
		planOrg: map[string]string{"line-1": "org-a"},
		plan:    []*pb.OrgProductAllowanceRow{{Id: "line-1", Product: "alpha"}},
		grants:  []*pb.ProductRoleGrantRow{{Id: "g-1", UserId: "alice", OrgId: "org-a", Product: "alpha", RoleKey: "admin"}},
	}
	h := &AuthServiceHandler{Query: m, Mutation: m, ProductRolesTable: testProductRoles,
		Lock: &acllock.Lock{Permissions: map[string]int{
			"AUTH_AUTH_SERVICE_ASSIGN_PRODUCT_ROLE": 1, "AUTH_AUTH_SERVICE_REVOKE_PRODUCT_ROLE": 2, "AUTH_AUTH_SERVICE_LIST_PRODUCT_ROLE_GRANTS": 3,
			"AUTH_AUTH_SERVICE_ALLOW_ORG_PRODUCT": 4, "AUTH_AUTH_SERVICE_DISALLOW_ORG_PRODUCT": 5, "AUTH_AUTH_SERVICE_LIST_ORG_PRODUCT_PLAN": 6}}}
	if err := parseProductRoleCatalogue(h); err != nil {
		t.Fatal(err)
	}
	return h, m
}

// answer runs answerProductRoles the way Authenticate does: the request's
// headers and memo on the context, the resolved scopes on the response.
func answer(t *testing.T, h *AuthServiceHandler, userID, orgID, product string) (*pb.AuthResp, error) {
	t.Helper()
	ctx := context.WithValue(context.Background(), authHeadersKey{}, map[string]string{productHeader: product})
	ctx = context.WithValue(ctx, requestMemoKey{}, map[string]any{})
	resp := &pb.AuthResp{PermissionIds: []int32{7, 8}, Scopes: map[string]string{"user_id": userID}}
	if orgID != "" {
		resp.Scopes["org_id"] = orgID
	}
	err := answerProductRoles(ctx, h, &authPrincipal{userID: userID}, resp)
	return resp, err
}

// A product's gateway gets the keys the caller holds there — realm-wide and
// in the active organization, within its plan — and none of the identity's
// own permission ids.
func TestAnswerProductRoles(t *testing.T) {
	h, m := prodHandler(t)
	m.grants = append(m.grants,
		&pb.ProductRoleGrantRow{Id: "g-2", UserId: "alice", Product: "alpha", RoleKey: "auditor"},                 // realm-wide
		&pb.ProductRoleGrantRow{Id: "g-3", UserId: "alice", OrgId: "org-b", Product: "alpha", RoleKey: "viewer"},  // another organization
		&pb.ProductRoleGrantRow{Id: "g-4", UserId: "alice", OrgId: "org-a", Product: "alpha", RoleKey: "retired"}, // no longer declared
		&pb.ProductRoleGrantRow{Id: "g-5", UserId: "alice", OrgId: "org-a", Product: "alpha", RoleKey: "auditor"}, // realm-held, in an org
		&pb.ProductRoleGrantRow{Id: "g-6", UserId: "alice", OrgId: "org-a", Product: "beta", RoleKey: "viewer"},   // outside org-a's plan
	)
	resp, err := answer(t, h, "alice", "org-a", "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resp.GetProductRoles(), []string{"admin", "auditor"}) || resp.GetPermissionIds() != nil {
		t.Errorf("alpha in org-a: roles %v ids %v, want [admin auditor] and no ids", resp.GetProductRoles(), resp.GetPermissionIds())
	}
	if resp, _ := answer(t, h, "alice", "", "alpha"); !slices.Equal(resp.GetProductRoles(), []string{"auditor"}) {
		t.Errorf("alpha realm-wide: %v, want [auditor]", resp.GetProductRoles())
	}
	if resp, _ := answer(t, h, "alice", "org-a", "beta"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("beta outside org-a's plan: %v, want none", resp.GetProductRoles())
	}
	// No product header: the identity's own answer, untouched.
	ctx := context.WithValue(context.Background(), authHeadersKey{}, map[string]string{})
	own := &pb.AuthResp{PermissionIds: []int32{7}}
	if err := answerProductRoles(ctx, h, &authPrincipal{userID: "alice"}, own); err != nil || !slices.Equal(own.GetPermissionIds(), []int32{7}) {
		t.Errorf("the identity's own request: err %v ids %v", err, own.GetPermissionIds())
	}
	// A product the catalogue does not name is a deployment error, loudly.
	if _, err := answer(t, h, "alice", "org-a", "gamma"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("an unknown product: err = %v, want FailedPrecondition", err)
	}
}

func TestAnswerProductRolesIsInstalled(t *testing.T) {
	// The seams are vars set by init: a moved file takes them along, and a
	// direct call to the function would still pass. So run what is
	// installed, as Authenticate does — another feature's enricher, which
	// reads what this mock does not answer, is skipped.
	h, _ := prodHandler(t)
	ctx := context.WithValue(context.Background(), authHeadersKey{}, map[string]string{productHeader: "alpha"})
	ctx = context.WithValue(ctx, requestMemoKey{}, map[string]any{})
	resp := &pb.AuthResp{PermissionIds: []int32{7}, Scopes: map[string]string{"user_id": "alice", "org_id": "org-a"}}
	for _, enrich := range authRespEnrichers {
		func() {
			defer func() { _ = recover() }()
			_ = enrich(ctx, h, &authPrincipal{userID: "alice"}, resp)
		}()
	}
	if !slices.Equal(resp.GetProductRoles(), []string{"admin"}) || resp.GetPermissionIds() != nil {
		t.Errorf("through the installed enrichers: roles %v ids %v, want [admin] and no ids", resp.GetProductRoles(), resp.GetPermissionIds())
	}
	if len(membershipRemovalCascades) == 0 || len(orgRemovalCascades) == 0 || len(productRoleBounds) == 0 {
		t.Fatal("product_roles / product_plans installed no cascade or bound")
	}
}

// Inside an organization a member hands out what they hold there, to
// members, within the plan.
func TestAssignOrgProductRole(t *testing.T) {
	h, m := prodHandler(t)
	alice := whoAmICtx("alice", "org-a")
	give := func(ctx context.Context, user, product, role string) error {
		_, err := h.AssignOrgProductRole(ctx, &pb.OrgProductRoleReq{UserId: user, Product: product, RoleKey: role})
		return err
	}
	// The ceiling: alice's admin covers viewer (it carries all of it); bob,
	// a viewer, does not cover editor.
	if err := give(alice, "bob", "alpha", "viewer"); err != nil || !slices.Equal(m.written, []string{"bob/org-a/alpha:viewer"}) {
		t.Errorf("viewer, which alice's admin covers: err = %v, wrote %v", err, m.written)
	}
	if err := give(whoAmICtx("bob", "org-a"), "alice", "alpha", "editor"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("editor, which bob's viewer does not cover: err = %v, want PermissionDenied (the ceiling)", err)
	}
	m.written = nil
	if err := give(alice, "bob", "alpha", "admin"); err != nil || !slices.Equal(m.written, []string{"bob/org-a/alpha:admin"}) {
		t.Errorf("admin, which alice holds: err = %v, wrote %v", err, m.written)
	}
	if err := give(alice, "bob", "alpha", "admin"); err != nil || len(m.written) != 1 {
		t.Errorf("a role already held: err = %v, wrote %v", err, m.written)
	}
	if err := give(alice, "carol", "alpha", "admin"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("carol, outside org-a: err = %v, want FailedPrecondition", err)
	}
	if err := give(alice, "bob", "alpha", "auditor"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a realm-held role in an organization: err = %v, want InvalidArgument", err)
	}
	if err := give(alice, "bob", "gamma", "viewer"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an unknown product: err = %v, want InvalidArgument", err)
	}
	// bob now holds admin and takes it from himself only as one who holds it.
	if _, err := h.RevokeOrgProductRole(whoAmICtx("bob", "org-a"), &pb.OrgProductRoleReq{UserId: "bob", Product: "alpha", RoleKey: "admin"}); err != nil || len(m.ended) != 1 {
		t.Errorf("bob giving up admin: err = %v, ended %v", err, m.ended)
	}
	// Taken out of the plan, alpha is held by nobody in org-a — alice
	// included — so nobody hands it out either.
	m.plan = nil
	if err := give(alice, "bob", "alpha", "admin"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("alpha outside the plan: err = %v, want PermissionDenied", err)
	}
}

// The backoffice acts realm-wide, gated by the endpoint ACL, with no
// ceiling; a role outside an organization's plan is refused there.
func TestBackofficeProductRoles(t *testing.T) {
	h, m := prodHandler(t)
	req := &pb.ProductRoleReq{UserId: "carol", Product: "alpha", RoleKey: "auditor"}
	if _, err := h.AssignProductRole(whoAmICtx("ops", "org-a"), req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside an organization: err = %v, want PermissionDenied", err)
	}
	if _, err := h.AssignProductRole(whoAmICtx("ops", ""), req); err != nil || !slices.Equal(m.written, []string{"carol//alpha:auditor"}) {
		t.Errorf("a realm-wide grant: err = %v, wrote %v", err, m.written)
	}
	if _, err := h.AssignProductRole(whoAmICtx("ops", ""), &pb.ProductRoleReq{UserId: "bob", OrgId: "org-a", Product: "beta", RoleKey: "viewer"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("beta, outside org-a's plan: err = %v, want FailedPrecondition", err)
	}
	if _, err := h.RevokeProductRole(whoAmICtx("ops", ""), req); err != nil || len(m.ended) != 1 {
		t.Errorf("revoking the realm-wide grant: err = %v, ended %v", err, m.ended)
	}
	h.Lock = &acllock.Lock{Permissions: map[string]int{"AUTH_AUTH_SERVICE_SIGN_IN": 1}}
	if _, err := h.AssignProductRole(whoAmICtx("ops", ""), req); status.Code(err) != codes.PermissionDenied {
		t.Errorf("without the method in the lock: err = %v, want PermissionDenied", err)
	}
}

// Leaving an organization ends the product roles held there; the realm-wide
// ones stay.
func TestProductRolesEndWithTheMembership(t *testing.T) {
	h, m := prodHandler(t)
	m.grants = append(m.grants, &pb.ProductRoleGrantRow{Id: "g-2", UserId: "alice", Product: "alpha", RoleKey: "auditor"})
	// Every installed cascade runs, as RemoveOrgMembership runs them; another
	// feature's, which writes what this mock does not keep, is skipped.
	for _, cascade := range membershipRemovalCascades {
		func() {
			defer func() { _ = recover() }()
			_ = cascade(context.Background(), h, "alice", "org-a", "ops")
		}()
	}
	if len(m.grants) != 1 || m.grants[0].GetOrgId() != "" {
		t.Errorf("after leaving org-a alice holds %v, want the realm-wide grant only", m.grants)
	}
}

// The plan's lines are the backoffice's, realm-wide.
func TestProductPlanLines(t *testing.T) {
	h, m := prodHandler(t)
	line := &pb.OrgProductPlanLineReq{OrgId: "org-a", Product: "beta", RoleKey: "viewer"}
	if _, err := h.AllowOrgProduct(whoAmICtx("alice", "org-a"), line); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside the organization: err = %v, want PermissionDenied", err)
	}
	ops := whoAmICtx("ops", "")
	if _, err := h.AllowOrgProduct(ops, &pb.OrgProductPlanLineReq{OrgId: "org-a", Product: "gamma"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an unknown product: err = %v, want InvalidArgument", err)
	}
	if _, err := h.AllowOrgProduct(ops, &pb.OrgProductPlanLineReq{OrgId: "org-a", Product: "alpha"}); err != nil || len(m.written) != 0 {
		t.Errorf("a line already carried: err = %v, wrote %v", err, m.written)
	}
	if _, err := h.AllowOrgProduct(ops, line); err != nil || !slices.Equal(m.written, []string{"plan:org-a/beta:viewer"}) {
		t.Errorf("adding beta's viewer: err = %v, wrote %v", err, m.written)
	}
	if resp, _ := answer(t, h, "alice", "org-a", "beta"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("a plan line grants nobody a role: %v", resp.GetProductRoles())
	}
	plan, err := h.ListMyOrgProductPlan(whoAmICtx("alice", "org-a"), &pb.ListMyOrgProductPlanReq{})
	if err != nil || len(plan.GetLines()) != 2 {
		t.Errorf("org-a's plan: %v (err %v), want two lines", plan.GetLines(), err)
	}
	if _, err := h.DisallowOrgProduct(ops, &pb.OrgProductPlanLineReq{OrgId: "org-a", Product: "alpha"}); err != nil || !slices.Equal(m.ended, []string{"line-1"}) {
		t.Errorf("taking alpha: err = %v, ended %v", err, m.ended)
	}
	if resp, _ := answer(t, h, "alice", "org-a", "alpha"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("alpha out of the plan: alice holds %v there, want nothing", resp.GetProductRoles())
	}
}

// The cascades product_roles installs run under every other feature's tests
// too: the shared org mocks end nothing.
func (o *orgTables) EndUserProductRoleGrantsInOrg(context.Context, *pb.EndUserProductRoleGrantsInOrgReq, ...grpc.CallOption) (*pb.EndUserProductRoleGrantsInOrgResp, error) {
	return &pb.EndUserProductRoleGrantsInOrgResp{}, nil
}

func (o *orgTables) EndProductRoleGrantsOfOrg(context.Context, *pb.EndProductRoleGrantsOfOrgReq, ...grpc.CallOption) (*pb.EndProductRoleGrantsOfOrgResp, error) {
	return &pb.EndProductRoleGrantsOfOrgResp{}, nil
}

func (m *membershipRoleMock) EndUserProductRoleGrantsInOrg(context.Context, *pb.EndUserProductRoleGrantsInOrgReq, ...grpc.CallOption) (*pb.EndUserProductRoleGrantsInOrgResp, error) {
	return &pb.EndUserProductRoleGrantsInOrgResp{}, nil
}
