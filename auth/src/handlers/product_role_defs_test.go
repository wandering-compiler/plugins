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

// defsMock keeps the identity's own roles (ProductRoleDef) beside prodMock.
type defsMock struct {
	*prodMock
	defs []*pb.ProductRoleDefRow
}

func (m *defsMock) ListProductRoleDefs(_ context.Context, in *pb.ListProductRoleDefsReq, _ ...grpc.CallOption) (*pb.ListProductRoleDefsResp, error) {
	out := &pb.ListProductRoleDefsResp{}
	for _, d := range m.defs {
		if d.GetOrgId() == "" || d.GetOrgId() == in.GetOrgId() {
			out.Roles = append(out.Roles, d)
		}
	}
	return out, nil
}

func (m *defsMock) InsertProductRoleDef(_ context.Context, in *pb.InsertProductRoleDefReq, _ ...grpc.CallOption) (*pb.ProductRoleDefChangeResp, error) {
	id := m.next()
	m.defs = append(m.defs, &pb.ProductRoleDefRow{Id: id, OrgId: in.GetOrgId(), Key: in.GetKey(), Name: in.GetName(), OrgScoped: in.GetOrgScoped(), Permissions: in.GetPermissions()})
	return &pb.ProductRoleDefChangeResp{Id: id}, nil
}

func (m *defsMock) UpdateProductRoleDef(_ context.Context, in *pb.UpdateProductRoleDefReq, _ ...grpc.CallOption) (*pb.ProductRoleDefChangeResp, error) {
	for _, d := range m.defs {
		if d.GetId() == in.GetId() {
			d.Name, d.OrgScoped, d.Permissions = in.GetName(), in.GetOrgScoped(), in.GetPermissions()
		}
	}
	return &pb.ProductRoleDefChangeResp{Id: in.GetId()}, nil
}

func (m *defsMock) EndProductRoleDef(_ context.Context, in *pb.EndProductRoleDefReq, _ ...grpc.CallOption) (*pb.ProductRoleDefChangeResp, error) {
	m.defs = slices.DeleteFunc(m.defs, func(d *pb.ProductRoleDefRow) bool { return d.GetId() == in.GetId() })
	return &pb.ProductRoleDefChangeResp{Id: in.GetId()}, nil
}

func defsHandler(t *testing.T) (*AuthServiceHandler, *defsMock) {
	t.Helper()
	h, pm := prodHandler(t)
	m := &defsMock{prodMock: pm}
	h.Query, h.Mutation = m, m
	return h, m
}

// The backoffice composes a role of its own from the products' permissions —
// across products — and a grant of it (product `*`) gives each product what
// the role grants there; the plan carries it by its line, and a product the
// catalogue lacks, or a permission no product has, is refused.
func TestIdentityRoles_TheBackofficeComposesThem(t *testing.T) {
	h, m := defsHandler(t)
	ops := whoAmICtx("ops", "")
	define := func(perms ...string) error {
		_, err := h.DefineProductRole(ops, &pb.DefineProductRoleReq{Key: "reader", Name: "Reader", OrgScoped: true, Permissions: perms})
		return err
	}
	if err := define("alpha:notes.NoteQuery.GetNote", "beta:notes.NoteQuery.ListNotes"); err != nil {
		t.Fatalf("defining a role across alpha and beta: %v", err)
	}
	if err := define("gamma:notes.NoteQuery.GetNote"); refusalCodeOf(err) != CodeProductPermissionUnknown {
		t.Errorf("a permission of no product: %v, want %s", err, CodeProductPermissionUnknown)
	}
	if err := define("alpha:notes.NoteQuery.Nothing"); refusalCodeOf(err) != CodeProductPermissionUnknown {
		t.Errorf("a permission alpha does not have: %v, want %s", err, CodeProductPermissionUnknown)
	}
	if _, err := h.DefineProductRole(whoAmICtx("ops", "org-a"), &pb.DefineProductRoleReq{Key: "x", Name: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("from inside an organization, holding nothing realm-wide: err = %v, want PermissionDenied", err)
	}

	// bob holds it in org-a, whose plan carries the whole of alpha only.
	m.grants = append(m.grants, &pb.ProductRoleGrantRow{Id: "g-9", UserId: "bob", OrgId: "org-a", Product: identityRoleProduct, RoleKey: "reader"})
	if resp, _ := answer(t, h, "bob", "org-a", "alpha"); !slices.Equal(resp.GetProductRoles(), []string{"notes.NoteQuery.GetNote"}) {
		t.Errorf("alpha for bob's reader: %v, want GetNote", resp.GetProductRoles())
	}
	if resp, _ := answer(t, h, "bob", "org-a", "beta"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("beta for bob's reader, outside org-a's plan: %v, want none", resp.GetProductRoles())
	}
	// A line for the role carries it in every product it grants in.
	m.plan = append(m.plan, &pb.OrgProductAllowanceRow{Id: "line-2", Product: identityRoleProduct, RoleKey: "reader"})
	m.planOrg["line-2"] = "org-a"
	if resp, _ := answer(t, h, "bob", "org-a", "beta"); !slices.Equal(resp.GetProductRoles(), []string{"notes.NoteQuery.ListNotes"}) {
		t.Errorf("beta for bob's reader, the plan carrying the role: %v, want ListNotes", resp.GetProductRoles())
	}

	// Redefined: the grant holds the new definition on the next request.
	if err := define("alpha:notes.NoteQuery.ListNotes"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := answer(t, h, "bob", "org-a", "alpha"); !slices.Equal(resp.GetProductRoles(), []string{"notes.NoteQuery.ListNotes"}) {
		t.Errorf("alpha after the redefinition: %v, want ListNotes", resp.GetProductRoles())
	}
	if len(m.defs) != 1 {
		t.Errorf("a redefinition wrote a second role: %v", m.defs)
	}
	// Retired: the grant holds nothing.
	if _, err := h.RetireProductRole(ops, &pb.RetireProductRoleReq{Key: "reader"}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := answer(t, h, "bob", "org-a", "alpha"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("alpha after the role was retired: %v, want none", resp.GetProductRoles())
	}

	// The catalogue lists the presets (with what they grant) and the
	// identity's own.
	if _, err := h.DefineProductRole(ops, &pb.DefineProductRoleReq{Key: "both", Name: "Both", OrgScoped: true, Permissions: []string{"beta:notes.NoteQuery.ListNotes"}}); err != nil {
		t.Fatal(err)
	}
	list, err := h.ListProductRoles(ops, &pb.ListProductRolesReq{})
	if err != nil {
		t.Fatal(err)
	}
	var sawPreset, sawOwn bool
	for _, r := range list.GetRoles() {
		if r.GetProduct() == "alpha" && r.GetKey() == "viewer" && r.GetPreset() && slices.Equal(r.GetPermissions(), alphaViewer) {
			sawPreset = true
		}
		if r.GetProduct() == identityRoleProduct && r.GetKey() == "both" && !r.GetPreset() && slices.Equal(r.GetPermissions(), []string{"beta:notes.NoteQuery.ListNotes"}) {
			sawOwn = true
		}
	}
	if !sawPreset || !sawOwn {
		t.Errorf("the catalogue: preset listed %v, own listed %v: %v", sawPreset, sawOwn, list.GetRoles())
	}
	perms, err := h.ListProductPermissions(ops, &pb.ListProductPermissionsReq{})
	if err != nil || len(perms.GetProducts()) != 2 || perms.GetProducts()[0].GetProduct() != "alpha" {
		t.Errorf("the products' permissions: %v, %v", perms.GetProducts(), err)
	}
}

// An organization defines roles of its own under the ceiling — every
// permission held by its definer there — hands them out like any, and only
// it retires them; the backoffice's are not its to retire.
func TestIdentityRoles_AnOrganizationsOwn(t *testing.T) {
	h, m := defsHandler(t)
	alice := whoAmICtx("alice", "org-a") // alpha's admin in org-a
	if _, err := h.DefineOrgProductRole(alice, &pb.DefineOrgProductRoleReq{Key: "lister", Name: "Lister", Permissions: []string{"alpha:notes.NoteQuery.ListNotes"}}); err != nil {
		t.Fatalf("alice defining a role within what she holds: %v", err)
	}
	if _, err := h.DefineOrgProductRole(alice, &pb.DefineOrgProductRoleReq{Key: "beta-lister", Name: "x", Permissions: []string{"beta:notes.NoteQuery.ListNotes"}}); refusalCodeOf(err) != CodeProductRoleAbove {
		t.Errorf("a role with beta's permission, which alice does not hold: %v, want %s", err, CodeProductRoleAbove)
	}
	if _, err := h.AssignOrgProductRole(alice, &pb.OrgProductRoleReq{UserId: "bob", Product: identityRoleProduct, RoleKey: "lister"}); err != nil {
		t.Fatalf("alice giving bob org-a's own role: %v", err)
	}
	if !slices.Contains(m.written, "bob/org-a/*:lister") {
		t.Errorf("wrote %v, want bob's lister", m.written)
	}
	if resp, _ := answer(t, h, "bob", "org-a", "alpha"); !slices.Equal(resp.GetProductRoles(), []string{"notes.NoteQuery.ListNotes"}) {
		t.Errorf("alpha for bob's lister: %v, want ListNotes", resp.GetProductRoles())
	}
	// bob, holding only ListNotes, cannot give the editor's preset.
	if _, err := h.AssignOrgProductRole(whoAmICtx("bob", "org-a"), &pb.OrgProductRoleReq{UserId: "alice", Product: "alpha", RoleKey: "editor"}); refusalCodeOf(err) != CodeProductRoleAbove {
		t.Errorf("bob giving alpha's editor: %v, want %s", err, CodeProductRoleAbove)
	}
	// Another organization does not see org-a's role.
	if _, err := h.lookupRole(context.Background(), mustCatalogue(t, h), "org-b", identityRoleProduct, "lister"); refusalCodeOf(err) != CodeProductRoleUnknown {
		t.Errorf("org-a's role from org-b: %v, want %s", err, CodeProductRoleUnknown)
	}
	// The backoffice's role is not org-a's to retire.
	if _, err := h.DefineProductRole(whoAmICtx("ops", ""), &pb.DefineProductRoleReq{Key: "realm", Name: "Realm", OrgScoped: true, Permissions: []string{"alpha:notes.NoteQuery.ListNotes"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.RetireOrgProductRole(alice, &pb.RetireOrgProductRoleReq{Key: "realm"}); refusalCodeOf(err) != CodeProductRolesRealmOnly {
		t.Errorf("org-a retiring the backoffice's role: %v, want %s", err, CodeProductRolesRealmOnly)
	}
	if _, err := h.RetireOrgProductRole(alice, &pb.RetireOrgProductRoleReq{Key: "lister"}); err != nil {
		t.Errorf("org-a retiring its own: %v", err)
	}
	if resp, _ := answer(t, h, "bob", "org-a", "alpha"); len(resp.GetProductRoles()) != 0 {
		t.Errorf("alpha for bob after lister was retired: %v, want none", resp.GetProductRoles())
	}
}

func mustCatalogue(t *testing.T, h *AuthServiceHandler) *productRoleCatalogue {
	t.Helper()
	c, err := h.productRoleCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
