package handlers

import (
	"context"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The identity's own roles (product_roles). A product declares presets —
// its (w17.acl_roles), baked into the catalogue with the permission codes
// they grant — and the identity composes roles of its own from every
// product's permissions: the backoffice's, realm-wide (ProductRoleDef with no
// organization), and an organization's own, under the role ceiling there. A
// grant, an invitation, a registration policy, a plan line or a token names
// one as product `*` (identityRoleProduct): it may span products.
//
// What a caller holds in a product is then a set of the product's permission
// codes — the union of what their roles grant there — and that is what
// Authenticate answers the product's gateway, which resolves the codes
// against its own lock. The identity still keeps no permission id of
// another domain: a code is a name.

// identityRoleProduct is the product a grant names for the identity's own
// role: any, since one may span products. A product is a domain name, which
// never is `*`.
const identityRoleProduct = "*"

// roleGrant is what one role grants: product → permission codes.
type roleGrant struct {
	orgScoped bool
	perms     map[string][]string
	preset    bool
	orgID     string
	name      string
}

// productRoleDefs are the identity's own roles live for orgID: the
// backoffice's and (orgID set) that organization's — read once per request.
func productRoleDefs(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.ProductRoleDefRow, error) {
	key := "product_role_defs:" + orgID
	if m := requestMemoOf(ctx); m != nil {
		if v, ok := m[key].([]*pb.ProductRoleDefRow); ok {
			return v, nil
		}
	}
	resp, err := h.Query.ListProductRoleDefs(ctx, &pb.ListProductRoleDefsReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	if m := requestMemoOf(ctx); m != nil {
		m[key] = resp.GetRoles()
	}
	return resp.GetRoles(), nil
}

// identityRoleDef is the identity's own role key live for orgID: the
// organization's own first, then the backoffice's. nil when there is none.
func identityRoleDef(ctx context.Context, h *AuthServiceHandler, orgID, key string) (*pb.ProductRoleDefRow, error) {
	defs, err := productRoleDefs(ctx, h, orgID)
	if err != nil {
		return nil, err
	}
	var realm *pb.ProductRoleDefRow
	for _, d := range defs {
		if d.GetKey() != key {
			continue
		}
		if d.GetOrgId() != "" {
			return d, nil
		}
		realm = d
	}
	return realm, nil
}

// lookupRole is what the role (product, key) grants, refusing one the
// catalogue does not name or the identity does not define (for orgID: its
// own roles and the backoffice's).
func (h *AuthServiceHandler) lookupRole(ctx context.Context, c *productRoleCatalogue, orgID, product, key string) (roleGrant, error) {
	if product != identityRoleProduct {
		entry, err := c.role(ctx, product, key)
		if err != nil {
			return roleGrant{}, err
		}
		return roleGrant{orgScoped: entry.OrgScoped, perms: map[string][]string{product: entry.Permissions}, preset: true, name: entry.Name}, nil
	}
	def, err := identityRoleDef(ctx, h, orgID, key)
	if err != nil {
		return roleGrant{}, err
	}
	if def == nil {
		return roleGrant{}, refusal(ctx, codes.InvalidArgument, "product_roles: the identity defines no such role", CodeProductRoleUnknown, "role_key", MsgProductRoleUnknown, nil)
	}
	return roleGrant{orgScoped: def.GetOrgScoped(), perms: decodeRolePermissions(def.GetPermissions()), orgID: def.GetOrgId(), name: def.GetName()}, nil
}

// encodeRolePermissions is the column form of a role's permissions:
// `<product>:<code>` pairs, sorted and deduplicated, comma-separated. A code
// carries neither ':' nor ','.
func encodeRolePermissions(perms map[string][]string) string {
	var pairs []string
	for p, cs := range perms {
		for _, c := range cs {
			pairs = append(pairs, p+":"+c)
		}
	}
	sort.Strings(pairs)
	return strings.Join(slices.Compact(pairs), ",")
}

func decodeRolePermissions(s string) map[string][]string {
	out := map[string][]string{}
	for _, pair := range strings.Split(s, ",") {
		if p, c, ok := strings.Cut(strings.TrimSpace(pair), ":"); ok && p != "" && c != "" {
			out[p] = append(out[p], c)
		}
	}
	return out
}

// heldProductPermissions is what userID holds, product by product, as
// Authenticate counts it: the roles granted realm-wide, and those granted in
// orgID (empty = none) that are held in an organization and every bound
// (product_plans) allows. A role the catalogue or the identity no longer
// has counts for nothing.
func heldProductPermissions(ctx context.Context, h *AuthServiceHandler, c *productRoleCatalogue, userID, orgID string) (map[string]map[string]bool, error) {
	resp, err := h.Query.ListUserProductRoleGrantRows(ctx, &pb.ListUserProductRoleGrantRowsReq{UserId: userID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	var bounds []func(product, roleProduct, roleKey string) bool
	if orgID != "" {
		for _, b := range productRoleBounds {
			allow, err := b(ctx, h, orgID)
			if err != nil {
				return nil, err
			}
			if allow != nil {
				bounds = append(bounds, allow)
			}
		}
	}
	out := map[string]map[string]bool{}
	for _, g := range resp.GetGrants() {
		if g.GetOrgId() != "" && g.GetOrgId() != orgID {
			continue
		}
		role, err := h.lookupRole(ctx, c, orgID, g.GetProduct(), g.GetRoleKey())
		if err != nil {
			if roleGone(err) {
				continue
			}
			return nil, err
		}
		if g.GetOrgId() != "" && !role.orgScoped {
			continue
		}
		for product, codes := range role.perms {
			if g.GetOrgId() != "" && !allowedByAllBounds(bounds, product, g.GetProduct(), g.GetRoleKey()) {
				continue
			}
			if out[product] == nil {
				out[product] = map[string]bool{}
			}
			for _, code := range codes {
				out[product][code] = true
			}
		}
	}
	return out, nil
}

// roleGone reports the refusal of a role the catalogue or the identity no
// longer has: a grant of it counts for nothing, and nothing fails.
func roleGone(err error) bool {
	st, ok := status.FromError(err)
	if !ok || err == nil {
		return false
	}
	for _, d := range st.Details() {
		if ed, ok := d.(interface{ GetCode() string }); ok {
			switch ed.GetCode() {
			case CodeProductUnknown, CodeProductRoleUnknown:
				return true
			}
		}
	}
	return false
}

func allowedByAllBounds(bounds []func(product, roleProduct, roleKey string) bool, product, roleProduct, roleKey string) bool {
	for _, allow := range bounds {
		if !allow(product, roleProduct, roleKey) {
			return false
		}
	}
	return true
}

// covers reports whether held carries every permission role grants.
func covers(held map[string]map[string]bool, role roleGrant) bool {
	for product, codes := range role.perms {
		for _, code := range codes {
			if !held[product][code] {
				return false
			}
		}
	}
	return true
}

// checkProductRolePermissions refuses a permission the catalogue does not name and
// returns the role's permissions, product by product, sorted.
func (h *AuthServiceHandler) checkProductRolePermissions(ctx context.Context, c *productRoleCatalogue, pairs []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, pair := range pairs {
		product, code, ok := strings.Cut(strings.TrimSpace(pair), ":")
		if !ok || !slices.Contains(c.Products[product], code) {
			return nil, refusal(ctx, codes.InvalidArgument, "product_roles: no product of this identity has the permission "+pair,
				CodeProductPermissionUnknown, "permissions", MsgProductPermissionUnknown, nil)
		}
		if !slices.Contains(out[product], code) {
			out[product] = append(out[product], code)
		}
	}
	for p := range out {
		sort.Strings(out[p])
	}
	return out, nil
}

// ListProductPermissions is every product's permission codes.
func (h *AuthServiceHandler) ListProductPermissions(ctx context.Context, req *pb.ListProductPermissionsReq) (*pb.ListProductPermissionsResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	if p := req.GetProduct(); p != "" {
		if _, ok := c.Products[p]; !ok {
			return nil, refusal(ctx, codes.InvalidArgument, "product_roles: no such product", CodeProductUnknown, "product", MsgProductUnknown, nil)
		}
	}
	products := make([]string, 0, len(c.Products))
	for p := range c.Products {
		products = append(products, p)
	}
	sort.Strings(products)
	out := &pb.ListProductPermissionsResp{}
	for _, p := range products {
		if req.GetProduct() == "" || req.GetProduct() == p {
			out.Products = append(out.Products, &pb.ProductPermissionSet{Product: p, Permissions: append([]string{}, c.Products[p]...)})
		}
	}
	return out, nil
}

// DefineProductRole is the backoffice's own role, realm-wide: defined, or
// redefined when the key is live. No ceiling — the endpoint ACL decides who
// is the backoffice.
func (h *AuthServiceHandler) DefineProductRole(ctx context.Context, req *pb.DefineProductRoleReq) (*pb.ProductRoleDefResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseProductRolesInsideOrg(ctx, "DefineProductRole"); err != nil {
		return nil, err
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	perms, err := h.checkProductRolePermissions(ctx, c, req.GetPermissions())
	if err != nil {
		return nil, err
	}
	return h.defineRole(ctx, caller, "", req.GetKey(), req.GetName(), req.GetOrgScoped(), perms)
}

// RetireProductRole ends the backoffice's own role: its grants hold nothing
// from the next request on. Nothing is deleted.
func (h *AuthServiceHandler) RetireProductRole(ctx context.Context, req *pb.RetireProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseProductRolesInsideOrg(ctx, "RetireProductRole"); err != nil {
		return nil, err
	}
	return h.retireRole(ctx, caller, "", req.GetKey())
}

// DefineOrgProductRole is the active organization's own role, held there:
// every permission of it carried by a role the caller holds there (the
// ceiling).
func (h *AuthServiceHandler) DefineOrgProductRole(ctx context.Context, req *pb.DefineOrgProductRoleReq) (*pb.ProductRoleDefResp, error) {
	if resp, done, err := underOrgLock(ctx, h, scopeOrg(ctx), req, h.DefineOrgProductRole); done {
		return resp, err
	}
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	perms, err := h.checkProductRolePermissions(ctx, c, req.GetPermissions())
	if err != nil {
		return nil, err
	}
	held, err := heldProductPermissions(ctx, h, c, caller, orgID)
	if err != nil {
		return nil, err
	}
	if !covers(held, roleGrant{perms: perms}) {
		return nil, refusal(ctx, codes.PermissionDenied, "product_roles: the role grants a permission the caller does not hold here",
			CodeProductRoleAbove, "permissions", MsgProductRoleAbove, nil)
	}
	return h.defineRole(ctx, caller, orgID, req.GetKey(), req.GetName(), true, perms)
}

// RetireOrgProductRole ends the active organization's own role.
func (h *AuthServiceHandler) RetireOrgProductRole(ctx context.Context, req *pb.RetireOrgProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	if resp, done, err := underOrgLock(ctx, h, scopeOrg(ctx), req, h.RetireOrgProductRole); done {
		return resp, err
	}
	caller, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	role, err := h.lookupRole(ctx, c, orgID, identityRoleProduct, req.GetKey())
	if err != nil {
		return nil, err
	}
	if role.orgID != orgID {
		// The backoffice's role is not the organization's to retire.
		return nil, refusal(ctx, codes.PermissionDenied, "product_roles: the role is the backoffice's",
			CodeProductRolesRealmOnly, "role_key", MsgProductRolesRealmOnly, nil)
	}
	held, err := heldProductPermissions(ctx, h, c, caller, orgID)
	if err != nil {
		return nil, err
	}
	if !covers(held, role) {
		return nil, refusal(ctx, codes.PermissionDenied, "product_roles: the role grants a permission the caller does not hold here",
			CodeProductRoleAbove, "role_key", MsgProductRoleAbove, nil)
	}
	return h.retireRole(ctx, caller, orgID, req.GetKey())
}

// defineRole writes the identity's own role in orgID ("" = the
// backoffice's): a live key is redefined in place, its grants keep it.
func (h *AuthServiceHandler) defineRole(ctx context.Context, caller, orgID, key, name string, orgScoped bool, perms map[string][]string) (*pb.ProductRoleDefResp, error) {
	if name == "" {
		name = key
	}
	encoded := encodeRolePermissions(perms)
	live, err := ownRoleDef(ctx, h, orgID, key)
	if err != nil {
		return nil, err
	}
	if live != nil {
		if _, err := h.Mutation.UpdateProductRoleDef(ctx, &pb.UpdateProductRoleDefReq{Id: live.GetId(), Name: name, OrgScoped: orgScoped, Permissions: encoded}); err != nil {
			return nil, err
		}
	} else if _, err := h.Mutation.InsertProductRoleDef(ctx, &pb.InsertProductRoleDefReq{
		OrgId: orgID, Key: key, Name: name, OrgScoped: orgScoped, Permissions: encoded, CreatedBy: caller,
	}); err != nil {
		return nil, err
	}
	forgetProductRoleDefs(ctx, orgID)
	return &pb.ProductRoleDefResp{Role: roleInfo(identityRoleProduct, key, roleGrant{orgScoped: orgScoped, perms: perms, orgID: orgID, name: name})}, nil
}

// retireRole ends the live role key defined in orgID ("" = the
// backoffice's). One not live changes nothing.
func (h *AuthServiceHandler) retireRole(ctx context.Context, caller, orgID, key string) (*pb.ProductRoleChangeResp, error) {
	live, err := ownRoleDef(ctx, h, orgID, key)
	if err != nil || live == nil {
		return &pb.ProductRoleChangeResp{}, err
	}
	if _, err := h.Mutation.EndProductRoleDef(ctx, &pb.EndProductRoleDefReq{Id: live.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	forgetProductRoleDefs(ctx, orgID)
	return &pb.ProductRoleChangeResp{}, nil
}

// ownRoleDef is the live role key defined by orgID itself ("" = the
// backoffice's), nil when there is none.
func ownRoleDef(ctx context.Context, h *AuthServiceHandler, orgID, key string) (*pb.ProductRoleDefRow, error) {
	defs, err := productRoleDefs(ctx, h, orgID)
	if err != nil {
		return nil, err
	}
	for _, d := range defs {
		if d.GetKey() == key && d.GetOrgId() == orgID {
			return d, nil
		}
	}
	return nil, nil
}

func forgetProductRoleDefs(ctx context.Context, orgID string) {
	if m := requestMemoOf(ctx); m != nil {
		delete(m, "product_role_defs:"+orgID)
		delete(m, "product_role_defs:")
	}
}

// roleInfo is a role as the catalogue lists it.
func roleInfo(product, key string, r roleGrant) *pb.ProductRoleInfo {
	info := &pb.ProductRoleInfo{Product: product, Key: key, Name: r.name, OrgScoped: r.orgScoped, Preset: r.preset, OrgId: r.orgID}
	if r.preset {
		info.Permissions = append([]string{}, r.perms[product]...)
		return info
	}
	var perms []string
	for p, cs := range r.perms {
		for _, c := range cs {
			perms = append(perms, p+":"+c)
		}
	}
	sort.Strings(perms)
	info.Permissions = perms
	return info
}
