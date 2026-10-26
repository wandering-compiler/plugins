package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `product_roles` feature: one identity for the
// project's PRODUCTS — domains whose (w17.domain).identity names this one.
// A product keeps no users. Its gateway authenticates every caller here,
// saying which product asks (x-w17-product), and the answer carries the KEYS
// of the roles the caller holds in that product (AuthResp.product_roles) —
// realm-wide and in the active organization — and no permission ids of this
// domain. The product turns the keys into its own ids from its own
// (w17.acl_roles), so nothing here holds another domain's permissions, and a
// product's deploy alone changes what its roles mean.
//
// The catalogue is the products' roles, baked in at codegen
// (w17_product_roles). Who holds what:
//
//   - inside an organization a member hands out and takes the product roles
//     covered by one they hold there themselves (the ceiling: it carries
//     every permission of the other), to members only;
//   - the backoffice, acting realm-wide and gated by the endpoint ACL, hands
//     out any — realm-wide ones too, which count in every organization.
//
// A member who leaves an organization loses the product roles held there; a
// deleted organization's end with it. Nothing is deleted.

// productHeader names the product whose gateway asks (principal.ProductKey;
// only a gateway writes it). The plugin keeps its own copy, as it does for the
// other gateway headers, so it builds against SDK releases that predate it.
const productHeader = "x-w17-product"

func init() {
	configChecks = append(configChecks, parseProductRoleCatalogue)
	authRespEnrichers = append(authRespEnrichers, answerProductRoles)
	membershipRemovalCascades = append(membershipRemovalCascades, endProductRolesOfMember)
	orgRemovalCascades = append(orgRemovalCascades, endProductRolesOfOrg)
}

// productRoleBounds narrow the product roles an organization's members hold
// to what the organization may hold (product_plans). Each returns whether
// the organization may hold `role` of `product`; nil when it bounds nothing.
var productRoleBounds []func(ctx context.Context, h *AuthServiceHandler, orgID, product string) (func(role string) bool, error)

// parseProductRoleCatalogue reads w17_product_roles once, at boot; one that
// does not parse refuses to boot.
func parseProductRoleCatalogue(h *AuthServiceHandler) error {
	c, err := readProductRoleCatalogue(h.ProductRolesTable)
	if err != nil {
		return err
	}
	h.productRoles, h.productRolesRead = c, true
	return nil
}

// productRoleCatalogue returns the parsed catalogue: the one read at boot, or
// read now for a handler that skipped ValidateConfig. Never nil: a project
// without products has an empty one, which names no product.
func (h *AuthServiceHandler) productRoleCatalogue() (*productRoleCatalogue, error) {
	if h.productRolesRead && h.productRoles != nil {
		return h.productRoles, nil
	}
	return readProductRoleCatalogue(h.ProductRolesTable)
}

func readProductRoleCatalogue(raw string) (*productRoleCatalogue, error) {
	c := &productRoleCatalogue{byProduct: map[string]map[string]productRoleEntry{}}
	if raw == "" {
		return c, nil
	}
	if err := json.Unmarshal([]byte(raw), c); err != nil {
		return nil, fmt.Errorf("auth plugin: w17_product_roles does not parse (%w) — the catalogue is generated; regenerate instead of editing it", err)
	}
	for _, r := range c.Roles {
		if r.Product == "" || r.Key == "" {
			return nil, fmt.Errorf("auth plugin: w17_product_roles names a role with no product or key — regenerate")
		}
		if c.byProduct[r.Product] == nil {
			c.byProduct[r.Product] = map[string]productRoleEntry{}
		}
		c.byProduct[r.Product][r.Key] = r
	}
	return c, nil
}

// role returns the catalogue's entry, refusing a product or a role it does
// not name.
func (c *productRoleCatalogue) role(ctx context.Context, product, key string) (productRoleEntry, error) {
	roles, ok := c.byProduct[product]
	if !ok {
		return productRoleEntry{}, refusal(ctx, codes.InvalidArgument, "product_roles: no such product", CodeProductUnknown, "product", MsgProductUnknown, nil)
	}
	r, ok := roles[key]
	if !ok {
		return productRoleEntry{}, refusal(ctx, codes.InvalidArgument, "product_roles: the product has no such role", CodeProductRoleUnknown, "role_key", MsgProductRoleUnknown, nil)
	}
	return r, nil
}

// heldProductRoles is what userID holds in product, as Authenticate counts it:
// the realm-wide grants, and those in orgID (empty = none) that the catalogue
// still holds in an organization and the organization may hold. A role the
// product no longer declares counts for nothing.
func heldProductRoles(ctx context.Context, h *AuthServiceHandler, c *productRoleCatalogue, userID, product, orgID string) ([]*pb.ProductRoleGrantRow, error) {
	resp, err := h.Query.ListProductRolesOfUser(ctx, &pb.ListProductRolesOfUserReq{UserId: userID, Product: product})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	var bounds []func(string) bool
	if orgID != "" {
		for _, b := range productRoleBounds {
			allow, err := b(ctx, h, orgID, product)
			if err != nil {
				return nil, err
			}
			if allow != nil {
				bounds = append(bounds, allow)
			}
		}
	}
	var out []*pb.ProductRoleGrantRow
	for _, g := range resp.GetGrants() {
		entry, ok := c.byProduct[product][g.GetRoleKey()]
		if !ok {
			continue
		}
		if g.GetOrgId() != "" {
			if g.GetOrgId() != orgID || !entry.OrgScoped {
				continue
			}
			if !allowedByAll(bounds, g.GetRoleKey()) {
				continue
			}
		}
		out = append(out, g)
	}
	return out, nil
}

func allowedByAll(bounds []func(string) bool, role string) bool {
	for _, allow := range bounds {
		if !allow(role) {
			return false
		}
	}
	return true
}

// answerProductRoles answers a product's gateway: the keys of the roles the
// caller holds in it, and none of this domain's permission ids.
func answerProductRoles(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, resp *pb.AuthResp) error {
	headers, _ := ctx.Value(authHeadersKey{}).(map[string]string)
	product := headers[productHeader]
	if product == "" {
		return nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	if _, ok := c.byProduct[product]; !ok {
		// Only a gateway writes the header, so this is a deployment whose
		// identity was generated without the product: say so loudly rather
		// than answer a product nobody declared.
		return status.Errorf(codes.FailedPrecondition, "product_roles: %q is no product of this identity — regenerate the identity with the product's (w17.domain).identity in place", product)
	}
	held, err := heldProductRoles(ctx, h, c, prin.userID, product, resp.GetScopes()["org_id"])
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(held))
	for _, g := range held {
		if !slices.Contains(keys, g.GetRoleKey()) {
			keys = append(keys, g.GetRoleKey())
		}
	}
	sort.Strings(keys)
	resp.ProductRoles = keys
	resp.PermissionIds = nil
	return nil
}

// endProductRolesOfMember is product_roles' membershipRemovalCascade.
func endProductRolesOfMember(ctx context.Context, h *AuthServiceHandler, userID, orgID, by string) error {
	_, err := h.Mutation.EndUserProductRoleGrantsInOrg(ctx, &pb.EndUserProductRoleGrantsInOrgReq{UserId: userID, OrgId: orgID, EndedBy: by})
	return err
}

// endProductRolesOfOrg is product_roles' orgRemovalCascade.
func endProductRolesOfOrg(ctx context.Context, h *AuthServiceHandler, orgID, by string) error {
	_, err := h.Mutation.EndProductRoleGrantsOfOrg(ctx, &pb.EndProductRoleGrantsOfOrgReq{OrgId: orgID, EndedBy: by})
	return err
}

// ListProductRoles is the catalogue: every product's roles, or one product's.
func (h *AuthServiceHandler) ListProductRoles(ctx context.Context, req *pb.ListProductRolesReq) (*pb.ListProductRolesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	if p := req.GetProduct(); p != "" {
		if _, ok := c.byProduct[p]; !ok {
			return nil, refusal(ctx, codes.InvalidArgument, "product_roles: no such product", CodeProductUnknown, "product", MsgProductUnknown, nil)
		}
	}
	out := &pb.ListProductRolesResp{}
	for _, r := range c.Roles {
		if req.GetProduct() == "" || r.Product == req.GetProduct() {
			out.Roles = append(out.Roles, &pb.ProductRoleInfo{Product: r.Product, Key: r.Key, Name: r.Name, OrgScoped: r.OrgScoped})
		}
	}
	return out, nil
}

// ListOrgProductRoleGrants is the active organization's grants.
func (h *AuthServiceHandler) ListOrgProductRoleGrants(ctx context.Context, req *pb.ListOrgProductRoleGrantsReq) (*pb.ProductRoleGrantsResp, error) {
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
	rows, err := h.Query.ListOrgProductRoleGrantRows(ctx, &pb.ListOrgProductRoleGrantRowsReq{OrgId: orgID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	return productRoleGrantsResp(rows.GetGrants(), req.GetUserId(), req.GetProduct()), nil
}

// AssignOrgProductRole gives a member of the active organization a role of a
// product, held there. The caller must hold that role there themselves.
func (h *AuthServiceHandler) AssignOrgProductRole(ctx context.Context, req *pb.OrgProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	caller, orgID, err := h.orgProductRoleCall(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := h.grantProductRole(ctx, caller, req.GetUserId(), orgID, req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	return &pb.ProductRoleChangeResp{}, nil
}

// RevokeOrgProductRole takes a product role held in the active organization.
// The caller must hold that role there themselves.
func (h *AuthServiceHandler) RevokeOrgProductRole(ctx context.Context, req *pb.OrgProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	caller, orgID, err := h.orgProductRoleCall(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := h.endProductRole(ctx, caller, req.GetUserId(), orgID, req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	return &pb.ProductRoleChangeResp{}, nil
}

// orgProductRoleCall checks what an organization's grant or revocation needs
// before it is made: the caller, the active organization, a role of the
// catalogue held in organizations, and the ceiling — a role the caller holds
// there (or realm-wide) covers it.
func (h *AuthServiceHandler) orgProductRoleCall(ctx context.Context, req *pb.OrgProductRoleReq) (caller, orgID string, err error) {
	if caller, err = callerUserID(ctx); err != nil {
		return "", "", Unauthenticated(err)
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return "", "", err
	}
	if orgID, err = activeOrgID(ctx); err != nil {
		return "", "", err
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return "", "", err
	}
	entry, err := c.role(ctx, req.GetProduct(), req.GetRoleKey())
	if err != nil {
		return "", "", err
	}
	if !entry.OrgScoped {
		return "", "", refusal(ctx, codes.InvalidArgument, "product_roles: the role is held realm-wide, not in an organization",
			CodeProductRoleRealmHeld, "role_key", MsgProductRoleRealmHeld, nil)
	}
	held, err := heldProductRoles(ctx, h, c, caller, req.GetProduct(), orgID)
	if err != nil {
		return "", "", err
	}
	// The ceiling: a role the caller holds here covers the one handed out —
	// it carries every permission of it (Covers, computed at codegen from the
	// product's roles; the role itself always).
	for _, g := range held {
		if g.GetRoleKey() == req.GetRoleKey() || slices.Contains(c.byProduct[req.GetProduct()][g.GetRoleKey()].Covers, req.GetRoleKey()) {
			return caller, orgID, nil
		}
	}
	return "", "", refusal(ctx, codes.PermissionDenied, "product_roles: no role the caller holds here covers this one",
		CodeProductRoleAbove, "role_key", MsgProductRoleAbove, nil)
}

// ListProductRoleGrants is the backoffice's view: an organization's grants,
// a user's everywhere, or (neither) the realm-wide ones.
func (h *AuthServiceHandler) ListProductRoleGrants(ctx context.Context, req *pb.ListProductRoleGrantsReq) (*pb.ProductRoleGrantsResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.refuseProductRolesInsideOrg(ctx, "ListProductRoleGrants"); err != nil {
		return nil, err
	}
	var rows *pb.ProductRoleGrantRowsResp
	var err error
	switch {
	case req.GetUserId() != "":
		rows, err = h.Query.ListUserProductRoleGrantRows(ctx, &pb.ListUserProductRoleGrantRowsReq{UserId: req.GetUserId()})
	case req.GetOrgId() != "":
		rows, err = h.Query.ListOrgProductRoleGrantRows(ctx, &pb.ListOrgProductRoleGrantRowsReq{OrgId: req.GetOrgId()})
	default:
		rows, err = h.Query.ListRealmProductRoleGrantRows(ctx, &pb.ListRealmProductRoleGrantRowsReq{})
	}
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	grants := rows.GetGrants()
	if req.GetUserId() != "" && req.GetOrgId() != "" {
		var inOrg []*pb.ProductRoleGrantRow
		for _, g := range grants {
			if g.GetOrgId() == req.GetOrgId() {
				inOrg = append(inOrg, g)
			}
		}
		grants = inOrg
	}
	return productRoleGrantsResp(grants, "", req.GetProduct()), nil
}

// AssignProductRole is the backoffice's grant: in an organization (org_id) or
// realm-wide. No ceiling — the endpoint ACL decides who is the backoffice.
func (h *AuthServiceHandler) AssignProductRole(ctx context.Context, req *pb.ProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	caller, err := h.backofficeProductRoleCall(ctx, "AssignProductRole", req)
	if err != nil {
		return nil, err
	}
	if err := h.grantProductRole(ctx, caller, req.GetUserId(), req.GetOrgId(), req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	return &pb.ProductRoleChangeResp{}, nil
}

// RevokeProductRole is the backoffice's revocation.
func (h *AuthServiceHandler) RevokeProductRole(ctx context.Context, req *pb.ProductRoleReq) (*pb.ProductRoleChangeResp, error) {
	caller, err := h.backofficeProductRoleCall(ctx, "RevokeProductRole", req)
	if err != nil {
		return nil, err
	}
	if err := h.endProductRole(ctx, caller, req.GetUserId(), req.GetOrgId(), req.GetProduct(), req.GetRoleKey()); err != nil {
		return nil, err
	}
	return &pb.ProductRoleChangeResp{}, nil
}

func (h *AuthServiceHandler) backofficeProductRoleCall(ctx context.Context, method string, req *pb.ProductRoleReq) (string, error) {
	caller, err := callerUserID(ctx)
	if err != nil {
		return "", Unauthenticated(err)
	}
	if err := h.refuseProductRolesInsideOrg(ctx, method); err != nil {
		return "", err
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return "", err
	}
	entry, err := c.role(ctx, req.GetProduct(), req.GetRoleKey())
	if err != nil {
		return "", err
	}
	if req.GetOrgId() != "" && !entry.OrgScoped {
		return "", refusal(ctx, codes.InvalidArgument, "product_roles: the role is held realm-wide, not in an organization",
			CodeProductRoleRealmHeld, "role_key", MsgProductRoleRealmHeld, nil)
	}
	return caller, nil
}

// refuseProductRolesInsideOrg holds the backoffice's calls to the realm, and
// to the callers the endpoint ACL lets make them (refuseInsideOrg's rule).
func (h *AuthServiceHandler) refuseProductRolesInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" {
		return refusal(ctx, codes.PermissionDenied, "product_roles: the backoffice's grants are made realm-wide, not from inside an organization",
			CodeProductRolesRealmOnly, "", MsgProductRolesRealmOnly, nil)
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "product_roles: the backoffice's grant methods need the endpoint ACL — "+method+" is not in the lock")
	}
	return nil
}

// grantProductRole writes a grant: in orgID (to a member, within the
// organization's plan) or realm-wide. One already held changes nothing.
func (h *AuthServiceHandler) grantProductRole(ctx context.Context, caller, userID, orgID, product, role string) error {
	if orgID != "" {
		member, err := h.Query.GetOrgMember(ctx, &pb.GetOrgMemberReq{UserId: userID, OrgId: orgID})
		if err != nil && status.Code(err) != codes.NotFound {
			return err
		}
		if member.GetUserId() == "" {
			return refusal(ctx, codes.FailedPrecondition, "product_roles: the user is not a member of the organization",
				CodeProductRoleNotMember, "user_id", MsgProductRoleNotMember, nil)
		}
		for _, b := range productRoleBounds {
			allow, err := b(ctx, h, orgID, product)
			if err != nil {
				return err
			}
			if allow != nil && !allow(role) {
				return refusal(ctx, codes.FailedPrecondition, "product_roles: the organization's plan does not carry the role",
					CodeProductRoleNotInPlan, "role_key", MsgProductRoleNotInPlan, nil)
			}
		}
	}
	if g, err := h.liveProductRoleGrant(ctx, userID, orgID, product, role); err != nil {
		return err
	} else if g != nil {
		return nil
	}
	// A concurrent grant of the same role lands on the unique index: it is
	// held either way, which is what was asked.
	if _, err := h.Mutation.GrantProductRoleRow(ctx, &pb.GrantProductRoleRowReq{
		UserId: userID, OrgId: orgID, Product: product, RoleKey: role, GrantedBy: caller,
	}); err != nil && !isUniqueConflict(err) {
		return err
	}
	return nil
}

// endProductRole ends a live grant. One not held changes nothing.
func (h *AuthServiceHandler) endProductRole(ctx context.Context, caller, userID, orgID, product, role string) error {
	g, err := h.liveProductRoleGrant(ctx, userID, orgID, product, role)
	if err != nil || g == nil {
		return err
	}
	if _, err := h.Mutation.EndProductRoleGrantRow(ctx, &pb.EndProductRoleGrantRowReq{Id: g.GetId(), EndedBy: caller}); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

// liveProductRoleGrant is userID's live grant of role in product, held in
// orgID (empty = realm-wide); nil when there is none.
func (h *AuthServiceHandler) liveProductRoleGrant(ctx context.Context, userID, orgID, product, role string) (*pb.ProductRoleGrantRow, error) {
	resp, err := h.Query.ListUserProductRoleGrantRows(ctx, &pb.ListUserProductRoleGrantRowsReq{UserId: userID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	for _, g := range resp.GetGrants() {
		if g.GetOrgId() == orgID && g.GetProduct() == product && g.GetRoleKey() == role {
			return g, nil
		}
	}
	return nil, nil
}

func productRoleGrantsResp(rows []*pb.ProductRoleGrantRow, userID, product string) *pb.ProductRoleGrantsResp {
	out := &pb.ProductRoleGrantsResp{}
	for _, g := range rows {
		if (userID != "" && g.GetUserId() != userID) || (product != "" && g.GetProduct() != product) {
			continue
		}
		out.Grants = append(out.Grants, &pb.ProductRoleGrantInfo{
			Id: g.GetId(), UserId: g.GetUserId(), OrgId: g.GetOrgId(), Product: g.GetProduct(),
			RoleKey: g.GetRoleKey(), GrantedBy: g.GetGrantedBy(), GrantedAt: g.GetGrantedAt(),
		})
	}
	return out
}
