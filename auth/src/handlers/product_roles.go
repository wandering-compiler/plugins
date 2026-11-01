package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `product_roles` feature: one identity for the
// project's PRODUCTS — domains whose (w17.domain).identity names this one.
// A product keeps no users. Its gateway authenticates every caller here,
// saying which product asks (x-w17-product), and the answer carries the
// product's PERMISSION CODES the caller holds there (AuthResp.product_roles,
// the keys the product's gateway translates) — through the roles they hold
// realm-wide and in the active organization — and no permission ids of this
// domain. The product resolves the codes against its own lock.
//
// The roles are the identity's (product_role_defs.go): presets the products
// declare in their (w17.acl_roles), baked into the catalogue at codegen
// (w17_product_roles) with the codes they grant, and roles the identity
// composes itself from every product's permissions — the backoffice's and an
// organization's own. Who holds what:
//
//   - inside an organization a member hands out and takes the roles whose
//     every permission they hold there themselves (the ceiling), to members
//     only;
//   - the backoffice, acting realm-wide and gated by the endpoint ACL, hands
//     out any — realm-wide ones too, which count in every organization.
//
// A member who leaves an organization loses the product roles held there; a
// deleted organization's end with it. Nothing is deleted.

// productHeader names the product whose gateway asks (principal.ProductKey;
// only a gateway writes it). The plugin keeps its own copy, as it does for the
// other gateway headers, so it builds against SDK releases that predate it.
const productHeader = "x-w17-product"

// callerDomainKey is the calling domain the identity's private gateway
// admitted (sdk privatesurface.CallerDomainKey): only that gateway writes it.
const callerDomainKey = "x-w17-caller-domain"

func init() {
	configChecks = append(configChecks, parseProductRoleCatalogue)
	authRespEnrichers = append(authRespEnrichers, answerProductRoles)
	membershipRemovalCascades = append(membershipRemovalCascades, endProductRolesOfMember)
	memberManageChecks = append(memberManageChecks, checkMemberProductRolesWithinCaller)
	orgRemovalCascades = append(orgRemovalCascades, endProductRolesOfOrg)
}

// productRoleBounds narrow what an organization's members hold through the
// roles granted there to what the organization may hold (product_plans).
// Each returns whether a role (roleProduct, roleKey — a preset, or the
// identity's own as `*`) may grant its permissions of `product` there; nil
// when it bounds nothing.
var productRoleBounds []func(ctx context.Context, h *AuthServiceHandler, orgID string) (func(product, roleProduct, roleKey string) bool, error)

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
	for p := range c.Products {
		if c.byProduct[p] == nil {
			c.byProduct[p] = map[string]productRoleEntry{}
		}
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

// productRoleNarrowers narrow the permission codes Authenticate answers a
// product by what the credential itself carries (product_roles with
// api_token: an API token's own share). Appended by the combination's init.
var productRoleNarrowers []func(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, orgID, product string, codes []string) ([]string, error)

// answerProductRoles answers a product's gateway: the product's permission
// codes the caller holds, and none of this domain's permission ids.
func answerProductRoles(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, resp *pb.AuthResp) error {
	headers, _ := ctx.Value(authHeadersKey{}).(map[string]string)
	product := headers[productHeader]
	if product == "" {
		return nil
	}
	// A product asks only through this identity's PRIVATE surface, and only
	// for itself: its private gateway admitted the calling domain by its
	// certificate and says which one it was. Anything else — a product
	// dialing this domain's tiers, one product asking as another — is refused.
	md, _ := metadata.FromIncomingContext(ctx)
	if caller := firstMeta(md, callerDomainKey); caller != product {
		return status.Errorf(codes.PermissionDenied, "product_roles: %q may ask only through the identity's private surface, as itself (the private gateway admitted %q)", product, caller)
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
	orgID := resp.GetScopes()["org_id"]
	held, err := heldProductPermissions(ctx, h, c, prin.userID, orgID)
	if err != nil {
		return err
	}
	codes := make([]string, 0, len(held[product]))
	for code := range held[product] {
		codes = append(codes, code)
	}
	for _, narrow := range productRoleNarrowers {
		if codes, err = narrow(ctx, h, prin, orgID, product, codes); err != nil {
			return err
		}
	}
	sort.Strings(codes)
	resp.ProductRoles = codes
	resp.PermissionIds = nil
	// What the identity set aside for a request naming no organization is in
	// THIS domain's ids, which mean nothing against the product's lock; the
	// product is told its own codes instead, and its gateway translates them
	// as it does the set above (acllock.OrgPermissionsOfProductRoles).
	delete(resp.GetScopes(), orgPermissionsScope)
	if mark, ok := orgUnnamed(ctx); orgID == "" && ok {
		aside, err := productCodesHeldInOrgs(ctx, h, c, prin, product, mark)
		if err != nil {
			return err
		}
		if len(aside) > 0 && resp.Scopes != nil {
			resp.Scopes[orgProductRolesScope] = strings.Join(aside, ",")
		}
	}
	return nil
}

// productCodesHeldInOrgs is the product's permission codes the caller holds
// only through roles granted inside an organization — what a request naming
// none does not count, and what lets the product's gateway answer "name one"
// (ORGANIZATION_REQUIRED) rather than "no access" for a code among them. Every
// organization the caller holds such a role in, with no plan applied: a hint
// that over-reaches only means the request, once it names one, is refused as
// MISSING_PERMISSION after all. Only organizations the request could have
// named count (mark): on an audience admitting some membership kinds, those.
// An API token's own share narrows it as it narrows the set
// (productRoleNarrowers).
func productCodesHeldInOrgs(ctx context.Context, h *AuthServiceHandler, c *productRoleCatalogue, prin *authPrincipal, product string, mark orgUnnamedMark) ([]string, error) {
	resp, err := h.Query.ListUserProductRoleGrantRows(ctx, &pb.ListUserProductRoleGrantRowsReq{UserId: prin.userID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	held := map[string]bool{}
	for _, g := range resp.GetGrants() {
		// Realm-wide grants already count; one in an organization the
		// audience does not admit is no "name it" (orgUnnamedMark).
		if g.GetOrgId() == "" || !mark.covers(g.GetOrgId()) {
			continue
		}
		role, err := h.lookupRole(ctx, c, g.GetOrgId(), g.GetProduct(), g.GetRoleKey())
		if err != nil {
			if roleGone(err) {
				continue
			}
			return nil, err
		}
		if !role.orgScoped {
			continue
		}
		for _, code := range role.perms[product] {
			held[code] = true
		}
	}
	out := make([]string, 0, len(held))
	for code := range held {
		out = append(out, code)
	}
	for _, narrow := range productRoleNarrowers {
		if out, err = narrow(ctx, h, prin, "", product, out); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
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
	if p := req.GetProduct(); p != "" && p != identityRoleProduct {
		if _, ok := c.byProduct[p]; !ok {
			return nil, refusal(ctx, codes.InvalidArgument, "product_roles: no such product", CodeProductUnknown, "product", MsgProductUnknown, nil)
		}
	}
	out := &pb.ListProductRolesResp{}
	for _, r := range c.Roles {
		if req.GetProduct() == "" || r.Product == req.GetProduct() {
			out.Roles = append(out.Roles, roleInfo(r.Product, r.Key, roleGrant{orgScoped: r.OrgScoped, perms: map[string][]string{r.Product: r.Permissions}, preset: true, name: r.Name}))
		}
	}
	if req.GetProduct() == "" || req.GetProduct() == identityRoleProduct {
		// The identity's own: the backoffice's, and the active
		// organization's when the request acts in one.
		orgID, _ := principal.Scope(ctx, "org_id")
		defs, err := productRoleDefs(ctx, h, orgID)
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			out.Roles = append(out.Roles, roleInfo(identityRoleProduct, d.GetKey(), roleGrant{orgScoped: d.GetOrgScoped(), perms: decodeRolePermissions(d.GetPermissions()), orgID: d.GetOrgId(), name: d.GetName()}))
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
	if resp, done, err := underOrgLock(ctx, h, scopeOrg(ctx), req, h.AssignOrgProductRole); done {
		return resp, err
	}
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
	if resp, done, err := underOrgLock(ctx, h, scopeOrg(ctx), req, h.RevokeOrgProductRole); done {
		return resp, err
	}
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
	if err := h.checkOrgProductRole(ctx, c, orgID, req.GetProduct(), req.GetRoleKey()); err != nil {
		return "", "", err
	}
	if err := h.checkProductRoleCeiling(ctx, c, caller, orgID, req.GetProduct(), req.GetRoleKey()); err != nil {
		return "", "", err
	}
	return caller, orgID, nil
}

// checkOrgProductRole refuses a role the catalogue does not name, the
// identity does not define for orgID, or one held realm-wide only.
func (h *AuthServiceHandler) checkOrgProductRole(ctx context.Context, c *productRoleCatalogue, orgID, product, role string) error {
	r, err := h.lookupRole(ctx, c, orgID, product, role)
	if err != nil {
		return err
	}
	if !r.orgScoped {
		return refusal(ctx, codes.InvalidArgument, "product_roles: the role is held realm-wide, not in an organization",
			CodeProductRoleRealmHeld, "role_key", MsgProductRoleRealmHeld, nil)
	}
	return nil
}

// checkProductRoleCeiling refuses a role carrying a permission the caller
// does not hold in orgID (or realm-wide): a caller hands out only what their
// own roles there include.
func (h *AuthServiceHandler) checkProductRoleCeiling(ctx context.Context, c *productRoleCatalogue, caller, orgID, product, role string) error {
	r, err := h.lookupRole(ctx, c, orgID, product, role)
	if err != nil {
		return err
	}
	held, err := heldProductPermissions(ctx, h, c, caller, orgID)
	if err != nil {
		return err
	}
	if covers(held, r) {
		return nil
	}
	return refusal(ctx, codes.PermissionDenied, "product_roles: no role the caller holds here covers this one",
		CodeProductRoleAbove, "role_key", MsgProductRoleAbove, nil)
}

// checkProductRoleInPlan refuses a role the organization's plan does not
// carry for every product it grants in (product_plans; nothing bounds it
// without).
func (h *AuthServiceHandler) checkProductRoleInPlan(ctx context.Context, orgID, product, role string) error {
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	r, err := h.lookupRole(ctx, c, orgID, product, role)
	if err != nil {
		return err
	}
	for _, b := range productRoleBounds {
		allow, err := b(ctx, h, orgID)
		if err != nil {
			return err
		}
		if allow == nil {
			continue
		}
		for p := range r.perms {
			if !allow(p, product, role) {
				return refusal(ctx, codes.FailedPrecondition, "product_roles: the organization's plan does not carry the role",
					CodeProductRoleNotInPlan, "role_key", MsgProductRoleNotInPlan, nil)
			}
		}
	}
	return nil
}

// orgProductRoleRefs checks the products' roles an invitation or an open
// registration gives in orgID — each named by the catalogue, held in an
// organization and carried by the plan; and, with a caller, covered by one
// they hold there — and returns them as the column stores them.
func (h *AuthServiceHandler) orgProductRoleRefs(ctx context.Context, orgID, caller string, refs []*pb.ProductRoleRef) (string, error) {
	if len(refs) == 0 {
		return "", nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return "", err
	}
	for _, r := range refs {
		if err := h.checkOrgProductRole(ctx, c, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return "", err
		}
		if err := h.checkProductRoleInPlan(ctx, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
			return "", err
		}
		if caller != "" {
			if err := h.checkProductRoleCeiling(ctx, c, caller, orgID, r.GetProduct(), r.GetRoleKey()); err != nil {
				return "", err
			}
		}
	}
	return encodeProductRoleRefs(refs), nil
}

// encodeProductRoleRefs is the column form of a set of product roles:
// `<product>:<role key>` pairs, sorted and deduplicated, comma-separated.
// Neither a domain name (or `*`, the identity's own) nor a role key carries
// ':' or ','.
func encodeProductRoleRefs(refs []*pb.ProductRoleRef) string {
	pairs := make([]string, 0, len(refs))
	for _, r := range refs {
		pairs = append(pairs, r.GetProduct()+":"+r.GetRoleKey())
	}
	sort.Strings(pairs)
	return strings.Join(slices.Compact(pairs), ",")
}

// decodeProductRoleRefs reads encodeProductRoleRefs' form back.
func decodeProductRoleRefs(s string) []*pb.ProductRoleRef {
	var out []*pb.ProductRoleRef
	for _, pair := range strings.Split(s, ",") {
		if product, role, ok := strings.Cut(strings.TrimSpace(pair), ":"); ok && product != "" && role != "" {
			out = append(out, &pb.ProductRoleRef{Product: product, RoleKey: role})
		}
	}
	return out
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
	if resp, done, err := underOrgLock(ctx, h, req.GetOrgId(), req, h.AssignProductRole); done {
		return resp, err
	}
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
	if resp, done, err := underOrgLock(ctx, h, req.GetOrgId(), req, h.RevokeProductRole); done {
		return resp, err
	}
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
	entry, err := h.lookupRole(ctx, c, req.GetOrgId(), req.GetProduct(), req.GetRoleKey())
	if err != nil {
		return "", err
	}
	if req.GetOrgId() != "" && !entry.orgScoped {
		return "", refusal(ctx, codes.InvalidArgument, "product_roles: the role is held realm-wide, not in an organization",
			CodeProductRoleRealmHeld, "role_key", MsgProductRoleRealmHeld, nil)
	}
	return caller, nil
}

// refuseProductRolesInsideOrg holds the backoffice's calls to the realm, and
// to the callers the endpoint ACL lets make them (refuseInsideOrg's rule).
func (h *AuthServiceHandler) refuseProductRolesInsideOrg(ctx context.Context, method string) error {
	if orgID, ok := principal.Scope(ctx, "org_id"); ok && orgID != "" && !h.heldRealmWide(ctx, method) {
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
		if err := h.checkProductRoleInPlan(ctx, orgID, product, role); err != nil {
			return err
		}
	}
	return h.writeProductRoleGrant(ctx, caller, userID, orgID, product, role)
}

// writeProductRoleGrant writes the grant with no check of the membership or
// the plan: for the joins (an accepted invitation, an open registration)
// that wrote the membership in the same transaction — a read of it outside
// that transaction would not see it — and checked the plan before.
func (h *AuthServiceHandler) writeProductRoleGrant(ctx context.Context, caller, userID, orgID, product, role string) error {
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

// checkMemberProductRolesWithinCaller refuses managing a member who holds,
// through the products' roles granted in orgID, a permission the caller does
// not hold there: removing them ends those grants, and the caller could not
// have given them. Their realm-wide grants are not the organization's and
// stay whatever happens to the membership.
func checkMemberProductRolesWithinCaller(ctx context.Context, h *AuthServiceHandler, memberID, orgID string) error {
	// No principal holds nothing: anything the member holds here is above it.
	caller, _ := callerUserID(ctx)
	c, err := h.productRoleCatalogue()
	if err != nil {
		return err
	}
	if len(c.Products) == 0 {
		return nil // no product, no product role to hold
	}
	resp, err := h.Query.ListUserProductRoleGrantRows(ctx, &pb.ListUserProductRoleGrantRowsReq{UserId: memberID})
	if err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	var held map[string]map[string]bool
	for _, g := range resp.GetGrants() {
		if g.GetOrgId() != orgID {
			continue
		}
		role, err := h.lookupRole(ctx, c, orgID, g.GetProduct(), g.GetRoleKey())
		if roleGone(err) {
			continue
		}
		if err != nil {
			return err
		}
		if held == nil && caller != "" {
			if held, err = heldProductPermissions(ctx, h, c, caller, orgID); err != nil {
				return err
			}
		}
		if !covers(held, role) {
			return refusal(ctx, codes.PermissionDenied,
				"the member holds product role "+g.GetProduct()+":"+g.GetRoleKey()+" here, which the caller does not cover",
				CodeMemberAboveCaller, "", MsgMemberAboveCaller, nil)
		}
	}
	return nil
}
