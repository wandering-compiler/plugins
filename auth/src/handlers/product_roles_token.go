package handlers

import (
	"context"
	"slices"

	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What product_roles adds to api_token, staged only when both are on: an API
// token names the products' roles it may use, as it names the permissions it
// may use here (TokenProductRole beside TokenPermission). A product is
// answered the permissions its holder holds there that a role the token
// names grants — narrow-only: naming a role gives nothing the holder does
// not hold.
//
// A token minted narrow stays narrow on the products' axis too: one that
// carries a permission subset and names no product role reaches the products
// with none. Only a token narrowed on neither axis reaches them with every
// role its holder holds, as a session does.

func init() {
	tokenMintChecks = append(tokenMintChecks, checkTokenProductRoles)
	productRoleNarrowers = append(productRoleNarrowers, narrowByTokenProductRoles)
}

// productRolesOf is a mint request that names the products' roles
// (CreateApiTokenReq, IssueBotTokenReq).
type productRolesOf interface {
	GetProductRoles() []*pb.ProductRoleRef
}

// checkTokenProductRoles holds the roles a mint request names to the
// catalogue — a product and a role it declares, in an organization or
// realm-wide — and returns the write that records them with the token.
func checkTokenProductRoles(ctx context.Context, h *AuthServiceHandler, req any) (tokenMintWrite, error) {
	r, ok := req.(productRolesOf)
	if !ok || len(r.GetProductRoles()) == 0 {
		return nil, nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	var refs []*pb.ProductRoleRef
	for _, ref := range r.GetProductRoles() {
		// A token belongs to no organization: it names presets and the
		// backoffice's own roles.
		if _, err := h.lookupRole(ctx, c, "", ref.GetProduct(), ref.GetRoleKey()); err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(refs, func(x *pb.ProductRoleRef) bool {
			return x.GetProduct() == ref.GetProduct() && x.GetRoleKey() == ref.GetRoleKey()
		}) {
			refs = append(refs, ref)
		}
	}
	return func(txCtx context.Context, tokenID string) error {
		for _, ref := range refs {
			if _, err := h.Mutation.AddTokenProductRole(txCtx, &pb.AddTokenProductRoleReq{
				TokenId: tokenID, Product: ref.GetProduct(), RoleKey: ref.GetRoleKey(),
			}); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// narrowByTokenProductRoles answers an API token the codes it holds in
// product that a role it names grants there — none when it names none but is
// narrowed on either axis. A session is not narrowed here.
func narrowByTokenProductRoles(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, orgID, product string, codes []string) ([]string, error) {
	if prin.realm != pb.TokenType_TOKEN_TYPE_API {
		return codes, nil
	}
	resp, err := h.Query.ListTokenProductRoles(ctx, &pb.ListTokenProductRolesReq{TokenId: prin.usedTokenID})
	if err != nil && status.Code(err) != grpccodes.NotFound {
		return nil, err
	}
	named := resp.GetRoles()
	if len(named) == 0 && !prin.permissionSubset {
		return codes, nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, r := range named {
		role, err := h.lookupRole(ctx, c, orgID, r.GetProduct(), r.GetRoleKey())
		if err != nil {
			if roleGone(err) {
				continue
			}
			return nil, err
		}
		for _, code := range role.perms[product] {
			allowed[code] = true
		}
	}
	var out []string
	for _, code := range codes {
		if allowed[code] {
			out = append(out, code)
		}
	}
	return out, nil
}
