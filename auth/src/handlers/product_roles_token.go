package handlers

import (
	"context"
	"slices"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What product_roles adds to api_token, staged only when both are on: an API
// token names the products' roles it may use, as it names the permissions it
// may use here (TokenProductRole beside TokenPermission). A product is
// answered the roles the token names that a role its holder holds there
// covers — narrow-only: naming a role gives nothing the holder could not
// hand out themselves.
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
		if _, err := c.role(ctx, ref.GetProduct(), ref.GetRoleKey()); err != nil {
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

// narrowByTokenProductRoles answers an API token the roles it names in
// product that a role its holder holds there covers (the catalogue's covers,
// the ceiling of handing a role out) — none when it names none there but is
// narrowed on either axis. A session is not narrowed here.
func narrowByTokenProductRoles(ctx context.Context, h *AuthServiceHandler, prin *authPrincipal, product string, keys []string) ([]string, error) {
	if prin.realm != pb.TokenType_TOKEN_TYPE_API {
		return keys, nil
	}
	resp, err := h.Query.ListTokenProductRoles(ctx, &pb.ListTokenProductRolesReq{TokenId: prin.usedTokenID})
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	named := resp.GetRoles()
	if len(named) == 0 && !prin.permissionSubset {
		return keys, nil
	}
	c, err := h.productRoleCatalogue()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range named {
		if r.GetProduct() != product || slices.Contains(out, r.GetRoleKey()) {
			continue
		}
		if slices.ContainsFunc(keys, func(held string) bool {
			return held == r.GetRoleKey() || slices.Contains(c.byProduct[product][held].Covers, r.GetRoleKey())
		}) {
			out = append(out, r.GetRoleKey())
		}
	}
	return out, nil
}
