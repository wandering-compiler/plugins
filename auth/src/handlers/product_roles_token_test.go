package handlers

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// tokenRolesMock adds an API token's product roles (TokenProductRole) to
// prodMock.
type tokenRolesMock struct {
	*prodMock
	tokenRoles map[string][]*pb.TokenProductRoleRow // token id → rows
}

func (m *tokenRolesMock) ListTokenProductRoles(_ context.Context, in *pb.ListTokenProductRolesReq, _ ...grpc.CallOption) (*pb.ListTokenProductRolesResp, error) {
	return &pb.ListTokenProductRolesResp{Roles: m.tokenRoles[in.GetTokenId()]}, nil
}

func (m *tokenRolesMock) AddTokenProductRole(_ context.Context, in *pb.AddTokenProductRoleReq, _ ...grpc.CallOption) (*pb.AddTokenProductRoleResp, error) {
	m.tokenRoles[in.GetTokenId()] = append(m.tokenRoles[in.GetTokenId()], &pb.TokenProductRoleRow{Product: in.GetProduct(), RoleKey: in.GetRoleKey()})
	return &pb.AddTokenProductRoleResp{Id: m.next()}, nil
}

func tokenRolesHandler(t *testing.T) (*AuthServiceHandler, *tokenRolesMock) {
	t.Helper()
	h, pm := prodHandler(t)
	pm.grants = append(pm.grants, &pb.ProductRoleGrantRow{Id: "g-2", UserId: "alice", OrgId: "org-a", Product: "alpha", RoleKey: "viewer"})
	m := &tokenRolesMock{prodMock: pm, tokenRoles: map[string][]*pb.TokenProductRoleRow{}}
	h.Query, h.Mutation = m, m
	return h, m
}

// A mint names only roles the catalogue declares, in an organization or
// realm-wide, and records each once with the token, in its transaction.
func TestTokenProductRoles_TheMintHoldsThemToTheCatalogue(t *testing.T) {
	h, m := tokenRolesHandler(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		rs   []*pb.ProductRoleRef
		code string
	}{
		{"a product the catalogue does not name", refs("gamma", "viewer"), CodeProductUnknown},
		{"a role the product does not declare", refs("alpha", "owner"), CodeProductRoleUnknown},
	} {
		if _, err := checkTokenProductRoles(ctx, h, &pb.CreateApiTokenReq{ProductRoles: c.rs}); refusalCodeOf(err) != c.code {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	if w, err := checkTokenProductRoles(ctx, h, &pb.CreateApiTokenReq{}); err != nil || w != nil {
		t.Errorf("a token naming no product role: write %v, err %v; want neither", w != nil, err)
	}
	if w, err := checkTokenProductRoles(ctx, h, &pb.ListApiTokensReq{}); err != nil || w != nil {
		t.Errorf("a request that names no product roles at all: write %v, err %v", w != nil, err)
	}

	writes, err := h.checkTokenMint(ctx, &pb.IssueBotTokenReq{ProductRoles: refs("alpha", "viewer", "alpha", "auditor", "alpha", "viewer")})
	if err != nil || len(writes) != 1 {
		t.Fatalf("checkTokenMint: %d writes, %v", len(writes), err)
	}
	if err := writeTokenMint(ctx, writes, "tok-1"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range m.tokenRoles["tok-1"] {
		got = append(got, r.GetProduct()+":"+r.GetRoleKey())
	}
	if !slices.Equal(got, []string{"alpha:viewer", "alpha:auditor"}) {
		t.Errorf("recorded %v, want alpha:viewer and alpha:auditor once each", got)
	}
}

// A product is answered the permissions the holder holds there that a role
// the token names grants.
// A token narrowed on either axis stays narrow on the products'; only one
// narrowed on neither carries every role its holder holds, as a session does.
func TestTokenProductRoles_AProductIsAnsweredTheTokensShare(t *testing.T) {
	h, m := tokenRolesHandler(t)
	m.tokenRoles["viewer-only"] = []*pb.TokenProductRoleRow{{Product: "alpha", RoleKey: "viewer"}, {Product: "alpha", RoleKey: "auditor"}}
	m.tokenRoles["beta-only"] = []*pb.TokenProductRoleRow{{Product: "beta", RoleKey: "viewer"}}
	m.tokenRoles["editor"] = []*pb.TokenProductRoleRow{{Product: "alpha", RoleKey: "editor"}}

	answerFor := func(prin *authPrincipal) []string {
		t.Helper()
		ctx := context.WithValue(privateCallerCtx("alpha"), authHeadersKey{}, map[string]string{productHeader: "alpha"})
		ctx = context.WithValue(ctx, requestMemoKey{}, map[string]any{})
		resp := &pb.AuthResp{Scopes: map[string]string{"user_id": "alice", "org_id": "org-a"}}
		if err := answerProductRoles(ctx, h, prin, resp); err != nil {
			t.Fatal(err)
		}
		return resp.GetProductRoles()
	}
	api := func(token string, permissionSubset bool) *authPrincipal {
		return &authPrincipal{userID: "alice", realm: pb.TokenType_TOKEN_TYPE_API, usedTokenID: token, permissionSubset: permissionSubset}
	}
	for _, c := range []struct {
		name string
		prin *authPrincipal
		want []string
	}{
		{"a session", &authPrincipal{userID: "alice", realm: pb.TokenType_TOKEN_TYPE_SESSION, usedTokenID: "viewer-only"}, alphaAdmin},
		{"a token narrowed on neither axis", api("plain", false), alphaAdmin},
		{"a token naming alpha's viewer (and an auditor alice does not hold)", api("viewer-only", false), alphaViewer},
		{"a token naming only beta's roles", api("beta-only", false), nil},
		{"a token naming alpha's editor, which alice's admin covers", api("editor", false), alphaEditor},
		{"a token with a permission subset and no product role", api("plain", true), nil},
		{"a token with a permission subset naming alpha's viewer", api("viewer-only", true), alphaViewer},
	} {
		if got := answerFor(c.prin); !slices.Equal(got, c.want) {
			t.Errorf("%s: answered %v, want %v", c.name, got, c.want)
		}
	}
}
