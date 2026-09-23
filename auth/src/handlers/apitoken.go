package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"
)

// This file implements the `api_token` feature. It is staged into a
// bundle ONLY when the activation enables `api_token` (plugin.yaml maps
// the feature to this file via go_files). With the feature off it is
// not staged, so the base resolvePrincipal (single-realm session path)
// stays in effect and the token schema carries no token_type column.
// Standalone (the plugin author's own `go test`) always compiles it,
// since gating happens at activation staging, not in the source tree.

// init swaps in the realm-aware principal resolver on package load. The
// bundle imports this package (alias-imported under the activation
// name), so the init runs once during server bring-up.
func init() {
	resolvePrincipal = resolvePrincipalRealmAware
}

// resolvePrincipalRealmAware resolves a token to its principal +
// effective permission IDs, honouring the token's realm and (for API
// tokens) its permission subset:
//
//  1. GetTokenWithType — the token's owner, id, and kind (SESSION/API).
//  2. GetUserRolePermissionsByRealm — the permissions the user holds
//     through roles of THAT realm (a session token never sees the
//     user's API-realm roles and vice-versa).
//  3. For API tokens only: GetTokenPermissionSubset — the per-token
//     subset. When non-empty, the effective set is realm-perms ∩ subset
//     (least-privilege narrowing; a token can only narrow, never
//     escalate). Empty subset = no narrowing.
//
// Any query error propagates and fails Authenticate closed (the same
// opaque Unauthenticated path).
func resolvePrincipalRealmAware(ctx context.Context, h *AuthServiceHandler, token string) (*authPrincipal, error) {
	tok, err := h.Query.GetTokenWithType(ctx, &pb.GetTokenWithTypeReq{Token: token})
	if err != nil {
		return nil, err
	}
	userID := tok.GetUserId()

	realm, err := h.Query.GetUserRolePermissionsByRealm(ctx, &pb.GetUserRolePermissionsByRealmReq{
		UserId:    userID,
		TokenType: tok.GetTokenType(),
	})
	if err != nil {
		return nil, err
	}
	prin := &authPrincipal{
		userID:  userID,
		tokenID: tok.GetTokenId(),
		realm:   tok.GetTokenType(),
		grants:  realm.GetGrants(),
	}

	if tok.GetTokenType() == pb.TokenType_TOKEN_TYPE_API {
		sub, err := h.Query.GetTokenPermissionSubset(ctx, &pb.GetTokenPermissionSubsetReq{TokenId: tok.GetTokenId()})
		if err != nil {
			return nil, err
		}
		if subset := sub.GetPermissionIds(); len(subset) > 0 {
			applyTokenSubset(prin, subset, h.Lock)
		}
		// B21-auth-1: an API token is NOT a session token — it must not be
		// stamped as the caller's session_token_id. Logout deletes whatever
		// session_token_id the envelope carries, and DeleteSessionToken's DQL
		// drops the token_type filter (Q64-auth-1), so a non-empty value here
		// would let Logout silently revoke the API token (it should only be
		// removed via RevokeApiToken). Empty id → Logout no-ops, matching its
		// documented "API-token bearer still gets a clean success" contract.
		prin.tokenID = ""
	}
	return prin, nil
}

// applyTokenSubset narrows every grant to the token's own permission subset.
//
// Applied per ROLE rather than to a flattened set, so the subset survives the
// axes that run after it: the org narrower still has role ids to intersect on,
// and a subset-narrowed wildcard does not silently re-expand at flatten time.
// A wildcard grant becomes an ordinary grant of exactly the subset — GrantAll
// ∩ subset is the subset — which is also what keeps it from outliving the
// narrowing.
func applyTokenSubset(p *authPrincipal, subset []int32, lock *acllock.Lock) {
	for _, g := range p.grants {
		if g.GetAllPermissions() {
			g.AllPermissions = false
			g.PermissionIds = intersectInt32(acllock.GrantAll(lock), subset)
			continue
		}
		g.PermissionIds = intersectInt32(g.GetPermissionIds(), subset)
	}
}

// CreateApiToken issues an API token for the calling user, optionally
// narrowed to a permission subset. The opaque token is returned ONCE.
func (h *AuthServiceHandler) CreateApiToken(ctx context.Context, req *pb.CreateApiTokenReq) (*pb.CreateApiTokenResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	issued, err := h.Mutation.IssueApiToken(ctx, &pb.IssueApiTokenReq{
		UserId:    userID,
		Name:      req.GetName(),
		TokenType: pb.TokenType_TOKEN_TYPE_API,
	})
	if err != nil {
		return nil, err
	}
	tokenID := issued.GetToken().GetId()
	for _, perm := range req.GetPermissionSubset() {
		if _, err := h.Mutation.AddTokenPermission(ctx, &pb.AddTokenPermissionReq{
			TokenId:      tokenID,
			PermissionId: perm,
		}); err != nil {
			return nil, err
		}
	}
	return &pb.CreateApiTokenResp{
		Token:   issued.GetToken().GetToken(),
		TokenId: tokenID,
	}, nil
}

// ListApiTokens returns the calling user's API tokens (management view —
// id / label / audit timestamps, never the secret token string).
func (h *AuthServiceHandler) ListApiTokens(ctx context.Context, req *pb.ListApiTokensReq) (*pb.ListApiTokensResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListApiTokensByUser(ctx, &pb.ListApiTokensByUserReq{
		UserId:    userID,
		TokenType: pb.TokenType_TOKEN_TYPE_API,
	})
	if err != nil {
		return nil, err
	}
	return &pb.ListApiTokensResp{Tokens: resp.GetTokens()}, nil
}

// RevokeApiToken deletes one of the calling user's API tokens + its
// permission-subset rows. The token delete is ownership + realm guarded
// (id AND user_id AND token_type=API), so a caller can't revoke another
// user's token or a session token. Subset cleanup runs only AFTER an
// owned token was actually deleted — never on a token the caller doesn't
// own. Idempotent (revoking an absent token is a no-op).
func (h *AuthServiceHandler) RevokeApiToken(ctx context.Context, req *pb.RevokeApiTokenReq) (*pb.RevokeApiTokenResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	del, err := h.Mutation.DeleteApiToken(ctx, &pb.DeleteApiTokenReq{
		TokenId:   req.GetTokenId(),
		UserId:    userID,
		TokenType: pb.TokenType_TOKEN_TYPE_API,
	})
	if err != nil {
		return nil, err
	}
	if del.GetTokenId() == "" {
		// Nothing deleted — not the caller's, or not an API token. Don't
		// touch the subset rows (they may belong to someone else's token).
		return &pb.RevokeApiTokenResp{}, nil
	}
	// A token with NO subset rows has nothing to clean up, and that is the
	// COMMON case — CreateApiToken leaves the subset empty unless the caller
	// narrows it, and a machine account's token carries its rights through a
	// ROLE rather than a per-token subset.
	//
	// The cleanup's DELETE fills its response from RETURNING, so matching no
	// row is a mutation that produced no result — NotFound. Propagating that
	// turned every such revoke into a 404 while the token was ALREADY DELETED
	// one statement earlier: the caller reads "no such token", retries, gets
	// 404 again, and concludes the token is still live. Found by running
	// examples/plugin-surfaces against a database (docs/todos/
	// revoke-api-token-404-on-empty-subset.md).
	//
	// Only NotFound is swallowed. Any other failure still fails the call — a
	// subset that could not be removed is a credential narrower than it looks.
	if _, err := h.Mutation.DeleteTokenPermissions(ctx, &pb.DeleteTokenPermissionsReq{TokenId: req.GetTokenId()}); err != nil {
		if status.Code(err) != codes.NotFound {
			return nil, err
		}
	}
	return &pb.RevokeApiTokenResp{}, nil
}
