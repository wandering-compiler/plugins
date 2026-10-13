package handlers

import (
	"time"

	"context"
	"google.golang.org/protobuf/types/known/timestamppb"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/acllock"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
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
	recordTokenUse = touchTokenLastUsed
}

// tokenUseWindow is how often, at most, a token's last_used_at is written.
// last_used_at answers "is this token still in use", for which a minute is
// plenty; writing it on every request would turn every authenticated read
// into a write on the token row.
const tokenUseWindow = time.Minute

// touchTokenLastUsed records that the token was just used, at most once per
// tokenUseWindow. Two guards, for two different costs:
//
//   - here, against the last_used_at the lookup already read: a token used
//     within the window skips the round trip entirely, so a busy token costs
//     no statement at all on most requests;
//   - in TouchTokenLastUsed's WHERE, against concurrent requests that all
//     passed the first guard on the same stale value: only the first UPDATE
//     still matches, the rest write nothing.
//
// Best effort, like upgradeLegacyToken: a failed write leaves last_used_at
// stale and the request it rides on succeeds — an audit timestamp is not a
// reason to refuse a valid credential. The error is not logged: this package
// has no logger by design (see AuthServiceHandler), and the next request in a
// new window tries again.
func touchTokenLastUsed(ctx context.Context, h *AuthServiceHandler, p *authPrincipal) {
	if p.usedTokenID == "" {
		return
	}
	now := time.Now()
	if last := p.lastUsedAt; last != nil && now.Sub(last.AsTime()) < tokenUseWindow {
		return
	}
	_, _ = h.Mutation.TouchTokenLastUsed(ctx, &pb.TouchTokenLastUsedReq{
		TokenId: p.usedTokenID,
		Cutoff:  timestamppb.New(now.Add(-tokenUseWindow)),
	})
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
	hash := sha256Hex(token)
	tok, err := h.Query.GetTokenWithType(ctx, &pb.GetTokenWithTypeReq{LegacyToken: token, TokenHash: hash})
	if err != nil {
		// Expired API tokens answer SESSION_EXPIRED too: the holder knows the
		// token, and its expiry is all the refusal adds.
		return nil, expiredTokenRefusal(ctx, err, func() (*timestamppb.Timestamp, pb.TokenType, error) {
			exp, err := h.Query.GetExpiredTokenWithType(ctx, &pb.GetExpiredTokenWithTypeReq{LegacyToken: token, TokenHash: hash})
			return exp.GetExpiresAt(), exp.GetTokenType(), err
		})
	}
	h.upgradeLegacyToken(ctx, token, hash, tok.GetStoredTokenHash())
	// Same rule as the session path: a disabled account authenticates with no
	// token, including one minted after the disable deleted the rest.
	if err := signInDisabledGate(tok.GetUser()); err != nil {
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
		userID:      userID,
		tokenID:     tok.GetTokenId(),
		realm:       tok.GetTokenType(),
		grants:      realm.GetGrants(),
		usedTokenID: tok.GetTokenId(),
		lastUsedAt:  tok.GetLastUsedAt(),
	}

	if tok.GetTokenType() == pb.TokenType_TOKEN_TYPE_API {
		sub, err := h.Query.GetTokenPermissionSubset(ctx, &pb.GetTokenPermissionSubsetReq{TokenId: tok.GetTokenId()})
		if err != nil {
			return nil, err
		}
		if subset := sub.GetPermissionIds(); len(subset) > 0 {
			applyTokenSubset(prin, subset, h.Lock)
		}
	}
	// Only a SESSION token is stamped as the caller's session_token_id. Two
	// things read it. Logout deletes whatever id the envelope carries, and
	// DeleteSessionToken's DQL drops the token_type filter (the column is
	// api_token-gated), so an API token's id there would let Logout revoke it
	// (it is removed only via RevokeApiToken). requireSessionCaller reads
	// "non-empty" as "this caller is a session" and lets it mint credentials,
	// so the test is "is SESSION", not "is not API": a row of any other type
	// fails closed instead of passing as a session.
	if tok.GetTokenType() != pb.TokenType_TOKEN_TYPE_SESSION {
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
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	// The token and its narrowing are ONE unit — the same reason IssueBotToken
	// gives, and this is the endpoint a PERSON calls.
	//
	// Minting first is forced: a permission row points at the token's id. So a
	// failure partway leaves a LIVE token carrying a partial subset — or none,
	// which the resolver reads as `all_permissions` (applyTokenSubset narrows
	// only a non-empty subset). A caller who asked for a narrow credential and
	// got an error back would be left owning a WIDER one, believing nothing
	// happened.
	//
	// ⚠️ IssueBotToken and CreateBot hold their writes in one transaction for
	// the same reason; a change to one belongs in all three. The bot endpoints are
	// called by an admin, and this one is called by everybody.
	var tx *distx.TxHandle
	txCtx := ctx
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	expiresAt, err := h.apiTokenExpiry(ctx, req.GetExpiresAt())
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	token, tokenID, err := h.issueApiTokenTx(txCtx, userID, req.GetName(), req.GetPermissionSubset(), expiresAt)
	if err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return &pb.CreateApiTokenResp{
		Token:     token,
		TokenId:   tokenID,
		ExpiresAt: expiresAt,
	}, nil
}

// issueApiTokenTx mints the token and writes its permission subset on the SAME
// context, so a transaction wrapped around the pair holds both. Separated for
// exactly that reason: a caller that inlined the two could not roll them back
// together, and the seam is what a test can drive.
//
// The one minting path for every API token — a person's (CreateApiToken) and a
// machine account's (IssueBotToken, service_account requires api_token). They
// were two copies of this function, which is how one of them would have been
// left minting never-expiring tokens.
func (h *AuthServiceHandler) issueApiTokenTx(txCtx context.Context, userID, name string, subset []int32, expiresAt *timestamppb.Timestamp) (token, tokenID string, err error) {
	token, hash, err := newBearerToken()
	if err != nil {
		return "", "", err
	}
	issued, err := h.Mutation.IssueApiToken(txCtx, &pb.IssueApiTokenReq{
		UserId:    userID,
		Name:      name,
		TokenType: pb.TokenType_TOKEN_TYPE_API,
		ExpiresAt: expiresAt,
		TokenHash: hash,
	})
	if err != nil {
		return "", "", err
	}
	id := issued.GetToken().GetId()
	for _, perm := range subset {
		if _, err := h.Mutation.AddTokenPermission(txCtx, &pb.AddTokenPermissionReq{
			TokenId:      id,
			PermissionId: perm,
		}); err != nil {
			return "", "", err
		}
	}
	return token, id, nil
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
	// examples/plugin-surfaces against a database.
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

// MsgExpiryInPast is what a person reads for an expiry already gone. (Named
// without "Token": gosec reads a const whose name says token as a credential.)
//
//w17:msgid
const (
	MsgExpiryInPast  = "A token cannot expire in the past. Choose a later date."
	MsgExpiryInvalid = "That expiry date is not a valid date."
)

// apiTokenExpiry decides when a token being minted expires: the caller's
// expires_at when they gave one (it must be in the future), else the
// deployment's default lifetime (api_token_default_ttl_hours; 0 there means
// "never", the behaviour before the default existed). nil = never expires —
// the token-validation queries treat a NULL expires_at as valid forever.
//
// Optional, with a default, on purpose: an unattended
// credential nobody remembers to rotate is the one that leaks, so the safe
// state is the one a deployment gets without asking.
func (h *AuthServiceHandler) apiTokenExpiry(ctx context.Context, requested *timestamppb.Timestamp) (*timestamppb.Timestamp, error) {
	now := time.Now()
	if requested != nil {
		// A timestamp outside 0001-9999 is not one a caller meant, and it is
		// not one every reader can carry: Postgres stores it, then a JSON
		// ListApiTokens of the same user fails to serialize. Refused on the
		// field, like a past one.
		if err := requested.CheckValid(); err != nil {
			return nil, refusal(ctx, codes.InvalidArgument,
				"expires_at is not a valid timestamp: "+err.Error(),
				"TOKEN_EXPIRY_INVALID", "expires_at", MsgExpiryInvalid, nil)
		}
		if !requested.AsTime().After(now) {
			return nil, refusal(ctx, codes.InvalidArgument,
				"expires_at "+requested.AsTime().UTC().Format(time.RFC3339)+" is not in the future",
				"TOKEN_EXPIRY_IN_PAST", "expires_at", MsgExpiryInPast, nil)
		}
		return requested, nil
	}
	hours := h.APITokenDefaultTTLHours
	if hours < 0 {
		hours = defaultAPITokenTTLHours
	}
	if hours == 0 {
		return nil, nil
	}
	return timestamppb.New(now.Add(time.Duration(hours) * time.Hour)), nil
}
