package handlers

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/sdk/go/lib/acllock"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/plugins/auth/lib/devicekey"
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
	revokeApprovedAPITokens = revokeAPITokensOfDevice
	callerRealmGrants = realmGrantsOfCaller
}

// realmGrantsOfCaller is callerRealmGrants with realms: a session's roles for
// a session, and for any other caller the roles of both token realms (API and
// MCP), since the envelope says only whether the caller is a session.
func realmGrantsOfCaller(ctx context.Context, h *AuthServiceHandler, userID string, session bool) ([]*pb.RoleGrant, error) {
	realms := []pb.TokenType{pb.TokenType_TOKEN_TYPE_API, pb.TokenType_TOKEN_TYPE_MCP}
	if session {
		realms = []pb.TokenType{pb.TokenType_TOKEN_TYPE_SESSION}
	}
	var out []*pb.RoleGrant
	for _, realm := range realms {
		resp, err := h.Query.GetUserRolePermissionsByRealm(ctx, &pb.GetUserRolePermissionsByRealmReq{UserId: userID, TokenType: realm})
		if err != nil {
			return nil, err
		}
		out = append(out, resp.GetGrants()...)
	}
	return out, nil
}

// revokeAPITokensOfDevice revokes the owner's live API tokens the device
// created — a stolen browser session could have created one bound to the
// thief's own key. Revoking nothing is no failure.
func revokeAPITokensOfDevice(ctx context.Context, h *AuthServiceHandler, userID, deviceID, revokedBy string) error {
	_, err := h.Mutation.RevokeApprovedApiTokens(ctx, &pb.RevokeApprovedApiTokensReq{
		UserId:    userID,
		DeviceId:  deviceID,
		RevokedBy: revokedBy,
		TokenType: pb.TokenType_TOKEN_TYPE_API,
	})
	return notFoundOK(err)
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
	// Stamp and cutoff from ONE clock, this one: the pre-check above reads
	// a value this function wrote, so app/database skew never enters it.
	_, _ = h.Mutation.TouchTokenLastUsed(ctx, &pb.TouchTokenLastUsedReq{
		TokenId: p.usedTokenID,
		UsedAt:  timestamppb.New(now),
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
		return nil, expiredTokenRefusal(err, func() (endedToken, error) {
			exp, err := h.Query.GetExpiredTokenWithType(ctx, &pb.GetExpiredTokenWithTypeReq{LegacyToken: token, TokenHash: hash})
			return endedToken{
				expiresAt:       exp.GetExpiresAt(),
				revokedAt:       exp.GetRevokedAt(),
				kind:            exp.GetTokenType(),
				thumbprint:      exp.GetDeviceThumbprint(),
				deviceRevokedAt: exp.GetDeviceRevokedAt(),
				bearer:          exp.GetBearer(),
			}, err
		})
	}
	// Same rule as the session path: a disabled account authenticates with no
	// token, including one minted after the disable revoked the rest.
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

		deviceThumbprint: tok.GetDeviceThumbprint(),
		deviceRevokedAt:  tok.GetDeviceRevokedAt(),
		mcpOnly:          tok.GetMcpOnly(),
		oauthResource:    tok.GetOauthResource(),
		oauthOrgID:       tok.GetOauthOrgId(),
		bearer:           tok.GetBearer(),
		botAccount:       isBotAccount(tok.GetUser()),
		user:             tok.GetUser(),
		legacyToken:      legacyPlaintext(token, tok.GetStoredTokenHash()),
	}

	if tok.GetTokenType() == pb.TokenType_TOKEN_TYPE_API {
		sub, err := h.Query.GetTokenPermissionSubset(ctx, &pb.GetTokenPermissionSubsetReq{TokenId: tok.GetTokenId()})
		if err != nil {
			return nil, err
		}
		if subset := sub.GetPermissionIds(); len(subset) > 0 {
			applyTokenSubset(prin, subset, h.Lock)
			prin.permissionSubset = true
		}
	}
	// Only a SESSION token is stamped as the caller's session_token_id. Two
	// things read it. Logout revokes whatever id the envelope carries, and
	// RevokeSessionToken's DQL drops the token_type filter (the column is
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
// narrowed to a permission subset, bound to the public key the request names
// — the program that will use the token, not the browser creating it. The
// opaque token is returned ONCE.
//
// The issuance is recorded in the sign-in history (method API_TOKEN), like a
// sign-in: one row whatever the outcome, the success row in the transaction
// that mints the token.
func (h *AuthServiceHandler) CreateApiToken(ctx context.Context, req *pb.CreateApiTokenReq) (_ *pb.CreateApiTokenResp, err error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	attempt := beginKeyedMint(ctx, pb.SignInMethod_SIGN_IN_METHOD_API_TOKEN)
	// The caller authenticated, and Authenticate refuses a disabled account
	// (an erased one is disabled): the account is not erased, and the history
	// needs no read to know it.
	attempt.userID, attempt.account = userID, &pb.User{Id: userID}
	defer func() { h.endSignIn(ctx, attempt, err) }()

	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	key, err := parseTokenKey(ctx, req.GetPublicKey())
	if err != nil {
		return nil, err
	}
	attempt.thumbprint = key.Thumbprint
	// A token outlives the session that mints it, so minting one is the
	// moment a stolen session would choose: with api_token_step_up_seconds
	// set, the session must have stepped up recently (step_up.go fills the
	// seam; ValidateConfig refuses the setting without it).
	for _, check := range apiTokenStepUpChecks {
		if err := check(ctx, h, userID, callerSessionTokenID(ctx)); err != nil {
			return nil, err
		}
	}
	extras, err := h.checkTokenMint(ctx, req)
	if err != nil {
		return nil, err
	}
	expiresAt, err := h.personTokenExpiry(ctx, req.GetExpiresAt())
	if err != nil {
		return nil, err
	}
	// The device, the token, its narrowing and the history row are ONE unit
	// — the same reason IssueBotToken gives, and this is the endpoint a
	// PERSON calls.
	//
	// Minting before narrowing is forced: a permission row points at the
	// token's id. So a failure partway leaves a LIVE token carrying a partial
	// subset — or none, which the resolver reads as `all_permissions`
	// (applyTokenSubset narrows only a non-empty subset). A caller who asked
	// for a narrow credential and got an error back would be left owning a
	// WIDER one, believing nothing happened.
	//
	// ⚠️ IssueBotToken and CreateBot hold their writes in one transaction for
	// the same reason; a change to one belongs in all three. The bot endpoints are
	// called by an admin, and this one is called by everybody.
	var token, tokenID string
	err = h.inTx(ctx, func(txCtx context.Context) error {
		dev, err := h.registerKeyDevice(txCtx, attempt, userID, key, "API token: "+req.GetName())
		if err != nil {
			return err
		}
		approver, err := h.approverDevice(txCtx, userID)
		if err != nil {
			return err
		}
		token, tokenID, err = h.issueApiTokenTx(txCtx, attempt, userID, req.GetName(), req.GetPermissionSubset(), extras, expiresAt, dev, approver)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &pb.CreateApiTokenResp{
		Token:     token,
		TokenId:   tokenID,
		ExpiresAt: expiresAt,
		DeviceId:  key.Thumbprint,
	}, nil
}

// beginKeyedMint opens the history row of an API-token issuance: the
// creating request's client address and user agent, and NO thumbprint yet —
// the token is bound to the key the request NAMES, not to the one its proof
// was signed with, so the row's key is set once that key is read.
func beginKeyedMint(ctx context.Context, method pb.SignInMethod) *signInAttempt {
	a := &signInAttempt{method: method}
	a.userAgent, a.ip = deviceLabel(ctx)
	return a
}

// parseTokenKey reads the public key an API token is to be bound to, or
// refuses it on the public_key field: DEVICE_KEY_REQUIRED when there is none,
// DEVICE_KEY_INVALID when it is not a public P-256 or Ed25519 JWK — with its
// own sentence when it carries a private member.
//
// device/private-key-never-leaves: the key is never stored, logged or echoed —
// only its thumbprint is kept, and a refusal names members, never values. A
// private key that reached this far is dropped with the request.
func parseTokenKey(ctx context.Context, raw string) (devicekey.Key, error) {
	if raw == "" {
		return devicekey.Key{}, refusal(ctx, codes.InvalidArgument,
			"public_key is required: the token is bound to the key of the program that will use it",
			CodeDeviceKeyRequired, "public_key", MsgClientKeyNeeded, nil)
	}
	key, err := devicekey.Parse(raw)
	switch {
	case err == nil:
		return key, nil
	case errors.Is(err, devicekey.ErrPrivateKey):
		return devicekey.Key{}, refusal(ctx, codes.InvalidArgument,
			"public_key carries a private key member; send the public key only",
			CodeDeviceKeyInvalid, "public_key", MsgClientKeyPrivate, nil)
	default:
		return devicekey.Key{}, refusal(ctx, codes.InvalidArgument,
			"public_key: "+err.Error(),
			CodeDeviceKeyInvalid, "public_key", MsgClientKeyInvalid, nil)
	}
}

// registerKeyDevice finds or registers the (owner, thumbprint) Device an API
// token is bound to, on txCtx: the same UPSERT a sign-in runs (RegisterDevice),
// labelled after the token, with no client address — the creating request's
// address is not the program's — and marked a program's key (api_key, written
// when the row is created). A key that already signs in for the owner is
// refused: keys are a program's or a signed-in client's, never both (see
// Device.api_key). A REVOKED pair is refused for
// good, as at sign-in, but as DEVICE_KEY_REVOKED (FailedPrecondition): the
// revoked key is the one in the request body, not the caller's own, so the
// refusal must not read as the caller's device being gone. The history row
// names a revoked device (it exists already); a new one, rolled back with
// the refusal, it does not.
func (h *AuthServiceHandler) registerKeyDevice(txCtx context.Context, a *signInAttempt, ownerID string, key devicekey.Key, label string) (signInDevice, error) {
	resp, err := h.Mutation.RegisterDevice(txCtx, &pb.RegisterDeviceReq{
		UserId:     ownerID,
		Thumbprint: key.Thumbprint,
		Label:      truncate(strings.ToValidUTF8(label, invalidUTF8), maxLabelLen),
		ApiKey:     true,
	})
	if err != nil {
		return signInDevice{}, err
	}
	dev := resp.GetDevice()
	if dev.GetId() == "" || dev.GetThumbprint() != key.Thumbprint {
		return signInDevice{}, errDeviceNotRegistered
	}
	if !dev.GetApiKey() {
		// The key already signs in for this account: a device, not a
		// program. Bound to it, the token would be ended by the owner's
		// device management and would let a session's key outlive the
		// session lifetime as an API token.
		return signInDevice{}, refusal(txCtx, codes.InvalidArgument,
			"the key is a device that signs in to this account; generate a separate key for the program",
			CodeDeviceKeyInvalid, "public_key", MsgClientKeySignsIn, nil)
	}
	if dev.GetRevokedAt() != nil {
		a.deviceID = dev.GetId()
		return signInDevice{}, refusal(txCtx, codes.FailedPrecondition,
			"the key names a revoked device; generate a new key",
			CodeDeviceKeyRevoked, "public_key", MsgClientKeyRevoked, nil)
	}
	return signInDevice{id: dev.GetId(), thumbprint: key.Thumbprint}, nil
}

// approverDevice is the ROOT approver recorded on the token
// (UserToken.approved_by_device_id): the device whose revocation must end it.
//
//   - When the caller's session was itself approved by another device — a CLI
//     session, approved by a browser (cli_login) — it is THAT device. A stolen
//     browser session can approve the thief's CLI key and create API tokens
//     from the CLI session; revoking the browser ends the CLI session, and must
//     end those tokens too, which it does only if they name the browser. The
//     immediate creator (the CLI's key) stays visible as ApiTokenCreated's
//     device_id.
//   - Otherwise the Device row of the caller's own device — the key its
//     request was proved with.
//
// "" when the request carries no device (project code calling the handler
// directly) or the pair has no live row; an outage fails the mint. One level
// is enough: a CLI session's approver is the session that approved it at
// CliAuthorize, recorded the same way.
func (h *AuthServiceHandler) approverDevice(txCtx context.Context, callerID string) (string, error) {
	jkt := requestThumbprint(txCtx)
	if jkt == "" {
		return "", nil
	}
	if sid := callerSessionTokenID(txCtx); sid != "" {
		root, err := h.Query.GetSessionApprover(txCtx, &pb.GetSessionApproverReq{TokenId: sid, UserId: callerID})
		if err != nil && status.Code(err) != codes.NotFound {
			return "", err
		}
		if id := root.GetApprovedByDeviceId(); id != "" {
			return id, nil
		}
	}
	resp, err := h.Query.GetUserDeviceByThumbprint(txCtx, &pb.GetUserDeviceByThumbprintReq{UserId: callerID, Thumbprint: jkt})
	if status.Code(err) == codes.NotFound {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return resp.GetDeviceId(), nil
}

// tokenMintWrite is a staged combination's write in a token's mint
// transaction, once the token row exists (tokenID).
type tokenMintWrite func(txCtx context.Context, tokenID string) error

// tokenMintChecks are what a staged combination adds to minting an API token
// (product_roles: the products' roles the token may use), read off the mint
// request — CreateApiTokenReq, IssueBotTokenReq — before anything is written.
// Each refuses a request it cannot honour, or returns the write that records
// it beside the token's permission subset, in the same transaction (nil when
// the request asks nothing of it). Appended by the combination's init, so
// several can stage.
var tokenMintChecks []func(ctx context.Context, h *AuthServiceHandler, req any) (tokenMintWrite, error)

// checkTokenMint runs tokenMintChecks for req.
func (h *AuthServiceHandler) checkTokenMint(ctx context.Context, req any) ([]tokenMintWrite, error) {
	var writes []tokenMintWrite
	for _, check := range tokenMintChecks {
		w, err := check(ctx, h, req)
		if err != nil {
			return nil, err
		}
		if w != nil {
			writes = append(writes, w)
		}
	}
	return writes, nil
}

// writeTokenMint runs the writes checkTokenMint returned, for tokenID.
func writeTokenMint(txCtx context.Context, writes []tokenMintWrite, tokenID string) error {
	for _, w := range writes {
		if err := w(txCtx, tokenID); err != nil {
			return err
		}
	}
	return nil
}

// issueApiTokenTx mints the token bound to dev, writes its permission subset
// and the history's success row, all on the SAME context, so a transaction
// wrapped around them holds every one. Separated for exactly that reason: a
// caller that inlined them could not roll them back together, and the seam
// is what a test can drive.
//
// The one minting path for every BOUND API token — a person's (CreateApiToken)
// and a machine account's keyed one (IssueBotToken, service_account requires
// api_token); a machine account's bearer token is service_account.go's. They
// were two copies of this function, which is how one of them would have been
// left minting never-expiring tokens. No device, no token
// (device/no-unbound-credential): this guard is the only one —
// IssueApiTokenReq.device_id is nullable for the bearer token.
func (h *AuthServiceHandler) issueApiTokenTx(txCtx context.Context, a *signInAttempt, userID, name string, subset []int32, extras []tokenMintWrite, expiresAt *timestamppb.Timestamp, dev signInDevice, approvedBy string) (token, tokenID string, err error) {
	if dev.id == "" {
		return "", "", errDeviceNotRegistered
	}
	token, hash, err := newBearerToken()
	if err != nil {
		return "", "", err
	}
	// ApiTokenCreated's creator: the account calling, "" for project code.
	creator, _ := callerUserID(txCtx)
	issued, err := h.Mutation.IssueApiToken(txCtx, &pb.IssueApiTokenReq{
		UserId:             userID,
		Name:               name,
		TokenType:          pb.TokenType_TOKEN_TYPE_API,
		ExpiresAt:          expiresAt,
		TokenHash:          hash,
		DeviceId:           dev.id,
		ApprovedByDeviceId: approvedBy,

		Thumbprint:    requestThumbprint(txCtx),
		KeyThumbprint: dev.thumbprint,
		CreatedBy:     creator,
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
	if err := writeTokenMint(txCtx, extras, id); err != nil {
		return "", "", err
	}
	if err := h.recordSignInOK(txCtx, a, userID, dev); err != nil {
		return "", "", err
	}
	return token, id, nil
}

// ListApiTokens returns the calling user's API tokens (management view —
// id / label / audit timestamps, never the secret token string).
//
// A session only, as CreateApiToken: an API token is a credential for
// automation, and one that leaked must not be able to read the holder's
// other credentials, or revoke them (below).
func (h *AuthServiceHandler) ListApiTokens(ctx context.Context, req *pb.ListApiTokensReq) (*pb.ListApiTokensResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
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

// RevokeApiToken revokes one of the calling user's API tokens: the row stays,
// with revoked_at, reason API_TOKEN_REVOKED and the caller as revoked_by, and
// every lookup refuses it from then on. The revoke is ownership + realm
// guarded (id AND user_id AND token_type=API), so a caller can't revoke
// another user's token or a session token. Its TokenPermission subset rows
// stay too: they narrow a token that is refused anyway, and they record what
// it was allowed to do. Idempotent — revoking a token that is already revoked,
// unknown or not the caller's matches no row (NotFound) and is no error.
//
// A session only: a leaked API token revoking every other token of its holder
// is a denial of service to all of the holder's automation at once.
func (h *AuthServiceHandler) RevokeApiToken(ctx context.Context, req *pb.RevokeApiTokenReq) (*pb.RevokeApiTokenResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if _, err := h.Mutation.MarkApiTokenRevoked(ctx, &pb.MarkApiTokenRevokedReq{
		TokenId:    req.GetTokenId(),
		UserId:     userID,
		TokenType:  pb.TokenType_TOKEN_TYPE_API,
		Thumbprint: requestThumbprint(ctx),
	}); notFoundOK(err) != nil {
		return nil, err
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
	MsgExpiryTooLate = "A token can last at most {days} days. Choose an earlier date."
)

// CodeExpiryTooLate — a requested expiry past api_token_max_ttl_hours.
const CodeExpiryTooLate = "TOKEN_EXPIRY_TOO_LATE"

func init() {
	configChecks = append(configChecks, checkAPITokenConfig)
}

// checkAPITokenConfig refuses settings the activation cannot honour: a
// negative cap, and a step-up nobody can perform.
func checkAPITokenConfig(h *AuthServiceHandler) error {
	if h.APITokenMaxTTLHours < 0 {
		return fmt.Errorf("api_token_max_ttl_hours = %d: must be 0 (no cap) or a number of hours", h.APITokenMaxTTLHours)
	}
	if h.APITokenStepUpSeconds > 0 && len(apiTokenStepUpChecks) == 0 {
		return fmt.Errorf("api_token_step_up_seconds = %d needs the step_up feature: without it no session can step up, so no person could create a token", h.APITokenStepUpSeconds)
	}
	return nil
}

// personTokenExpiry is apiTokenExpiry for a token a PERSON creates, under the
// deployment's cap (api_token_max_ttl_hours): a later expiry is refused, and
// a token minted without one — or with a default of "never" — takes the
// default, never more than the cap. So with a cap every person's token
// expires. Machine accounts' tokens are the operator's and keep their rules.
func (h *AuthServiceHandler) personTokenExpiry(ctx context.Context, requested *timestamppb.Timestamp) (*timestamppb.Timestamp, error) {
	exp, err := h.apiTokenExpiry(ctx, requested)
	if err != nil || h.APITokenMaxTTLHours <= 0 {
		return exp, err
	}
	limit := time.Now().Add(time.Duration(h.APITokenMaxTTLHours) * time.Hour)
	if requested != nil {
		if exp.AsTime().After(limit) {
			days := strconv.Itoa(h.APITokenMaxTTLHours / 24)
			return nil, refusal(ctx, codes.InvalidArgument,
				"expires_at "+exp.AsTime().UTC().Format(time.RFC3339)+" is past the cap of "+strconv.Itoa(h.APITokenMaxTTLHours)+" hours",
				CodeExpiryTooLate, "expires_at", MsgExpiryTooLate, map[string]string{"days": days})
		}
		return exp, nil
	}
	if exp == nil || exp.AsTime().After(limit) {
		return timestamppb.New(limit), nil
	}
	return exp, nil
}

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
