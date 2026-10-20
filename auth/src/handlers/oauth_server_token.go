package handlers

import (
	"context"
	"crypto/hmac"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The token endpoint of the oauth_server feature: the code exchange, the
// refresh, and the revocation endpoint (RFC 7009).

const (
	// The prefixes of what this server issues an MCP client, so a token
	// found in a log says what it is. The rest is 256 random bits.
	mcpAccessTokenPrefix  = "w17mcp_"
	mcpRefreshTokenPrefix = "w17mcpr_"
)

// ExchangeOAuthToken is the token endpoint: authorization_code and
// refresh_token. Every refusal is an OAuth error in the response; only a
// failure of the store is a gRPC error.
func (h *AuthServiceHandler) ExchangeOAuthToken(ctx context.Context, req *pb.ExchangeOAuthTokenReq) (*pb.ExchangeOAuthTokenResp, error) {
	var (
		resp *pb.ExchangeOAuthTokenResp
		err  error
	)
	switch req.GetGrantType() {
	case "authorization_code":
		resp, err = h.exchangeOAuthCode(ctx, req)
	case "refresh_token":
		resp, err = h.refreshOAuthToken(ctx, req)
	default:
		err = oauthRefuse(oauthUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")
	}
	if oe, ok := asOAuthError(err); ok {
		return &pb.ExchangeOAuthTokenResp{OauthError: oe.code, OauthErrorDescription: oe.desc}, nil
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// errOAuthCodeRefused is the sign-in history's cause for every code that
// does not redeem; the client hears invalid_grant.
var errOAuthCodeRefused = errors.New("oauth: the authorization code is unknown, spent, expired or not this client's")

func init() {
	signInOutcomeRules = append(signInOutcomeRules,
		outcomeRule{errOAuthCodeRefused, pb.SignInOutcome_SIGN_IN_OUTCOME_WRONG_CODE},
	)
}

// exchangeOAuthCode redeems a code. It is spent before anything else is
// checked — a wrong verifier still burns it, so it cannot be guessed at —
// and every way it fails is the same invalid_grant.
func (h *AuthServiceHandler) exchangeOAuthCode(ctx context.Context, req *pb.ExchangeOAuthTokenReq) (_ *pb.ExchangeOAuthTokenResp, err error) {
	attempt := beginSignIn(ctx, pb.SignInMethod_SIGN_IN_METHOD_AUTHORIZED_APP)
	defer func() {
		// A refusal the client hears is still a refused sign-in.
		if oe, ok := asOAuthError(err); ok && oe.code == oauthInvalidGrant {
			h.endSignIn(ctx, attempt, errOAuthCodeRefused)
			return
		}
		h.endSignIn(ctx, attempt, err)
	}()

	client, err := h.oauthClientByID(ctx, req.GetClientId())
	if err != nil {
		return nil, err
	}
	if client == nil || client.GetDisabledAt() != nil {
		return nil, oauthRefuse(oauthInvalidClient, "unknown client")
	}
	if len(req.GetCodeVerifier()) < pkceMinVerifierLen || req.GetCode() == "" {
		return nil, oauthRefuse(oauthInvalidGrant, "the code or its verifier is invalid")
	}
	code, err := h.Mutation.ConsumeOAuthCode(ctx, &pb.ConsumeOAuthCodeReq{CodeHash: sha256Hex(req.GetCode())})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, oauthRefuse(oauthInvalidGrant, "the code is unknown, spent or expired")
		}
		return nil, err
	}
	attempt.userID = code.GetUserId()
	switch {
	case code.GetId() == "" || code.GetUserId() == "":
		return nil, oauthRefuse(oauthInvalidGrant, "the code is unknown, spent or expired")
	case code.GetClientRowId() != client.GetId():
		return nil, oauthRefuse(oauthInvalidGrant, "the code was issued to another client")
	case !verifyPKCES256(req.GetCodeVerifier(), code.GetCodeChallenge()):
		return nil, oauthRefuse(oauthInvalidGrant, "the code verifier does not match")
	case req.GetRedirectUri() != "" && !hmac.Equal([]byte(req.GetRedirectUri()), []byte(code.GetRedirectUri())):
		return nil, oauthRefuse(oauthInvalidGrant, "the redirect_uri is not the one the code was issued for")
	case len(req.GetResources()) > 1 || (len(req.GetResources()) == 1 && req.GetResources()[0] != code.GetResource()):
		return nil, oauthRefuse(oauthInvalidTarget, "the resource is not the one the user approved")
	}
	if err := h.refuseRevokedOAuthApprover(ctx, code.GetApprovedByDeviceId()); err != nil {
		return nil, err
	}
	account, err := refuseUnsignableAccount(ctx, h, code.GetUserId())
	attempt.account = account
	if err != nil {
		return nil, oauthRefuse(oauthInvalidGrant, "the account cannot sign in")
	}
	switch code.GetKind() {
	case pb.OAuthGrantKind_OAUTH_GRANT_KIND_MCP:
		resp, err := h.issueMCPGrant(ctx, client, code)
		if err == nil {
			attempt.outcome = pb.SignInOutcome_SIGN_IN_OUTCOME_OK
		}
		return resp, err
	case pb.OAuthGrantKind_OAUTH_GRANT_KIND_SESSION:
		return h.issueSessionGrant(ctx, attempt, code)
	}
	return nil, oauthRefuse(oauthInvalidGrant, "the code is of no known kind")
}

// refuseRevokedOAuthApprover: the device that approved a grant was revoked
// since — the approval ends with it. A read that does not answer refuses.
func (h *AuthServiceHandler) refuseRevokedOAuthApprover(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return nil
	}
	got, err := h.Query.GetOAuthDeviceRevocation(ctx, &pb.GetOAuthDeviceRevocationReq{DeviceId: deviceID})
	if err != nil {
		if notFoundOK(err) == nil {
			return oauthRefuse(oauthInvalidGrant, "the approving device is gone")
		}
		return err
	}
	if got.GetDeviceId() != deviceID || got.GetRevokedAt() != nil {
		return oauthRefuse(oauthInvalidGrant, "the approving device was revoked")
	}
	return nil
}

// issueMCPGrant turns a redeemed code into a connected app: the grant, its
// first access token and its first refresh token, in one transaction.
func (h *AuthServiceHandler) issueMCPGrant(ctx context.Context, client *pb.OAuthClientRow, code *pb.ConsumeOAuthCodeResp) (*pb.ExchangeOAuthTokenResp, error) {
	if oauthCheckOrg != nil {
		// Membership may have ended between the approval and now.
		if err := oauthCheckOrg(ctx, h, code.GetUserId(), code.GetOrgId()); err != nil {
			return nil, oauthRefuse(oauthInvalidGrant, "the organization the user chose is no longer theirs")
		}
	}
	var resp *pb.ExchangeOAuthTokenResp
	err := h.inTx(ctx, func(txCtx context.Context) error {
		grant, err := h.Mutation.CreateOAuthGrant(txCtx, &pb.CreateOAuthGrantReq{
			UserId:             code.GetUserId(),
			OrgId:              code.GetOrgId(),
			ClientRowId:        client.GetId(),
			AuthorizationId:    code.GetId(),
			Resource:           code.GetResource(),
			Scope:              code.GetScope(),
			ApprovedByDeviceId: code.GetApprovedByDeviceId(),
			ExpiresAt:          timestamppb.New(time.Now().Add(h.oauthGrantMax())),
			ClientId:           client.GetClientId(),
		})
		if err != nil {
			return err
		}
		resp, err = h.issueMCPTokens(txCtx, mcpGrant{
			id: grant.GetId(), userID: code.GetUserId(), orgID: code.GetOrgId(), resource: code.GetResource(),
			scope: code.GetScope(), approvedBy: code.GetApprovedByDeviceId(), clientName: client.GetClientName(),
			expiresAt: time.Now().Add(h.oauthGrantMax()),
		})
		return err
	})
	return resp, err
}

// mcpGrant is what an access token and a refresh token are minted from.
type mcpGrant struct {
	id, userID, orgID, resource, scope, approvedBy, clientName string
	expiresAt                                                  time.Time
}

// issueMCPTokens mints one access token and one refresh token of a grant.
// Neither outlives the grant.
func (h *AuthServiceHandler) issueMCPTokens(ctx context.Context, g mcpGrant) (*pb.ExchangeOAuthTokenResp, error) {
	access, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	refresh, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	access, refresh = mcpAccessTokenPrefix+access, mcpRefreshTokenPrefix+refresh
	now := time.Now()
	accessEnd := minTime(now.Add(h.oauthAccessTTL()), g.expiresAt)
	refreshEnd := minTime(now.Add(h.oauthRefreshTTL()), g.expiresAt)
	name := g.clientName
	if name == "" {
		name = "MCP client"
	}
	if _, err := h.Mutation.IssueOAuthAccessToken(ctx, &pb.IssueOAuthAccessTokenReq{
		UserId:             g.userID,
		TokenHash:          sha256Hex(access),
		ExpiresAt:          timestamppb.New(accessEnd),
		GrantId:            g.id,
		Resource:           g.resource,
		OrgId:              g.orgID,
		ApprovedByDeviceId: g.approvedBy,
		Name:               truncate(name, 128),
	}); err != nil {
		return nil, err
	}
	if _, err := h.Mutation.CreateOAuthRefreshToken(ctx, &pb.CreateOAuthRefreshTokenReq{
		GrantId: g.id, TokenHash: sha256Hex(refresh), ExpiresAt: timestamppb.New(refreshEnd),
	}); err != nil {
		return nil, err
	}
	return &pb.ExchangeOAuthTokenResp{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(accessEnd).Round(time.Second) / time.Second),
		RefreshToken: refresh,
		Scope:        g.scope,
	}, nil
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// issueSessionGrant is w17ctl's browser login: a session bound to the key
// that signs the token request (its DPoP proof, which the gateway verified),
// no longer than the session that approved it — the same session a CLI
// login mints, so a session cannot renew itself through this server.
func (h *AuthServiceHandler) issueSessionGrant(ctx context.Context, attempt *signInAttempt, code *pb.ConsumeOAuthCodeResp) (*pb.ExchangeOAuthTokenResp, error) {
	thumbprint, err := mintThumbprint(ctx)
	if err != nil {
		return nil, oauthRefuse(oauthInvalidDPoPProof, "a session is issued only to a request signed with a DPoP proof")
	}
	expiresAt := capSessionExpiry(h.sessionTokenExpiry(), code.GetSessionExpiresAt())
	if !expiresAt.AsTime().After(time.Now()) {
		return nil, oauthRefuse(oauthInvalidGrant, "the approving session has ended")
	}
	dev, err := mintDevice(ctx, h, code.GetUserId(), thumbprint)
	attempt.deviceID = dev.id
	switch {
	case dev.id != "" && err != nil:
		// The key is this account's revoked device, or a program's key: no
		// session is bound to it. Said in OAuth terms, so the client makes a
		// new key and signs in again rather than reading a server failure.
		return nil, oauthRefuse(oauthInvalidDPoPProof, "this key cannot sign in for the account (revoked, or a program's key): sign in again with a new key")
	case err != nil:
		return nil, err
	}
	token, err := h.mintSession(ctx, attempt, code.GetUserId(), dev, expiresAt, code.GetApprovedByDeviceId())
	if err != nil {
		return nil, err
	}
	return &pb.ExchangeOAuthTokenResp{
		AccessToken: token,
		TokenType:   "DPoP",
		ExpiresIn:   int64(time.Until(expiresAt.AsTime()).Round(time.Second) / time.Second),
	}, nil
}

// capSessionExpiry: the normal session lifetime, but never past the
// approving session's (nil = that one never expires).
func capSessionExpiry(normal, approving *timestamppb.Timestamp) *timestamppb.Timestamp {
	if approving == nil || !approving.AsTime().Before(normal.AsTime()) {
		return normal
	}
	return approving
}

// refreshOAuthToken rotates a refresh token. A token presented after it was
// used means two parties hold it — the grant ends (OAuth 2.1 §4.3.1). Every
// revocation that reached the grant's newest access token — logging out
// everywhere, a password change, a disabled account, an operator — ends the
// grant here too, so the user's other controls reach their connected apps.
func (h *AuthServiceHandler) refreshOAuthToken(ctx context.Context, req *pb.ExchangeOAuthTokenReq) (*pb.ExchangeOAuthTokenResp, error) {
	client, err := h.oauthClientByID(ctx, req.GetClientId())
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, oauthRefuse(oauthInvalidClient, "unknown client")
	}
	hash := sha256Hex(req.GetRefreshToken())
	used, err := h.Mutation.UseOAuthRefreshToken(ctx, &pb.UseOAuthRefreshTokenReq{TokenHash: hash})
	if err != nil {
		if notFoundOK(err) != nil {
			return nil, err
		}
		return nil, h.refreshRefused(ctx, hash)
	}
	if used.GetGrantId() == "" {
		return nil, h.refreshRefused(ctx, hash)
	}
	g, err := h.Query.GetOAuthGrant(ctx, &pb.GetOAuthGrantReq{Id: used.GetGrantId()})
	if err != nil {
		return nil, err
	}
	end := func(reason pb.RevokeReason, desc string) error {
		if _, err := h.Mutation.RevokeOAuthGrant(ctx, &pb.RevokeOAuthGrantReq{Id: g.GetId(), Reason: reason}); err != nil {
			return err
		}
		return oauthRefuse(oauthInvalidGrant, desc)
	}
	switch {
	case g.GetClientRowId() != client.GetId():
		return nil, oauthRefuse(oauthInvalidGrant, "the refresh token was issued to another client")
	case g.GetRevokedAt() != nil:
		return nil, oauthRefuse(oauthInvalidGrant, "the grant was revoked")
	case !g.GetExpiresAt().AsTime().After(time.Now()):
		return nil, oauthRefuse(oauthInvalidGrant, "the grant has ended; sign in again")
	case g.GetClientDisabledAt() != nil:
		return nil, end(pb.RevokeReason_REVOKE_REASON_GRANT_REVOKED, "the client was disabled")
	case len(req.GetResources()) > 1 || (len(req.GetResources()) == 1 && req.GetResources()[0] != g.GetResource()):
		return nil, oauthRefuse(oauthInvalidTarget, "the resource is not the grant's")
	}
	if err := h.refuseRevokedOAuthApprover(ctx, g.GetApprovedByDeviceId()); err != nil {
		if _, ok := asOAuthError(err); ok {
			return nil, end(pb.RevokeReason_REVOKE_REASON_DEVICE_REVOKED, "the approving device was revoked")
		}
		return nil, err
	}
	last, err := h.Query.GetOAuthGrantLastToken(ctx, &pb.GetOAuthGrantLastTokenReq{GrantId: g.GetId()})
	if err != nil && notFoundOK(err) != nil {
		return nil, err
	}
	if last.GetRevokedAt() != nil {
		return nil, end(pb.RevokeReason_REVOKE_REASON_GRANT_REVOKED, "the user's sessions were ended")
	}
	if _, err := refuseUnsignableAccount(ctx, h, g.GetUserId()); err != nil {
		return nil, end(pb.RevokeReason_REVOKE_REASON_USER_DISABLED, "the account cannot sign in")
	}
	if oauthCheckOrg != nil {
		if err := oauthCheckOrg(ctx, h, g.GetUserId(), g.GetOrgId()); err != nil {
			return nil, end(pb.RevokeReason_REVOKE_REASON_GRANT_REVOKED, "the organization is no longer the user's")
		}
	}
	var resp *pb.ExchangeOAuthTokenResp
	err = h.inTx(ctx, func(txCtx context.Context) error {
		var err error
		resp, err = h.issueMCPTokens(txCtx, mcpGrant{
			id: g.GetId(), userID: g.GetUserId(), orgID: g.GetOrgId(), resource: g.GetResource(),
			scope: g.GetScope(), approvedBy: g.GetApprovedByDeviceId(), clientName: client.GetClientName(),
			expiresAt: g.GetExpiresAt().AsTime(),
		})
		if err != nil {
			return err
		}
		_, err = h.Mutation.TouchOAuthGrant(txCtx, &pb.TouchOAuthGrantReq{Id: g.GetId()})
		return err
	})
	return resp, err
}

// refreshRefused answers a refresh token that did not rotate: unknown or
// expired is invalid_grant; one already used is a copy in someone else's
// hands, and its grant ends.
func (h *AuthServiceHandler) refreshRefused(ctx context.Context, hash string) error {
	got, err := h.Query.GetOAuthRefreshToken(ctx, &pb.GetOAuthRefreshTokenReq{TokenHash: hash})
	if err != nil {
		if notFoundOK(err) == nil {
			return oauthRefuse(oauthInvalidGrant, "the refresh token is unknown or expired")
		}
		return err
	}
	if got.GetUsedAt() != nil && got.GetGrantId() != "" {
		if _, err := h.Mutation.RevokeOAuthGrant(ctx, &pb.RevokeOAuthGrantReq{
			Id: got.GetGrantId(), Reason: pb.RevokeReason_REVOKE_REASON_REFRESH_REUSED,
		}); err != nil {
			return err
		}
		return oauthRefuse(oauthInvalidGrant, "the refresh token was already used; the grant is revoked")
	}
	return oauthRefuse(oauthInvalidGrant, "the refresh token is unknown or expired")
}

// RevokeOAuthToken is the revocation endpoint (RFC 7009): an access or a
// refresh token of a grant ends the grant. Anything else — unknown, another
// client's, already revoked — answers the same success (§2.2), so the
// endpoint tells nobody what a token is.
func (h *AuthServiceHandler) RevokeOAuthToken(ctx context.Context, req *pb.RevokeOAuthTokenReq) (*pb.RevokeOAuthTokenResp, error) {
	hash := sha256Hex(req.GetToken())
	grantID := ""
	if req.GetTokenTypeHint() != "refresh_token" {
		got, err := h.Query.GetOAuthAccessTokenGrant(ctx, &pb.GetOAuthAccessTokenGrantReq{TokenHash: hash})
		if err != nil && notFoundOK(err) != nil {
			return nil, err
		}
		grantID = got.GetGrantId()
	}
	if grantID == "" {
		got, err := h.Query.GetOAuthRefreshToken(ctx, &pb.GetOAuthRefreshTokenReq{TokenHash: hash})
		if err != nil && notFoundOK(err) != nil {
			return nil, err
		}
		grantID = got.GetGrantId()
	}
	if grantID == "" {
		return &pb.RevokeOAuthTokenResp{}, nil
	}
	g, err := h.Query.GetOAuthGrant(ctx, &pb.GetOAuthGrantReq{Id: grantID})
	if err != nil {
		if notFoundOK(err) == nil {
			return &pb.RevokeOAuthTokenResp{}, nil
		}
		return nil, err
	}
	// The client that holds the token may revoke it; a client naming
	// another's token is answered as though it had.
	if req.GetClientId() != "" && req.GetClientId() != g.GetClientId() {
		return &pb.RevokeOAuthTokenResp{}, nil
	}
	if _, err := h.Mutation.RevokeOAuthGrant(ctx, &pb.RevokeOAuthGrantReq{
		Id: grantID, Reason: pb.RevokeReason_REVOKE_REASON_GRANT_REVOKED,
	}); err != nil {
		return nil, err
	}
	return &pb.RevokeOAuthTokenResp{}, nil
}
