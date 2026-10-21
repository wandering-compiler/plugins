package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `oauth_server` feature — an OAuth 2.1
// authorization server (the MCP authorization specification, 2025-11-25) for
// MCP clients and for w17ctl's browser login. Staged only when the
// activation enables `oauth_server`.
//
// The OAuth wire — form bodies, the OAuth error JSON, the 302 to the
// client's redirect, the metadata document — is SDK lib/oauthas in the REST
// gateway; it calls the RPCs here. What lives here is every decision: which
// clients exist, whether a request may proceed, what the user approved, and
// what each code and refresh token is worth. Nothing is deleted: a request
// is decided, a code consumed, a refresh token used, a grant revoked.
//
// The flow:
//
//  1. BeginOAuthAuthorization (the authorization endpoint) checks the client,
//     the redirect, PKCE, the scope and the resource, and keeps the request
//     pending; the browser goes to the project's consent page.
//  2. The consent page (signed in as the user) reads it
//     (GetOAuthAuthorization) and approves or denies it; approval mints the
//     code and answers the redirect to send the browser to.
//  3. ExchangeOAuthToken (the token endpoint, oauth_server_token.go) redeems
//     the code: an MCP grant (a resource was named) yields an mcp_only access
//     token for that resource and a rotating refresh token; a session grant
//     (no resource, a loopback redirect, a DPoP proof) yields a session bound
//     to the program's key — w17ctl's login.

const (
	// oauthRequestTTL is how long the user has to decide on the consent page.
	oauthRequestTTL = 10 * time.Minute
	// oauthCodeTTL is a code's life: the browser → client hop is immediate.
	oauthCodeTTL = 60 * time.Second
	// oauthScope is the one scope: what an MCP client may do is the user's
	// mcp-realm roles, not a scope string the client picked.
	oauthScope = "mcp"

	defaultOAuthAccessTTLSeconds = 3600
	defaultOAuthRefreshTTLDays   = 30
	defaultOAuthGrantMaxDays     = 365
)

// The OAuth error codes the handlers answer (RFC 6749 §4.1.2.1, §5.2; RFC
// 8707 §2; RFC 7591 §3.2.2).
const (
	oauthInvalidRequest          = "invalid_request"
	oauthInvalidClient           = "invalid_client"
	oauthInvalidGrant            = "invalid_grant"
	oauthUnsupportedResponseType = "unsupported_response_type"
	oauthUnsupportedGrantType    = "unsupported_grant_type"
	oauthInvalidScope            = "invalid_scope"
	oauthInvalidTarget           = "invalid_target"
	oauthAccessDenied            = "access_denied"
	oauthInvalidRedirectURI      = "invalid_redirect_uri"
	oauthInvalidClientMetadata   = "invalid_client_metadata"
	oauthInvalidDPoPProof        = "invalid_dpop_proof"
	// oauthDeviceKeyRefused: the proof is valid but its key cannot sign in for
	// the account (a revoked device, a program's key). An extension error
	// (RFC 6749 §8.5) heard only by w17ctl — session grants are its alone —
	// which then discards the key: an invalid_dpop_proof from the gateway's
	// own checks (clock skew, a replayed proof) must not cost it its key.
	oauthDeviceKeyRefused = "w17_device_key_refused"
)

// oauthError is a refusal the OAuth client hears: it travels in the response
// (oauth_error), not as a gRPC error, so the adapter can tell it from a
// failure.
type oauthError struct {
	code, desc string
	noRedirect bool
}

func (e *oauthError) Error() string { return e.code + ": " + e.desc }

func oauthRefuse(code, desc string) *oauthError { return &oauthError{code: code, desc: desc} }

// asOAuthError splits an error into the OAuth refusal it is, or a failure.
func asOAuthError(err error) (*oauthError, bool) {
	var oe *oauthError
	ok := errors.As(err, &oe)
	return oe, ok
}

// Hooks the oauth_server + org_membership file (oauth_server_org.go) sets:
// the organizations a user may give a grant to, and the check that one is
// theirs. Nil without organizations: a grant then belongs to no
// organization.
var (
	oauthConsentOrgs func(ctx context.Context, h *AuthServiceHandler, userID string) ([]*pb.OAuthConsentOrg, error)
	oauthCheckOrg    func(ctx context.Context, h *AuthServiceHandler, userID, orgID string) error
)

func init() {
	erasers = append(erasers, eraseOAuthGrants)
	configChecks = append(configChecks, checkOAuthServerConfig)
}

// checkOAuthServerConfig refuses, at boot, settings that would silently
// admit nothing or anything.
func checkOAuthServerConfig(h *AuthServiceHandler) error {
	if _, err := parseOAuthRedirectHosts(h.OAuthRedirectHosts); err != nil {
		return err
	}
	if _, err := parseOAuthResources(h.OAuthResources); err != nil {
		return err
	}
	return nil
}

// parseOAuthRedirectHosts reads oauth_redirect_hosts: host names, comma- or
// space-separated, lower-cased. Empty = any https host.
func parseOAuthRedirectHosts(raw string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, f := range splitList(raw) {
		h := strings.ToLower(f)
		if h == "" || strings.ContainsAny(h, "/:@?#") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
			return nil, fmt.Errorf("auth plugin: oauth_redirect_hosts entry %q is not a host name", f)
		}
		out[h] = true
	}
	return out, nil
}

// parseOAuthResources reads oauth_resources: absolute URLs, comma- or
// space-separated. Empty = any https resource.
func parseOAuthResources(raw string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, f := range splitList(raw) {
		if err := checkResourceURL(f); err != nil {
			return nil, fmt.Errorf("auth plugin: oauth_resources entry %q: %w", f, err)
		}
		out[normalizeResource(f)] = true
	}
	return out, nil
}

func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// checkResourceURL is RFC 8707 §2: an absolute URI without a fragment; this
// server takes https, and http only on a loopback host (development).
func checkResourceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || u.User != nil {
		return errors.New("not an absolute URL without fragment or credentials")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return errors.New("not https")
	}
	return nil
}

func isLoopbackHost(h string) bool {
	return h == "127.0.0.1" || h == "::1" || h == "localhost"
}

func (h *AuthServiceHandler) oauthAccessTTL() time.Duration {
	if h.OAuthAccessTTLSeconds <= 0 {
		return defaultOAuthAccessTTLSeconds * time.Second
	}
	return time.Duration(h.OAuthAccessTTLSeconds) * time.Second
}

func (h *AuthServiceHandler) oauthRefreshTTL() time.Duration {
	if h.OAuthRefreshTTLDays <= 0 {
		return defaultOAuthRefreshTTLDays * 24 * time.Hour
	}
	return time.Duration(h.OAuthRefreshTTLDays) * 24 * time.Hour
}

func (h *AuthServiceHandler) oauthGrantMax() time.Duration {
	if h.OAuthGrantMaxDays <= 0 {
		return defaultOAuthGrantMaxDays * 24 * time.Hour
	}
	return time.Duration(h.OAuthGrantMaxDays) * 24 * time.Hour
}

// GetOAuthServerSettings — what the metadata document publishes.
func (h *AuthServiceHandler) GetOAuthServerSettings(context.Context, *pb.GetOAuthServerSettingsReq) (*pb.GetOAuthServerSettingsResp, error) {
	return &pb.GetOAuthServerSettingsResp{DynamicRegistration: h.OAuthDynamicRegistration}, nil
}

// BeginOAuthAuthorization is the authorization endpoint's decision: is this
// a request the user may be asked about at all? The client and its redirect
// are checked first, and a refusal about either is shown, never redirected
// (RFC 6749 §4.1.2.1): an unchecked redirect is where an attacker would
// have the error — and the user — sent.
func (h *AuthServiceHandler) BeginOAuthAuthorization(ctx context.Context, req *pb.BeginOAuthAuthorizationReq) (*pb.BeginOAuthAuthorizationResp, error) {
	id, err := h.beginOAuthAuthorization(ctx, req)
	if oe, ok := asOAuthError(err); ok {
		return &pb.BeginOAuthAuthorizationResp{OauthError: oe.code, OauthErrorDescription: oe.desc, NoRedirect: oe.noRedirect}, nil
	}
	if err != nil {
		return nil, err
	}
	return &pb.BeginOAuthAuthorizationResp{RequestId: id}, nil
}

func (h *AuthServiceHandler) beginOAuthAuthorization(ctx context.Context, req *pb.BeginOAuthAuthorizationReq) (string, error) {
	client, err := h.resolveOAuthClient(ctx, req.GetClientId(), req.GetClientAddr())
	if err != nil {
		if oe, ok := asOAuthError(err); ok {
			oe.noRedirect = true
		}
		return "", err
	}
	if !redirectRegistered(client.GetRedirectUris(), req.GetRedirectUri()) {
		return "", &oauthError{code: oauthInvalidRequest, desc: "the redirect_uri is not one the client registered", noRedirect: true}
	}
	// From here on the redirect is the client's own, so a refusal goes back
	// to it.
	if req.GetResponseType() != "code" {
		return "", oauthRefuse(oauthUnsupportedResponseType, "only response_type=code is supported")
	}
	if req.GetCodeChallengeMethod() != "S256" || len(req.GetCodeChallenge()) != 43 {
		return "", oauthRefuse(oauthInvalidRequest, "PKCE with code_challenge_method=S256 is required")
	}
	if len(req.GetState()) > 1024 {
		return "", oauthRefuse(oauthInvalidRequest, "state is longer than 1024 characters")
	}
	scope, err := oauthRequestedScope(req.GetScope())
	if err != nil {
		return "", err
	}
	kind, resource, err := h.oauthGrantKind(client, req.GetResources(), req.GetRedirectUri())
	if err != nil {
		return "", err
	}
	requestID, err := randomURLToken()
	if err != nil {
		return "", err
	}
	if _, err := h.Mutation.CreateOAuthAuthorization(ctx, &pb.CreateOAuthAuthorizationReq{
		RequestHash:   sha256Hex(requestID),
		ClientRowId:   client.GetId(),
		Kind:          kind,
		RedirectUri:   req.GetRedirectUri(),
		State:         req.GetState(),
		CodeChallenge: req.GetCodeChallenge(),
		Scope:         scope,
		Resource:      resource,
		Issuer:        req.GetIssuer(),
		CreatedIp:     truncate(req.GetClientAddr(), 64),
		ExpiresAt:     timestamppb.New(time.Now().Add(oauthRequestTTL)),
	}); err != nil {
		return "", err
	}
	return requestID, nil
}

// oauthRequestedScope: only `mcp`; none asked = `mcp`.
func oauthRequestedScope(raw string) (string, error) {
	for _, s := range strings.Fields(raw) {
		if s != oauthScope {
			return "", oauthRefuse(oauthInvalidScope, "the only scope is "+oauthScope)
		}
	}
	return oauthScope, nil
}

// oauthGrantKind decides what the authorization yields. A resource named:
// an MCP grant for it. None: a session grant — the whole account, bound to a
// program's key — which only w17ctl asks for: a client that registered as it
// (software_id), on the user's own computer (a loopback redirect). Every
// other client without a resource is refused, so an MCP client that forgot
// the parameter is not offered a whole session on the consent page. The
// software_id is the client's own claim; what bounds a false one is the
// loopback redirect (a program already on the user's computer) and the
// consent page, which says plainly that the program signs in as the user.
func (h *AuthServiceHandler) oauthGrantKind(client *pb.OAuthClientRow, resources []string, redirectURI string) (pb.OAuthGrantKind, string, error) {
	switch len(resources) {
	case 0:
		if !isLoopbackRedirect(redirectURI) || client.GetSoftwareId() != sessionGrantSoftwareID {
			return 0, "", oauthRefuse(oauthInvalidTarget, "a resource is required")
		}
		return pb.OAuthGrantKind_OAUTH_GRANT_KIND_SESSION, "", nil
	case 1:
	default:
		return 0, "", oauthRefuse(oauthInvalidTarget, "one resource per authorization")
	}
	res := resources[0]
	if err := checkResourceURL(res); err != nil {
		return 0, "", oauthRefuse(oauthInvalidTarget, "the resource is "+err.Error())
	}
	res = normalizeResource(res)
	allowed, _ := parseOAuthResources(h.OAuthResources)
	if len(allowed) > 0 && !allowed[res] {
		return 0, "", oauthRefuse(oauthInvalidTarget, "this server issues no tokens for that resource")
	}
	return pb.OAuthGrantKind_OAUTH_GRANT_KIND_MCP, res, nil
}

// sessionGrantSoftwareID is the software_id w17ctl registers under: the only
// client a session grant is issued to.
const sessionGrantSoftwareID = "w17ctl"

// errOAuthRequestGone is the consent page's answer for a request that is
// unknown, decided or expired: the user starts again from the application.
var errOAuthRequestGone = errors.New("oauth: the authorization request is unknown, decided or expired")

func oauthRequestGone(ctx context.Context) error {
	return refusal(ctx, codes.NotFound, errOAuthRequestGone.Error(), CodeOAuthRequestGone, "request_id", MsgOAuthRequestGone, nil)
}

// GetOAuthAuthorization — what the consent page shows the signed-in user.
func (h *AuthServiceHandler) GetOAuthAuthorization(ctx context.Context, req *pb.GetOAuthAuthorizationReq) (*pb.GetOAuthAuthorizationResp, error) {
	userID, err := h.consentCaller(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := h.pendingOAuthAuthorization(ctx, req.GetRequestId())
	if err != nil {
		return nil, err
	}
	resp := &pb.GetOAuthAuthorizationResp{
		ClientName:   pending.GetClient().GetClientName(),
		ClientUri:    pending.GetClient().GetClientUri(),
		LogoUri:      pending.GetClient().GetLogoUri(),
		ClientId:     pending.GetClient().GetClientId(),
		RedirectHost: redirectHost(pending.GetRedirectUri()),
		Kind:         pending.GetKind(),
		Resource:     pending.GetResource(),
		Scope:        pending.GetScope(),
		ExpiresAt:    pending.GetExpiresAt(),
	}
	if oauthConsentOrgs != nil && pending.GetKind() == pb.OAuthGrantKind_OAUTH_GRANT_KIND_MCP {
		if resp.Orgs, err = oauthConsentOrgs(ctx, h, userID); err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// consentCaller is the user deciding: a signed-in session, never an API or
// MCP token — approving hands out a credential.
func (h *AuthServiceHandler) consentCaller(ctx context.Context) (string, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return "", Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return "", err
	}
	return userID, nil
}

func (h *AuthServiceHandler) pendingOAuthAuthorization(ctx context.Context, requestID string) (*pb.GetPendingOAuthAuthorizationResp, error) {
	if requestID == "" {
		return nil, oauthRequestGone(ctx)
	}
	got, err := h.Query.GetPendingOAuthAuthorization(ctx, &pb.GetPendingOAuthAuthorizationReq{RequestHash: sha256Hex(requestID)})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, oauthRequestGone(ctx)
		}
		return nil, err
	}
	if got.GetId() == "" {
		return nil, oauthRequestGone(ctx)
	}
	return got, nil
}

// ApproveOAuthAuthorization records the user's approval, mints the code, and
// answers where the browser goes: the client's redirect with the code, the
// client's state and this server's issuer (RFC 9207).
func (h *AuthServiceHandler) ApproveOAuthAuthorization(ctx context.Context, req *pb.ApproveOAuthAuthorizationReq) (*pb.ApproveOAuthAuthorizationResp, error) {
	userID, err := h.consentCaller(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := h.pendingOAuthAuthorization(ctx, req.GetRequestId())
	if err != nil {
		return nil, err
	}
	orgID := ""
	if oauthCheckOrg != nil && pending.GetKind() == pb.OAuthGrantKind_OAUTH_GRANT_KIND_MCP {
		orgID = req.GetOrgId()
		if err := oauthCheckOrg(ctx, h, userID, orgID); err != nil {
			return nil, err
		}
	}
	approving, err := h.oauthApprovingSession(ctx, userID)
	if err != nil {
		return nil, err
	}
	code, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	decided, err := h.Mutation.DecideOAuthAuthorization(ctx, &pb.DecideOAuthAuthorizationReq{
		RequestHash:        sha256Hex(req.GetRequestId()),
		Decision:           pb.OAuthDecision_OAUTH_DECISION_APPROVED,
		UserId:             userID,
		OrgId:              orgID,
		ApprovedByDeviceId: approving.GetDeviceId(),
		SessionExpiresAt:   approving.GetExpiresAt(),
		CodeHash:           sha256Hex(code),
		CodeExpiresAt:      timestamppb.New(time.Now().Add(oauthCodeTTL)),
	})
	if err != nil {
		if notFoundOK(err) == nil {
			// Decided in another tab, or expired, between the read and now.
			return nil, oauthRequestGone(ctx)
		}
		return nil, err
	}
	to, err := clientRedirect(decided.GetRedirectUri(), map[string]string{
		"code": code, "state": decided.GetState(), "iss": decided.GetIssuer(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.ApproveOAuthAuthorizationResp{RedirectUrl: to}, nil
}

// DenyOAuthAuthorization records the refusal and answers the redirect that
// tells the client (access_denied).
func (h *AuthServiceHandler) DenyOAuthAuthorization(ctx context.Context, req *pb.DenyOAuthAuthorizationReq) (*pb.DenyOAuthAuthorizationResp, error) {
	userID, err := h.consentCaller(ctx)
	if err != nil {
		return nil, err
	}
	decided, err := h.Mutation.DecideOAuthAuthorization(ctx, &pb.DecideOAuthAuthorizationReq{
		RequestHash: sha256Hex(req.GetRequestId()),
		Decision:    pb.OAuthDecision_OAUTH_DECISION_DENIED,
		UserId:      userID,
	})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, oauthRequestGone(ctx)
		}
		return nil, err
	}
	to, err := clientRedirect(decided.GetRedirectUri(), map[string]string{
		"error": oauthAccessDenied, "error_description": "the user denied the request",
		"state": decided.GetState(), "iss": decided.GetIssuer(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.DenyOAuthAuthorizationResp{RedirectUrl: to}, nil
}

// oauthApprovingSession reads the approving session: its device (recorded
// as the approver, whose revocation ends the grant) and its expiry (a session
// grant mints no later). A session that is gone approves nothing.
func (h *AuthServiceHandler) oauthApprovingSession(ctx context.Context, userID string) (*pb.GetOAuthApprovingSessionResp, error) {
	tokenID := callerSessionTokenID(ctx)
	got, err := h.Query.GetOAuthApprovingSession(ctx, &pb.GetOAuthApprovingSessionReq{TokenId: tokenID, UserId: userID})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, Unauthenticated(errOAuthSessionGone)
		}
		return nil, err
	}
	if got.GetTokenId() != tokenID || tokenID == "" {
		return nil, Unauthenticated(errOAuthSessionGone)
	}
	return got, nil
}

var errOAuthSessionGone = errors.New("oauth: the approving session is not live")

// clientRedirect adds params (empty ones left out) to the client's redirect,
// keeping any query it registered.
func clientRedirect(redirectURI string, params map[string]string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// redirectHost is what the consent page shows as where the code goes: the
// one part of the request the client cannot dress up.
func redirectHost(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	switch {
	case isLoopbackHost(u.Hostname()) && u.Scheme == "http":
		return "this computer"
	case u.Scheme != "http" && u.Scheme != "https":
		// A private-use scheme (RFC 8252 §7.1): an app on this device that
		// claims it.
		return "the " + u.Scheme + " app on this device"
	}
	return u.Host
}

// redirectRegistered: the requested redirect equals one the client
// registered, as a whole string — except a loopback redirect's port, which a
// native app picks per run (RFC 8252 §7.3).
func redirectRegistered(registered, requested string) bool {
	if requested == "" {
		return false
	}
	for _, r := range strings.Split(registered, "\n") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if r == requested {
			return true
		}
		if isLoopbackRedirect(r) && isLoopbackRedirect(requested) && sameExceptPort(r, requested) {
			return true
		}
	}
	return false
}

func sameExceptPort(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil {
		return false
	}
	return ua.Scheme == ub.Scheme && ua.Hostname() == ub.Hostname() && ua.Path == ub.Path && ua.RawQuery == ub.RawQuery
}

// ListMyOAuthGrants — the caller's connected apps.
func (h *AuthServiceHandler) ListMyOAuthGrants(ctx context.Context, _ *pb.ListMyOAuthGrantsReq) (*pb.ListMyOAuthGrantsResp, error) {
	userID, err := h.consentCaller(ctx)
	if err != nil {
		return nil, err
	}
	got, err := h.Query.ListUserOAuthGrants(ctx, &pb.ListUserOAuthGrantsReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	resp := &pb.ListMyOAuthGrantsResp{}
	for _, g := range got.GetGrants() {
		resp.Grants = append(resp.Grants, &pb.MyOAuthGrant{
			Id: g.GetId(), ClientName: g.GetClientName(), ClientUri: g.GetClientUri(), LogoUri: g.GetLogoUri(),
			ClientId: g.GetClientId(), Resource: g.GetResource(), OrgId: g.GetOrgId(),
			CreatedAt: g.GetCreatedAt(), LastUsedAt: g.GetLastUsedAt(), ExpiresAt: g.GetExpiresAt(),
		})
	}
	return resp, nil
}

// RevokeMyOAuthGrant disconnects one of the caller's apps: the grant and
// every access token of it end now, its refresh tokens with the grant.
func (h *AuthServiceHandler) RevokeMyOAuthGrant(ctx context.Context, req *pb.RevokeMyOAuthGrantReq) (*pb.RevokeMyOAuthGrantResp, error) {
	userID, err := h.consentCaller(ctx)
	if err != nil {
		return nil, err
	}
	g, err := h.Query.GetOAuthGrant(ctx, &pb.GetOAuthGrantReq{Id: req.GetGrantId()})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, refusal(ctx, codes.NotFound, errOAuthGrantUnknown.Error(), CodeOAuthAppUnknown, "grant_id", MsgOAuthAppUnknown, nil)
		}
		return nil, err
	}
	// Another user's grant answers as an unknown one.
	if g.GetUserId() != userID {
		return nil, refusal(ctx, codes.NotFound, errOAuthGrantUnknown.Error(), CodeOAuthAppUnknown, "grant_id", MsgOAuthAppUnknown, nil)
	}
	if _, err := h.Mutation.RevokeOAuthGrant(ctx, &pb.RevokeOAuthGrantReq{
		Id: g.GetId(), RevokedBy: userID, Reason: pb.RevokeReason_REVOKE_REASON_GRANT_REVOKED,
	}); err != nil {
		return nil, err
	}
	return &pb.RevokeMyOAuthGrantResp{}, nil
}

var errOAuthGrantUnknown = errors.New("oauth: no such connected app")

// eraseOAuthGrants ends the erased user's grants; their access tokens were
// revoked with every other token by the erasure's first step.
func eraseOAuthGrants(ctx context.Context, h *AuthServiceHandler, userID, _, _ string) error {
	_, err := h.Mutation.RevokeUserOAuthGrants(ctx, &pb.RevokeUserOAuthGrantsReq{
		UserId: userID, Reason: pb.RevokeReason_REVOKE_REASON_USER_ERASED,
	})
	return err
}
