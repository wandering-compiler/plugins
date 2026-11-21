package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file exists only when BOTH `admin_accounts` and `service_account` are on
// (plugin.yaml, `go_files_combined`): the admin's machine accounts. They are
// CreateBot and IssueBotToken for an operator acting realm-wide — every rule
// of those (the API realm, the ceiling, the organization's lock, one key per
// account, a bearer token's year, the history, BotCreated / ApiTokenCreated)
// holds unchanged, because these run them. What differs is only WHERE: the
// organization the request names, or the one the machine account belongs to,
// instead of the caller's active one (withBotOrg).

// CreateServiceAccount creates a machine account realm-wide.
func (h *AuthServiceHandler) CreateServiceAccount(ctx context.Context, req *pb.CreateServiceAccountReq) (*pb.CreateServiceAccountResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if err := h.adminAccountsGate(ctx, "CreateServiceAccount"); err != nil {
		return nil, err
	}
	orgID, err := h.adminAccountOrg(ctx, "CreateServiceAccount", req.GetOrg())
	if err != nil {
		return nil, err
	}
	if orgID != "" {
		ctx = withBotOrg(ctx, orgID)
	}
	// The role by its name, among the API realm's: what an operator types.
	roles, err := h.Query.ListApiRealmRoles(ctx, &pb.ListApiRealmRolesReq{})
	if err != nil {
		return nil, err
	}
	roleID := ""
	for _, r := range roles.GetRoles() {
		if r.GetName() == req.GetRole() {
			roleID = r.GetId()
		}
	}
	if roleID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "role: no API-realm role named %q — a machine account holds one of those", req.GetRole())
	}
	created, err := h.CreateBot(ctx, &pb.CreateBotReq{Email: req.GetEmail(), RoleId: roleID})
	if err != nil {
		return nil, err
	}
	return &pb.CreateServiceAccountResp{UserId: created.GetUserId()}, nil
}

// IssueServiceAccountToken issues a token for one machine account, in the
// organization it belongs to.
func (h *AuthServiceHandler) IssueServiceAccountToken(ctx context.Context, req *pb.IssueServiceAccountTokenReq) (*pb.IssueServiceAccountTokenResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if err := h.adminAccountsGate(ctx, "IssueServiceAccountToken"); err != nil {
		return nil, err
	}
	if len(req.GetIds()) != 1 || req.GetIds()[0] == "" {
		return nil, status.Error(codes.InvalidArgument, "ids: name exactly one machine account")
	}
	target := req.GetIds()[0]
	if adminAccountOrgs != nil {
		orgID, err := adminAccountOrgs.orgOf(ctx, h, target)
		if err != nil {
			return nil, err
		}
		if orgID == "" {
			// A machine account always belongs to one; none reads like "not a
			// machine account", as IssueBotToken answers every such target.
			return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
		}
		ctx = withBotOrg(ctx, orgID)
	}
	issued, err := h.IssueBotToken(ctx, &pb.IssueBotTokenReq{
		UserId: target, Name: req.GetName(), ExpiresAt: req.GetExpiresAt(), PublicKey: req.GetPublicKey(),
	})
	if err != nil {
		return nil, err
	}
	return &pb.IssueServiceAccountTokenResp{
		Token: issued.GetToken(), TokenId: issued.GetTokenId(), ExpiresAt: issued.GetExpiresAt(), Bearer: issued.GetBearer(),
	}, nil
}
