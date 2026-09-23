package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// errAuthnBotNoPassword is the internal reason a machine account was refused a
// password sign-in. It never reaches the caller: SignIn wraps every refusal in
// the same opaque Unauthenticated, so an address cannot be probed to learn it
// belongs to a bot.
var errAuthnBotNoPassword = errors.New("machine account: password sign-in is not available")

// This file implements the `service_account` feature — MACHINE accounts.
//
// A bot is an ordinary user row with `kind = BOT`: same tables, same org
// membership, same role grant, same token machinery. What differs is that it
// cannot sign in with a password and that an admin may mint a token FOR it —
// two halves of one property, and the reason both live here.
//
// ⚠️ Why a machine account is not just "a user whose password nobody knows".
// An API token's permissions are the INTERSECTION with its owner's, so a bot
// with one narrow role is a CEILING: a leaked token cannot outgrow the
// account, because the account cannot do more. For a human owner the same rule
// is only a limit — the token can still do anything that person can. That is
// what makes "CI holds a credential" safe to offer at all
// (docs/todos/api-tokens-for-unattended-callers.md).
//
// Staged ONLY when the activation enables `service_account` (plugin.yaml maps
// the feature to this file). With the feature off it is not staged, the
// sign-in bot gate keeps its no-op default, and `User.kind` is not emitted —
// which is why the always-compiled handlers reach it through the seam below
// and never name the field.
func init() {
	signInBotGate = func(user *pb.User) error {
		if user.GetKind() == pb.AccountKind_BOT {
			return errAuthnBotNoPassword
		}
		return nil
	}
}

// errNotABotAccount is the refusal for minting a token against a person.
var errNotABotAccount = errors.New("api tokens may only be minted for machine accounts")

// IssueBotToken mints an API token FOR another account, and only for a machine
// one.
//
// ⚠️ THE TARGET CHECK IS THE FEATURE. Everything else here is CreateApiToken
// with a different owner — and that difference is exactly what makes this the
// only endpoint in the plugin that hands out a credential for somebody else.
// Without the check it is a primitive for acting as any user, which no amount
// of UI filtering would take back: a dropdown that offers only bots is not a
// control, it is a default.
//
// Refused with PermissionDenied rather than InvalidArgument: the caller may
// name a real account and still not be allowed to mint for it, which is an
// authorisation answer, not a malformed request.
func (h *AuthServiceHandler) IssueBotToken(ctx context.Context, req *pb.IssueBotTokenReq) (*pb.IssueBotTokenResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	target := req.GetUserId()
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// The target must be a bot IN THE CALLER'S ORGANIZATION. Both halves are
	// load-bearing and the second was missing: `user_id` arrives on the wire,
	// so an operator in one company could name a machine account in another
	// and mint a working credential for it. The listing that leaked those ids
	// made that a two-step attack with no barrier between the steps.
	orgID, orgErr := activeOrgID(ctx)
	if orgErr != nil {
		return nil, status.Error(codes.FailedPrecondition,
			"select an organization — a token is minted for a machine account inside one")
	}
	inOrg, err := h.Query.GetBotInOrg(ctx, &pb.GetBotInOrgReq{UserId: target, OrgId: orgID})
	if err != nil {
		return nil, err
	}
	if inOrg.GetUserId() == "" {
		// One message for "not a bot", "not here", and "does not exist": the
		// caller must not learn which, or the refusal becomes a directory of
		// other companies' accounts.
		return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
	}

	// Read the target and refuse a person. Read FIRST: minting and then
	// checking would leave a live credential behind on the refusal path.
	userResp, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: target})
	if err != nil {
		return nil, err
	}
	if userResp.GetUser().GetKind() != pb.AccountKind_BOT {
		// The message names the RULE, not the account: a caller must not
		// learn from the refusal whether the id belongs to a person, a bot it
		// may not touch, or nothing at all.
		return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
	}

	issued, err := h.Mutation.IssueApiToken(ctx, &pb.IssueApiTokenReq{
		UserId:    target,
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
	return &pb.IssueBotTokenResp{Token: issued.GetToken().GetToken(), TokenId: tokenID}, nil
}

// init installs the decorator that BROADCASTS what kind of account is
// calling, so authorization rules outside this plugin can act on it.
func init() {
	scopeDecorators = append(scopeDecorators, labelMachineAccount)
}

// AccountKindLabel is the label a BOT principal carries. A project reads it
// through the ordinary `w17-label-<name>` plumbing, so a hand-written
// business rule can say "machines only" without querying this plugin.
const AccountKindLabel = "account_kind"

// AccountKindBot is the only value ever stamped.
//
// Only bots are labelled, and that asymmetry is the safety property: a rule
// written as "refuse unless the label says bot" fails CLOSED. If this
// decorator stops running, or the label is dropped somewhere on the way, the
// answer becomes "not a bot" and the guarded endpoint refuses — rather than
// waving through every caller because a string went missing.
const AccountKindBot = "bot"

// labelMachineAccount stamps the calling principal's account kind.
//
// A lookup failure is NOT fatal: it leaves the label unset, which denies. The
// alternative — failing Authenticate — would take the whole console down on a
// single unreadable row, and the conservative answer is already available.
func labelMachineAccount(ctx context.Context, h *AuthServiceHandler, userID string, _, _, labels map[string]string) error {
	resp, err := h.Query.GetUser(ctx, &pb.GetUserReq{UserId: userID})
	if err != nil {
		return nil
	}
	if resp.GetKind() == pb.AccountKind_BOT {
		labels[AccountKindLabel] = AccountKindBot
	}
	return nil
}

// errRoleNotForBots is the refusal when an operator names a role a machine
// account cannot usefully hold.
var errRoleNotForBots = errors.New("that role belongs to the session realm — a machine account cannot use it")

// CreateBot provisions a machine account and grants it its role in ONE call.
//
// The role is not optional and not a second step. A bot with no role can hold
// a token that resolves to nothing, and the operator discovers that when CI
// fails rather than here — so the endpoint that creates the account is the one
// that gives it its rights.
//
// The role is re-checked against the API realm SERVER-side. ListBotRoles
// already offers only those, but an endpoint that trusts the list its own UI
// rendered is trusting the caller: this one takes a role id from the wire.
func (h *AuthServiceHandler) CreateBot(ctx context.Context, req *pb.CreateBotReq) (*pb.CreateBotResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetRoleId() == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required — a bot with no role holds a token that does nothing")
	}

	allowed, err := h.Query.ListApiRealmRoles(ctx, &pb.ListApiRealmRolesReq{})
	if err != nil {
		return nil, err
	}
	if !containsRole(allowed.GetRoles(), req.GetRoleId()) {
		return nil, status.Error(codes.InvalidArgument, errRoleNotForBots.Error())
	}

	// The organization comes from the CALLER's active scope, never from the
	// request. The client already had to select one to get here, and taking an
	// id off the wire would let an operator provision a machine account into a
	// company they are not acting in.
	orgID, orgErr := activeOrgID(ctx)
	if orgErr != nil {
		return nil, status.Error(codes.FailedPrecondition,
			"select an organization before creating a machine account — its role is granted inside one")
	}

	created, err := h.Mutation.CreateBotUser(ctx, &pb.CreateBotUserReq{Email: req.GetEmail()})
	if err != nil {
		return nil, err
	}
	userID := created.GetUser().GetId()

	// MEMBERSHIP FIRST, and it is not decoration.
	//
	// An org-scoped role granted with no organization lands as `org_id NULL`,
	// which the org axis counts only for roles declared realm-wide — so the
	// grant applies NOWHERE and the bot authenticates with an empty permission
	// set. And without a membership there is no organization for the console to
	// infer, so an unattended caller with no `W17-Org` header has no scope
	// either. Both were live: a token minted through the UI pushed nothing and
	// reported "no permissions resolved for this principal" (2026-09-20).
	if _, err := h.Mutation.AddOrgMembership(ctx, &pb.AddOrgMembershipReq{
		UserId: userID,
		OrgId:  orgID,
		Role:   "member",
	}); err != nil {
		return nil, err
	}

	// Granted INSIDE that organization, for the same reason.
	if _, err := h.Mutation.AssignRoleToUser(ctx, &pb.AssignRoleToUserReq{
		UserId: userID,
		RoleId: req.GetRoleId(),
		OrgId:  orgID,
	}); err != nil {
		return nil, err
	}
	return &pb.CreateBotResp{UserId: userID}, nil
}

func containsRole(roles []*pb.OrgScopedRole, id string) bool {
	for _, r := range roles {
		if r.GetId() == id {
			return true
		}
	}
	return false
}

// ListBots returns the machine accounts for an operator's directory.
func (h *AuthServiceHandler) ListBots(ctx context.Context, _ *pb.ListBotsReq) (*pb.ListBotsResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	// ⚠️ The organization is REQUIRED, and the reason is a leak that shipped:
	// `User` is not an org-scoped model — a person belongs to several — so
	// scope does not narrow this list on its own. Without the filter the
	// answer was every machine account on the console, and one company's
	// operator saw another's (reported on production 2026-09-21).
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition,
			"select an organization — machine accounts belong to one")
	}
	resp, err := h.Query.ListBotUsers(ctx, &pb.ListBotUsersReq{OrgId: orgID})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.BotSummary, 0, len(resp.GetBots()))
	for _, u := range resp.GetBots() {
		out = append(out, &pb.BotSummary{
			Id:       u.GetId(),
			Email:    u.GetEmail(),
			Disabled: u.GetDisabledAt() != nil,
		})
	}
	return &pb.ListBotsResp{Bots: out}, nil
}

// ListBotRoles returns the roles a machine account may hold — API-realm only.
func (h *AuthServiceHandler) ListBotRoles(ctx context.Context, _ *pb.ListBotRolesReq) (*pb.ListBotRolesResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	resp, err := h.Query.ListApiRealmRoles(ctx, &pb.ListApiRealmRolesReq{})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.BotRole, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		out = append(out, &pb.BotRole{Id: r.GetId(), Name: r.GetName(), Description: r.GetDescription()})
	}
	return &pb.ListBotRolesResp{Roles: out}, nil
}
