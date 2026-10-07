package handlers

import (
	"context"
	"errors"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// errAuthnBotNoPassword is the internal reason a machine account was refused a
// password sign-in. It never reaches the caller: SignIn wraps every refusal in
// the same opaque Unauthenticated, so an address cannot be probed to learn it
// belongs to a bot.
var errAuthnBotNoPassword = errors.New("machine account: password sign-in is not available")

// This file implements the `service_account` feature — MACHINE accounts.
//
// A bot is an ordinary user row with `kind = BOT`: same tables, same role
// grant (and org membership, where the realm has organizations), same token
// machinery. What differs is that it
// cannot sign in with a password and that an admin may mint a token FOR it —
// two halves of one property, and the reason both live here.
//
// ⚠️ Why a machine account is not just "a user whose password nobody knows".
// An API token's permissions are the INTERSECTION with its owner's, so a bot
// with one narrow role is a CEILING: a leaked token cannot outgrow the
// account, because the account cannot do more. For a human owner the same rule
// is only a limit — the token can still do anything that person can. That is
// what makes "CI holds a credential" safe to offer at all.
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

// The refusals when a realm with organizations is called with none selected.
var (
	errSelectOrgForToken = status.Error(codes.FailedPrecondition,
		"select an organization — a token is minted for a machine account inside one")
	errSelectOrgForBots = status.Error(codes.FailedPrecondition,
		"select an organization — machine accounts belong to one")
)

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

	// The target must be a bot IN THE CALLER'S ORGANIZATION, where the realm
	// has organizations. Both halves are load-bearing and the second was
	// missing: `user_id` arrives on the wire, so an operator in one company
	// could name a machine account in another and mint a working credential
	// for it. The listing that leaked those ids made that a two-step attack
	// with no barrier between the steps. A realm without organizations is one
	// organization, and every machine account in it is the operator's.
	orgs, err := botOrgScopeOrNil()
	if err != nil {
		return nil, err
	}
	if orgs != nil {
		inOrg, err := orgs.isMember(ctx, h, target)
		if err != nil {
			return nil, err
		}
		if !inOrg {
			// One message for "not a bot", "not here", and "does not exist":
			// the caller must not learn which, or the refusal becomes a
			// directory of other companies' accounts.
			return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
		}
	}

	// Read the target and refuse a person. Read FIRST: minting and then
	// checking would leave a live credential behind on the refusal path.
	userResp, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: target})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			// Does not exist reads like "not a bot" — see above.
			return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
		}
		return nil, err
	}
	if userResp.GetUser().GetKind() != pb.AccountKind_BOT || !visibleBot(ctx, userResp.GetUser()) {
		// The message names the RULE, not the account: a caller must not
		// learn from the refusal whether the id belongs to a person, a bot it
		// may not touch, or nothing at all.
		return nil, status.Error(codes.PermissionDenied, errNotABotAccount.Error())
	}

	// Not above the minting operator. A token acts with the bot's roles, so
	// minting for a bot whose role the operator could not have GRANTED is
	// handing out what they themselves may not do — the rule CreateBot holds
	// at creation, held here too, because the bot may have been created by
	// someone with more. (The token's subset only narrows the bot; it cannot
	// lift this.)
	if err := h.checkMayActAsBot(ctx, target); err != nil {
		return nil, err
	}

	// The token and its narrowing are ONE unit, and this is the sharpest
	// reason in this file for a transaction.
	//
	// Minted first and narrowed after, a failure partway leaves a LIVE token
	// with a partial subset — or with none, which the resolver reads as
	// `all_permissions` (applyTokenSubset only narrows when the subset is
	// non-empty). So a caller who asked for a narrow credential, and got an
	// error back, could be leaving behind a WIDER one than they asked for,
	// believing nothing happened (a consumer).
	//
	// Rolled back together, the failure means what the caller was told.
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
	token, tokenID, err := h.issueApiTokenTx(txCtx, target, req.GetName(), req.GetPermissionSubset(), expiresAt)
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
	return &pb.IssueBotTokenResp{Token: token, TokenId: tokenID, ExpiresAt: expiresAt}, nil
}

// botUserFillers complete a CreateBotUser request with what another feature's
// columns need. Appended, never assigned: each feature pair that adds a column
// to a machine account brings its own filler, and an assignment would let the
// last one staged erase the others. Empty unless such a pair is active —
// handlers/service_account_tenant.go is the one today.
var botUserFillers []func(ctx context.Context, req *pb.CreateBotUserReq) error

// botOrgs is what a realm WITH organizations adds to machine accounts: each
// belongs to one, is listed and served only there, and holds its role inside
// it. Installed by service_account_org.go, which is staged only when both
// `service_account` and `org_membership` are on (plugin.yaml,
// `go_files_combined`) — this file cannot name the membership calls itself,
// they do not exist without org_membership.
//
// Nil in a realm WITHOUT organizations — one organization, the owner of the
// software (Jiri, 2026-10-06: the platform's own backoffice). There a machine
// account is the realm's: created with a realm-wide grant, listed with every
// other machine account, and minted for by any operator who may mint at all.
var botOrgs *botOrgScope

// errBotOrgScopeMissing is the refusal when a build has organizations but not
// the code that scopes machine accounts to them — see orgMembershipStaged.
var errBotOrgScopeMissing = status.Error(codes.Internal,
	"machine accounts: this build has organizations but not their scoping (service_account_org.go) — refusing rather than serving every organization's machine accounts")

// botOrgScopeOrNil returns the org scope, nil for a realm without
// organizations — and refuses a build that has organizations but no scope.
func botOrgScopeOrNil() (*botOrgScope, error) {
	if botOrgs == nil && orgMembershipStaged {
		return nil, errBotOrgScopeMissing
	}
	return botOrgs, nil
}

// botVisible are the checks another feature adds to "may this caller see and
// mint for this machine account" — tenant_scope's tenant, today
// (service_account_tenant.go). Appended, never assigned, like botUserFillers.
// A machine account fails if ANY check says no.
var botVisible []func(ctx context.Context, bot *pb.User) bool

func visibleBot(ctx context.Context, bot *pb.User) bool {
	for _, ok := range botVisible {
		if !ok(ctx, bot) {
			return false
		}
	}
	return true
}

type botOrgScope struct {
	// active is the organization the caller acts in; an error when none is
	// selected, which every caller refuses.
	active func(ctx context.Context) (string, error)
	// enroll makes the new account a member of orgID and grants it roleID
	// there, inside the caller's transaction.
	enroll func(txCtx context.Context, h *AuthServiceHandler, userID, roleID, orgID string) error
	// accounts lists the members of the caller's organization.
	accounts func(ctx context.Context, h *AuthServiceHandler) ([]*pb.User, error)
	// isMember reports whether userID is a member of the caller's organization.
	isMember func(ctx context.Context, h *AuthServiceHandler, userID string) (bool, error)
}

// createBotUserTx creates the machine account and its grant — and, where the
// realm has organizations, its membership. Kept together so one transaction
// can hold them; this is about all of them or none.
func (h *AuthServiceHandler) createBotUserTx(txCtx context.Context, email, orgID, roleID string) (string, error) {
	req := &pb.CreateBotUserReq{Email: email}
	for _, fill := range botUserFillers {
		if err := fill(txCtx, req); err != nil {
			return "", err
		}
	}
	created, err := h.Mutation.CreateBotUser(txCtx, req)
	if err != nil {
		return "", err
	}
	userID := created.GetUser().GetId()
	orgs, err := botOrgScopeOrNil()
	if err != nil {
		return "", err
	}
	if orgs != nil {
		if err := orgs.enroll(txCtx, h, userID, roleID, orgID); err != nil {
			return "", err
		}
		return userID, nil
	}
	// A realm without organizations: the grant is realm-wide, which is where
	// every role of such a realm applies.
	if _, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{
		UserId: userID, RoleId: roleID,
	}); err != nil {
		return "", err
	}
	return userID, nil
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
	// Not above the operator. A bot is the sharpest place for this rule: its
	// token acts with the role's permissions, so a role above the operator's
	// own would be a credential for what they themselves may not do — an
	// administrator who may not push minting a machine that can.
	if _, err := h.checkMayGrantRole(ctx, req.GetRoleId()); err != nil {
		return nil, err
	}

	// Where the realm has organizations, the one the account joins comes from
	// the CALLER's active scope, never from the request. The client already
	// had to select one to get here, and taking an id off the wire would let
	// an operator provision a machine account into a company they are not
	// acting in.
	orgs, err := botOrgScopeOrNil()
	if err != nil {
		return nil, err
	}
	var orgID string
	if orgs != nil {
		var orgErr error
		if orgID, orgErr = orgs.active(ctx); orgErr != nil {
			return nil, status.Error(codes.FailedPrecondition,
				"select an organization before creating a machine account — its role is granted inside one")
		}
	}

	// The account, its membership (where there are organizations) and its
	// grant are ONE unit.
	//
	// Run apart, a failure after the first leaves an orphan bot: no
	// membership, so no organization to infer and an empty permission set —
	// and the address is now TAKEN by the unique index, so the operator's
	// retry fails on a conflict with an account they were told was never
	// created (a consumer). The comment below already explains why the order
	// matters; a transaction is what makes the order survive a failure.
	var tx *distx.TxHandle
	txCtx := ctx
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	userID, err := h.createBotUserTx(txCtx, req.GetEmail(), orgID, req.GetRoleId())
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
	return &pb.CreateBotResp{UserId: userID}, nil
}

func containsRole(roles []*pb.ApiRealmRole, id string) bool {
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
	// ⚠️ Where the realm has organizations, the caller's is REQUIRED, and the
	// reason is a leak that shipped: `User` is not an org-scoped model — a
	// person belongs to several — so scope does not narrow this list on its
	// own. Without the filter the answer was every machine account on the
	// console, and one company's operator saw another's (reported on
	// production 2026-09-21). A realm without organizations is one, and the
	// list is all of its machine accounts.
	orgs, err := botOrgScopeOrNil()
	if err != nil {
		return nil, err
	}
	var accounts []*pb.User
	if orgs != nil {
		members, err := orgs.accounts(ctx, h)
		if err != nil {
			return nil, err
		}
		accounts = members
	} else {
		resp, err := h.Query.ListRealmMachineAccounts(ctx, &pb.ListRealmMachineAccountsReq{})
		if err != nil {
			return nil, err
		}
		accounts = resp.GetAccounts()
	}
	out := make([]*pb.BotSummary, 0, len(accounts))
	for _, u := range accounts {
		// The kind is checked HERE for both sources: a membership is held by
		// people and machines alike.
		if u.GetKind() != pb.AccountKind_BOT || !visibleBot(ctx, u) {
			continue
		}
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
	// The same ceiling CreateBot enforces, so what is offered is accepted.
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*pb.BotRole, 0, len(resp.GetRoles()))
	for _, r := range resp.GetRoles() {
		if !grantable[r.GetId()] {
			continue
		}
		out = append(out, &pb.BotRole{Id: r.GetId(), Name: r.GetName(), Description: r.GetDescription()})
	}
	return &pb.ListBotRolesResp{Roles: out}, nil
}

// errBotAboveCaller is the refusal for minting for a machine account that holds
// a role the operator could not grant. Named like the CreateBot refusal: the
// rule, not the bot's contents.
var errBotAboveCaller = errors.New("that machine account holds a role carrying permissions you do not hold — a token for it would act beyond your own")

// checkMayActAsBot refuses when the bot holds any role above the caller's
// ceiling (grantableRoleIDs, the one answer CreateBot also reads).
func (h *AuthServiceHandler) checkMayActAsBot(ctx context.Context, botID string) error {
	grants, err := h.Query.GetUserRoleGrants(ctx, &pb.GetUserRoleGrantsReq{UserId: botID})
	if err != nil {
		return err
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return err
	}
	for _, g := range grants.GetGrants() {
		if !grantable[g.GetRoleId()] {
			return refusal(ctx, codes.PermissionDenied, errBotAboveCaller.Error(),
				CodeRoleAboveCaller, "user_id", MsgBotAboveCaller, nil)
		}
	}
	return nil
}
