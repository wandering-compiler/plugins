package handlers

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `admin_accounts` feature: an operator acting
// REALM-WIDE from the admin creates any account — a person's here, a machine
// account's in admin_accounts_bot.go — in whichever organization the request
// names, the way the backoffice invites into one (InviteToOrgAdmin).
//
// A person's account is created with NO usable password ('!', as a machine
// account's). Its owner sets one through a one-time setup link the admin shows
// once (SetUpAccount); until then nobody signs in to it, the operator
// included. The operator holds that link for a moment, which is no more than
// an operator who may create the account could do anyway; a link for an
// account above the operator's own ceiling is refused, so the link is never a
// way into an account the operator could not have created.
//
// Realm-wide, these are methods of their own and not modes of the member ones,
// for the reason the backoffice's invitation is: a project's default role
// commonly grants AuthService.* to every account. They serve only under the
// endpoint ACL, and from inside an organization only for a caller holding the
// method realm-wide (adminAccountsGate).

// The organizations a realm with them adds: installed by
// admin_accounts_org.go, staged only with org_membership. Nil in a realm
// without organizations, where every account and role is the realm's.
var adminAccountOrgs *adminAccountOrgScope

type adminAccountOrgScope struct {
	// refuseInsideOrg refuses a call made from inside an organization by a
	// caller who does not hold method realm-wide.
	refuseInsideOrg func(ctx context.Context, h *AuthServiceHandler, method string) error
	// bySlug is the live organization named by slug.
	bySlug func(ctx context.Context, h *AuthServiceHandler, method, slug string) (string, error)
	// roleID is the session-realm role named name, assignable in orgID.
	roleID func(ctx context.Context, h *AuthServiceHandler, orgID, name string) (string, error)
	// lock takes orgID's lock in txCtx and marks it (as withOrgLock does).
	lock func(h *AuthServiceHandler, txCtx context.Context, orgID string) (context.Context, error)
	// enroll makes userID a member of orgID under the role, in txCtx.
	enroll func(txCtx context.Context, h *AuthServiceHandler, userID, orgID, roleName, roleID string) error
	// orgOf is the organization an account belongs to ("" for none).
	orgOf func(ctx context.Context, h *AuthServiceHandler, userID string) (string, error)
}

// The setup link's refusals.
const (
	// CodeAccountSetupInvalid: the link is spent, superseded, lapsed or not
	// one at all — one answer, so the page cannot be used to probe which.
	CodeAccountSetupInvalid = "ACCOUNT_SETUP_INVALID"
	// CodeAccountAlreadySetUp: a link was asked for an account that has a
	// password.
	CodeAccountAlreadySetUp = "ACCOUNT_ALREADY_SET_UP"
)

// MsgAccountSetupInvalid is what a person reads for a link that no longer
// works.
//
//w17:msgid
const MsgAccountSetupInvalid = "This setup link no longer works. Ask the person who created your account for a new one."

// MsgAccountAlreadySetUp is what an operator reads asking a link for an
// account whose owner has set a password.
//
//w17:msgid
const MsgAccountAlreadySetUp = "This account already has a password, so it needs no setup link."

// MsgAccountAboveCaller is what an operator reads for an account holding a
// role with permissions the operator does not have.
//
//w17:msgid
const MsgAccountAboveCaller = "This account holds a role with permissions you do not have, so you cannot issue its setup link."

// defaultAccountSetupTTLHours is account_setup_ttl_hours' default: 3 days.
const defaultAccountSetupTTLHours = 72

func (h *AuthServiceHandler) accountSetupTTL() time.Duration {
	if h.AccountSetupTTLHours > 0 {
		return time.Duration(h.AccountSetupTTLHours) * time.Hour
	}
	return defaultAccountSetupTTLHours * time.Hour
}

// accountSetupLink is account_setup_url with the token in it; "" when the
// deployment configures none.
func (h *AuthServiceHandler) accountSetupLink(token string) string {
	if h.AccountSetupURL == "" {
		return ""
	}
	return strings.ReplaceAll(h.AccountSetupURL, "{token}", token)
}

// adminAccountsGate is every admin_accounts method's gate, the one the
// backoffice's invitation has: only under the endpoint ACL (a method nothing
// binds says nobody may call it, so nobody does), and from inside an
// organization only for a caller holding it realm-wide.
func (h *AuthServiceHandler) adminAccountsGate(ctx context.Context, method string) error {
	if adminAccountOrgs != nil {
		if err := adminAccountOrgs.refuseInsideOrg(ctx, h, method); err != nil {
			return err
		}
	}
	if !lockGatesCall(ctx, h.Lock, pb.AuthService_ServiceDesc.ServiceName, method) {
		return status.Error(codes.PermissionDenied, "admin_accounts: "+method+" needs the endpoint ACL — it is not in the lock")
	}
	return nil
}

// adminAccountOrg is the organization a realm-wide account method acts in:
// the one req names by slug where the realm has organizations (required), ""
// where it has none (and naming one is refused — there is nothing to name).
func (h *AuthServiceHandler) adminAccountOrg(ctx context.Context, method, slug string) (string, error) {
	if adminAccountOrgs == nil {
		if orgMembershipStaged {
			return "", status.Error(codes.Internal, "admin_accounts: this build has organizations but not their scoping (admin_accounts_org.go)")
		}
		if slug != "" {
			return "", status.Errorf(codes.InvalidArgument, "%s: this realm has no organizations — leave org empty", method)
		}
		return "", nil
	}
	return adminAccountOrgs.bySlug(ctx, h, method, slug)
}

// CreateAccount creates a person's account realm-wide, with its role and —
// where the realm has organizations — its membership, and answers its setup
// link, shown once.
func (h *AuthServiceHandler) CreateAccount(ctx context.Context, req *pb.CreateAccountReq) (*pb.CreateAccountResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	// A signed-in person, as every method minting a credential for someone
	// else requires: an API token must not create accounts.
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if err := h.adminAccountsGate(ctx, "CreateAccount"); err != nil {
		return nil, err
	}
	email := normalizeEmail(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if err := refuseReservedEmail(ctx, email); err != nil {
		return nil, err
	}
	if req.GetRole() == "" {
		return nil, status.Error(codes.InvalidArgument, "role is required — an account with no role can do nothing")
	}
	orgID, err := h.adminAccountOrg(ctx, "CreateAccount", req.GetOrg())
	if err != nil {
		return nil, err
	}
	roleID, err := h.adminAccountRoleID(ctx, orgID, req.GetRole())
	if err != nil {
		return nil, err
	}
	// Not above the operator: the account acts with the role, and the
	// operator holds its setup link for a moment.
	if _, err := h.checkMayGrantRole(ctx, roleID); err != nil {
		return nil, err
	}
	token, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(time.Now().Add(h.accountSetupTTL()))

	// The account, its membership, its grant and its link are ONE unit: a
	// failure part-way must not leave an address taken by an account nobody
	// can set up.
	var userID string
	err = h.inTx(ctx, func(txCtx context.Context) error {
		if orgID != "" {
			// The ceiling again under the organization's lock: a change of the
			// role at the same moment comes before or after the grant.
			if txCtx, err = adminAccountOrgs.lock(h, txCtx, orgID); err != nil {
				return err
			}
			if _, err := h.checkMayGrantRole(txCtx, roleID); err != nil {
				return err
			}
		}
		created, err := h.Mutation.CreateAdminUser(txCtx, &pb.CreateAdminUserReq{
			Email: email, CreatedBy: operator, Thumbprint: requestThumbprint(txCtx),
		})
		if err != nil {
			return err
		}
		userID = created.GetUser().GetId()
		if orgID != "" {
			if err := adminAccountOrgs.enroll(txCtx, h, userID, orgID, req.GetRole(), roleID); err != nil {
				return err
			}
		} else if _, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{UserId: userID, RoleId: roleID}); err != nil {
			return err
		}
		_, err = h.Mutation.CreateAccountSetup(txCtx, &pb.CreateAccountSetupReq{
			UserId: userID, TokenHash: sha256Hex(token), ExpiresAt: expiresAt, CreatedBy: operator,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &pb.CreateAccountResp{UserId: userID, SetupToken: token, SetupLink: h.accountSetupLink(token), ExpiresAt: expiresAt}, nil
}

// adminAccountRoleID is the session-realm role a person's account is given:
// in orgID where the realm has organizations (as an invitation's role), from
// the realm's catalogue where it has none.
func (h *AuthServiceHandler) adminAccountRoleID(ctx context.Context, orgID, name string) (string, error) {
	if orgID != "" {
		return adminAccountOrgs.roleID(ctx, h, orgID, name)
	}
	roles, err := h.Query.ListRoles(ctx, &pb.ListRolesReq{})
	if err != nil {
		return "", err
	}
	for _, r := range roles.GetRoles() {
		if r.GetName() != name {
			continue
		}
		if isAPIRealmRow(r) {
			return "", status.Errorf(codes.InvalidArgument,
				"role %s belongs to the API realm (a machine account's); a person's account carries a session-realm role", name)
		}
		return r.GetId(), nil
	}
	return "", status.Errorf(codes.InvalidArgument, "no role by that name: %s", name)
}

// IssueAccountSetupLink issues a new setup link for an account an operator
// created whose owner has not set a password, ending its earlier links.
func (h *AuthServiceHandler) IssueAccountSetupLink(ctx context.Context, req *pb.IssueAccountSetupLinkReq) (*pb.IssueAccountSetupLinkResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	if err := h.adminAccountsGate(ctx, "IssueAccountSetupLink"); err != nil {
		return nil, err
	}
	if len(req.GetIds()) != 1 || req.GetIds()[0] == "" {
		return nil, status.Error(codes.InvalidArgument, "ids: name exactly one account")
	}
	userID := req.GetIds()[0]
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	user := got.GetUser()
	if isBotAccount(user) {
		return nil, status.Error(codes.FailedPrecondition, "a machine account has no password to set up — issue it a token")
	}
	if user.GetErasedAt() != nil || user.GetDisabledAt() != nil {
		return nil, status.Error(codes.FailedPrecondition, "the account is disabled; enable it first")
	}
	if user.GetPasswordHash() != "!" {
		return nil, refusal(ctx, codes.FailedPrecondition, "the account already has a password",
			CodeAccountAlreadySetUp, "ids", MsgAccountAlreadySetUp, nil)
	}
	// Not an account above the operator: whoever holds the link can set the
	// password, so issuing it is acting as the account.
	if err := h.checkMayActAsAccount(ctx, userID); err != nil {
		return nil, err
	}
	token, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(time.Now().Add(h.accountSetupTTL()))
	err = h.inTx(ctx, func(txCtx context.Context) error {
		// One link works at a time. No row: the account had none live.
		if _, err := h.Mutation.SupersedeAccountSetups(txCtx, &pb.SupersedeAccountSetupsReq{UserId: userID}); err != nil && status.Code(err) != codes.NotFound {
			return err
		}
		_, err := h.Mutation.CreateAccountSetup(txCtx, &pb.CreateAccountSetupReq{
			UserId: userID, TokenHash: sha256Hex(token), ExpiresAt: expiresAt, CreatedBy: operator,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &pb.IssueAccountSetupLinkResp{SetupToken: token, SetupLink: h.accountSetupLink(token), ExpiresAt: expiresAt}, nil
}

// checkMayActAsAccount refuses when the account holds any role above the
// caller's ceiling (grantableRoleIDs, the answer CreateAccount reads).
func (h *AuthServiceHandler) checkMayActAsAccount(ctx context.Context, userID string) error {
	grants, err := h.Query.GetUserRoleGrants(ctx, &pb.GetUserRoleGrantsReq{UserId: userID})
	if err != nil {
		return err
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return err
	}
	for _, g := range grants.GetGrants() {
		if !grantable[g.GetRoleId()] {
			return refusal(ctx, codes.PermissionDenied, "the account holds a role above the caller's",
				CodeRoleAboveCaller, "ids", MsgAccountAboveCaller, nil)
		}
	}
	return nil
}

// SetUpAccount sets the first password of an account an operator created,
// with its setup link's token.
func (h *AuthServiceHandler) SetUpAccount(ctx context.Context, req *pb.SetUpAccountReq) (*pb.SetUpAccountResp, error) {
	invalid := func() error {
		return refusal(ctx, codes.InvalidArgument, "the setup link is spent, superseded, lapsed or unknown",
			CodeAccountSetupInvalid, "token", MsgAccountSetupInvalid, nil)
	}
	if req.GetToken() == "" {
		return nil, invalid()
	}
	// The sign-up's rules for the password, before anything is spent: a
	// refused password leaves the link usable.
	hashed, err := h.PasswordHash.Hash(req.GetPassword())
	if err != nil {
		return nil, hashPasswordErr(ctx, err, "password")
	}
	var email string
	err = h.inTx(ctx, func(txCtx context.Context) error {
		// Spent by the statement that finds it: two requests with one link
		// cannot both set a password.
		spent, err := h.Mutation.ConsumeAccountSetup(txCtx, &pb.ConsumeAccountSetupReq{TokenHash: sha256Hex(req.GetToken())})
		if status.Code(err) == codes.NotFound {
			return invalid()
		}
		if err != nil {
			return err
		}
		got, err := h.Query.GetUserById(txCtx, &pb.GetUserByIdReq{UserId: spent.GetUserId()})
		if err != nil {
			return err
		}
		// A disabled account gets no password through its link either.
		if got.GetUser().GetDisabledAt() != nil {
			return invalid()
		}
		// Only while it has none, and never an erased account's.
		if _, err := h.Mutation.SetUpAccountPassword(txCtx, &pb.SetUpAccountPasswordReq{
			UserId: spent.GetUserId(), PasswordHash: hashed, Thumbprint: requestThumbprint(txCtx),
		}); status.Code(err) == codes.NotFound {
			return invalid()
		} else if err != nil {
			return err
		}
		email = got.GetUser().GetEmail()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.SetUpAccountResp{Email: email}, nil
}
