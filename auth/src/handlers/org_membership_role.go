package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
)

// Changing or removing a member, and the role catalogue every org-role grant
// reads.
//
// Staged with `org_membership`: the role lookup used to live in org_invite.go,
// staged only with `org_invite`, while changing a membership's role — an
// org_membership operation — is a grant just as much as an invitation is.
//
// The role ceiling holds BOTH ways here. A role change and a removal each
// revoke every role the member holds in the organization, so the caller must
// cover those (whoever could only hand out org-viewer must not be able to strip
// an org-admin), and a role change grants one, so the caller must cover that
// too. Covering is the one test the ceiling already has: hold every permission
// the role carries.

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// by `make plugin-msgids-sync` (see errors.go).
//
//w17:msgid
const (
	MsgUnknownOrgRole       = "There is no organization role named {role}."
	MsgRoleNotOrgScoped     = "{role} is a realm-wide role. An organization membership can only carry an organization-scoped role."
	MsgMembershipInOtherOrg = "This membership belongs to another organization."
	MsgMemberAboveCaller    = "This member holds a role with permissions you do not have, so you cannot change or remove their membership."
	MsgLastSuperadmin       = "This is the organization's last superadmin. Make someone else a superadmin first."
	MsgRoleIsForBots        = "{role} is a role for machine accounts. A person's membership carries a person's role."
)

// The codes a client branches on for the same refusals.
const (
	CodeUnknownOrgRole       = "UNKNOWN_ORG_ROLE"
	CodeRoleNotOrgScoped     = "ROLE_NOT_ORG_SCOPED"
	CodeMembershipInOtherOrg = "MEMBERSHIP_IN_ANOTHER_ORG"
	CodeMemberAboveCaller    = "MEMBER_ABOVE_CALLER"
	CodeLastSuperadmin       = "LAST_SUPERADMIN"
	CodeRoleIsForBots        = "ROLE_IS_FOR_BOTS"
)

// UpdateOrgMembershipRole changes a member's role, under the role ceiling.
//
// The admin's OrgMemberships page edits through this, not through
// AuthMutation.UpdateOrgMembership directly. That mutation moves the member's
// org grant to the role it names, and as a storage method it can check
// nothing about the CALLER — so whoever could edit a membership could hand
// anyone, themselves included, any org role, org-admin among them. An
// invitation and a bot were already held to the ceiling; this was the one
// grant path that was not.
//
// The mutation still does the work — its row lock, the grant it revokes and
// writes, the OrgMembershipUpdated event — so the rule sits in front of it
// rather than beside it. It is handed the role by ID, the role checked here:
// a lookup by name there would let a rename between the two grant another.
func (h *AuthServiceHandler) UpdateOrgMembershipRole(ctx context.Context, req *pb.UpdateOrgMembershipRoleReq) (*pb.UpdateOrgMembershipRoleResp, error) {
	if resp, done, err := underOrgLock(ctx, h, h.membershipOrg(ctx, req.GetId()), req, h.UpdateOrgMembershipRole); done {
		return resp, err
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	m, err := h.checkMayManageMembership(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	roleID, err := h.roleIDByName(ctx, m.GetOrgId(), req.GetRole())
	if err != nil {
		return nil, err
	}
	// The caller is recorded as revoked_by on the grants the change replaces
	// (they stay, revoked). No caller id (a direct call) leaves it NULL.
	callerID, _ := callerUserID(ctx)
	var membershipID string
	err = h.guardSuperadmins(ctx, m.GetOrgId(), func(txCtx context.Context) error {
		if err := h.refuseLastSuperadmin(txCtx, m, roleID); err != nil {
			return err
		}
		// The snapshot is for a grant written LATER (an invitation's
		// acceptance); this one is written now, by the call below.
		_, err := h.checkMayGrantRole(txCtx, roleID)
		return err
	}, func(txCtx context.Context) error {
		resp, err := h.Mutation.UpdateOrgMembership(txCtx, &pb.UpdateOrgMembershipReq{Id: req.GetId(), RoleId: roleID, ChangedBy: callerID})
		if err != nil {
			return err
		}
		membershipID = resp.GetMembershipId()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.UpdateOrgMembershipRoleResp{MembershipId: membershipID}, nil
}

// RemoveOrgMembership removes a member, under the role ceiling: the removal
// revokes every role they hold in the organization, so the caller must cover
// them. AuthMutation.MarkOrgMembershipRemoved does the work: the membership
// and its grants end (removed_at / revoked_at, the caller recorded as the one
// who removed them) and the rows stay.
func (h *AuthServiceHandler) RemoveOrgMembership(ctx context.Context, req *pb.RemoveOrgMembershipReq) (*pb.RemoveOrgMembershipResp, error) {
	if resp, done, err := underOrgLock(ctx, h, h.membershipOrg(ctx, req.GetId()), req, h.RemoveOrgMembership); done {
		return resp, err
	}
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	m, err := h.checkMayManageMembership(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	callerID, _ := callerUserID(ctx)
	var membershipID string
	err = h.guardSuperadmins(ctx, m.GetOrgId(), func(txCtx context.Context) error {
		return h.refuseLastSuperadmin(txCtx, m, "")
	}, func(txCtx context.Context) error {
		resp, err := h.Mutation.MarkOrgMembershipRemoved(txCtx, &pb.MarkOrgMembershipRemovedReq{Id: req.GetId(), RemovedBy: callerID})
		if err != nil {
			return err
		}
		membershipID = resp.GetMembershipId()
		for _, cascade := range membershipRemovalCascades {
			if err := cascade(txCtx, h, m.GetUserId(), m.GetOrgId(), callerID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.RemoveOrgMembershipResp{MembershipId: membershipID}, nil
}

// membershipRemovalCascades are what other features end with one person's
// membership, run by RemoveOrgMembership in its transaction after the
// membership and its grants ended: teams ends their team memberships in the
// organization. userID / orgID are the membership's, by the account removing
// it (empty: nobody named).
var membershipRemovalCascades []func(ctx context.Context, h *AuthServiceHandler, userID, orgID, by string) error

// memberHeldRoleSources are the roles a member holds in an organization through
// another feature, which removing them takes away as surely as their own
// grants: teams answers their teams' roles. checkMayManageMembership asks the
// caller to cover them too.
var memberHeldRoleSources []func(ctx context.Context, h *AuthServiceHandler, userID, orgID string) ([]string, error)

// superadminSources are the organization's superadmins through another
// feature — teams answers the wildcard roles its members hold through a team
// — read with ListOrgSuperadmins' direct grants by orgSuperadmins, the one
// definition of who keeps an organization administered.
var superadminSources []func(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.OrgSuperadminRow, error)

// roleHolderCounters count who else holds a role through another feature — a
// team (teams) — for a role that may not be deleted while anyone holds it
// (DeleteOrgRole).
var roleHolderCounters []func(ctx context.Context, h *AuthServiceHandler, roleID string) (int64, error)

// orgRemovalCascades are what other features end with an organization, run by
// RemoveOrganization BEFORE the organization itself is deleted and in its
// transaction: org_invite appends the closing of its pending invitations,
// which AuthMutation.DeleteOrganization cannot do — a statement cannot name a
// table its activation may not have. orgID is the organization, by the
// account deleting it.
var orgRemovalCascades []func(ctx context.Context, h *AuthServiceHandler, orgID, by string) error

// RemoveOrganization deletes an organization — the admin Organizations page's
// delete. Nothing is deleted: the cascades end what other features hold for
// it (its pending invitations), then AuthMutation.DeleteOrganization removes
// its memberships, revokes its org grants and stamps it deleted_at. One
// transaction with a coordinator. Without one the cascades run first, so a
// failure leaves the organization live and a retry completes it; the cascades
// are idempotent UPDATEs. The organization's row is locked first
// (withOrgLock), as every change to who holds what in it locks it: the
// cascades and DeleteOrganization lock team and membership rows before the
// organization's, and taking them in the other order than a concurrent member
// removal would deadlock the two.
func (h *AuthServiceHandler) RemoveOrganization(ctx context.Context, req *pb.RemoveOrganizationReq) (*pb.RemoveOrganizationResp, error) {
	callerID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	var orgID string
	err = h.withOrgLock(ctx, req.GetId(), func(txCtx context.Context) error {
		for _, cascade := range orgRemovalCascades {
			if err := cascade(txCtx, h, req.GetId(), callerID); err != nil {
				return err
			}
		}
		resp, err := h.Mutation.DeleteOrganization(txCtx, &pb.DeleteOrganizationReq{Id: req.GetId()})
		if err != nil {
			return err
		}
		orgID = resp.GetOrgId()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &pb.RemoveOrganizationResp{OrgId: orgID}, nil
}

// inOrgTx runs fn in one distributed transaction when the bundle has a
// coordinator, plainly otherwise.
func (h *AuthServiceHandler) inOrgTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	if h.DistTx == nil {
		return fn(ctx)
	}
	tx, txCtx, err := distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection})
	if err != nil {
		return err
	}
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// orgLockKey marks a context whose transaction already holds an
// organization's row lock (withOrgLock); its value is the organization.
type orgLockKey struct{}

// withOrgLock runs fn — the whole of a change to who holds what in
// organization orgID, its checks and its writes — in one transaction that
// first locks the organization's row (LockOrganization, SELECT … FOR UPDATE).
//
// Every such change takes the same lock first, so two of them in one
// organization run one after the other, and the second one's checks read what
// the first one wrote. Checked before the write's transaction, two of them
// judged the same state: two superadmins demoting each other at the same
// moment both passed the last-superadmin rule, each still seeing the other;
// a caller removed a member someone was promoting above them at that moment,
// passing a ceiling read off the member's roles as they were; a role was
// granted as it carried less than an edit was giving it.
//
// A context already under orgID's lock runs fn on it — a method composed into
// another one's change takes no second lock. An organization the lock finds no
// live row for (unknown, deleted) has nothing to serialise: fn runs in the
// same transaction and answers with its own refusal. Without a coordinator (no
// DistTx) every statement commits on its own, the lock is held for none of
// them, and only the order is kept.
func (h *AuthServiceHandler) withOrgLock(ctx context.Context, orgID string, fn func(txCtx context.Context) error) error {
	if held, _ := ctx.Value(orgLockKey{}).(string); held != "" && held == orgID {
		return fn(ctx)
	}
	return h.inOrgTx(ctx, func(txCtx context.Context) error {
		if err := h.lockOrgRow(txCtx, orgID); err != nil {
			return err
		}
		return fn(context.WithValue(txCtx, orgLockKey{}, orgID))
	})
}

// lockOrgRow takes organization orgID's row lock (LockOrganization) in the
// transaction txCtx runs in — the one statement withOrgLock, an open
// registration's join and a machine account's transaction share. An
// organization with no live row has nothing to serialise. Without a
// coordinator (no DistTx) there is no transaction to hold the lock, and the
// statement is not sent.
func (h *AuthServiceHandler) lockOrgRow(txCtx context.Context, orgID string) error {
	if h.DistTx == nil {
		return nil
	}
	if _, err := h.Query.LockOrganization(txCtx, &pb.LockOrganizationReq{OrgId: orgID}); err != nil && status.Code(err) != codes.NotFound {
		return err
	}
	return nil
}

// underOrgLock is withOrgLock for a whole method: when ctx is not under
// orgID's lock yet, it runs m(req) again inside it and reports done, and the
// method returns what that run returned; under the lock (or with no
// organization to lock) it reports not done and the method goes on.
//
//	if resp, done, err := underOrgLock(ctx, h, orgID, req, h.Method); done {
//		return resp, err
//	}
func underOrgLock[Req, Resp any](ctx context.Context, h *AuthServiceHandler, orgID string, req Req, m func(context.Context, Req) (Resp, error)) (resp Resp, done bool, err error) {
	if orgID == "" {
		return resp, false, nil
	}
	if held, _ := ctx.Value(orgLockKey{}).(string); held == orgID {
		return resp, false, nil
	}
	err = h.withOrgLock(ctx, orgID, func(txCtx context.Context) error {
		var mErr error
		resp, mErr = m(txCtx, req)
		return mErr
	})
	return resp, true, err
}

func init() { heldNow = heldUnderOrgLock }

// heldUnderOrgLock is heldNow: under an organization's lock, the caller's
// resolved permissions held keep only those a grant of theirs still carries,
// read now — the grants the organization narrowing reads (the active
// organization's and realm-wide roles, or realm-wide alone with no active
// organization) and, for a session, the active organization's own
// (orgGrantSources: a team's roles). It only ever removes: whatever Authenticate narrowed away (another
// organization's roles, the packages, a token's subset) stays away, and a
// permission the caller lost every grant of since the request arrived — a
// demotion that committed while this request waited for the lock — is gone.
// Outside a lock, or with no caller id, held is returned as it is.
func heldUnderOrgLock(ctx context.Context, h *AuthServiceHandler, held map[int32]bool) (map[int32]bool, error) {
	if locked, _ := ctx.Value(orgLockKey{}).(string); locked == "" {
		return held, nil
	}
	userID, err := callerUserID(ctx)
	if err != nil || userID == "" {
		return held, nil
	}
	var grants []*pb.RoleGrant
	active := scopeOrg(ctx)
	if active != "" {
		resp, err := h.Query.GetUserOrgPermissions(ctx, &pb.GetUserOrgPermissionsReq{UserId: userID, OrgId: active})
		if err != nil {
			return nil, err
		}
		grants = resp.GetGrants()
		// A team's roles count for a session only, as the narrowing adds them
		// (narrowGrantsToActiveOrg): an API or OAuth token never carried them,
		// so they cannot keep a permission its own roles no longer grant.
		// Authenticate stamps session_token_id for a session and for nothing
		// else.
		var who pb.AuthResp
		if principal.Envelope(ctx, &who) == nil && who.GetSessionTokenId() != "" {
			for _, source := range orgGrantSources {
				more, err := source(ctx, h, userID, active)
				if err != nil {
					return nil, err
				}
				grants = append(grants, more...)
			}
		}
	} else {
		resp, err := h.Query.GetUserRealmWidePermissions(ctx, &pb.GetUserRealmWidePermissionsReq{UserId: userID})
		if err != nil {
			return nil, err
		}
		grants = resp.GetGrants()
	}
	carried := map[int32]bool{}
	for _, g := range grants {
		for _, id := range expandRoleGrant(g, h.Lock) {
			carried[id] = true
		}
	}
	out := make(map[int32]bool, len(held))
	for id := range held {
		if carried[id] {
			out[id] = true
		}
	}
	return out, nil
}

// scopeOrg is the organization the caller acts in, "" when none is selected
// (the method then refuses or acts realm-wide, as it did).
func scopeOrg(ctx context.Context) string {
	orgID, _ := principal.Scope(ctx, "org_id")
	return orgID
}

// membershipOrg is the organization a change to membership membershipID
// locks: the caller's active one (a membership elsewhere is refused anyway),
// or, for a realm-wide caller, the membership's own. "" when it cannot be
// read — the method's own read then answers.
func (h *AuthServiceHandler) membershipOrg(ctx context.Context, membershipID string) string {
	if orgID := scopeOrg(ctx); orgID != "" {
		return orgID
	}
	// The method's run under the lock (underOrgLock) asks again: the
	// organization it locked is the answer, without a second read.
	if held, _ := ctx.Value(orgLockKey{}).(string); held != "" {
		return held
	}
	m, err := h.Query.GetOrgMembership(ctx, &pb.GetOrgMembershipReq{Id: membershipID})
	if err != nil {
		return ""
	}
	return m.GetOrgId()
}

// guardSuperadmins runs a change that can take a superadmin away from
// organization orgID under its lock (withOrgLock): check runs the
// last-superadmin rule, then write makes the change.
func (h *AuthServiceHandler) guardSuperadmins(ctx context.Context, orgID string, check, write func(txCtx context.Context) error) error {
	return h.withOrgLock(ctx, orgID, func(txCtx context.Context) error {
		if err := check(txCtx); err != nil {
			return err
		}
		return write(txCtx)
	})
}

// checkMayManageMembership is what a change or a removal of one membership
// requires of the caller, before either writes anything:
//
//   - the membership is in the organization the caller acts in, when they act
//     in one. Their permissions were resolved FOR that organization (an
//     org-scoped role grants only there), so a ceiling checked there says
//     nothing about another. A caller with no active
//     organization acts on realm-wide grants, which reach every organization.
//   - the caller covers every role the member holds in that organization —
//     exactly the grants the change or removal revokes — and every role they
//     hold there through a team (memberHeldRoleSources): a removal ends those
//     too, and whoever cannot hand out a team's role must not be able to strip
//     a member of it either. Realm-wide grants stay with the member and are
//     not asked about.
//
// It returns the membership, read once, for the caller to act on.
func (h *AuthServiceHandler) checkMayManageMembership(ctx context.Context, membershipID string) (*pb.OrgMembership, error) {
	m, err := h.Query.GetOrgMembership(ctx, &pb.GetOrgMembershipReq{Id: membershipID})
	if err != nil {
		return nil, err
	}
	if active, ok := principal.Scope(ctx, "org_id"); ok && active != "" && active != m.GetOrgId() {
		return nil, refusal(ctx, codes.PermissionDenied,
			"membership "+membershipID+" is in organization "+m.GetOrgId()+", not the caller's active "+active,
			CodeMembershipInOtherOrg, "", MsgMembershipInOtherOrg, nil)
	}
	held, err := h.Query.ListUserOrgGrants(ctx, &pb.ListUserOrgGrantsReq{UserId: m.GetUserId(), OrgId: m.GetOrgId()})
	if err != nil {
		return nil, err
	}
	roleIDs := held.GetRoleIds()
	for _, source := range memberHeldRoleSources {
		more, err := source(ctx, h, m.GetUserId(), m.GetOrgId())
		if err != nil {
			return nil, err
		}
		roleIDs = append(roleIDs, more...)
	}
	if len(roleIDs) == 0 {
		return m, nil
	}
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	for _, roleID := range roleIDs {
		if !grantable[roleID] {
			return nil, refusal(ctx, codes.PermissionDenied,
				"the member of "+membershipID+" holds role "+roleID+", which the caller does not cover",
				CodeMemberAboveCaller, "", MsgMemberAboveCaller, nil)
		}
	}
	return m, nil
}

// Two refusals for the two reasons a role name is not org-assignable, a typo
// and a realm role, which a caller fixes in completely different ways.
//
// ⚠️ As one refusal, the adjective would carry the whole distinction — "no
// ORG-ASSIGNABLE role by that name exists". A realm role exists and is still
// refused, and calling that "does not exist" sends the reader hunting for a
// typo that is not there, or for a row that IS there. Each carries its own
// code, and both name the `role` field.

// assignableRoles is the ONE catalogue every org-role grant reads — an
// invitation, its acceptance, a membership's role change: the roles an org
// admin may hand out, which is the org-scoped ones.
//
// It is a function rather than a rule each caller applies because the two
// callers already drifted. The picker moved to ListOrgScopedRoles while
// roleIDByName kept reading ListRoles, so for a day the list a caller was
// OFFERED and the list that would be ACCEPTED disagreed: an org admin could
// invite at a realm role over the API by naming it, and only the UI knew not
// to. The picker's comment claimed the two could not disagree, which is why
// nothing caught it — a comment is not a check. They cannot disagree now
// because there is only one of them.
func (h *AuthServiceHandler) assignableRoles(ctx context.Context, orgID string) ([]*pb.OrgScopedRole, error) {
	roles, err := h.orgScopedRoles(ctx, orgID)
	if err != nil {
		return nil, err
	}
	// A membership carries a SESSION-realm role. An API-realm role (a bot's)
	// may be org-scoped too, and offered to a person it replaced their session
	// role with one their browser cannot use.
	out := roles[:0:0]
	for _, r := range roles {
		if !isAPIRealmRow(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// orgScopedRoles is every org-scoped role the organization may see, of
// either realm.
func (h *AuthServiceHandler) orgScopedRoles(ctx context.Context, orgID string) ([]*pb.OrgScopedRole, error) {
	if orgRoleCatalogue != nil {
		return orgRoleCatalogue(ctx, h, orgID)
	}
	resp, err := h.Query.ListOrgScopedRoles(ctx, &pb.ListOrgScopedRolesReq{})
	if err != nil {
		return nil, err
	}
	return resp.GetRoles(), nil
}

// orgRoleCatalogue, set by org_roles, is the catalogue of ONE organization:
// the shared org roles plus its own. Without org_roles there are no custom
// roles and every organization shares ListOrgScopedRoles.
var orgRoleCatalogue func(ctx context.Context, h *AuthServiceHandler, orgID string) ([]*pb.OrgScopedRole, error)

// isAPIRealmRow reports whether a role row read off the catalogue belongs to
// the API realm. By reflection, because its token_type field exists only with
// api_token: without it there is one realm and no row is an API one.
func isAPIRealmRow(m proto.Message) bool {
	fd := m.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name("token_type"))
	if fd == nil {
		return false
	}
	return m.ProtoReflect().Get(fd).Enum() == protoreflect.EnumNumber(pb.TokenType_TOKEN_TYPE_API)
}

// refuseLastSuperadmin keeps an organization from losing its last
// superadmin through a membership change or removal: m's role change to
// newRoleID ends their direct grants there (a wildcard newRoleID keeps them a
// superadmin; what they hold through a team stays), and a removal (newRoleID
// "") ends their team memberships too. Holds for everyone, the member who
// created the organization included: whoever is its last superadmin cannot
// demote or remove themselves (organization ownership, which once counted as
// a superadmin here, grants nothing).
func (h *AuthServiceHandler) refuseLastSuperadmin(ctx context.Context, m *pb.OrgMembership, newRoleID string) error {
	if newRoleID != "" {
		wildcard, err := h.wildcardRoleIDs(ctx)
		if err != nil {
			return err
		}
		if wildcard[newRoleID] {
			return nil
		}
	}
	return h.refuseLeavingNoSuperadmin(ctx, m.GetOrgId(), func(g *pb.OrgSuperadminRow) bool {
		return g.GetUserId() == m.GetUserId() && (newRoleID == "" || g.GetTeamId() == "")
	})
}

// orgSuperadmins is the ONE answer to who keeps an organization administered:
// every live session-realm wildcard grant there of an account that can act
// (not disabled, not erased, with a live membership) — held directly (ListOrgSuperadmins) or
// through another feature (superadminSources: a team's wildcard role).
func (h *AuthServiceHandler) orgSuperadmins(ctx context.Context, orgID string) ([]*pb.OrgSuperadminRow, error) {
	direct, err := h.Query.ListOrgSuperadmins(ctx, &pb.ListOrgSuperadminsReq{OrgId: orgID})
	if notFoundOK(err) != nil {
		return nil, err
	}
	all := append([]*pb.OrgSuperadminRow(nil), direct.GetGrants()...)
	for _, source := range superadminSources {
		more, err := source(ctx, h, orgID)
		if err != nil {
			return nil, err
		}
		all = append(all, more...)
	}
	// A disabled or erased account holds no working credential, and an
	// API-realm wildcard is a machine account's (SetBotRoles revokes it
	// without asking this rule). The stamps and the realm are projected
	// (user_admin, api_token) rather than filtered in SQL: a SELECT's WHERE
	// conjunct cannot be feature-gated.
	rows := all[:0]
	for _, g := range all {
		if g.GetDisabledAt() == nil && g.GetErasedAt() == nil && !isAPIRealmRow(g) {
			rows = append(rows, g)
		}
	}
	return rows, nil
}

// refuseLeavingNoSuperadmin refuses a change that would leave the organization
// with no superadmin (LAST_SUPERADMIN, FailedPrecondition): ends names the
// grants the change ends, and the change goes through while one grant of
// orgSuperadmins survives it. An organization that has none already is not
// one a change can take its last from, so nothing is refused there.
//
// Every path that can take a superadmin away asks this, with what it ends: a
// membership's role change or removal (refuseLastSuperadmin), and with teams
// a team member's removal, a change of the team's roles and the team's
// deletion. An operator's DisableUsers / EraseUsers is realm-level and not
// held to it, by design.
func (h *AuthServiceHandler) refuseLeavingNoSuperadmin(ctx context.Context, orgID string, ends func(*pb.OrgSuperadminRow) bool) error {
	rows, err := h.orgSuperadmins(ctx, orgID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	for _, g := range rows {
		if !ends(g) {
			return nil
		}
	}
	return refusal(ctx, codes.FailedPrecondition,
		"the change leaves organization "+orgID+" without a superadmin",
		CodeLastSuperadmin, "", MsgLastSuperadmin, nil)
}

// wildcardRoleIDs is the set of roles that carry every permission
// (all_permissions), off the role catalogue.
func (h *AuthServiceHandler) wildcardRoleIDs(ctx context.Context) (map[string]bool, error) {
	catalogue, err := h.Query.ListRoleGrants(ctx, &pb.ListRoleGrantsReq{})
	if err != nil {
		return nil, err
	}
	wildcard := map[string]bool{}
	for _, g := range catalogue.GetGrants() {
		if g.GetAllPermissions() {
			wildcard[g.GetRoleId()] = true
		}
	}
	return wildcard, nil
}

// roleIDByName resolves an assignable Role.name to its id.
//
// Validated when the invitation is CREATED rather than when it is
// accepted: a typo is then the inviter's error at the moment they make it,
// instead of a failure the invitee walks into days later with no way to
// tell what is wrong or who to ask.
//
// It runs AGAIN at accept, against the same catalogue. That is not
// belt-and-braces: a role can be retired or unscoped between the two
// moments, and the accept is where the grant is actually written.
//
// Its refusals name the `role` field and the value — the request field every
// caller of this names `role`, invitation and membership change alike.
func (h *AuthServiceHandler) roleIDByName(ctx context.Context, orgID, name string) (string, error) {
	roles, err := h.orgScopedRoles(ctx, orgID)
	if err != nil {
		return "", err
	}
	for _, r := range roles {
		if r.GetName() != name {
			continue
		}
		if isAPIRealmRow(r) {
			return "", refusal(ctx, codes.InvalidArgument,
				"role "+name+" belongs to the API realm (a machine account's), and a person's membership carries a session-realm role",
				CodeRoleIsForBots, "role", MsgRoleIsForBots, map[string]string{"role": name})
		}
		return r.GetId(), nil
	}
	// Not org-assignable — and the two reasons for that are a typo and a realm
	// role, which a caller fixes in completely different ways. The full catalogue
	// tells them apart; `org_membership` requires `rbac`, so ListRoles is always here.
	//
	// Another organization's own role (org_roles) is org-scoped and so in
	// ListOrgScopedRoles; for this organization it is the typo answer, never
	// "realm-wide" — the refusal must not say that some other company has a
	// role by that name.
	if scoped, serr := h.Query.ListOrgScopedRoles(ctx, &pb.ListOrgScopedRolesReq{}); serr == nil {
		for _, r := range scoped.GetRoles() {
			if r.GetName() == name {
				return "", refusal(ctx, codes.InvalidArgument,
					"no role by that name exists in this organization's role catalogue: "+name,
					CodeUnknownOrgRole, "role", MsgUnknownOrgRole, map[string]string{"role": name})
			}
		}
	}
	if all, lerr := h.Query.ListRoles(ctx, &pb.ListRolesReq{}); lerr == nil {
		for _, r := range all.GetRoles() {
			if r.GetName() == name {
				return "", refusal(ctx, codes.InvalidArgument,
					"role "+name+" exists but is realm-wide, and an organization membership may only carry an organization-scoped role",
					CodeRoleNotOrgScoped, "role", MsgRoleNotOrgScoped, map[string]string{"role": name})
			}
		}
	}
	// A catalogue lookup that could not answer must not invent the distinction:
	// the typo message is the one that holds for both.
	return "", refusal(ctx, codes.InvalidArgument,
		"no role by that name exists in this project's role catalogue: "+name,
		CodeUnknownOrgRole, "role", MsgUnknownOrgRole, map[string]string{"role": name})
}
