package handlers

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `org_invite` feature. Staged only when the
// activation enables it (plugin.yaml maps the feature to this file via
// go_files); the plugin author's own `go test` always compiles it.
//
// The shape, and why it is this one:
//
// An invitation names an EMAIL and an ORGANIZATION, never a user id. The
// sibling token tables (PasswordResetToken, EmailVerificationToken) hang
// off `user_id` because the person is already known; an invitation is the
// one flow where they may not exist yet. Anchoring on the address collapses
// "invite someone who has an account" and "invite someone who has to
// register" into ONE object with two endings, decided at acceptance — which
// is also the only correct time to decide it, since the invitee can go and
// register on their own between the two.
//
// Accepting writes BOTH halves in one transaction: the OrgMembership row
// AND the UserRole grant scoped to that org. A membership without the grant
// is a label with nothing behind it — the state this console was in before
// this feature existed, where the only way to give an invited person any
// permission was to edit the database by hand.

const defaultOrgInviteTTLHours = 24 * 7 // 7 days

// init installs the enforcing invite gate. The seam it replaces lives in
// auth_service.go and defaults to permissive; this file is staged only
// when the activation enables `org_invite`, so the enforcing version
// exists exactly when there are invitations to enforce.
//
// ⚠️ NOTHING REFERENCES THIS FUNCTION, which is exactly how it was lost
// once. A refactor that moved `ListOrgMembers` out of this file took the
// init() with it. The three helpers in the same span came back because the
// compiler demanded them; nothing demands an init, and removing one is
// always valid Go. So it compiled, the plugin's tests passed, `make ci`
// passed, codegen staged it, the image built, the deploy succeeded — and
// the deployed console accepted an UNINVITED registration on the public
// internet: HTTP 200, account created, `invite_only` at its default and
// then pinned explicitly in the stack env, twice (2026-09-08).
//
// The compiler cannot miss what nobody calls. If you move things out of
// this file, check that this survived — and note that the behavioural test
// in org_invite_gate_test.go fails exactly when it has not, because the
// permissive default returns nil for everything.
func init() {
	signupInviteGate = requirePendingInvite
	signupClaimInvite = claimOpenInvite
}

// claimOpenInvite binds an OPEN invitation to the address registering
// through its link. The link used to be only READ at registration, and
// acceptance (which spends it) comes later: until somebody accepted, one open
// link registered any number of accounts — under `invite_only`, a way to
// create accounts with nothing but a forwarded URL. Bound, the invitation
// admits that address and no other, and the account it belongs to accepts it
// as before.
//
// Two registrations racing on one link both passed the read-only gate; the
// bind decides between them. The update matches only while the invitation is
// still open, so the second matches nothing and reads back somebody else's
// address — and under `invite_only` it is refused, unless the address holds
// an invitation of its own (the gate's other path).
//
// A bound or unknown link is not claimed here; the gate already decided what
// it admits.
func claimOpenInvite(ctx context.Context, h *AuthServiceHandler, email, inviteToken string) error {
	if inviteToken == "" {
		return nil
	}
	tokenHash := sha256Hex(inviteToken)
	if _, err := h.Mutation.BindOpenOrgInvite(ctx, &pb.BindOpenOrgInviteReq{TokenHash: tokenHash, Email: email}); err != nil {
		return err
	}
	if !h.InviteOnly {
		return nil // the invitation decides the org, not whether one may register
	}
	pending, err := h.Query.GetPendingOrgInviteByToken(ctx, &pb.GetPendingOrgInviteByTokenReq{TokenHash: tokenHash})
	switch {
	case err == nil && pending.GetEmail() == email:
		return nil
	case err != nil && status.Code(err) != codes.NotFound:
		return err
	}
	resp, err := h.Query.ListPendingInvitesForEmail(ctx, &pb.ListPendingInvitesForEmailReq{Email: email})
	if err != nil {
		return err
	}
	if len(resp.GetInvites()) == 0 {
		return errSignUpNotInvited
	}
	return nil
}

// requirePendingInvite refuses an address that holds no acceptable
// invitation, when the activation asked for invite-only registration.
//
// Reads h.InviteOnly at call time, not at install time: enabling
// `org_invite` gives an activation invitations, and must not by itself
// close a registration surface the operator left open. The two knobs are
// independent on purpose — invitations without invite_only means "anyone
// may register, and an invitation only decides which org they land in".
//
// Fail-CLOSED on a query error. The alternative admits everybody whenever
// the query tier is unreachable, which is the one moment nobody is
// watching the registration form.
//
// Expiry is the query's business (it selects pending, unaccepted, unexpired
// rows), so this gate does not re-derive it — two places deciding what
// "pending" means is how the two halves drift apart.
func requirePendingInvite(ctx context.Context, h *AuthServiceHandler, email, inviteToken string) error {
	if !h.InviteOnly {
		return nil
	}
	// An OPEN invitation names no address, so the address lookup below can never
	// find it — and `invite_only` defaults ON, which made path 1 unusable in the
	// default configuration until this branch existed. The token is the whole
	// authorisation there: holding the link IS the invitation.
	//
	// Read, not consumed. Acceptance is what spends a single-use invitation, and a
	// signup that fails after this point must leave the link usable.
	if inviteToken != "" {
		pending, err := h.Query.GetPendingOrgInviteByToken(ctx, &pb.GetPendingOrgInviteByTokenReq{
			TokenHash: sha256Hex(inviteToken),
		})
		if err == nil {
			// A BOUND invitation's token still has to go to its own address — the
			// link being secret does not make it transferable to another mailbox.
			if invited := pending.GetEmail(); invited == "" || invited == email {
				return nil
			}
		} else if status.Code(err) != codes.NotFound {
			// Fail-CLOSED on a real query failure, for the reason below: the
			// alternative admits everybody exactly when nobody is watching.
			return err
		}
		// A token that matched nothing falls through to the address check rather
		// than refusing here, so a stale link plus a legitimately invited address
		// still registers — and the refusal, when it comes, is the same one for
		// both causes.
	}
	resp, err := h.Query.ListPendingInvitesForEmail(ctx, &pb.ListPendingInvitesForEmailReq{Email: email})
	if err != nil {
		return err
	}
	if len(resp.GetInvites()) == 0 {
		return errSignUpNotInvited
	}
	return nil
}

// Every refusal in this file is a gRPC STATUS, never a bare error: the
// gateway maps an unclassified error to INTERNAL, and the caller then
// reads a 500 "internal error" instead of the sentence explaining what
// to do about it.
//
// errInviteInvalid is the opaque answer to every failed acceptance:
// unknown id, expired, already accepted, or addressed to somebody else.
// One message for four causes on purpose — an invite id is guessable and
// telling a guesser WHICH of the four they hit turns this into an oracle
// that reports whether an address has been invited somewhere.
var errInviteInvalid = status.Error(codes.NotFound,
	"invitation invalid, expired, already accepted, or addressed to another account")

func (h *AuthServiceHandler) orgInviteTTL() time.Duration {
	if h.OrgInviteTTLHours > 0 {
		return time.Duration(h.OrgInviteTTLHours) * time.Hour
	}
	return defaultOrgInviteTTLHours * time.Hour
}

// callerEmail resolves the authenticated principal's address. Invitations
// are keyed on it, so this is what decides which ones the caller may see
// and accept — and it comes from the user row the principal resolves to,
// never from anything the request carried.
func (h *AuthServiceHandler) callerEmail(ctx context.Context, userID string) (string, error) {
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return "", err
	}
	return normalizeEmail(got.GetUser().GetEmail()), nil
}

// ListAssignableRoles returns the roles an invitation in this org may name.
//
// Reads the same catalogue roleIDByName validates against — literally the
// same function — so the choices a caller is offered and the values that
// will be accepted cannot disagree. That is the whole reason this exists
// rather than a list written down in a UI: a hardcoded picker would keep
// offering a role the day it is renamed.
//
// ORG-SCOPED ONLY. A realm role reaches every organization, so it is not an
// org admin's to hand out; filtering here rather than in the caller means a
// second consumer cannot forget to.
func (h *AuthServiceHandler) ListAssignableRoles(ctx context.Context, req *pb.ListAssignableRolesReq) (*pb.ListAssignableRolesResp, error) {
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	// ListOrgScopedRoles, not ListRoles: the shared catalogue query cannot
	// return `org_scoped` at all (the column only exists under the
	// org_membership feature, so naming it there fails the typecheck for
	// projects without it — the query's own comment says so). Filtering in Go
	// on a field that is never populated silently returned an EMPTY list,
	// which is how this was found.
	roles, err := h.assignableRoles(ctx)
	if err != nil {
		return nil, err
	}
	// Narrowed to the caller's ceiling with the function InviteToOrg enforces,
	// so a role offered here is one the invitation will accept.
	grantable, err := h.grantableRoleIDs(ctx)
	if err != nil {
		return nil, err
	}
	out := &pb.ListAssignableRolesResp{}
	for _, r := range roles {
		if !grantable[r.GetId()] {
			continue
		}
		out.Roles = append(out.Roles, &pb.AssignableRole{
			Name:        r.GetName(),
			Description: r.GetDescription(),
		})
	}
	return out, nil
}

// metadataOrEmptyObject turns "the caller sent nothing" into the empty JSON
// object, because the column is JSON NOT NULL and ” is not a document.
//
// Only whitespace counts as nothing. Anything else is the consumer's document and
// is stored as given — including a value this plugin would not have chosen,
// because the column is theirs and nothing here reads it.
//
// As a JSON DOCUMENT, not as bytes: Postgres keeps the column as jsonb, so what
// comes back (list, acceptance) is the same value re-serialised — key order and
// whitespace are the database's (measured by examples/auth-proof). A consumer
// that compares or signs it must parse it, not compare strings.
func metadataOrEmptyObject(m string) string {
	if strings.TrimSpace(m) == "" {
		return "{}"
	}
	return m
}

// InviteToOrg records an invitation for an address to join the caller's
// active organization with a named role.
func (h *AuthServiceHandler) InviteToOrg(ctx context.Context, req *pb.InviteToOrgReq) (*pb.InviteToOrgResp, error) {
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	inviter, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	// Normalized here, once, and stored normalized: SignIn lower-cases the
	// address it looks up, so an invitation stored as typed would never
	// match the account that arrives to accept it.
	// An EMPTY address is a real request now: the invitation is OPEN and whoever
	// holds the link picks their own. Bound (non-empty) is the corporate case —
	// this address and no other — and the only one that can derive a verified
	// address later, because only there does "the invitation named it" say
	// anything about what the registrant types.
	email := normalizeEmail(req.GetEmail())
	roleID, err := h.roleIDByName(ctx, req.GetRole())
	if err != nil {
		return nil, err
	}
	// Not above the inviter. Checked here, when the inviter is the caller —
	// the accept path runs as the invitee, whose permissions say nothing about
	// what the inviter was allowed to hand out.
	snapshot, err := h.checkMayGrantRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	// The link's secret. Minted here, stored hashed, returned once — the same
	// three steps a password reset takes, and for the same reason: a stored
	// plaintext is a stored credential.
	token, err := randomURLToken()
	if err != nil {
		return nil, err
	}

	// Release a lapsed invitation for this address before writing a new one.
	//
	// The pending-invite index cannot exclude expired rows — a partial index
	// predicate has to be IMMUTABLE and `NOW()` is not — so an invitation that
	// ran out still holds (org, email), and the re-invite fails on a unique
	// violation that reads like a race between two inviters. It is not one:
	// the blocker is a dead row the inviter can see in their own list and
	// cannot get past.
	//
	// NOT_FOUND here is the ORDINARY answer: nothing had lapsed. Treating it
	// as a failure would refuse every first invitation to an address, which is
	// the same unreachable-branch mistake D13-7 shipped one function away.
	//
	// Only for a BOUND invitation. An open one stores NULL, which the unique
	// index never compares, so nothing can block it — and the clear's own
	// request requires the address, so calling it with "" refused every open
	// invitation with REQUIRED_VIOLATION before it was written (found live by
	// examples/auth-proof, after the request field itself had been fixed).
	if email != "" {
		if _, cerr := h.Mutation.ClearExpiredOrgInvite(ctx, &pb.ClearExpiredOrgInviteReq{
			OrgId: orgID,
			Email: email,
		}); cerr != nil && status.Code(cerr) != codes.NotFound {
			return nil, cerr
		}
	}

	created, err := h.Mutation.CreateOrgInvite(ctx, &pb.CreateOrgInviteReq{
		OrgId:     orgID,
		Email:     email,
		Role:      req.GetRole(),
		InvitedBy: inviter,
		ExpiresAt: timestamppb.New(time.Now().Add(h.orgInviteTTL())),
		TokenHash: sha256Hex(token),
		// Stored as given (as a JSON value — see metadataOrEmptyObject) and never
		// read here. The plugin has no opinion
		// about the shape; see OrgInvite.metadata for why that is what makes an
		// opaque column answerable without deciding the general plugin-model
		// question.
		//
		// The one thing it DOES decide: what "no metadata" is. The column is JSON
		// and NOT NULL, and the empty string is not a JSON document — so passing a
		// caller's omission straight through reached Postgres as '' and came back
		// as INVALID_ARGUMENT with code VALUE_OUT_OF_RANGE and an EMPTY field,
		// because that code is grpcerr's FALLBACK for a PG data exception and PG
		// reports neither the column nor the value (grpcerr/wrap.go:433). Measured
		// against production on rc.8: an invitation with no metadata was refused,
		// the same one with `{}` was not — so an optional field had silently become
		// required, and it refused in the one shape a client cannot act on.
		//
		// An absent opaque value is therefore the empty OBJECT, which is what it
		// means. Deliberately NOT a column default: a default is a schema change
		// bought to settle a decision that belongs here, in the only place that
		// knows the field is optional.
		Metadata: metadataOrEmptyObject(req.GetMetadata()),
		// What the ceiling checked — accept holds the grant to it.
		RoleSnapshot: snapshot,
	})
	if err != nil {
		return nil, err
	}
	inv := created.GetInvite()
	return &pb.InviteToOrgResp{
		Invite: &pb.OrgInviteSummary{
			InviteId:  inv.GetId(),
			Email:     inv.GetEmail(),
			Role:      inv.GetRole(),
			ExpiresAt: inv.GetExpiresAt(),
			CreatedAt: inv.GetCreatedAt(),
			// Echoed from the WRITTEN row rather than from the request, so the
			// caller sees what was actually stored.
			Metadata: inv.GetMetadata(),
		},
		// Handed back ONCE. The row keeps only the hash, so there is no second
		// chance to read it and no list that can show it — the inviter is the
		// delivery channel and this is the moment they are holding the link.
		Token: token,
	}, nil
}

// ListOrgInvites returns the active organization's outstanding invitations.
func (h *AuthServiceHandler) ListOrgInvites(ctx context.Context, req *pb.ListOrgInvitesReq) (*pb.ListOrgInvitesResp, error) {
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := h.Query.ListOrgInvitesByOrg(ctx, &pb.ListOrgInvitesByOrgReq{OrgId: orgID})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.OrgInviteSummary, 0, len(resp.GetInvites()))
	for _, i := range resp.GetInvites() {
		out = append(out, &pb.OrgInviteSummary{
			InviteId:  i.GetId(),
			Email:     i.GetEmail(),
			Role:      i.GetRole(),
			ExpiresAt: i.GetExpiresAt(),
			CreatedAt: i.GetCreatedAt(),
			// So an admin screen can show WHAT each pending invitation is for.
			Metadata: i.GetMetadata(),
		})
	}
	return &pb.ListOrgInvitesResp{Invites: out}, nil
}

// RevokeOrgInvite withdraws a pending invitation of the active org.
func (h *AuthServiceHandler) RevokeOrgInvite(ctx context.Context, req *pb.RevokeOrgInviteReq) (*pb.RevokeOrgInviteResp, error) {
	if err := refuseOtherOrg(ctx, req.GetOrg()); err != nil {
		return nil, err
	}
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	orgID, err := activeOrgID(ctx)
	if err != nil {
		return nil, err
	}
	// org_id goes into the statement's WHERE, not just into a check here:
	// the delete itself refuses an invitation belonging to another
	// organization, so guessing a uuid is not a way to revoke somebody
	// else's.
	if _, err := h.Mutation.DeleteOrgInvite(ctx, &pb.DeleteOrgInviteReq{
		InviteId: req.GetInviteId(),
		OrgId:    orgID,
	}); err != nil {
		return nil, err
	}
	return &pb.RevokeOrgInviteResp{}, nil
}

// ListMyInvites returns the invitations addressed to the CALLER, across
// every organization — the list a person sees in their own account.
func (h *AuthServiceHandler) ListMyInvites(ctx context.Context, _ *pb.ListMyInvitesReq) (*pb.ListMyInvitesResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	email, err := h.callerEmail(ctx, userID)
	if err != nil {
		return nil, err
	}
	resp, err := h.Query.ListPendingInvitesForEmail(ctx, &pb.ListPendingInvitesForEmailReq{Email: email})
	if err != nil {
		return nil, err
	}
	out := make([]*pb.MyInvite, 0, len(resp.GetInvites()))
	for _, i := range resp.GetInvites() {
		out = append(out, &pb.MyInvite{
			InviteId:  i.GetInviteId(),
			OrgSlug:   i.GetOrgSlug(),
			OrgName:   i.GetOrgName(),
			Role:      i.GetRole(),
			ExpiresAt: i.GetExpiresAt(),
		})
	}
	return &pb.ListMyInvitesResp{Invites: out}, nil
}

// AcceptOrgInvite joins the caller to the inviting organization.
//
// One distributed transaction over three writes, and all three have to
// land together: consuming the invitation without the membership loses the
// invitation, and the membership without the role grant produces a member
// who can do nothing and no screen to fix them from.
func (h *AuthServiceHandler) AcceptOrgInvite(ctx context.Context, req *pb.AcceptOrgInviteReq) (*pb.AcceptOrgInviteResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	email, err := h.callerEmail(ctx, userID)
	if err != nil {
		return nil, err
	}
	// READ, then gate, then consume — and the order is the design rather than a
	// preference.
	//
	// The gate now has to know whether this invitation BINDS an address, and it
	// cannot: only the row says. So the row is read first. Consuming first and
	// rolling back on refusal would do it too, but only where a transaction is
	// running, and the one below begins only when DistTx is wired — a refusal on
	// a plain connection would have spent the invitation to say no.
	//
	// Reading leaks nothing the caller did not bring: it answers only for a token
	// they presented, and a wrong token is NOT_FOUND exactly like a spent one.
	tokenHash := sha256Hex(req.GetToken())
	pending, err := h.Query.GetPendingOrgInviteByToken(ctx, &pb.GetPendingOrgInviteByTokenReq{
		TokenHash: tokenHash,
	})
	if status.Code(err) == codes.NotFound {
		return nil, errInviteInvalid
	}
	if err != nil {
		return nil, err
	}
	invitedEmail := pending.GetEmail()
	bound := invitedEmail != ""
	// A BOUND invitation is for one address and no other. That test used to live
	// in the claim's own WHERE (`AND email = :email`); it moves here because the
	// claim is now keyed on the token, and the same opaque refusal covers it — a
	// guesser must not learn that the token was good but the account was wrong.
	if bound && invitedEmail != email {
		return nil, errInviteInvalid
	}
	if err := inviteVerifiedEmailGate(ctx, h, userID, bound); err != nil {
		return nil, err
	}

	var tx *distx.TxHandle
	txCtx := ctx
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	resp, err := h.acceptInviteTx(txCtx, tokenHash, userID, bound)
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
	return resp, nil
}

func (h *AuthServiceHandler) acceptInviteTx(txCtx context.Context, tokenHash, userID string, bound bool) (*pb.AcceptOrgInviteResp, error) {
	// Claim by TOKEN. The not-yet-accepted and not-expired tests still sit in the
	// UPDATE's own WHERE, so there is no window between deciding an invitation is
	// good and consuming it — two clicks cannot both win, and the read above is
	// advisory rather than a decision this relies on.
	claimed, err := h.Mutation.ConsumeOrgInviteByToken(txCtx, &pb.ConsumeOrgInviteByTokenReq{
		TokenHash: tokenHash,
		UserId:    userID,
	})
	// A claim that matches nothing arrives as NotFound, not as an empty
	// response: the mutation carries RETURNING, and the generated write
	// reports zero rows as an error.
	//
	// That is what made the opaque refusal below unreachable. `errInviteInvalid`
	// exists precisely so an unauthenticated guess cannot learn WHICH of the
	// four causes it hit — expired, already accepted, addressed to somebody
	// else, or never existed — and instead of it the caller got a NotFound
	// naming an internal RPC. The anti-probe wording was written, tested by
	// eye, and never sent.
	if status.Code(err) == codes.NotFound {
		return nil, errInviteInvalid
	}
	if err != nil {
		return nil, err
	}
	// Kept as well, and deliberately not as belt-and-braces: the two are
	// different shapes of "no row". NotFound is what the generator emits
	// today; an empty org_id is what a caller would see if that ever changed,
	// and proceeding with one would write a membership into no organization.
	// Both answer with the same refusal, which is the property that matters.
	orgID := claimed.GetOrgId()
	if orgID == "" {
		return nil, errInviteInvalid
	}
	roleName := claimed.GetRole()

	// The role is resolved from the CLAIMED row, not from anything the
	// request said: the invitation decides the role, the acceptor only
	// decides whether to take it.
	roleID, err := h.roleIDByName(txCtx, roleName)
	if err != nil {
		return nil, err
	}
	// The role the grant is about to write must be the one the inviter was
	// checked against, and no wider. Refusing rolls the claim back, so the
	// invitation stays unspent for the inviter to replace.
	if err := h.checkRoleWithinSnapshot(txCtx, roleID, claimed.GetRoleSnapshot()); err != nil {
		return nil, err
	}

	if _, err := h.Mutation.AddOrgMembership(txCtx, &pb.AddOrgMembershipReq{
		UserId: userID,
		OrgId:  orgID,
		Role:   roleName,
	}); err != nil {
		return nil, err
	}
	// org_id on the grant is what scopes it. Empty would mean REALM-WIDE
	// — the role would count in every organization the person belongs to,
	// which is the one outcome an org invitation must never produce.
	if _, err := h.Mutation.AssignRoleToUser(txCtx, &pb.AssignRoleToUserReq{
		UserId: userID,
		RoleId: roleID,
		OrgId:  orgID,
	}); err != nil {
		return nil, err
	}
	// A BOUND invitation proved the address by being accepted, so record HOW —
	// inside the same transaction as the membership, because a proof recorded
	// against a membership that rolled back is a proof of nothing.
	//
	// Open invitations deliberately do not reach here: the registrant chose the
	// address, so what was proved is that they were authorised, not that the
	// address is theirs.
	//
	// The seam is nil unless `email_verification` is staged — the column does not
	// exist otherwise, and an invitation must not stop working because a project
	// declined that feature.
	if bound {
		if err := markEmailDerived(txCtx, h, userID); err != nil {
			return nil, err
		}
	}
	// Metadata comes from the CLAIMED row — the same statement that spent the
	// invitation — so a caller acting on the pairing knows the acceptance
	// committed. Reading it back with a second query could answer for a row a
	// different request had since consumed.
	return &pb.AcceptOrgInviteResp{OrgId: orgID, Role: roleName, Metadata: claimed.GetMetadata()}, nil
}
