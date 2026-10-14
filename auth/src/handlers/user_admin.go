package handlers

import (
	"context"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `user_admin` feature — turnkey admin user
// management (the admin Users page + soft-disable/enable + erase, and the
// Sessions page's revoke). It is staged into a bundle ONLY when the
// activation enables `user_admin` (plugin.yaml maps the feature to this file
// via go_files). With the feature off it is not staged, so the sign-in
// disabled gate keeps its no-op default and `User.disabled_at` isn't emitted.
// Standalone (the plugin author's own `go test`) always compiles it, since
// gating happens at activation staging, not in the source tree.

// init wires the disabled-account gate on package load. `disabled_at`
// exists on the User message only when `user_admin` is active (this file
// is staged), so naming it via GetDisabledAt() is safe to compile here.
func init() {
	signInDisabledGate = func(user *pb.User) error {
		if user.GetDisabledAt() != nil {
			return errAuthnUserDisabled
		}
		return nil
	}
}

// erasedAddress is the placeholder an erased account's address becomes:
// unique (the id is), non-routable (`.invalid` is reserved, RFC 2606), and a
// valid address, so the EMAIL column's checks hold. Replacing the address is
// what frees it: the person can sign up again with it. No other path may write
// an address in this domain (refuseReservedEmail), so nothing can hold the
// placeholder before the erasure needs it.
func erasedAddress(userID string) string {
	return "erased-" + userID + "@" + erasedEmailDomain
}

// UpdateAccount is the admin Users page's detail `update`: the email only,
// through AuthMutation.UpdateUser, after refusing the erased-account domain —
// an account given `erased-<id>@erased.invalid` would block the erasure of
// account <id> for good. The page binds this method rather than the mutation
// so the refusal cannot be skipped from the admin.
func (h *AuthServiceHandler) UpdateAccount(ctx context.Context, req *pb.UpdateAccountReq) (*pb.UpdateAccountResp, error) {
	if _, err := callerUserID(ctx); err != nil {
		return nil, Unauthenticated(err)
	}
	if err := refuseReservedEmail(ctx, req.GetEmail()); err != nil {
		return nil, err
	}
	resp, err := h.Mutation.UpdateUser(ctx, &pb.UpdateUserReq{UserId: req.GetUserId(), Email: req.GetEmail()})
	if err != nil {
		return nil, err
	}
	return &pb.UpdateAccountResp{UserId: resp.GetUserId(), Email: resp.GetEmail()}, nil
}

// errEmptySelection refuses an admin action with no ids. The admin's "apply to
// all filtered rows" sends an empty selection; for an erasure or a revocation
// that would mean every account or every session, and neither is a bulk
// operation an operator should reach by leaving the selection empty.
var errEmptySelection = status.Error(codes.InvalidArgument,
	"select the rows to act on: an empty selection would apply to every row, which this action does not do")

// EraseUsers erases each selected account (GDPR) without deleting anything —
// the admin Users page's `erase` action. Each account in its own transaction:
// one that fails leaves the ones before it erased and itself untouched. The
// operator is recorded as revoked_by on every token the erasure ends.
func (h *AuthServiceHandler) EraseUsers(ctx context.Context, req *pb.EraseUsersReq) (*pb.EraseUsersResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if len(req.GetIds()) == 0 {
		return nil, errEmptySelection
	}
	for _, id := range req.GetIds() {
		if err := h.eraseUser(ctx, id, operator); err != nil {
			return nil, err
		}
	}
	return &pb.EraseUsersResp{}, nil
}

// eraseUser erases one account: every feature's eraser over the tables it
// owns and the account's reset links FIRST, then AuthMutation.EraseUser over
// the base tables (the row pseudonymised in place, the account disabled, its
// tokens and devices revoked). With a transaction coordinator that is one unit
// of work. Without one each statement commits on its own, and the order is
// what makes a retry complete a failed erasure: every eraser is an idempotent
// UPDATE, and EraseUser — the step that stamps erased_at and replaces the
// address the invitation eraser looks for — runs last, so an erasure that
// failed part-way is not yet marked erased and the next attempt does all of it
// again. An account already erased skips EraseUser alone and still runs the
// erasers, which change nothing that is already erased and finish anything an
// earlier attempt left; EraseUser's own `erased_at IS NULL` guard settles a
// race between two operators (NotFound is done).
func (h *AuthServiceHandler) eraseUser(ctx context.Context, userID, operator string) error {
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return err
	}
	user := got.GetUser()
	email, placeholder := user.GetEmail(), erasedAddress(userID)

	var tx *distx.TxHandle
	txCtx := ctx
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return err
		}
	}
	rollback := func() {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
	}
	for _, erase := range erasers {
		if err := erase(txCtx, h, userID, email, placeholder); err != nil {
			rollback()
			return err
		}
	}
	// A reset link sent before the erasure would set a password on it.
	if err := spendResetLinks(txCtx, h, userID); err != nil {
		rollback()
		return err
	}
	if user.GetErasedAt() == nil {
		if _, err := h.Mutation.EraseUser(txCtx, &pb.EraseUserReq{
			UserId:    userID,
			Email:     placeholder,
			RevokedBy: operator,
		}); notFoundOK(err) != nil {
			rollback()
			return err
		}
		// NotFound: erased by somebody else since the read — done.
	}
	if tx != nil {
		return tx.Commit(ctx)
	}
	return nil
}

// RevokeSessions revokes each selected token — the admin Sessions page's
// `revoke` action. The operator is recorded as revoked_by, the reason is
// ADMIN_REVOKED, and the rows stay (the page lists them as revoked). A token
// already revoked keeps its first revocation: the statement matches no row,
// which is done, not an error, so revoking a revoked row is a no-op.
func (h *AuthServiceHandler) RevokeSessions(ctx context.Context, req *pb.RevokeSessionsReq) (*pb.RevokeSessionsResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if len(req.GetIds()) == 0 {
		return nil, errEmptySelection
	}
	for _, id := range req.GetIds() {
		if _, err := h.Mutation.RevokeUserToken(ctx, &pb.RevokeUserTokenReq{Id: id, RevokedBy: operator}); notFoundOK(err) != nil {
			return nil, err
		}
	}
	return &pb.RevokeSessionsResp{}, nil
}
