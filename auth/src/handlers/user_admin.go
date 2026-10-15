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
	// An attempt at an erased account is recorded pseudonymised.
	signInAccountErased = func(user *pb.User) bool { return user.GetErasedAt() != nil }
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
// the bulk form of EraseAccount, for project code. Account by account: with a
// transaction coordinator each account is one transaction, so one that fails
// leaves the ones before it erased and itself untouched; without one, the
// account that failed is left with its access already ended and is completed
// by running the erasure again (see eraseUser). The operator is recorded as
// revoked_by on every token the erasure ends.
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

// EraseAccount erases one account — the admin Users and ServiceAccounts pages'
// `delete`, which kept its name when deleting became erasing, so an existing
// admin keeps its button, its ACL code and its tests. The same erasure as
// EraseUsers, the operator recorded; it answers the account's id as the delete
// it replaces did. An account already erased is completed, not refused.
func (h *AuthServiceHandler) EraseAccount(ctx context.Context, req *pb.EraseAccountReq) (*pb.EraseAccountResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := h.eraseUser(ctx, req.GetUserId(), operator); err != nil {
		return nil, err
	}
	return &pb.EraseAccountResp{UserId: req.GetUserId()}, nil
}

// eraseUser erases one account in three steps:
//
//  1. BeginUserErasure ends the account's access — disabled, password
//     unusable, every token and device revoked — and leaves its address
//     alone;
//  2. every feature's eraser blanks or spends the rows it owns, the
//     account's reset links are spent, and its sign-in history is
//     pseudonymised;
//  3. EraseUser replaces the address with the placeholder and stamps
//     erased_at.
//
// With a transaction coordinator that is one unit of work. Without one each
// statement commits on its own, and the order is what keeps a partial run
// safe and a retry complete: access ends FIRST, so an erasure stopped at any
// later point never leaves a usable account (a password sign-in, a live
// session) with half of its data gone, and nothing the person does in the
// meantime — a new reset link, a re-enrolled authenticator — can sign anyone
// in; every step is an idempotent UPDATE; and EraseUser — which replaces the
// address the invitation eraser looks for and stamps the erased_at a retry
// reads — comes last, so a failed erasure is not yet marked erased and the
// next attempt does all of it again. An account already erased skips only
// EraseUser; its own `erased_at IS NULL` guard settles a race between two
// operators (NotFound is done).
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
	if _, err := h.Mutation.BeginUserErasure(txCtx, &pb.BeginUserErasureReq{UserId: userID, RevokedBy: operator}); err != nil {
		rollback()
		return err
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
	// The sign-in history (base tier, so not one of the feature erasers):
	// the account's rows, and the rows that named its address without
	// reaching an account, lose the address, client address and user agent.
	if _, err := h.Mutation.EraseSignInEvents(txCtx, &pb.EraseSignInEventsReq{
		UserId:      userID,
		Email:       truncate(normalizeEmail(email), maxAddressLen),
		Placeholder: placeholder,
	}); err != nil {
		rollback()
		return err
	}
	if user.GetErasedAt() == nil {
		if _, err := h.Mutation.EraseUser(txCtx, &pb.EraseUserReq{UserId: userID, Email: placeholder}); notFoundOK(err) != nil {
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

// RevokeDevices revokes each selected device for good — the admin Devices
// page's `revoke` action: every token bound to it is revoked (reason
// DEVICE_REVOKED, the operator as revoked_by) and the Device row is stamped
// revoked, in one transaction per device when the bundle has a coordinator,
// so a device is never left revoked with live sessions or the other way
// round. The key can never sign in to that account again (DEVICE_REVOKED).
// The statements are the ones the `devices` self-service calls use, guarded
// by the device's own account read here first.
//
// A device already revoked is left as it is (its first revocation stands, and
// its tokens were revoked with it); an unknown id is done, not an error, as
// for RevokeSessions. A LEGACY device (no key, recorded before device
// binding) can never be used, but revoking one is allowed and records the
// operator's decision like any other: it is the same two statements.
func (h *AuthServiceHandler) RevokeDevices(ctx context.Context, req *pb.RevokeDevicesReq) (*pb.RevokeDevicesResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if len(req.GetIds()) == 0 {
		return nil, errEmptySelection
	}
	for _, id := range req.GetIds() {
		dev, err := h.Query.GetDevice(ctx, &pb.GetDeviceReq{Id: id})
		if err != nil {
			if notFoundOK(err) == nil {
				continue
			}
			return nil, err
		}
		if dev.GetId() != id {
			// Not the row asked for: an answer that names another row is no
			// answer.
			continue
		}
		if dev.GetRevokedAt() != nil {
			// Already revoked — by its owner's RevokeOtherDevices, say, which
			// spares API tokens. Its tokens and its row stay as the first
			// revocation left them; only the API tokens it created are ended
			// now, which is why an operator revokes it again. Idempotent.
			if err := endApprovedAPITokens(ctx, h, dev.GetUser(), id, operator); err != nil {
				return nil, err
			}
			continue
		}
		userID := dev.GetUser()
		if err := h.inTx(ctx, func(txCtx context.Context) error {
			// The API tokens this device created end with it: a stolen
			// session could have created one bound to the thief's key.
			if err := endApprovedAPITokens(txCtx, h, userID, id, operator); err != nil {
				return err
			}
			if _, err := h.Mutation.RevokeDeviceTokens(txCtx, &pb.RevokeDeviceTokensReq{UserId: userID, DeviceId: id, RevokedBy: operator, KeepTokenId: noTokenKept}); notFoundOK(err) != nil {
				return err
			}
			// NotFound: revoked by someone else since the read — done.
			if _, err := h.Mutation.MarkDeviceRevoked(txCtx, &pb.MarkDeviceRevokedReq{UserId: userID, DeviceId: id}); notFoundOK(err) != nil {
				return err
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return &pb.RevokeDevicesResp{}, nil
}

// RevokeSessions revokes each selected token — the bulk form of
// RevokeSession, for project code. The operator is recorded as revoked_by, the reason is
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
		if _, err := h.Mutation.RevokeUserToken(ctx, &pb.RevokeUserTokenReq{Id: id, RevokedBy: operator, Thumbprint: requestThumbprint(ctx)}); notFoundOK(err) != nil {
			return nil, err
		}
	}
	return &pb.RevokeSessionsResp{}, nil
}

// RevokeSession revokes one token — the admin Sessions page's `delete`, which
// kept its name when deleting became revoking, so an existing admin keeps its
// button, its ACL code and its tests. The operator is recorded as revoked_by,
// the reason is ADMIN_REVOKED and the row stays, listed as revoked; a token
// already revoked keeps its first revocation and is not an error. It answers
// the token's id, as the delete it replaces did.
func (h *AuthServiceHandler) RevokeSession(ctx context.Context, req *pb.RevokeSessionReq) (*pb.RevokeSessionResp, error) {
	operator, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if _, err := h.Mutation.RevokeUserToken(ctx, &pb.RevokeUserTokenReq{Id: req.GetId(), RevokedBy: operator, Thumbprint: requestThumbprint(ctx)}); notFoundOK(err) != nil {
		return nil, err
	}
	return &pb.RevokeSessionResp{TokenId: req.GetId()}, nil
}
