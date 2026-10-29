package handlers

import (
	"context"
	"errors"

	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `password_change` feature: an authenticated
// principal rotating its OWN password. Staged only when the activation
// enables `password_change` (plugin.yaml maps the feature to this file via
// go_files); the plugin author's own `go test` always compiles it.
//
// Distinct from `password_reset`, which is the FORGOTTEN-password flow and
// needs a channel to deliver a token. Here the proof is the current
// password, so a deployment with no way to send mail can still let people
// change their credentials — which is not a nicety: without it the only
// way to rotate a password is an operator with shell access to the box.

// errCurrentPasswordWrong is deliberately not more specific. The caller is
// already authenticated, so this leaks nothing about whether an account
// exists — but a message distinguishing "wrong password" from "account has
// no password set" would say something about the account's auth method
// that the caller has not proven they may know.
var errCurrentPasswordWrong = errors.New("current password does not match")

// currentPasswordWrong is the refusal of a wrong current password: on the
// field, as ConfirmPassword's. Not Unauthenticated — the caller's session is
// fine, and a client answers Unauthenticated by signing the person out.
func currentPasswordWrong(ctx context.Context) error {
	return refusal(ctx, codes.PermissionDenied, errCurrentPasswordWrong.Error(),
		CodePasswordNotConfirmed, "current_password", MsgPasswordNotConfirmed, nil)
}

// nilUUID names no token: RevokeOtherSessionTokens keeps none when the caller
// holds no session (an API-token bearer). The column is a uuid, so an empty
// string would not compare — it would fail to bind.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// ChangePassword verifies the caller's current password and replaces it,
// and ends every OTHER session of the account in the same unit of work.
//
// Bearer tokens do not derive from the password, so without the sweep they
// kept working: changing a password after a session leaked did not evict
// whoever held it. The sweep is RevokeOtherSessionTokens, a primitive this
// feature owns — not RevokeTokensForReset (`password_reset`) or
// RevokeAllUserTokens (`devices`), which would make this feature depend on
// one of them. The sessions are revoked (reason PASSWORD_CHANGED, the caller
// as revoked_by), not deleted. API tokens are kept; see below.
func (h *AuthServiceHandler) ChangePassword(ctx context.Context, req *pb.ChangePasswordReq) (*pb.ChangePasswordResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}

	// Read the stored hash for the AUTHENTICATED principal, never for an
	// address out of the request: a handler that looked the user up by a
	// client-supplied email would let anyone with a valid token change
	// anybody's password by knowing their address.
	// GetUserById, not GetUser: the latter is the `user_admin` admin read
	// and projects NO password_hash, by design — a PASSWORD column that
	// must never leave the storage tier for a list or detail page.
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	// The current password is a guess like a sign-in's, so it spends the same
	// per-account budget, counted before it is checked: a stolen session is
	// no unlimited oracle for the password (password_change/guess-budget).
	md, _ := metadata.FromIncomingContext(ctx)
	thumbprint := firstMeta(md, dpopJKTKey)
	if err := spendSignInBudget(ctx, h, userID, thumbprint); err != nil {
		if errors.Is(err, errSignInThrottled) {
			return nil, refusal(ctx, codes.ResourceExhausted, "password_change: the account's password guess budget is spent",
				CodePasswordAttemptsSpent, "current_password", MsgPasswordAttemptsSpent, nil)
		}
		return nil, err
	}
	currentHash := got.GetUser().GetPasswordHash()
	ok, _, _ := h.PasswordHash.VerifyAndRotate(currentHash, req.GetCurrentPassword(), nil)
	if !ok {
		return nil, currentPasswordWrong(ctx)
	}
	resetSignInBudget(ctx, h, userID, thumbprint)

	// Hashing is CPU-bound and deliberately outside any transaction, the
	// same shape SignUp uses.
	hashed, err := h.PasswordHash.Hash(req.GetNewPassword())
	if err != nil {
		return nil, hashPasswordErr(ctx, err, "new_password")
	}
	// COMPARE-AND-SWAP on the hash that was just verified, not a bare write
	// keyed on the user id.
	//
	// Everything above this line is a READ followed by a decision, and the
	// hash on line 64 puts tens of milliseconds between that decision and the
	// write — not incidentally, but because argon2id is built to be slow. A
	// write keyed only on the id lets the last writer win across that window:
	// someone who knows the old password can overwrite a rotation the account's
	// owner just made (the owner's new password verifies against nothing the
	// attacker holds, yet the attacker's write lands second and stands), and
	// two honest tabs lose one of the two changes with no sign that they did.
	//
	// Zero rows means the stored hash is no longer the one verified: somebody
	// else changed the password in between. That is reported as the current
	// password not matching, which by then is precisely true — the proof this
	// request carried is stale — and keeps the refusal identical to the wrong-
	// password case, which is what stops the two being told apart.
	// The new password and the end of every OTHER session are one unit of
	// work. A person changes a password because someone else may have it, and
	// whoever has it may also hold a session: a change that left those alive
	// would tell the person "done" while the other side stayed signed in.
	// Together they commit or neither does — a failed sign-out keeps the old
	// password, and the person is told the change failed.
	//
	// The caller's own session is kept (they are in the middle of using it);
	// a caller on an API token has none, and keeps no session. API tokens
	// stay: they are credentials minted on purpose, for CI, and a password
	// change is not a decision about them — revoke one with RevokeApiToken.
	var tx *distx.TxHandle
	txCtx := ctx
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	fail := func(err error) (*pb.ChangePasswordResp, error) {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	if _, err := h.Mutation.UpdateUserPasswordIfUnchanged(txCtx, &pb.UpdateUserPasswordIfUnchangedReq{
		UserId:       userID,
		PasswordHash: hashed,
		CurrentHash:  currentHash,
	}); err != nil {
		if status.Code(err) == codes.NotFound {
			return fail(currentPasswordWrong(ctx))
		}
		return fail(err)
	}
	keep := callerSessionTokenID(ctx)
	if keep == "" {
		keep = nilUUID
	}
	if _, err := h.Mutation.RevokeOtherSessionTokens(txCtx, &pb.RevokeOtherSessionTokensReq{
		UserId:      userID,
		KeepTokenId: keep,
	}); err != nil {
		return fail(err)
	}
	// A reset link asked for before the change would undo it.
	if err := spendResetLinks(txCtx, h, userID); err != nil {
		return fail(err)
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return &pb.ChangePasswordResp{}, nil
}
