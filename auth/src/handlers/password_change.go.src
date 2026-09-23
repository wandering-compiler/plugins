package handlers

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
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

// ChangePassword verifies the caller's current password and replaces it.
//
// ⚠️ It does NOT revoke the caller's other sessions, and that is a real
// limitation rather than an oversight. Bearer tokens do not derive from the
// password, so they keep working: changing a password after a token has
// leaked does not evict whoever holds it. Revoking them needs
// DeleteUserSessionsForReset (owned by `password_reset`) or
// DeleteAllUserTokens (owned by `devices`), and reaching into either would
// make this feature depend on one of them — the exact dependency it exists
// to avoid. Documented here so a deployment can decide knowingly; the fix
// is a session-revocation primitive this feature can own, not a quiet
// borrow from a neighbour.
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
	currentHash := got.GetUser().GetPasswordHash()
	ok, _, _ := h.PasswordHash.VerifyAndRotate(currentHash, req.GetCurrentPassword(), nil)
	if !ok {
		return nil, Unauthenticated(errCurrentPasswordWrong)
	}

	// Hashing is CPU-bound and deliberately outside any transaction, the
	// same shape SignUp uses.
	hashed, err := h.PasswordHash.Hash(req.GetNewPassword())
	if err != nil {
		return nil, err
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
	if _, err := h.Mutation.UpdateUserPasswordIfUnchanged(ctx, &pb.UpdateUserPasswordIfUnchangedReq{
		UserId:       userID,
		PasswordHash: hashed,
		CurrentHash:  currentHash,
	}); err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, Unauthenticated(errCurrentPasswordWrong)
		}
		return nil, err
	}
	return &pb.ChangePasswordResp{}, nil
}
