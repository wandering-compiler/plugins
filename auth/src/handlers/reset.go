package handlers

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `password_reset` feature (E1). It is staged into
// a bundle only when the activation enables `password_reset` (plugin.yaml
// maps the feature to this file via go_files). Standalone (the plugin
// author's own `go test`) always compiles it.

const defaultPasswordResetTTLSeconds = 60 * 60 // 1 hour

// errResetTokenInvalid is the opaque error for any bad ResetPassword: an
// unknown / expired / already-used token. Never distinguishes the cause.
var errResetTokenInvalid = errors.New("password reset token invalid/expired/used")

func (h *AuthServiceHandler) passwordResetTTL() time.Duration {
	if h.PasswordResetTTLSeconds > 0 {
		return time.Duration(h.PasswordResetTTLSeconds) * time.Second
	}
	return defaultPasswordResetTTLSeconds * time.Second
}

// RequestPasswordReset mints a single-use reset token for the account with
// the given email and emits PasswordResetRequested (carrying the plaintext
// token + email) for a hand-written delivery channel. It ALWAYS returns an
// empty success — whether or not the email exists — so the endpoint can't
// be used to enumerate registered accounts. The token's hash + expiry are
// stored; the plaintext is never persisted.
func (h *AuthServiceHandler) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetReq) (*pb.RequestPasswordResetResp, error) {
	email := normalizeEmail(req.GetEmail())
	userResp, err := h.Query.GetUserByEmail(ctx, &pb.GetUserByEmailReq{Email: email})
	// Unknown email (or any lookup miss): no-op success — never reveal
	// whether the account exists.
	if err != nil || userResp.GetUser() == nil || userResp.GetUser().GetId() == "" {
		return &pb.RequestPasswordResetResp{}, nil
	}
	user := userResp.GetUser()

	token, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(time.Now().Add(h.passwordResetTTL()))
	if _, err := h.Mutation.CreatePasswordResetToken(ctx, &pb.CreatePasswordResetTokenReq{
		UserId:    user.GetId(),
		TokenHash: sha256Hex(token),
		ExpiresAt: expiresAt,
		Email:     user.GetEmail(), // canonical stored email for the delivery channel
		Token:     token,           // plaintext — event-only, never persisted
	}); err != nil {
		return nil, err
	}
	return &pb.RequestPasswordResetResp{}, nil
}

// ResetPassword consumes a reset token (atomically: single-use + not
// expired), sets the new password, and revokes every existing session so a
// stolen-then-reset credential can't keep a live session. Any bad token is
// an opaque Unauthenticated — no enumeration of valid tokens.
func (h *AuthServiceHandler) ResetPassword(ctx context.Context, req *pb.ResetPasswordReq) (*pb.ResetPasswordResp, error) {
	consumed, err := h.Mutation.ConsumePasswordResetToken(ctx, &pb.ConsumePasswordResetTokenReq{
		TokenHash: sha256Hex(req.GetToken()),
	})
	if err != nil {
		return nil, err
	}
	userID := consumed.GetUserId()
	if userID == "" {
		// Zero rows matched the live-token WHERE → invalid/expired/used.
		return nil, Unauthenticated(errResetTokenInvalid)
	}

	hash, err := h.PasswordHash.Hash(req.GetNewPassword())
	if err != nil {
		return nil, err
	}
	if _, err := h.Mutation.UpdateUserPassword(ctx, &pb.UpdateUserPasswordReq{
		UserId:       userID,
		PasswordHash: hash,
	}); err != nil {
		return nil, err
	}
	// Revoke every existing token (sessions + API tokens): a reset implies the
	// prior credential may be compromised. Still best-effort — the password is
	// already changed and a failed sweep must not undo it — but the outcome is
	// REPORTED now.
	//
	// It used to be `_, _ =` under a comment saying the error was "logged by
	// the caller's interceptor". It was discarded here, before any interceptor
	// could see it, and this plugin has no logging at all. So the one case the
	// sweep exists for — a reset after a theft — could leave the thief's
	// session alive and tell nobody, least of all the person who had just
	// reset their password believing it had done something.
	_, sweepErr := h.Mutation.DeleteUserSessionsForReset(ctx, &pb.DeleteUserSessionsForResetReq{UserId: userID})
	return &pb.ResetPasswordResp{SessionsRevoked: sweepErr == nil}, nil
}
