package handlers

import (
	"context"
	"errors"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `password_reset` feature. It is staged into
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
//
// The answer must not differ in TIME either (password_reset gap 3). Both
// paths do the same work before answering — the address lookup — and the
// known address's link is minted after the answer, detached from the request
// (mintResetLinkDetached). Minting inline made a registered address answer an
// INSERT and an event emit slower than an unknown one, and its failure came
// back to the caller: an error only an existing account can produce. Now
// neither the clock nor the error channel says anything.
func (h *AuthServiceHandler) RequestPasswordReset(ctx context.Context, req *pb.RequestPasswordResetReq) (*pb.RequestPasswordResetResp, error) {
	email := normalizeEmail(req.GetEmail())
	userResp, err := h.Query.GetUserByEmail(ctx, &pb.GetUserByEmailReq{Email: email})
	// Unknown email (or any lookup miss): no-op success — never reveal
	// whether the account exists.
	if err != nil || userResp.GetUser() == nil || userResp.GetUser().GetId() == "" {
		return &pb.RequestPasswordResetResp{}, nil
	}
	user := userResp.GetUser()
	detached := context.WithoutCancel(ctx)
	runDetached(func() { _ = h.mintResetLink(detached, user) })
	return &pb.RequestPasswordResetResp{}, nil
}

// runDetached runs a request's follow-up work after the answer is sent. A
// seam so a test can run it inline or hold it.
var runDetached = func(f func()) { go f() }

// mintResetLink stores a fresh reset link for user and emits
// PasswordResetRequested through CreatePasswordResetToken. Its error has no
// caller to reach (see RequestPasswordReset): a link that failed to mint is
// the same to the person as a mail that did not arrive — they ask again.
func (h *AuthServiceHandler) mintResetLink(ctx context.Context, user *pb.User) error {
	token, err := randomURLToken()
	if err != nil {
		return err
	}
	expiresAt := timestamppb.New(time.Now().Add(h.passwordResetTTL()))
	_, err = h.Mutation.CreatePasswordResetToken(ctx, &pb.CreatePasswordResetTokenReq{
		UserId:    user.GetId(),
		TokenHash: sha256Hex(token),
		ExpiresAt: expiresAt,
		Email:     user.GetEmail(), // canonical stored email for the delivery channel
		Token:     token,           // plaintext — event-only, never persisted
	})
	return err
}

// ResetPassword consumes a reset token (atomically: single-use + not
// expired), sets the new password, and revokes every existing session so a
// stolen-then-reset credential can't keep a live session. Any bad token is
// an opaque Unauthenticated — no enumeration of valid tokens.
func (h *AuthServiceHandler) ResetPassword(ctx context.Context, req *pb.ResetPasswordReq) (*pb.ResetPasswordResp, error) {
	// The consume and the write it authorises are ONE unit.
	//
	// Apart, the token is spent before the password changes: a failure in
	// between burns a valid link and leaves the old password in place, so the
	// person is left with NEITHER — and they asked for that link precisely
	// because they could not get in. The consume must come first
	// (it is the check), so the only honest arrangement is to roll the pair
	// back together.
	var tx *distx.TxHandle
	txCtx := ctx
	var err error
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	userID, err := h.consumeAndSetPassword(txCtx, sha256Hex(req.GetToken()), req.GetNewPassword())
	if err == nil && tx != nil {
		// Every existing token (sessions + API tokens; reason PASSWORD_RESET,
		// the rows stay) is revoked IN the reset's transaction: a reset
		// implies the prior credential may be compromised, and a thief's
		// session that survives the reset is the one outcome the reset exists
		// to prevent (password_reset gap 4). A sweep that fails rolls the
		// whole reset back — the password unchanged, the link not spent — so
		// the person retries instead of believing they are safe.
		_, err = h.Mutation.RevokeTokensForReset(txCtx, &pb.RevokeTokensForResetReq{UserId: userID})
	}
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
		return &pb.ResetPasswordResp{SessionsRevoked: true}, nil
	}

	// Without a transaction coordinator (a hand-built handler; a generated
	// bundle always wires one) the statements commit one by one: the password
	// is already written, so a failed sweep cannot undo it. It is still never
	// silent — the outcome is REPORTED, so the person is told to sign out
	// everywhere rather than left believing the reset ended every session.
	_, sweepErr := h.Mutation.RevokeTokensForReset(ctx, &pb.RevokeTokensForResetReq{UserId: userID})
	return &pb.ResetPasswordResp{SessionsRevoked: sweepErr == nil}, nil
}

// consumeAndSetPassword spends the token and writes the new password. Kept
// together so one transaction can hold them; separated again, a rollback has
// no password write to undo and the link is gone either way.
//
// Hashing sits BETWEEN them rather than before: hashing first would pay an
// argon2 derivation for every bogus token somebody posts, on an endpoint that
// needs no credential to reach.
func (h *AuthServiceHandler) consumeAndSetPassword(txCtx context.Context, tokenHash, newPassword string) (string, error) {
	consumed, err := h.Mutation.ConsumePasswordResetToken(txCtx, &pb.ConsumePasswordResetTokenReq{
		TokenHash: tokenHash,
	})
	if err != nil {
		// Through the opaque constructor, not raw.
		//
		// The statement carries RETURNING, so "no live row" arrives as
		// NotFound — an ERROR, not an empty response. Returned raw it would
		// tell a caller apart "this token is unknown/used/expired" from every
		// other outcome, which is the enumeration the opaque refusal exists to
		// prevent, and the `== ""` branch below is unreachable for it: that
		// branch handles a shape this mutation never produces.
		//
		// Unauthenticated() classifies: a refusal stays opaque, an outage
		// comes back as Unavailable rather than dressed as a bad token.
		return "", Unauthenticated(err)
	}
	userID := consumed.GetUserId()
	if userID == "" {
		return "", Unauthenticated(errResetTokenInvalid)
	}
	hash, err := h.PasswordHash.Hash(newPassword)
	if err != nil {
		return "", hashPasswordErr(txCtx, err, "new_password")
	}
	if _, err := h.Mutation.UpdateUserPassword(txCtx, &pb.UpdateUserPasswordReq{
		UserId:       userID,
		PasswordHash: hash,
	}); err != nil {
		return "", err
	}
	// Every other link the person asked for dies with this one: each would
	// set the password again, and a link sitting in a mailbox someone else
	// reads is exactly what a reset is meant to end.
	if err := spendResetLinks(txCtx, h, userID); err != nil {
		return "", err
	}
	return userID, nil
}

// init lets the always-compiled password paths spend reset links when this
// feature is staged (see spendResetLinks in auth_service.go).
func init() {
	spendResetLinks = func(ctx context.Context, h *AuthServiceHandler, userID string) error {
		_, err := h.Mutation.SpendPasswordResetTokens(ctx, &pb.SpendPasswordResetTokensReq{UserId: userID})
		return err
	}
}
