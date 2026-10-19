package handlers

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `step_up` feature: the signed-in person confirms
// their password in their CURRENT session, and the session token records when
// (UserToken.stepped_up_at). Staged only when the activation enables
// `step_up` (plugin.yaml maps the feature to this file via go_files).
//
// It answers one question a sensitive action has to ask and a valid token
// cannot: "did the person prove, just now, that they are themselves?" A token
// and its device key can be copied off a machine; the password is not on it.
// The consumer reads its caller's own token row and asks for a confirmation
// recent enough for what it guards — this feature records, it does not decide.
// The console's write grants for secrets are the first such consumer.

// The guess budget, per session: the step-up exists for a token in the wrong
// hands, which would otherwise have an unbounded online oracle for the
// password. The same numbers as the authenticator's step-up (mfa_recovery.go).
const (
	maxPasswordStepUpAttempts = 5
	passwordStepUpLockout     = 15 * time.Minute
)

// ConfirmPassword verifies the caller's password and stamps their session.
//
// A session only: an API token has no session to step up, and confirming a
// password through one would let a token minted for CI vouch for a person.
// The stamp is on the caller's OWN token, keyed on the authenticated user, so
// a confirmation can never land on another session.
func (h *AuthServiceHandler) ConfirmPassword(ctx context.Context, req *pb.ConfirmPasswordReq) (*pb.ConfirmPasswordResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	session := callerSessionTokenID(ctx)
	locked := refusal(ctx, codes.ResourceExhausted, "step_up: locked after too many wrong passwords",
		CodePasswordStepUpLocked, "", MsgPasswordStepUpLocked, nil)
	// Counted BEFORE the check, in one statement: a guess that is not
	// accounted for is not checked.
	att, err := h.Mutation.RecordPasswordStepUpAttempt(ctx, &pb.RecordPasswordStepUpAttemptReq{TokenId: session, UserId: userID})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, locked // no row: locked (or the session just ended)
		}
		return nil, err
	}
	if att.GetAttempts() > maxPasswordStepUpAttempts {
		_, _ = h.Mutation.LockPasswordStepUp(ctx, &pb.LockPasswordStepUpReq{TokenId: session, Until: timestamppb.New(time.Now().Add(passwordStepUpLockout))})
		return nil, locked
	}
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	if ok, _, _ := h.PasswordHash.VerifyAndRotate(got.GetUser().GetPasswordHash(), req.GetPassword(), nil); !ok {
		return nil, refusal(ctx, codes.PermissionDenied, "the password does not match the caller's",
			CodePasswordNotConfirmed, "password", MsgPasswordNotConfirmed, nil)
	}
	marked, err := h.Mutation.MarkSessionSteppedUp(ctx, &pb.MarkSessionSteppedUpReq{
		TokenId: session,
		UserId:  userID,
	})
	if err != nil {
		// No row: the session was revoked between Authenticate and here.
		return nil, err
	}
	return &pb.ConfirmPasswordResp{SteppedUpAt: marked.GetSteppedUpAt()}, nil
}
