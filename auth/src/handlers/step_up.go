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

// passwordStepUpGates run before ConfirmPassword checks anything:
// step_up_code.go appends the one that refuses it when step_up_password is
// off. Empty without step_up_code: the password is then the only step-up.
var passwordStepUpGates []func(ctx context.Context, h *AuthServiceHandler) error

func init() {
	apiTokenStepUpChecks = append(apiTokenStepUpChecks, requireRecentStepUp)
}

// requireRecentStepUp is CreateApiToken's ask (api_token_step_up_seconds):
// the caller's session stepped up no longer ago than that. Off at 0.
// Reads the stamp, as a consumer of this feature would; a session without
// one, or with an older one, is refused with the code the client steps up on.
func requireRecentStepUp(ctx context.Context, h *AuthServiceHandler, userID, sessionTokenID string) error {
	if h.APITokenStepUpSeconds <= 0 {
		return nil
	}
	needs := refusal(ctx, codes.PermissionDenied, "CreateApiToken: the session has not stepped up recently",
		CodeCreateNeedsStepUp, "", MsgNeedsStepUp, nil)
	if sessionTokenID == "" {
		return needs
	}
	got, err := h.Query.GetSessionSteppedUpAt(ctx, &pb.GetSessionSteppedUpAtReq{TokenId: sessionTokenID, UserId: userID})
	if err != nil {
		if notFoundOK(err) == nil {
			return needs
		}
		return err
	}
	at := got.GetSteppedUpAt()
	if at == nil {
		return needs
	}
	age := time.Since(at.AsTime())
	// A stamp from the future (clock skew between the database and this
	// process) counts as fresh only within a minute of it.
	if age > time.Duration(h.APITokenStepUpSeconds)*time.Second || age < -time.Minute {
		return needs
	}
	return nil
}

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
	for _, gate := range passwordStepUpGates {
		if err := gate(ctx, h); err != nil {
			return nil, err
		}
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
