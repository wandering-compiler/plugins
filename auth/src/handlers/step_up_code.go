package handlers

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `step_up_code` feature: a session steps up with
// the second factor instead of the password. Staged only when the activation
// enables `step_up_code` (plugin.yaml go_files), which needs step_up (the
// stamp and the guess budget on the session row) and two_factor (the
// authenticator and the recovery codes).
//
// The proof is the one the sign-in asks for. A person with a confirmed
// authenticator types its code (or a recovery code); anyone else gets a
// six-digit code mailed by a hand-written channel, exactly as the sign-in's
// fallback is: the plaintext travels once, in StepUpCodeRequested, and only
// its hash is kept — on the caller's OWN session row, so a code completes the
// session that asked for it and no other.
//
// The stamp is ConfirmPassword's (UserToken.stepped_up_at), so a consumer that
// asks for a recent step-up does not care which proof gave it. With
// step_up_password off, the second factor is the only one: a stolen session
// plus a phished password is then not enough.

// stepUpCodeResendGap is how soon a session may have a new code mailed: a
// stolen session must not be able to flood the person's mailbox.
const stepUpCodeResendGap = time.Minute

// errSessionGone — the caller's session ended between Authenticate and the
// write. The caller signs in again.
var errSessionGone = errors.New("step_up: the session has ended")

// The proofs RequestStepUpCode names.
const (
	stepUpMethodAuthenticator = "authenticator"
	stepUpMethodEmail         = "email"
)

// The sentences a person reads for these refusals. Mirrored into plugin.yaml
// msgids by `make plugin-msgids-sync`.
//
//w17:msgid
const (
	MsgStepUpPasswordOff = "Confirm it is you with your authenticator app or the code we email you." //nolint:gosec // G101: a message about passwords, not one
	MsgStepUpCodeWrong   = "That code is not right, or it has expired. Ask for a new one."
)

// The codes a client branches on for the same refusals.
const (
	// CodeStepUpPasswordOff — ConfirmPassword with step_up_password off: the
	// client asks for the second factor instead (RequestStepUpCode).
	CodeStepUpPasswordOff = "STEP_UP_PASSWORD_OFF"
	CodeStepUpCodeWrong   = "STEP_UP_CODE_WRONG"
)

func init() {
	passwordStepUpGates = append(passwordStepUpGates, passwordStepUpAllowed)
}

// passwordStepUpAllowed refuses ConfirmPassword when the deployment made the
// second factor the only step-up (step_up_password=false).
func passwordStepUpAllowed(ctx context.Context, h *AuthServiceHandler) error {
	if !h.NoPasswordStepUp {
		return nil
	}
	return refusal(ctx, codes.FailedPrecondition, "step_up: the password step-up is off (step_up_password=false)",
		CodeStepUpPasswordOff, "", MsgStepUpPasswordOff, nil)
}

// RequestStepUpCode tells the caller which proof ConfirmStepUp takes for
// their session, and mails a code when that is the one.
//
// A session only, like ConfirmPassword. A code sent less than a minute ago is
// not replaced: the answer is "email" with that code's expiry, so a client
// that asks twice does not mail twice.
func (h *AuthServiceHandler) RequestStepUpCode(ctx context.Context, _ *pb.RequestStepUpCodeReq) (*pb.RequestStepUpCodeResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	session := callerSessionTokenID(ctx)
	enrolled, _, err := h.totpEnrolled(ctx, userID)
	if err != nil {
		// Not "mail a code": an unreadable enrolment cannot tell us the
		// person has no authenticator.
		return nil, err
	}
	if enrolled && h.TwoFactorTOTP {
		return &pb.RequestStepUpCodeResp{Method: stepUpMethodAuthenticator}, nil
	}

	code, err := generateNumericCode(mfaCodeDigits)
	if err != nil {
		return nil, err
	}
	hash, err := h.PasswordHash.Hash(code)
	if err != nil {
		return nil, err
	}
	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expiresAt := timestamppb.New(now.Add(h.mfaTTL()))
	_, err = h.Mutation.SetStepUpCode(ctx, &pb.SetStepUpCodeReq{
		TokenId:      session,
		UserId:       userID,
		CodeHash:     hash,
		ResendBefore: timestamppb.New(now.Add(-stepUpCodeResendGap)),
		Email:        got.GetUser().GetEmail(),
		Code:         code,
		ExpiresAt:    expiresAt,
		Thumbprint:   requestThumbprint(ctx),
	})
	if err == nil {
		return &pb.RequestStepUpCodeResp{Method: stepUpMethodEmail, ExpiresAt: expiresAt}, nil
	}
	if notFoundOK(err) != nil {
		return nil, err
	}
	// No row: a code went out less than a minute ago, or the session ended
	// since Authenticate. The row tells which.
	out, err := h.Query.GetSessionStepUp(ctx, &pb.GetSessionStepUpReq{TokenId: session, UserId: userID})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, Unauthenticated(errSessionGone)
		}
		return nil, err
	}
	if out.GetSentAt() == nil {
		return nil, Unauthenticated(errSessionGone)
	}
	return &pb.RequestStepUpCodeResp{
		Method:    stepUpMethodEmail,
		ExpiresAt: timestamppb.New(out.GetSentAt().AsTime().Add(h.mfaTTL())),
	}, nil
}

// ConfirmStepUp checks the caller's second factor and stamps their session.
//
// Every guess is counted on the session first, in the budget ConfirmPassword
// uses (five wrong in a row lock the session's step-up for fifteen minutes):
// a guess that is not accounted for is not checked, and a stolen session gets
// one budget whichever proof it tries.
func (h *AuthServiceHandler) ConfirmStepUp(ctx context.Context, req *pb.ConfirmStepUpReq) (*pb.ConfirmStepUpResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	if err := requireSessionCaller(ctx); err != nil {
		return nil, err
	}
	session := callerSessionTokenID(ctx)
	locked := stepUpLocked(ctx)
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
	wrong := refusal(ctx, codes.PermissionDenied, "step_up: the code does not match",
		CodeStepUpCodeWrong, "code", MsgStepUpCodeWrong, nil)

	enrolled, row, err := h.totpEnrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if enrolled && h.TwoFactorTOTP {
		ok, err := h.acceptAuthenticatorOrRecovery(ctx, userID, row, req.GetCode())
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, wrong
		}
		marked, err := h.Mutation.MarkSessionSteppedUp(ctx, &pb.MarkSessionSteppedUpReq{TokenId: session, UserId: userID})
		if err != nil {
			return nil, err
		}
		return &pb.ConfirmStepUpResp{SteppedUpAt: marked.GetSteppedUpAt()}, nil
	}

	out, err := h.Query.GetSessionStepUp(ctx, &pb.GetSessionStepUpReq{TokenId: session, UserId: userID})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, wrong
		}
		return nil, err
	}
	hash, sent := out.GetCodeHash(), out.GetSentAt()
	if hash == "" || sent == nil || time.Since(sent.AsTime()) > h.mfaTTL() {
		return nil, wrong
	}
	if ok, _, _ := h.PasswordHash.VerifyAndRotate(hash, req.GetCode(), nil); !ok {
		return nil, wrong
	}
	// Spent with the stamp, and only while it is still the live code: a
	// second request with the same code, or one racing a newer code, gets
	// no row.
	marked, err := h.Mutation.ConsumeStepUpCode(ctx, &pb.ConsumeStepUpCodeReq{TokenId: session, UserId: userID, CodeHash: hash})
	if err != nil {
		if notFoundOK(err) == nil {
			return nil, wrong
		}
		return nil, err
	}
	return &pb.ConfirmStepUpResp{SteppedUpAt: marked.GetSteppedUpAt()}, nil
}

// acceptAuthenticatorOrRecovery takes the authenticator's current code (its
// time step claimed, so it is used once) or one of the recovery codes.
func (h *AuthServiceHandler) acceptAuthenticatorOrRecovery(ctx context.Context, userID string, row *pb.UserTotpSecret, code string) (bool, error) {
	if len(normaliseRecoveryCode(code)) == recoveryCodeLen {
		return h.acceptRecoveryCode(ctx, userID, code), nil
	}
	seed, err := h.seedOf(ctx, row)
	if err != nil {
		return false, err
	}
	return h.acceptTotp(ctx, row, seed, code)
}
