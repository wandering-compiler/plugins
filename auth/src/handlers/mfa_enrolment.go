package handlers

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/wandering-compiler/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// This file implements the `two_factor_enrolment` feature: the
// two_factor_policy value enrol, under which an account without a confirmed
// authenticator sets one up at sign-in instead of getting a code by message.
// Staged only when the activation enables it (plugin.yaml go_files); without
// it the seams below stay nil, enrol refuses the boot and an organization's
// policy, and VerifyMfa completes no enrolment challenge.
//
// The challenge SignIn raises is what the person holds instead of a session:
// bound to the key that passed the password, with its TTL, attempt budget and
// single-use consume — VerifyMfa's, unchanged. Nothing else is issued, so no
// token exists that would have to be limited to the enrolment.

func init() {
	enrolmentChallenge = signInEnrolmentChallenge
	confirmEnrolment = confirmEnrolmentAtSignIn
}

// signInEnrolmentChallenge raises the enrolment challenge through the
// issuance seam (superseding, under the cap) and answers it: mfa_required and
// enrolment_required, no code — CreateEnrolmentChallenge emits nothing, so no
// delivery channel is handed an empty one.
func signInEnrolmentChallenge(ctx context.Context, h *AuthServiceHandler, user *pb.User, thumbprint string, public bool) (*pb.SignInResp, error) {
	req := &pb.CreateMfaChallengeReq{UserId: user.GetId(), Thumbprint: thumbprint, PublicComputer: public}
	created, err := h.issueMfaChallenge(ctx, req, func(txCtx context.Context) (*pb.CreateMfaChallengeResp, error) {
		return h.Mutation.CreateEnrolmentChallenge(txCtx, &pb.CreateEnrolmentChallengeReq{
			UserId:         user.GetId(),
			Thumbprint:     thumbprint,
			PublicComputer: public,
		})
	})
	if err != nil {
		return nil, err
	}
	return &pb.SignInResp{
		MfaRequired:       true,
		ChallengeId:       created.GetChallenge().GetId(),
		EnrolmentRequired: true,
	}, nil
}

// EnrollTotpAtSignIn sets up the authenticator of an account that enrols at
// sign-in: under two_factor_policy=enrol, SignIn answered an enrolment
// challenge instead of sending a code, and the challenge stands in for the
// session the person does not have yet. It must be live, an enrolment's, and
// signed by the key that passed the password; the account must have no
// confirmed authenticator (one confirmed since is asked for by VerifyMfa
// instead). Calling it again replaces the authenticator not yet confirmed.
// VerifyMfa with its first code confirms it and issues the session.
//
// Every refusal is VerifyMfa's opaque one: the challenge id is all a caller
// holds, and an answer that told an enrolment from a code challenge, or a
// live one from a spent one, would tell them about the account.
func (h *AuthServiceHandler) EnrollTotpAtSignIn(ctx context.Context, req *pb.EnrollTotpAtSignInReq) (*pb.EnrollTotpResp, error) {
	thumbprint, err := mintThumbprint(ctx)
	if err != nil {
		return nil, err
	}
	if !h.TwoFactorTOTP {
		return nil, refusal(ctx, codes.FailedPrecondition, "two_factor: the built-in authenticator is off (two_factor_totp=false)",
			CodeTotpUnavailable, "", MsgTotpUnavailable, nil)
	}
	resp, err := h.Query.GetMfaChallenge(ctx, &pb.GetMfaChallengeReq{ChallengeId: req.GetChallengeId()})
	if err != nil || resp.GetChallenge() == nil {
		if operationalCode(err) != codes.OK {
			return nil, Unauthenticated(err)
		}
		return nil, UnauthenticatedMfaCode(errMfaChallengeInvalid)
	}
	ch := resp.GetChallenge()
	created := ch.GetCreatedAt()
	if !ch.GetEnrol() || ch.GetConsumedAt() != nil || ch.GetAttempts() >= maxMfaAttempts ||
		created == nil || time.Now().After(created.AsTime().Add(h.mfaTTL())) {
		return nil, UnauthenticatedMfaCode(errMfaChallengeInvalid)
	}
	if !sameKey(ch.GetThumbprint(), thumbprint) {
		return nil, UnauthenticatedMfaCode(errMfaChallengeOtherDevice)
	}
	userID := ch.GetUserId()
	enrolled, _, err := h.totpEnrolled(ctx, userID)
	if err != nil {
		return nil, err
	}
	if enrolled {
		return nil, UnauthenticatedMfaCode(errMfaChallengeInvalid)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	if err := h.inTx(ctx, func(txCtx context.Context) error {
		return h.replaceTotpSecret(txCtx, userID, secret)
	}); err != nil {
		return nil, err
	}
	return h.enrolmentOf(ctx, userID, secret)
}

// confirmEnrolmentAtSignIn is VerifyMfa's check of an enrolment challenge,
// inside its transaction: code is the first one of the authenticator
// EnrollTotpAtSignIn set up, which it confirms, and the response gets the
// account's new recovery codes. An authenticator confirmed since the
// challenge was raised is checked as any sign-in's (verifyMfaCode), and no
// codes are minted.
func confirmEnrolmentAtSignIn(txCtx context.Context, h *AuthServiceHandler, userID, code, thumbprint string) (bool, func(*pb.VerifyMfaResp), error) {
	enrolled, row, err := h.totpEnrolled(txCtx, userID)
	if err != nil {
		return false, nil, err
	}
	if enrolled {
		return h.verifyMfaCode(txCtx, userID, "", code), nil, nil
	}
	if row == nil {
		return false, nil, nil
	}
	plain, err := h.seedOf(txCtx, row)
	if err != nil {
		return false, nil, err
	}
	ok, err := h.acceptTotp(txCtx, row, plain, code)
	if err != nil || !ok {
		return false, nil, err
	}
	if _, err := h.Mutation.ConfirmTotpSecret(txCtx, &pb.ConfirmTotpSecretReq{UserId: userID, Thumbprint: thumbprint}); err != nil {
		return false, nil, err
	}
	recovery, err := h.replaceRecoveryCodes(txCtx, userID)
	if err != nil {
		return false, nil, err
	}
	return true, func(out *pb.VerifyMfaResp) { out.RecoveryCodes = recovery }, nil
}
