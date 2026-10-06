package handlers

import (
	"context"
	"errors"
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"github.com/wandering-compiler/sdk/go/service/tx/distx"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// This file implements the `email_verification` feature (E1). Staged only
// when the activation enables `email_verification` (plugin.yaml go_files).

const defaultEmailVerificationTTLSeconds = 24 * 60 * 60 // 24 hours

// errVerifyTokenInvalid is the opaque error for a bad VerifyEmail.
var errVerifyTokenInvalid = errors.New("email verification token invalid/expired/used")

func (h *AuthServiceHandler) emailVerificationTTL() time.Duration {
	if h.EmailVerificationTTLSeconds > 0 {
		return time.Duration(h.EmailVerificationTTLSeconds) * time.Second
	}
	return defaultEmailVerificationTTLSeconds * time.Second
}

// RequestEmailVerification mints a single-use verification token for the
// CALLER (bearer-authenticated — you verify your own address) and emits
// EmailVerificationRequested for a hand-written delivery channel. The
// token hash + expiry are stored; the plaintext is event-only.
func (h *AuthServiceHandler) RequestEmailVerification(ctx context.Context, req *pb.RequestEmailVerificationReq) (*pb.RequestEmailVerificationResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	userResp, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	user := userResp.GetUser()
	if user == nil || user.GetId() == "" {
		return nil, Unauthenticated(errVerifyTokenInvalid)
	}

	token, err := randomURLToken()
	if err != nil {
		return nil, err
	}
	expiresAt := timestamppb.New(time.Now().Add(h.emailVerificationTTL()))
	if _, err := h.Mutation.CreateEmailVerificationToken(ctx, &pb.CreateEmailVerificationTokenReq{
		UserId:    user.GetId(),
		TokenHash: sha256Hex(token),
		ExpiresAt: expiresAt,
		Email:     user.GetEmail(),
		Token:     token,
	}); err != nil {
		return nil, err
	}
	return &pb.RequestEmailVerificationResp{}, nil
}

// VerifyEmail consumes a verification token (atomically: single-use + not
// expired) and stamps the user's email_verified_at. Unauthenticated (the
// link click carries no session). Any bad token is an opaque error.
func (h *AuthServiceHandler) VerifyEmail(ctx context.Context, req *pb.VerifyEmailReq) (*pb.VerifyEmailResp, error) {
	// Same pairing as ResetPassword: the consume spends the token and the
	// write is what it authorised. Apart, a failure between them burns a
	// valid link and leaves the address unverified, so the person has to ask
	// for another one to reach a state the first one already paid for
	// (a consumer).
	var tx *distx.TxHandle
	txCtx := ctx
	var err error
	if h.DistTx != nil {
		if tx, txCtx, err = distx.Begin(ctx, h.DistTx, &distxpb.BeginRequest{ConnectionName: h.Connection}); err != nil {
			return nil, err
		}
	}
	if err := h.consumeAndMarkVerified(txCtx, sha256Hex(req.GetToken())); err != nil {
		if tx != nil {
			_ = tx.Rollback(ctx)
		}
		return nil, err
	}
	if tx != nil {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
	}
	return &pb.VerifyEmailResp{}, nil
}

// consumeAndMarkVerified spends the token and stamps the address. Kept
// together so one transaction can hold them.
func (h *AuthServiceHandler) consumeAndMarkVerified(txCtx context.Context, tokenHash string) error {
	consumed, err := h.Mutation.ConsumeEmailVerificationToken(txCtx, &pb.ConsumeEmailVerificationTokenReq{
		TokenHash: tokenHash,
	})
	if err != nil {
		// Opaque, not raw — see consumeAndSetPassword for why the RETURNING
		// shape makes the `== ""` branch below unreachable on its own.
		return Unauthenticated(err)
	}
	userID := consumed.GetUserId()
	if userID == "" {
		return Unauthenticated(errVerifyTokenInvalid)
	}
	if _, err := h.Mutation.MarkEmailVerified(txCtx, &pb.MarkEmailVerifiedReq{UserId: userID}); err != nil {
		return err
	}
	return nil
}

// init installs the invitation gate. This file is staged only when
// `email_verification` is active, which is what makes the field reference
// below safe to compile — `User.email_verified_at` does not exist otherwise.
func init() {
	inviteVerifiedEmailGate = inviteVerifiedEmailGateImpl
	markEmailDerived = markEmailDerivedImpl
	markEmailConfirmed = markEmailConfirmedImpl
}

// markEmailConfirmedImpl records a SELF_CONFIRMED address through the same
// mutation VerifyEmail uses: a sign_up_confirmation code returned from the
// address proves it exactly as a verification link clicked from it does.
func markEmailConfirmedImpl(ctx context.Context, h *AuthServiceHandler, userID string) error {
	_, err := h.Mutation.MarkEmailVerified(ctx, &pb.MarkEmailVerifiedReq{UserId: userID})
	return err
}

// markEmailDerivedImpl stamps EmailProof.DERIVED_FROM_INVITE.
//
// The statement itself refuses to downgrade a self-confirmed address, so this
// carries no guard of its own: a rule the caller can forget is a rule that gets
// forgotten, and this one has to hold for every future caller too.
func markEmailDerivedImpl(ctx context.Context, h *AuthServiceHandler, userID string) error {
	_, err := h.Mutation.MarkEmailDerivedFromInvite(ctx, &pb.MarkEmailDerivedFromInviteReq{UserId: userID})
	// Nothing moved is the ORDINARY case — the address was already confirmed, or
	// already derived — and the generated write reports zero rows as NotFound.
	if status.Code(err) == codes.NotFound {
		return nil
	}
	return err
}

// MsgInviteNeedsVerifiedEmail is what the person accepting is told.
//
// It is about the CALLER's OWN account and says nothing about whether an
// invitation exists, so it does not reopen the probe `errInviteInvalid`
// exists to close. Being specific is the point: "that invitation is not
// valid" would send somebody to ask an admin to re-send a perfectly good
// invitation, when what they have to do is confirm their address.
//
//w17:msgid
const MsgInviteNeedsVerifiedEmail = "Confirm your email address before accepting this invitation."

// inviteVerifiedEmailGateImpl refuses an acceptance from an unverified
// account, when the deployment asked for that.
//
// Reads the knob at CALL time rather than at install time, the same way
// invite_only is read: a deployment that turns it on should not have to
// restart to mean it.
func inviteVerifiedEmailGateImpl(ctx context.Context, h *AuthServiceHandler, userID string, inviteBindsAddress bool) error {
	floor := strings.TrimSpace(strings.ToLower(h.EmailProofRequired))
	if floor == "" || floor == emailProofNone {
		return nil
	}

	// What THIS acceptance is worth, before asking what the account already
	// holds. A BOUND invitation names the address and the secret link reached
	// whoever is registering, so accepting it derives the address — which is the
	// whole point of the middle mode: the corporate case closes the hole without
	// sending anybody on a round trip.
	//
	// An OPEN invitation derives nothing. The registrant picked the address, and
	// the link may have travelled by a channel that has no address at all, so
	// what was proved is that they were AUTHORISED, not that the address is
	// theirs. Treating those as the same is the mistake this gate exists to stop
	// being possible.
	if floor == emailProofDerived && inviteBindsAddress {
		return nil
	}

	got, err := h.Query.GetUserById(ctx, &pb.GetUserByIdReq{UserId: userID})
	if err != nil {
		return err
	}
	// A self-confirmed address satisfies every floor — it is the strongest proof
	// there is, so it is never refused by a gate asking for less.
	if got.GetUser().GetEmailVerifiedAt().IsValid() {
		return nil
	}
	// Already derived, on an earlier bound invitation, satisfies the middle floor
	// and not the top one.
	if floor == emailProofDerived && got.GetUser().GetEmailProof() == pb.EmailProof_DERIVED_FROM_INVITE {
		return nil
	}

	return withUserDetail(
		status.New(codes.FailedPrecondition, "accept org invite: caller's email proof is below "+floor),
		CodeEmailNotVerified, MsgInviteNeedsVerifiedEmail,
	).Err()
}

// The three floors, weakest first. Strings rather than an enum because the knob
// is an env var an operator types, and a typo has to be readable in the refusal
// rather than silently becoming zero.
const (
	emailProofNone    = "none"
	emailProofDerived = "derived"
	emailProofFull    = "full"
)
