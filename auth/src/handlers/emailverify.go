package handlers

import (
	"context"
	"errors"
	"time"

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
	consumed, err := h.Mutation.ConsumeEmailVerificationToken(ctx, &pb.ConsumeEmailVerificationTokenReq{
		TokenHash: sha256Hex(req.GetToken()),
	})
	if err != nil {
		return nil, err
	}
	userID := consumed.GetUserId()
	if userID == "" {
		return nil, Unauthenticated(errVerifyTokenInvalid)
	}
	if _, err := h.Mutation.MarkEmailVerified(ctx, &pb.MarkEmailVerifiedReq{UserId: userID}); err != nil {
		return nil, err
	}
	return &pb.VerifyEmailResp{}, nil
}
