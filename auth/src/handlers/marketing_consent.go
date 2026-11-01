package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The caller's consent to marketing messages (feature marketing_consent).
//
// It is a value of the identity and nothing more: what is recorded about a
// user does not depend on it. Authenticate answers it in AuthResp, the
// gateway copies it into every request record, and the tool that sends the
// messages decides with it. Only the user sets it, for themselves: the
// request names no user, and no admin path writes it, because a consent
// given by somebody else is not the user's. The one path that names a user,
// WithdrawMarketingConsent, can only withdraw: it carries a decision the user
// made in the marketing tool (an unsubscribe link), and is internal.

func init() {
	authRespEnrichers = append(authRespEnrichers, func(_ context.Context, _ *AuthServiceHandler, prin *authPrincipal, resp *pb.AuthResp) error {
		resp.MarketingConsent = prin.user.GetMarketingConsent()
		return nil
	})
}

// GetMarketingConsent answers the caller's consent and when they decided it;
// `decided_at` is unset when they were never asked.
func (h *AuthServiceHandler) GetMarketingConsent(ctx context.Context, _ *pb.GetMarketingConsentReq) (*pb.MarketingConsentResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	got, err := h.Query.GetUserMarketingConsent(ctx, &pb.GetUserMarketingConsentReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &pb.MarketingConsentResp{Consent: got.GetConsent(), DecidedAt: got.GetDecidedAt()}, nil
}

// SetMarketingConsent records the caller's decision — consent or withdrawal —
// with the time it was made, and announces it (MarketingConsentChanged).
// Recorded again when it is the same as before: the time of the latest
// decision is the record a controller shows.
func (h *AuthServiceHandler) SetMarketingConsent(ctx context.Context, req *pb.SetMarketingConsentReq) (*pb.MarketingConsentResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	got, err := h.Mutation.SetUserMarketingConsent(ctx, &pb.SetUserMarketingConsentReq{
		UserId: userID, Consent: req.GetConsent(), Thumbprint: requestThumbprint(ctx),
	})
	if err != nil {
		return nil, err
	}
	return &pb.MarketingConsentResp{Consent: got.GetConsent(), DecidedAt: got.GetDecidedAt()}, nil
}

// WithdrawMarketingConsent records that the user withdrew their consent in
// the marketing tool — they unsubscribed there — through the statement their
// own SetMarketingConsent writes, so MarketingConsentChanged announces it the
// same way. It only ever withdraws: a consent is the user's to give, and
// nobody else's. A withdrawal already on record is answered as it stands, not
// written again, so the time the user decided stays the time they decided
// (the tool may tell the project twice). Internal: the request names the user,
// so only the domain's own code calls it.
func (h *AuthServiceHandler) WithdrawMarketingConsent(ctx context.Context, req *pb.WithdrawMarketingConsentReq) (*pb.MarketingConsentResp, error) {
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "WithdrawMarketingConsent needs a user id")
	}
	got, err := h.Query.GetUserMarketingConsent(ctx, &pb.GetUserMarketingConsentReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	if !got.GetConsent() && got.GetDecidedAt() != nil {
		return &pb.MarketingConsentResp{Consent: false, DecidedAt: got.GetDecidedAt()}, nil
	}
	set, err := h.Mutation.SetUserMarketingConsent(ctx, &pb.SetUserMarketingConsentReq{UserId: userID, Consent: false})
	if err != nil {
		return nil, err
	}
	return &pb.MarketingConsentResp{Consent: set.GetConsent(), DecidedAt: set.GetDecidedAt()}, nil
}
