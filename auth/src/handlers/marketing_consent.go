package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The caller's consent to marketing messages (feature marketing_consent).
//
// It is a value of the identity and nothing more: what is recorded about a
// user does not depend on it. Authenticate answers it in AuthResp, the
// gateway copies it into every request record, and the tool that sends the
// messages decides with it. Only the user sets it, for themselves: the
// request names no user, and no admin path writes it, because a consent
// given by somebody else is not the user's.

func init() {
	authRespEnrich = func(prin *authPrincipal, resp *pb.AuthResp) {
		resp.MarketingConsent = prin.user.GetMarketingConsent()
	}
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
