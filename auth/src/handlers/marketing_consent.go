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
// the marketing tool — they unsubscribed there — at withdrawn_at, announced
// as MarketingConsentChanged like their own SetMarketingConsent. It is one
// conditional statement (WithdrawUserMarketingConsent): it writes only over a
// yes decided before withdrawn_at, or no decision, so a consent the user
// gives meanwhile, a newer one, or a withdrawal already on record stands and
// is answered as it is (a late or repeated report of an unsubscribe cancels
// nothing). It only ever withdraws: a consent is the user's to give.
// Internal: the request names the user, so only the domain's own code calls
// it.
func (h *AuthServiceHandler) WithdrawMarketingConsent(ctx context.Context, req *pb.WithdrawMarketingConsentReq) (*pb.MarketingConsentResp, error) {
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "WithdrawMarketingConsent needs a user id")
	}
	if req.GetWithdrawnAt() == nil {
		return nil, status.Error(codes.InvalidArgument, "WithdrawMarketingConsent needs withdrawn_at, when the user withdrew it")
	}
	set, err := h.Mutation.WithdrawUserMarketingConsent(ctx, &pb.WithdrawUserMarketingConsentReq{
		UserId: userID, WithdrawnAt: req.GetWithdrawnAt(), Thumbprint: requestThumbprint(ctx),
	})
	if err == nil {
		return &pb.MarketingConsentResp{Consent: set.GetConsent(), DecidedAt: set.GetDecidedAt()}, nil
	}
	if status.Code(err) != codes.NotFound {
		return nil, err
	}
	// Nothing written: the decision on record stands (or there is no such
	// user, which this read answers NotFound).
	got, err := h.Query.GetUserMarketingConsent(ctx, &pb.GetUserMarketingConsentReq{UserId: userID})
	if err != nil {
		return nil, err
	}
	return &pb.MarketingConsentResp{Consent: got.GetConsent(), DecidedAt: got.GetDecidedAt()}, nil
}
