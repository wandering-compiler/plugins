package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Staged with `invite_accept_from_list` (requires org_invite).

// AcceptMyOrgInvite joins the caller from their own list (ListMyInvites),
// without the link — the GitHub way: register first, accept later.
//
// Only an invitation bound to the caller's address: an open one names nobody,
// and is accepted only through its link. Without the link nothing is derived
// about the address, so the deployment's floor (email_proof_required) asks the
// account for the proof it already holds — under `derived` or `full`, an
// address nobody proved is refused, which closes the window in which whoever
// registers an invited address first takes the invitation.
func (h *AuthServiceHandler) AcceptMyOrgInvite(ctx context.Context, req *pb.AcceptMyOrgInviteReq) (*pb.AcceptOrgInviteResp, error) {
	userID, err := callerUserID(ctx)
	if err != nil {
		return nil, Unauthenticated(err)
	}
	email, err := h.callerEmail(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Found only if it is bound to the caller's address: another person's,
	// an open one or an unknown id are the same opaque refusal.
	found, err := h.Query.GetPendingOrgInviteForEmail(ctx, &pb.GetPendingOrgInviteForEmailReq{InviteId: req.GetInviteId(), Email: email})
	if status.Code(err) == codes.NotFound {
		return nil, errInviteInvalid
	}
	if err != nil {
		return nil, err
	}
	orgID, tokenHash := found.GetOrgId(), found.GetTokenHash()
	if err := inviteVerifiedEmailGate(ctx, h, userID, false); err != nil {
		return nil, err
	}
	var resp *pb.AcceptOrgInviteResp
	err = h.withOrgLock(ctx, orgID, func(txCtx context.Context) error {
		var txErr error
		resp, txErr = h.acceptInviteTx(txCtx, userID, false, func(txCtx context.Context) (*pb.ConsumeOrgInviteByTokenResp, error) {
			return h.Mutation.ConsumeOrgInviteByToken(txCtx, &pb.ConsumeOrgInviteByTokenReq{
				TokenHash: tokenHash,
				UserId:    userID,
				Email:     email,
			})
		})
		return txErr
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
