package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// Staged with `invite_accept_at_signup` (requires org_invite): a registration
// through an invitation's link accepts it in the transaction that creates the
// account.

func init() {
	signupAcceptInvite = acceptInviteAtSignup
}

// acceptInviteAtSignup accepts the invitation inviteToken names for the
// account just created, inside the registration's transaction.
//
// What decides whether to accept is read before anything is written, and a
// "no" there leaves the invitation for AcceptOrgInvite and the registration
// whole: a link that names nothing (the gate already admitted the address
// another way), an invitation bound to another address, an address below
// the floor `email_proof_required` asks. Once the claim is made, a refusal —
// the role or the plan moved since the invitation — refuses the registration:
// carrying on would commit an invitation spent with no membership behind it.
//
// proven says the registration itself proved the address (a confirmation
// code, a provider's verified email). The account row is not readable here
// (the query tier reads the pool, not this transaction), so the floor is
// answered from what the registration knows, not from the row.
func acceptInviteAtSignup(txCtx context.Context, h *AuthServiceHandler, userID, email, inviteToken string, proven bool) error {
	if inviteToken == "" {
		return nil
	}
	tokenHash := sha256Hex(inviteToken)
	pending, err := h.Query.GetPendingOrgInviteByToken(txCtx, &pb.GetPendingOrgInviteByTokenReq{TokenHash: tokenHash})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	invited := pending.GetEmail()
	if invited != "" && invited != email {
		return nil
	}
	if !proven && !reachesFloorAtSignup(h, invited != "") {
		return nil
	}
	orgID := pending.GetOrgId()
	if err := h.lockOrgRow(txCtx, orgID); err != nil {
		return err
	}
	_, err = h.acceptInviteTx(context.WithValue(txCtx, orgLockKey{}, orgID), userID, true, func(c context.Context) (*pb.ConsumeOrgInviteByTokenResp, error) {
		return h.Mutation.ConsumeOrgInviteByToken(c, &pb.ConsumeOrgInviteByTokenReq{TokenHash: tokenHash, UserId: userID, Email: email})
	})
	return err
}

// reachesFloorAtSignup answers the floor for an address with no proof of its
// own yet: `none` asks nothing, `derived` accepts a link bound to the address
// (accepting it derives the address), `full` asks a proof a registration
// without a confirmation does not have.
func reachesFloorAtSignup(h *AuthServiceHandler, bound bool) bool {
	switch normalizedFloor(h) {
	case "", emailProofNone:
		return true
	case emailProofDerived:
		return bound
	default:
		return false
	}
}
