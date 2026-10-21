package handlers

import (
	"context"
	"slices"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What membership_kinds adds to org_invite, staged only when both are on: an
// invitation names the kind of membership it creates, accepting it writes
// that kind onto the membership, and the kind is held to what the inviter may
// hand out — a client of an organization cannot invite its staff.

func init() {
	kindOfInvite = checkInviteKind
	kindOfClaim = func(claimed *pb.ConsumeOrgInviteByTokenResp, add *pb.AddOrgMembershipReq) {
		add.Kind = claimed.GetKind()
	}
}

// checkInviteKind writes the invitation's kind, after holding it to the kinds
// the inviter's membership may invite: the union of `invites` over the
// audiences that admit the inviter's kind (w17_audiences; an audience naming
// none invites its own kinds). An inviter with no membership of the
// organization — a backoffice admin — or its owner may invite any kind, and
// so may anyone when the domain publishes no audiences.
func checkInviteKind(ctx context.Context, h *AuthServiceHandler, inviterID string, req *pb.InviteToOrgReq, create *pb.CreateOrgInviteReq) error {
	create.Kind = req.GetKind()
	if len(h.audiences) == 0 {
		return nil
	}
	_, all, err := admittedOrgs(ctx, h, inviterID, nil)
	if err != nil {
		return err
	}
	m := orgByID(all, create.GetOrgId())
	if m == nil {
		return nil
	}
	var may []string
	for _, a := range h.audiences {
		if slices.Contains(a.kinds, m.GetMembershipKind()) {
			may = append(may, a.invites...)
		}
	}
	if slices.Contains(may, req.GetKind()) {
		return nil
	}
	owns, err := h.Query.GetUserOwnsOrg(ctx, &pb.GetUserOwnsOrgReq{UserId: inviterID, OrgId: create.GetOrgId()})
	if err != nil {
		return err
	}
	if owns.GetOwner() {
		return nil
	}
	return refusal(ctx, codes.PermissionDenied, "membership_kinds: the inviter's kind of membership may not invite this kind",
		CodeInviteKindNotAllowed, "kind", MsgInviteKindNotAllowed, nil)
}
