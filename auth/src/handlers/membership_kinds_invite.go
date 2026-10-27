package handlers

import (
	"context"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What membership_kinds adds to org_invite, staged only when both are on: an
// invitation names the kind of membership it creates, accepting it writes
// that kind onto the membership, and the kind is held to what the inviter may
// hand out — a client of an organization cannot invite its staff.

func init() {
	kindOfInvite = func(ctx context.Context, h *AuthServiceHandler, inviterID, orgID string, req *pb.InviteToOrgReq) (func(*pb.CreateOrgInviteReq), error) {
		kind, err := checkInviteKind(ctx, h, inviterID, orgID, req)
		if err != nil {
			return nil, err
		}
		return func(create *pb.CreateOrgInviteReq) { create.Kind = kind }, nil
	}
	kindOfClaim = func(claimed *pb.ConsumeOrgInviteByTokenResp, add *pb.AddOrgMembershipReq) {
		add.Kind = claimed.GetKind()
	}
}

// checkInviteKind is the invitation's kind, held to what the inviter may hand
// out. With the domain's audience table (w17_audiences):
//
//   - the kind must be one some audience admits, or ” (a membership of no
//     kind, which no kind-filtering gateway admits);
//   - a member may invite the union of `invites` over the audiences that
//     admit their own kind (an audience naming none invites its own kinds);
//   - an inviter from outside the organization (a backoffice admin) may
//     invite any kind the table knows.
//
// Organization ownership widens nothing here: a member who created the
// organization is held to their own kind's audiences like every other member.
//
// With no table — a domain without audiences — any kind goes.
func checkInviteKind(ctx context.Context, h *AuthServiceHandler, inviterID, orgID string, req *pb.InviteToOrgReq) (string, error) {
	kind := req.GetKind()
	if err := checkKindWithinCaller(ctx, h, inviterID, orgID, kind, true); err != nil {
		return "", err
	}
	return kind, nil
}
