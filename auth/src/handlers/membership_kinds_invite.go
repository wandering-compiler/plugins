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
	table, err := h.audienceTable()
	if err != nil {
		return "", err
	}
	if len(table) == 0 || kind == "" {
		return kind, nil
	}
	refuse := func() (string, error) {
		return "", refusal(ctx, codes.PermissionDenied, "membership_kinds: the inviter's kind of membership may not invite this kind",
			CodeInviteKindNotAllowed, "kind", MsgInviteKindNotAllowed, nil)
	}
	known := false
	for _, a := range table {
		known = known || slices.Contains(a.kinds, kind)
	}
	if !known {
		return refuse()
	}
	_, all, err := admittedOrgs(ctx, h, inviterID, nil)
	if err != nil {
		return "", err
	}
	m := orgByID(all, orgID)
	if m == nil {
		return kind, nil
	}
	for _, a := range table {
		if slices.Contains(a.kinds, m.GetMembershipKind()) && slices.Contains(a.invitable(), kind) {
			return kind, nil
		}
	}
	return refuse()
}
