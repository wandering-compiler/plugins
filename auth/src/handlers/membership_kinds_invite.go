package handlers

import (
	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// What membership_kinds adds to org_invite, staged only when both are on: an
// invitation names the kind of membership it creates, and accepting it writes
// that kind onto the membership and onto the role grant, so the role counts on
// the audiences that admit the kind (membership_kinds.go).

func init() {
	kindOfInvite = func(req *pb.InviteToOrgReq, create *pb.CreateOrgInviteReq) {
		create.Kind = req.GetKind()
	}
	kindOfClaim = func(claimed *pb.ConsumeOrgInviteByTokenResp, add *pb.AddOrgMembershipReq, grant *pb.AssignRoleToUserReq) {
		add.Kind = claimed.GetKind()
		grant.MembershipKind = claimed.GetKind()
	}
}
