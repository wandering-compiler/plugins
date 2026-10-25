package handlers

import (
	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The org_signup half of `sign_up_confirmation`, staged only with both
// (plugin.yaml go_files_combined): the pending row's join fields exist only
// then.
//
// Whether an open registration joins the host's organization is decided when
// it is REQUESTED — the request knows whether it carries an invitation, which
// then decides the organization instead — and carried on the pending row, so
// the confirmation writes what was decided and a person who came with an
// invitation is not also put in through the host.

func init() {
	pendingSignUpJoin = stampPendingSignUpJoin
	claimedSignUpJoin = readClaimedSignUpJoin
}

func stampPendingSignUpJoin(create *pb.CreatePendingSignUpReq, j *orgJoin) {
	if j == nil {
		return
	}
	create.JoinOrgId, create.JoinKind, create.JoinRole = j.orgID, j.kind, j.role
}

func readClaimedSignUpJoin(claimed *pb.ClaimPendingSignUpResp) *orgJoin {
	if claimed.GetJoinOrgId() == "" {
		return nil
	}
	return &orgJoin{orgID: claimed.GetJoinOrgId(), kind: claimed.GetJoinKind(), role: claimed.GetJoinRole()}
}
