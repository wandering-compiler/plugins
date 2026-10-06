package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// verifiedMock answers the user lookup, and RECORDS whether the claim was
// attempted — the gate has to refuse before the invitation is consumed.
type verifiedMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	verified   bool
	claimTried bool
	// What the account already holds, for the middle floor. Zero value is
	// UNPROVEN, which is what every account created before this change is.
	proof pb.EmailProof
	// openInvite makes the read answer with NO bound address, which is the path
	// that derives nothing.
	openInvite bool
}

func (m *verifiedMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u := &pb.User{Id: in.GetUserId(), Email: "invited@example.com"}
	u.EmailProof = m.proof
	if m.verified {
		u.EmailVerifiedAt = timestamppb.Now()
		u.EmailProof = pb.EmailProof_SELF_CONFIRMED
	}
	return &pb.GetUserByIdResp{User: u}, nil
}

// The read the gate depends on. Returns a BOUND invitation by default — the
// address matches what GetUserById answers — so a test that wants the open case
// says so, rather than getting it by accident from a zero value.
func (m *verifiedMock) GetPendingOrgInviteByToken(_ context.Context, _ *pb.GetPendingOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.GetPendingOrgInviteByTokenResp, error) {
	email := "invited@example.com"
	if m.openInvite {
		email = ""
	}
	return &pb.GetPendingOrgInviteByTokenResp{OrgId: "org-1", Role: "member", Email: email}, nil
}

func (m *verifiedMock) ConsumeOrgInviteByToken(_ context.Context, _ *pb.ConsumeOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	m.claimTried = true
	return &pb.ConsumeOrgInviteByTokenResp{OrgId: "org-1", Role: "member", Email: "invited@example.com"}, nil
}

func (m *verifiedMock) MarkOrgInviteAccepted(_ context.Context, _ *pb.MarkOrgInviteAcceptedReq, _ ...grpc.CallOption) (*pb.MarkOrgInviteAcceptedResp, error) {
	m.claimTried = true
	return &pb.MarkOrgInviteAcceptedResp{OrgId: "org-1", Role: "member"}, nil
}

// An invitation is keyed on an ADDRESS, so accepting one proves ownership of
// that mailbox only if somebody checked the address belongs to the account.
// Nothing did, and both the model and the invite_only knob claimed enabling
// `email_verification` closed the window — it adds a column and two RPCs and
// blocks nothing (a consumer measured 19 unverified accounts of 19 with it on).
func TestEmailProofGate_FullRefusesAnUnprovenAccount(t *testing.T) {
	m := &verifiedMock{verified: false}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofFull}

	err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false)
	if err == nil {
		t.Fatal("an account that never proved its address accepted an invitation " +
			"addressed to that address")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code = %s, want FailedPrecondition — the caller can fix this", status.Code(err))
	}
}

// And a verified one goes through.
func TestEmailProofGate_FullAllowsASelfConfirmedAccount(t *testing.T) {
	m := &verifiedMock{verified: true}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofFull}

	if err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false); err != nil {
		t.Errorf("a verified account was refused: %v", err)
	}
}

// OFF is the shipped default and must change nothing.
//
// Not a formality: a project can run `email_verification` with every account
// unverified, and a gate that defaulted on would lock all of those people out
// of invitations they were legitimately sent.
func TestEmailProofGate_NoneChangesNothing(t *testing.T) {
	m := &verifiedMock{verified: false}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofNone}

	if err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false); err != nil {
		t.Errorf("the gate fired with the floor at none: %v", err)
	}
}

// The refusal is readable AND says nothing about whether an invitation exists.
//
// Both halves matter. A person who is told "that invitation is not valid" goes
// and asks an admin to re-send a perfectly good one; a person told which
// invitations exist has been handed a probe. This describes the caller's own
// account, which they already know about.
func TestEmailProofGate_RefusalIsActionableAndLeaksNothing(t *testing.T) {
	m := &verifiedMock{verified: false}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofFull}

	err := inviteVerifiedEmailGateImpl(context.Background(), h, "u1", false)
	st, _ := status.FromError(err)
	var detail *w17pb.ErrorDetail
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			detail = ed
		}
	}
	if detail == nil {
		t.Fatal("no ErrorDetail: the gateway falls back to a generic sentence and the " +
			"person is not told what to do")
	}
	if detail.GetCode() != CodeEmailNotVerified {
		t.Errorf("code = %q, want %q", detail.GetCode(), CodeEmailNotVerified)
	}
	for _, leak := range []string{"invit", "organization", "org-"} {
		if strings.Contains(strings.ToLower(detail.GetMessage()), leak) {
			// "invitation" is allowed as the OBJECT being accepted; what must
			// not appear is any claim about one existing or not.
			if leak == "invit" && strings.Contains(detail.GetMessage(), "this invitation") {
				continue
			}
			t.Errorf("the refusal mentions %q: %q", leak, detail.GetMessage())
		}
	}
}

// The gate runs BEFORE the claim. Refusing after it would have consumed the
// invitation to say no — the person would then be locked out of an invitation
// that no longer exists.
func TestAcceptOrgInvite_ARefusedAcceptanceDoesNotConsumeTheInvitation(t *testing.T) {
	orig := inviteVerifiedEmailGate
	inviteVerifiedEmailGate = inviteVerifiedEmailGateImpl
	t.Cleanup(func() { inviteVerifiedEmailGate = orig })

	m := &verifiedMock{verified: false}
	h := &AuthServiceHandler{Query: m, Mutation: m, EmailProofRequired: emailProofFull}

	_, err := h.AcceptOrgInvite(ctxWithCaller("u1"), &pb.AcceptOrgInviteReq{Token: "a-secret"})
	if err == nil {
		t.Fatal("the acceptance was not refused")
	}
	if m.claimTried {
		t.Error("the invitation was CLAIMED and then refused — it is now spent, and " +
			"the person cannot accept it after verifying their address")
	}
}
