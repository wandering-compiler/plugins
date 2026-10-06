package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// acceptMock answers the claim the accept path makes.
type acceptMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	claimErr  error
	claimResp *pb.ConsumeOrgInviteByTokenResp
}

// The claim is keyed on the TOKEN now, not on (invite_id, email) — the row id
// stopped being the identifier the moment the link became the proof.
func (m *acceptMock) ConsumeOrgInviteByToken(ctx context.Context, in *pb.ConsumeOrgInviteByTokenReq, _ ...grpc.CallOption) (*pb.ConsumeOrgInviteByTokenResp, error) {
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	return m.claimResp, nil
}

// A claim that matches nothing must reach the caller as the OPAQUE refusal.
//
// The mutation carries RETURNING, so zero rows arrive as NOT_FOUND rather than
// as an empty response — which left `errInviteInvalid` on a branch nothing
// could reach. The anti-probe wording existed, was reviewed, and was never
// sent: what a caller actually saw was a NotFound naming an internal RPC.
func TestAcceptInvite_NotFoundBecomesTheOpaqueRefusal(t *testing.T) {
	h := &AuthServiceHandler{Mutation: &acceptMock{
		claimErr: status.Error(codes.NotFound, "ConsumeOrgInviteByToken: no rows"),
	}}

	_, err := h.acceptInviteTx(context.Background(), "deadbeef", "u1", false)
	if err == nil {
		t.Fatal("a claim matching nothing was accepted")
	}
	if !strings.Contains(err.Error(), "invitation invalid") {
		t.Fatalf("the caller does not get the opaque refusal: %v", err)
	}
	// The whole point of that wording is that it tells a guesser nothing. An
	// internal RPC's name in the message is a detail the refusal exists to
	// withhold.
	if strings.Contains(err.Error(), "MarkOrgInviteAccepted") {
		t.Errorf("the refusal names an internal RPC: %v", err)
	}
}

// The four causes stay indistinguishable. One answer, whichever it was —
// telling an unauthenticated guess which one it hit is an oracle.
func TestAcceptInvite_EmptyResponseGivesTheSameRefusal(t *testing.T) {
	h := &AuthServiceHandler{Mutation: &acceptMock{
		claimResp: &pb.ConsumeOrgInviteByTokenResp{}, // no org_id
	}}

	_, err := h.acceptInviteTx(context.Background(), "deadbeef", "u1", false)
	if err == nil {
		t.Fatal("an empty claim was treated as a successful one — the membership would be written into no organization")
	}
	if !strings.Contains(err.Error(), "invitation invalid") {
		t.Fatalf("a second shape of 'no row' produced a different answer: %v", err)
	}
}

// A real failure keeps its own identity: reporting a database outage as an
// invalid invitation sends somebody to re-check an invitation that is fine.
func TestAcceptInvite_OtherErrorsAreNotDisguised(t *testing.T) {
	h := &AuthServiceHandler{Mutation: &acceptMock{
		claimErr: status.Error(codes.Unavailable, "db down"),
	}}

	_, err := h.acceptInviteTx(context.Background(), "deadbeef", "u1", false)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable passed through, got %v", err)
	}
}
