package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// inviteGateMock answers the one query the invite gate asks: does this
// ADDRESS hold a pending invitation. It also answers GetUserByEmail so the
// OAuth case can be driven with no pre-existing account.
type inviteGateMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	pending map[string][]*pb.PendingInviteRow // email → invitations
	listErr error
}

func (m *inviteGateMock) ListPendingInvitesForEmail(_ context.Context, in *pb.ListPendingInvitesForEmailReq, _ ...grpc.CallOption) (*pb.ListPendingInvitesForEmailResp, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &pb.ListPendingInvitesForEmailResp{Invites: m.pending[in.GetEmail()]}, nil
}

func (m *inviteGateMock) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{}, nil // no account with this address
}

// TestInviteGate_RefusesAnUninvitedAddress is the regression pin for the
// defect this file was written for: `invite_only` was a flag nothing read.
// The seam that enforces it defaulted to permissive and the init() its own
// comment promised was never written, so a console that declared
// invite-only registration accepted anybody — over a public, exclude_auth
// /register endpoint.
//
// The assertion is on the SEAM rather than on SignUp because the seam is
// what a second account-creating surface (OAuth) also has to consult; a
// test that only drove SignUp would have gone green on a fix that left the
// other door open.
func TestInviteGate_RefusesAnUninvitedAddress(t *testing.T) {
	h := &AuthServiceHandler{
		Query:      &inviteGateMock{},
		InviteOnly: true,
	}
	err := signupInviteGate(context.Background(), h, "stranger@example.com")
	if err == nil {
		t.Fatal("an address with no pending invitation was admitted under invite_only — " +
			"registration is open on every deployment that believed this flag")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("refusal code = %s, want PermissionDenied (the gateway maps an "+
			"unclassified error to INTERNAL, so the caller would read a 500 instead "+
			"of the sentence telling them to ask for an invitation)", got)
	}
}

// TestInviteGate_AdmitsAnInvitedAddress guards the other direction: the
// refusal must not be unconditional, or invite-only registration would be
// no registration at all.
func TestInviteGate_AdmitsAnInvitedAddress(t *testing.T) {
	h := &AuthServiceHandler{
		Query: &inviteGateMock{pending: map[string][]*pb.PendingInviteRow{
			"invited@example.com": {{InviteId: "i1", OrgId: "o1", Role: "org-worker"}},
		}},
		InviteOnly: true,
	}
	if err := signupInviteGate(context.Background(), h, "invited@example.com"); err != nil {
		t.Fatalf("an invited address was refused: %v", err)
	}
}

// TestInviteGate_OffAdmitsEveryone pins the flag as the switch. An
// activation that never asked for invite-only must keep open registration
// — the gate is staged with the `org_invite` feature, and staging a
// feature must not silently close a surface the operator left open.
func TestInviteGate_OffAdmitsEveryone(t *testing.T) {
	h := &AuthServiceHandler{
		Query:      &inviteGateMock{},
		InviteOnly: false,
	}
	if err := signupInviteGate(context.Background(), h, "stranger@example.com"); err != nil {
		t.Fatalf("invite_only is off, yet registration was refused: %v", err)
	}
}

// TestInviteGate_RefusalIsOpaque: the refusal must not disclose whether the
// address holds an EXPIRED invitation, nor whether an account exists —
// either turns the registration form into a probe for who was invited
// where. Same wording for the invited-but-expired and the never-invited.
func TestInviteGate_RefusalIsOpaque(t *testing.T) {
	h := &AuthServiceHandler{Query: &inviteGateMock{}, InviteOnly: true}
	err := signupInviteGate(context.Background(), h, "stranger@example.com")
	if err == nil {
		t.Fatal("no refusal to inspect")
	}
	msg := status.Convert(err).Message()
	for _, leak := range []string{"expired", "exists", "already", "unknown address"} {
		if containsFold(msg, leak) {
			t.Errorf("refusal message discloses %q: %s", leak, msg)
		}
	}
}

// TestOAuthCreate_ConsultsTheInviteGate is the second door. OAuth's
// resolveOrCreateUserByEmail creates an account for any address the IdP
// asserts, so a fix that only reached SignUp would leave invite-only
// registration open to anyone with a Google account.
func TestOAuthCreate_ConsultsTheInviteGate(t *testing.T) {
	h := &AuthServiceHandler{
		Query:      &inviteGateMock{},
		InviteOnly: true,
	}
	_, err := h.resolveOrCreateUserByEmail(context.Background(), "stranger@example.com", true)
	if err == nil {
		t.Fatal("OAuth created an account for an uninvited address under invite_only")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("OAuth refusal code = %s, want PermissionDenied", got)
	}
}

func containsFold(s, sub string) bool {
	ls, lsub := []rune(s), []rune(sub)
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}
	for i := 0; i+len(lsub) <= len(ls); i++ {
		ok := true
		for j := range lsub {
			if lower(ls[i+j]) != lower(lsub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
