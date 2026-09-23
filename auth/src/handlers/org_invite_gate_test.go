package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// gateQuery answers the ONE query the sign-up gate makes. Embedding the
// interface satisfies the rest; anything else being called is a test bug.
type gateQuery struct {
	pb.AuthQueryClient
	invites []*pb.PendingInviteRow
}

func (q *gateQuery) ListPendingInvitesForEmail(_ context.Context, _ *pb.ListPendingInvitesForEmailReq, _ ...grpc.CallOption) (*pb.ListPendingInvitesForEmailResp, error) {
	return &pb.ListPendingInvitesForEmailResp{Invites: q.invites}, nil
}

// The gate that decides whether an uninvited address may register lives in
// a package-level var, permissive by default, replaced by org_invite.go's
// init(). Nothing REFERENCES that init, so nothing makes it survive a
// refactor — and on 2026-09-08 it did not: a move of unrelated symbols out
// of that file took it along, the package compiled (removing an init is
// always valid Go), every existing test stayed green, and the deployed
// console accepted an uninvited registration from the open internet.
//
// This test exists to make that specific loss loud. It asserts on the
// INSTALLED behaviour, not on the file's contents: the permissive default
// returns nil for everything, so a gate that allows an uninvited address
// while `invite_only` is on means the override is gone.
func TestSignupInviteGate_OverrideIsInstalled(t *testing.T) {
	h := &AuthServiceHandler{InviteOnly: true, Query: &gateQuery{}}

	err := signupInviteGate(context.Background(), h, "stranger@example.com")
	if err == nil {
		t.Fatal("an uninvited address was allowed to register with invite_only ON — " +
			"org_invite.go's init() is not installing the gate (the permissive default is still in place)")
	}
	if err != errSignUpNotInvited {
		t.Errorf("refused, but not with the sign-up refusal: %v", err)
	}
}

// The other half: an address that HAS a pending invitation must pass, or
// the gate would refuse everyone and the feature could never be used.
func TestSignupInviteGate_InvitedAddressPasses(t *testing.T) {
	h := &AuthServiceHandler{
		InviteOnly: true,
		Query:      &gateQuery{invites: []*pb.PendingInviteRow{{InviteId: "i1", OrgSlug: "acme"}}},
	}
	if err := signupInviteGate(context.Background(), h, "invited@example.com"); err != nil {
		t.Errorf("an invited address was refused: %v", err)
	}
}

// And with the knob off, the gate must not consult anything at all — this
// is what keeps `sign_up_turnkey` usable without invitations.
func TestSignupInviteGate_OffAllowsEveryone(t *testing.T) {
	h := &AuthServiceHandler{InviteOnly: false, Query: &gateQuery{}}
	if err := signupInviteGate(context.Background(), h, "stranger@example.com"); err != nil {
		t.Errorf("invite_only is off; registration must be open: %v", err)
	}
}
