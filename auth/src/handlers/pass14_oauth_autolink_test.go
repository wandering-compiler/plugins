package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// autolinkMock answers the one lookup the auto-link branch makes.
type autolinkMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	user *pb.User
}

func (m *autolinkMock) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	if m.user == nil {
		return &pb.GetUserByEmailResp{}, nil
	}
	return &pb.GetUserByEmailResp{User: m.user}, nil
}

// TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount — T3-7 pass #14,
// `B14-2`.
//
// Q36-auth-1 closed half of this: auto-link now requires the IdP to assert
// the email is verified, because otherwise anyone who set their IdP profile
// email to a victim's got a session for the victim's account.
//
// The other half was left open, and the verifier is what found it. The check
// interrogates the IdP side only. The LOCAL account may itself have been
// created from a claim nobody verified — by OAuth's own create branch, or by
// password sign-up. So:
//
//  1. the attacker signs in through an IdP whose profile email is the
//     victim's and which does NOT assert verification. No existing account,
//     so the create branch makes one — for the victim's address, owned by
//     the attacker.
//  2. the victim signs in later through a provider that DOES verify. The
//     lookup finds the account, `emailVerified` is true, and the auto-link
//     hands the victim a session inside the attacker's account — which the
//     attacker also holds.
//
// What is broken is not either branch on its own: it is that a VERIFIED
// assertion is bound to an UNVERIFIED local claim. My first plan was to
// require verification in the create branch, and the verifier showed that
// closes nothing — password sign-up is a second door to the same squat, and
// gating one leaves the other.
//
// So the check belongs on the local side, and this test pins it there.
func TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount(t *testing.T) {
	h := &AuthServiceHandler{
		Query: &autolinkMock{user: &pb.User{Id: "victim-addr-account", Email: "victim@example.com"}},
	}

	// The IdP verified its side. The local account has no
	// `email_verified_at`, so nobody ever proved that address belongs to
	// whoever created it.
	_, err := h.resolveOrCreateUserByEmail(context.Background(), "victim@example.com", true)
	if err == nil {
		t.Fatal("auto-linked a verified identity into a local account whose own address " +
			"was never verified — the account may have been created by whoever wanted " +
			"to be linked to")
	}
}

// The other direction: a locally verified account still links, or OAuth is
// broken for every account that legitimately owns its address.
func TestOAuthAutoLink_LinksIntoAVerifiedLocalAccount(t *testing.T) {
	h := &AuthServiceHandler{
		Query: &autolinkMock{user: &pb.User{
			Id:              "real-owner",
			Email:           "owner@example.com",
			EmailVerifiedAt: timestamppb.Now(),
		}},
	}
	id, err := h.resolveOrCreateUserByEmail(context.Background(), "owner@example.com", true)
	if err != nil {
		t.Fatalf("a verified local account was refused: %v", err)
	}
	if id != "real-owner" {
		t.Errorf("linked to %q, want real-owner", id)
	}
}
