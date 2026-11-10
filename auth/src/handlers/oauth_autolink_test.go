package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
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

// TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount.
//
// Half of this is the IdP side: auto-link requires the IdP to assert the
// email is verified, because otherwise anyone who set their IdP profile
// email to a victim's gets a session for the victim's account.
//
// The other half is the local side, which that check does not interrogate. The
// LOCAL account may itself have been created from a claim nobody verified — by
// OAuth's own create branch, or by password sign-up. So:
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
// assertion is bound to an UNVERIFIED local claim. Requiring verification in
// the create branch closes nothing — password sign-up is a second door to the
// same squat, and gating one leaves the other.
//
// So the check belongs on the local side, and this test pins it there.
func TestOAuthAutoLink_RefusesAnUnverifiedLocalAccount(t *testing.T) {
	h := &AuthServiceHandler{
		Query: &autolinkMock{user: &pb.User{Id: "victim-addr-account", Email: "victim@example.com"}},
	}

	// The IdP verified its side. The local account has no
	// `email_verified_at`, so nobody ever proved that address belongs to
	// whoever created it.
	_, err := h.findOAuthAccount(context.Background(), "p1", "sub-1", "victim@example.com", true)
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
	h.Mutation = &autolinkMock{}
	id, err := h.findOAuthAccount(context.Background(), "p1", "sub-1", "owner@example.com", true)
	if err != nil {
		t.Fatalf("a verified local account was refused: %v", err)
	}
	if id != "real-owner" {
		t.Errorf("linked to %q, want real-owner", id)
	}
}

func (m *autolinkMock) GetOAuthIdentity(context.Context, *pb.GetOAuthIdentityReq, ...grpc.CallOption) (*pb.GetOAuthIdentityResp, error) {
	return &pb.GetOAuthIdentityResp{}, nil
}

func (m *autolinkMock) CreateOAuthIdentity(_ context.Context, in *pb.CreateOAuthIdentityReq, _ ...grpc.CallOption) (*pb.CreateOAuthIdentityResp, error) {
	return &pb.CreateOAuthIdentityResp{Identity: &pb.OAuthIdentity{UserId: in.GetUserId()}}, nil
}

func (m *autolinkMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId()}}, nil
}

// outageIdentityMock: GetOAuthIdentity fails with identityErr; GetUserByEmail
// answers from autolinkMock (or fails with emailErr), and a link is recorded.
type outageIdentityMock struct {
	autolinkMock
	identityErr error
	emailErr    error
	linked      *pb.CreateOAuthIdentityReq
}

func (m *outageIdentityMock) GetOAuthIdentity(context.Context, *pb.GetOAuthIdentityReq, ...grpc.CallOption) (*pb.GetOAuthIdentityResp, error) {
	return nil, m.identityErr
}

func (m *outageIdentityMock) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, o ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	if m.emailErr != nil {
		return nil, m.emailErr
	}
	return m.autolinkMock.GetUserByEmail(ctx, in, o...)
}

func (m *outageIdentityMock) CreateOAuthIdentity(_ context.Context, in *pb.CreateOAuthIdentityReq, _ ...grpc.CallOption) (*pb.CreateOAuthIdentityResp, error) {
	m.linked = in
	return &pb.CreateOAuthIdentityResp{Identity: &pb.OAuthIdentity{UserId: in.GetUserId()}}, nil
}

// oauth/outage-is-not-no-row: only NotFound means "no row". A store that
// failed to answer whether (provider, subject) is linked must not be read as
// "not linked" — the exchange would then match the asserted address to
// another account and link the subject there, or (with the address lookup
// failing too) go on to create an account. The outage is returned, and
// reaches the wire as one.
func TestFindOAuthAccount_AnOutageIsNotNoRow(t *testing.T) {
	down := status.Error(codes.Unavailable, "store down")
	verified := &pb.User{Id: "u-B", Email: "owner@example.com", EmailVerifiedAt: timestamppb.Now()}
	for name, m := range map[string]*outageIdentityMock{
		"identity read fails":             {autolinkMock: autolinkMock{user: verified}, identityErr: down},
		"address read fails":              {autolinkMock: autolinkMock{user: verified}, identityErr: status.Error(codes.NotFound, "no rows"), emailErr: down},
		"identity and address reads fail": {identityErr: down, emailErr: down},
	} {
		t.Run(name, func(t *testing.T) {
			h := &AuthServiceHandler{Query: m, Mutation: m}
			id, err := h.findOAuthAccount(context.Background(), "p1", "sub-linked-elsewhere", "owner@example.com", true)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("an outage was read as no row: id=%q err=%v, want the outage", id, err)
			}
			if m.linked != nil {
				t.Errorf("an identity was linked to %s during the outage", m.linked.GetUserId())
			}
			if status.Code(oauthRefusal(err)) != codes.Unavailable {
				t.Errorf("the outage reaches the wire as %v, want Unavailable", status.Code(oauthRefusal(err)))
			}
		})
	}

	// A NotFound from either read is "no row", as before: no identity and no
	// account means the exchange creates one.
	m := &outageIdentityMock{identityErr: status.Error(codes.NotFound, "no rows"), emailErr: status.Error(codes.NotFound, "no rows")}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if id, err := h.findOAuthAccount(context.Background(), "p1", "sub", "new@example.com", true); id != "" || err != nil {
		t.Fatalf("NotFound from both reads: id=%q err=%v, want no account and no error", id, err)
	}
}
