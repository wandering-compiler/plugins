package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// The callback creates no account: an identity with none is kept on the
// login code, so the invitation can arrive with the exchange instead of
// through a URL.
func TestOAuthCallback_CreatesNoAccount(t *testing.T) {
	h, m, state := exchangeHandler(t)
	if _, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state}); err != nil {
		t.Fatal(err)
	}
	if m.createdUser != nil || m.createdIdent != nil {
		t.Errorf("the callback created an account (%+v) or a link (%+v)", m.createdUser, m.createdIdent)
	}
}

// The exchange creates the account with the invitation it carries, through
// the same gate as SignUp: an open invitation (no address) works by token,
// and its link is spent by this registration.
func TestOAuthExchange_SignsUpWithTheInvitationItCarries(t *testing.T) {
	h, m, state := exchangeHandler(t)
	var gated, claimed string
	savedGate, savedClaim := signupInviteGate, signupClaimInvite
	signupInviteGate = func(_ context.Context, _ *AuthServiceHandler, _, token string) error {
		gated = token
		if token != "open-invite" {
			return status.Error(codes.PermissionDenied, "not invited")
		}
		return nil
	}
	signupClaimInvite = func(_ context.Context, _ *AuthServiceHandler, _, token string) error {
		claimed = token
		return nil
	}
	t.Cleanup(func() { signupInviteGate, signupClaimInvite = savedGate, savedClaim })

	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier(), InviteToken: "open-invite"})
	if err != nil {
		t.Fatalf("exchange with the invitation: %v", err)
	}
	if gated != "open-invite" || claimed != "open-invite" {
		t.Errorf("the invitation did not reach the gate (%q) and the claim (%q)", gated, claimed)
	}
	if ex.GetToken() == "" || m.createdUser == nil || m.createdIdent == nil {
		t.Errorf("no account, link or session after the invited sign-up: %+v", ex)
	}
}

// Without a valid invitation the exchange refuses, and makes no account.
func TestOAuthExchange_RefusesASignUpWithoutAnInvitation(t *testing.T) {
	h, m, state := exchangeHandler(t)
	saved := signupInviteGate
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error {
		return errSignUpNotInvited // what the real gate answers
	}
	t.Cleanup(func() { signupInviteGate = saved })
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier()})
	if c, got := detailCode(t, err); c != codes.PermissionDenied || got != CodeSignUpNotInvited {
		t.Fatalf("err = %v (%v/%q), want the invite gate's refusal", err, c, got)
	}
	if m.createdUser != nil {
		t.Error("an account was created without an invitation")
	}
}

// An identity that already has an account ignores the invitation: accepting
// one is the product's separate step.
func TestOAuthExchange_AnExistingAccountIgnoresTheInvitation(t *testing.T) {
	h, m, state := exchangeHandler(t)
	m.identity = &pb.OAuthIdentity{Id: "id-1", UserId: "u-existing"}
	saved := signupInviteGate
	called := false
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error { called = true; return nil }
	t.Cleanup(func() { signupInviteGate = saved })
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	ex, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier(), InviteToken: "anything"})
	if err != nil || ex.GetUserId() != "u-existing" {
		t.Fatalf("exchange = %+v, %v; want the existing account", ex, err)
	}
	if called || m.createdUser != nil {
		t.Error("an existing account's sign-in went through the sign-up gate")
	}
}

// An identity that gained an account between the callback and the exchange
// (a second tab's code redeemed first) signs in to it: the exchange resolves
// again instead of creating a second account for the same subject.
func TestOAuthExchange_AnAccountMadeSinceTheCallbackIsUsed(t *testing.T) {
	h, m, state := exchangeHandler(t)
	resp, err := h.OAuthCallback(context.Background(), &pb.OAuthCallbackReq{Provider: "google", Code: "c", State: state})
	if err != nil {
		t.Fatal(err)
	}
	m.identity = &pb.OAuthIdentity{Id: "id-1", UserId: "u-meanwhile"}
	ex, err := h.OAuthExchange(context.Background(), &pb.OAuthExchangeReq{Code: resp.GetCode(), CodeVerifier: validVerifier()})
	if err != nil || ex.GetUserId() != "u-meanwhile" {
		t.Fatalf("exchange = %+v, %v; want the account made since the callback", ex, err)
	}
	if m.createdUser != nil || m.createdIdent != nil {
		t.Error("a second account or link was created for a subject that already has one")
	}
}
