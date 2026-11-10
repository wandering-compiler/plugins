package handlers

import (
	"context"
	"errors"
	"testing"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// --- sign_up_confirmation × org_invite --------------------------------------

// The invitation gate runs when the registration is REQUESTED and again when it
// is CONFIRMED: an invitation revoked or lapsed while the code is in the
// mailbox stops the confirmation, and no account is created. The open-link
// claim runs once, at SignUp — the pending registration holds the link.
func TestSignUpConfirmation_TheInviteGateRunsAgainAtConfirmation(t *testing.T) {
	h, s := confirmHandler(t)

	gateCalls, claimCalls, revoked := 0, 0, false
	prevGate, prevClaim := signupInviteGate, signupClaimInvite
	t.Cleanup(func() { signupInviteGate, signupClaimInvite = prevGate, prevClaim })
	signupInviteGate = func(context.Context, *AuthServiceHandler, string, string) error {
		gateCalls++
		if revoked {
			return errSignUpNotInvited
		}
		return nil
	}
	signupClaimInvite = func(context.Context, *AuthServiceHandler, string, string) error {
		claimCalls++
		return nil
	}

	pending, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-owner", InviteToken: "open-link"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if gateCalls != 1 || claimCalls != 1 {
		t.Fatalf("SignUp ran the gate %d and the claim %d times, want once each", gateCalls, claimCalls)
	}
	if len(s.users) != 0 {
		t.Fatal("SignUp created the account; the link was spent by the PENDING registration")
	}

	revoked = true // the invitation is withdrawn while the code is in the mailbox
	done, err := h.ConfirmSignUp(mintCtx(), &pb.ConfirmSignUpReq{PendingId: pending.GetPendingId(), Code: s.codes[pending.GetPendingId()]})
	if !errors.Is(err, errSignUpNotInvited) || done.GetUserId() != "" {
		t.Fatalf("ConfirmSignUp after the invitation was withdrawn: %v, %v — want the invitation refusal", done, err)
	}
	if len(s.users) != 0 {
		t.Fatalf("an account was created for a withdrawn invitation: %v", s.users)
	}
	if gateCalls != 2 || claimCalls != 1 {
		t.Errorf("gate ran %d times (want 2: SignUp and ConfirmSignUp), claim %d (want 1)", gateCalls, claimCalls)
	}

	// An invitation still standing at confirmation lets the registration in.
	revoked = false
	again, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "cto@example.com", Password: "pw-owner", InviteToken: "open-link"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if done, err := h.ConfirmSignUp(mintCtx(), &pb.ConfirmSignUpReq{PendingId: again.GetPendingId(), Code: s.codes[again.GetPendingId()]}); err != nil || done.GetUserId() == "" {
		t.Fatalf("ConfirmSignUp with the invitation standing: %v, %v", done, err)
	}
}
