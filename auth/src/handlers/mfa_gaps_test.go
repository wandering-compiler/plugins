package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// raisedChallenge signs u1 in through the gate and returns the handler, the
// store and the fallback code the challenge went out with.
func raisedChallenge(t *testing.T, tx *recordingDistTx) (*AuthServiceHandler, *mfaMock, string) {
	t.Helper()
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, challenged, err := signInMfaGate(ctxWithCaller("u1"), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil || !challenged {
		t.Fatalf("expected a challenge: %v", err)
	}
	// Attached after the challenge is raised, so what it records is the
	// verification's transaction alone.
	if tx != nil {
		h.DistTx = tx
	}
	return h, m, m.createdChallenge.GetCode()
}

// A challenge read without its creation time has no proof of age, and is
// refused rather than never expiring.
func TestVerifyMfa_AChallengeWithoutACreationTimeIsRefused(t *testing.T) {
	h, m, code := raisedChallenge(t, nil)
	m.chCreatedAt = nil
	if resp, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); err == nil || resp.GetToken() != "" {
		t.Fatalf("a challenge of unknown age signed in: %v %v", resp, err)
	}
}

// A disabled account's correct code consumes nothing: the consume announces
// MfaVerified, and it ran before the account check.
func TestVerifyMfa_ADisabledAccountDoesNotConsumeTheChallenge(t *testing.T) {
	tx := &recordingDistTx{}
	h, m, code := raisedChallenge(t, tx)
	m.disabled = true
	if _, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("a disabled account: %v", err)
	}
	if m.chConsumed {
		t.Error("the challenge was consumed (and MfaVerified announced) for a disabled account")
	}
	if got := tx.settled(); got != "rolled back" {
		t.Errorf("the verification was %s, want rolled back", got)
	}
}

// lostRace answers the consume as a concurrent request that got there first:
// no row.
type lostRace struct{ *mfaMock }

func (lostRace) ConsumeMfaChallenge(context.Context, *pb.ConsumeMfaChallengeReq, ...grpc.CallOption) (*pb.ConsumeMfaChallengeResp, error) {
	return &pb.ConsumeMfaChallengeResp{}, nil
}

// A verification that loses the consume rolls back what checking the code
// spent — a recovery code, a TOTP step — instead of burning it for a sign-in
// it does not get.
func TestVerifyMfa_ALostConsumeRollsTheCodeBack(t *testing.T) {
	tx := &recordingDistTx{}
	h, m, code := raisedChallenge(t, tx)
	h.Mutation = lostRace{m}
	if resp, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); err == nil || resp.GetToken() != "" {
		t.Fatalf("a lost consume signed in: %v %v", resp, err)
	}
	if got := tx.settled(); got != "rolled back" {
		t.Errorf("the verification was %s, want rolled back", got)
	}
}

func TestVerifyMfa_ASuccessCommitsOnce(t *testing.T) {
	tx := &recordingDistTx{}
	h, _, code := raisedChallenge(t, tx)
	resp, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code})
	if err != nil || resp.GetToken() == "" {
		t.Fatalf("verify: %v %v", resp, err)
	}
	if len(tx.committed) == 0 || len(tx.rolledBack) != 0 {
		t.Errorf("committed %v, rolled back %v", tx.committed, tx.rolledBack)
	}
}

func TestTwoFactorScope_AnUnknownValueRefusesTheBoot(t *testing.T) {
	for _, s := range []string{"", scopeAllLogins, scopeNewDevices} {
		if err := checkTwoFactorScope(&AuthServiceHandler{TwoFactorScope: s}); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"all-logins", "newdevices", "always"} {
		if err := checkTwoFactorScope(&AuthServiceHandler{TwoFactorScope: s}); err == nil {
			t.Errorf("%q was accepted — a typo would mean all_logins", s)
		}
	}
}
