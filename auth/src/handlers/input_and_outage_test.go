package handlers

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/plugins/auth/lib/passwordhash"
)

// The scheme name is case-insensitive (RFC 9110 §11.1): `bearer <t>` is the
// same credential as `Bearer <t>`.
func TestPresentedToken_TheSchemeIsCaseInsensitive(t *testing.T) {
	h := &AuthServiceHandler{Scheme: "Bearer"}
	for _, raw := range []string{"Bearer tok", "bearer tok", "BEARER tok"} {
		if token, viaDPoP, err := h.presentedToken(raw); err != nil || token != "tok" || viaDPoP {
			t.Errorf("%q: token %q, dpop %v, err %v", raw, token, viaDPoP, err)
		}
	}
	for _, raw := range []string{"Bearertok", "Basic tok", "Bear tok", "Bearer"} {
		if _, _, err := h.presentedToken(raw); err != errAuthnSchemeMismatch {
			t.Errorf("%q: %v, want a scheme mismatch", raw, err)
		}
	}
}

// storeDown answers the attempt count as an unreachable store.
type storeDown struct{ *mfaMock }

func (storeDown) RecordMfaAttempt(context.Context, *pb.RecordMfaAttemptReq, ...grpc.CallOption) (*pb.RecordMfaAttemptResp, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}

// A guess that cannot be counted is refused, as an outage: the person retries
// rather than retyping a code that was right.
func TestVerifyMfa_AnOutageIsSaidAsOne(t *testing.T) {
	h, m, code := raisedChallenge(t, nil)
	h.Mutation = storeDown{m}
	resp, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code})
	if resp.GetToken() != "" || status.Code(err) != codes.Unavailable {
		t.Fatalf("an uncounted guess: %v, %v — want refused as Unavailable", resp, err)
	}
}

// confirmStoreDown answers the attempt count as an unreachable store.
type confirmStoreDown struct{ *confirmStore }

func (confirmStoreDown) RecordPendingSignUpAttempt(context.Context, *pb.RecordPendingSignUpAttemptReq, ...grpc.CallOption) (*pb.RecordPendingSignUpAttemptResp, error) {
	return nil, status.Error(codes.Unavailable, "db down")
}

func TestSignUpConfirmation_AnOutageIsSaidAsOne(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := withJKT(context.Background(), testJKT)
	resp, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	down := confirmStoreDown{s}
	h.Query, h.Mutation = down, down
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]}); status.Code(err) != codes.Unavailable {
		t.Fatalf("an uncounted confirmation: %v — want Unavailable, not a wrong code", err)
	}
	if len(s.users) != 0 {
		t.Fatalf("an account was created: %v", s.users)
	}
}

// bcrypt takes at most 72 bytes. A longer password is the person's input to
// fix, refused on its field, not a server error.
func TestSignUp_APasswordTooLongForTheHashIsRefusedOnTheField(t *testing.T) {
	h, _ := confirmHandler(t)
	h.PasswordHash = passwordhash.Settings{Algo: passwordhash.Bcrypt, Params: passwordhash.Params{BcryptCost: 4}}
	_, err := h.SignUp(withJKT(context.Background(), testJKT), &pb.SignUpReq{Email: "a@example.com", Password: strings.Repeat("x", 73)})
	if c, code := detailCode(t, err); c != codes.InvalidArgument || code != CodePasswordTooLong {
		t.Fatalf("a 73-byte password under bcrypt: %v (%s), want InvalidArgument %s", c, code, CodePasswordTooLong)
	}
}

func TestHashPasswordErr_PassesOtherFailuresOn(t *testing.T) {
	other := status.Error(codes.Internal, "boom")
	if got := hashPasswordErr(context.Background(), other, "password"); got != other {
		t.Errorf("another failure became %v", got)
	}
}
