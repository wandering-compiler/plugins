package handlers

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// A refused second-factor code used to read "You are not signed in." — on
// ConfirmTotp to a caller whose bearer had just been accepted. Every cause of
// a refused code now carries the SAME status and the same pair about the
// code, so the sentence tells a guesser nothing the status did not; an outage
// keeps its own answer.
func TestMfaCodeRefusal_SaysTheCodeAndIsTheSameForEveryCause(t *testing.T) {
	var first *status.Status
	for _, cause := range []error{errMfaChallengeInvalid, errMfaAttemptsSpent, errMfaChallengeOtherDevice} {
		err := UnauthenticatedMfaCode(cause)
		if !errors.Is(err, cause) {
			t.Errorf("%v: the cause is lost (sign-in outcome rules match on it)", cause)
		}
		st := status.Convert(err)
		if st.Code() != codes.Unauthenticated {
			t.Errorf("%v: code = %v, want Unauthenticated (the contract)", cause, st.Code())
		}
		d := errorDetailOf(t, err)
		if d == nil || d.GetCode() != CodeMfaCodeRefused || d.GetMessage() != MsgMfaCodeRefused {
			t.Fatalf("%v: detail = %v, want %s / %q", cause, d, CodeMfaCodeRefused, MsgMfaCodeRefused)
		}
		if first == nil {
			first = st
			continue
		}
		if st.Message() != first.Message() {
			t.Errorf("%v: status message %q differs from %q — the causes must be indistinguishable", cause, st.Message(), first.Message())
		}
	}
	outage := status.Error(codes.Unavailable, "store down")
	if d := errorDetailOf(t, UnauthenticatedMfaCode(outage)); d != nil && d.GetCode() == CodeMfaCodeRefused {
		t.Errorf("an outage was reported as a refused code: %v", d)
	}
}

// An outage while ConfirmTotp reads the pending authenticator is said as one
// (AUTH_UNAVAILABLE): the person should retry, not retype a code that was
// never checked.
func TestConfirmTotp_AnOutageIsNotARefusedCode(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", totpReadErr: status.Error(codes.Unavailable, "store down")}
	h := newMfaHandler(m)
	_, err := h.ConfirmTotp(ctxWithCaller("u1"), &pb.ConfirmTotpReq{Code: "123456"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v (%v), want Unavailable", err, status.Code(err))
	}
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeAuthUnavailable {
		t.Fatalf("detail = %v, want %s", d, CodeAuthUnavailable)
	}
}
