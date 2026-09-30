package handlers_test

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/auth/handlers"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

func TestUnauthenticated_WireStatusIsAlwaysOpaque(t *testing.T) {
	cases := []struct {
		name  string
		cause error
	}{
		{"nil cause", nil},
		{"with cause", errors.New("upstream lookup failed")},
		{"with empty-string cause", errors.New("")},
		{"with wrapped chain", errors.New("layer1: layer2: root")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handlers.Unauthenticated(tc.cause)
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("FromError ok = false; want true (err = %v)", err)
			}
			if st.Code() != codes.Unauthenticated {
				t.Errorf("Code = %v, want Unauthenticated", st.Code())
			}
			if st.Message() != "invalid credentials" {
				t.Errorf("Message = %q, want %q", st.Message(), "invalid credentials")
			}
		})
	}
}

func TestUnauthenticated_ErrorStringIsOpaque(t *testing.T) {
	cause := errors.New("user enumeration leak attempt")
	err := handlers.Unauthenticated(cause)
	if err.Error() != "invalid credentials" {
		t.Errorf("Error() = %q, want %q (cause must not leak via Error)", err.Error(), "invalid credentials")
	}
}

func TestUnauthenticated_UnwrapExposesCause(t *testing.T) {
	root := errors.New("root cause")
	err := handlers.Unauthenticated(root)
	if got := errors.Unwrap(err); got != root {
		t.Fatalf("Unwrap = %v, want %v", got, root)
	}
}

func TestUnauthenticated_NilCauseUnwrapReturnsNil(t *testing.T) {
	err := handlers.Unauthenticated(nil)
	if got := errors.Unwrap(err); got != nil {
		t.Fatalf("Unwrap with nil cause = %v, want nil", got)
	}
}

// sentinel demonstrates errors.Is chains through Unwrap.
var errAuthnHeaderMissing = errors.New("authn header missing")

func TestUnauthenticated_IsMatchesCause(t *testing.T) {
	err := handlers.Unauthenticated(errAuthnHeaderMissing)
	if !errors.Is(err, errAuthnHeaderMissing) {
		t.Fatalf("errors.Is failed to walk Unwrap chain to cause")
	}
}

func TestUnauthenticated_TwoCallsWithDifferentCauses_WireResponseIdentical(t *testing.T) {
	a := handlers.Unauthenticated(errors.New("path A: bad password"))
	b := handlers.Unauthenticated(errors.New("path B: no such email"))
	stA, _ := status.FromError(a)
	stB, _ := status.FromError(b)
	if stA.Code() != stB.Code() {
		t.Errorf("Code(A) %v != Code(B) %v — anti-enumeration violated", stA.Code(), stB.Code())
	}
	if stA.Message() != stB.Message() {
		t.Errorf("Message(A) %q != Message(B) %q — anti-enumeration violated",
			stA.Message(), stB.Message())
	}
	if a.Error() != b.Error() {
		t.Errorf("Error(A) %q != Error(B) %q — anti-enumeration violated via Error()",
			a.Error(), b.Error())
	}
}

// --- a consumer 2026-09-23: an outage is not a refusal --------------------------
//
// GRPCStatus was fixed "regardless of cause", and its own comment listed what
// that collapsed: "no such email", "wrong password", "DB transient failure".
// The first two belong together. The third made a running service with a dead
// database tell people their password was wrong — a lie they cannot check,
// which sends them to reset a password that was fine.

func TestAuthnError_AnOutageIsNotReportedAsBadCredentials(t *testing.T) {
	for _, cause := range []error{
		status.Error(codes.Unavailable, "connection refused"),
		status.Error(codes.DeadlineExceeded, "context deadline exceeded"),
		status.Error(codes.Internal, "driver: bad connection"),
		status.Error(codes.ResourceExhausted, "too many connections"),
		status.Error(codes.Aborted, "serialization failure"),
	} {
		st, _ := status.FromError(handlers.Unauthenticated(cause))
		if st.Code() == codes.Unauthenticated {
			t.Errorf("%v reached the caller as `invalid credentials` — the user is told their "+
				"password is wrong while the service is down", status.Code(cause))
		}
		if st.Code() != codes.Unavailable {
			t.Errorf("%v became %v, not Unavailable", status.Code(cause), st.Code())
		}
		// And the message must not name the account or the cause: what makes
		// this safe is that every caller and every address get the same words.
		if strings.Contains(st.Message(), "connection") || strings.Contains(st.Message(), "deadline") {
			t.Errorf("the operational message leaks the cause: %q", st.Message())
		}
	}
}

// The contract that must NOT move: every refusal is still one opaque answer.
// Without this the change above is indistinguishable from removing
// anti-enumeration altogether.
func TestAuthnError_EveryRefusalIsStillTheSameOpaqueAnswer(t *testing.T) {
	refusals := []error{
		nil,                             // a shape gate with no cause
		errors.New("password mismatch"), // a package sentinel
		status.Error(codes.NotFound, "no such user"),   // THE enumeration case
		status.Error(codes.PermissionDenied, "denied"), // a downstream refusal
		status.Error(codes.InvalidArgument, "bad email"),
	}
	var seen []string
	for _, cause := range refusals {
		st, _ := status.FromError(handlers.Unauthenticated(cause))
		if st.Code() != codes.Unauthenticated {
			t.Errorf("a refusal (%v) became %v — that is a new way to enumerate", cause, st.Code())
		}
		seen = append(seen, st.Message())
	}
	for _, m := range seen {
		if m != seen[0] {
			t.Errorf("refusals no longer share one message: %q vs %q", m, seen[0])
		}
	}
}

// NotFound is called out on its own because it is the one an attacker steers:
// it is what "this email does not exist" looks like coming back from the
// store, and an allow-list that grew carelessly would let it through as an
// "operational" answer and hand back an enumeration oracle.
func TestAuthnError_NotFoundNeverBecomesOperational(t *testing.T) {
	st, _ := status.FromError(handlers.Unauthenticated(status.Error(codes.NotFound, "no rows")))
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("a missing account is distinguishable from a wrong password: %v", st.Code())
	}
}

// detailOf returns the ErrorDetail a gateway would render, or nil.
func detailOf(t *testing.T, err error) *w17pb.ErrorDetail {
	t.Helper()
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed
		}
	}
	return nil
}

// A failed sign-in must tell a person what actually happened.
//
// Without a detail the REST gateway falls back to the generic sentence for
// codes.Unauthenticated — "You are not signed in." — which is true, useless,
// and confusing beside the login form the caller just submitted. The code is
// what a front end branches on; today it has to parse English prose to tell a
// bad password from a service outage.
func TestUnauthenticatedSignIn_CarriesAUserFacingDetail(t *testing.T) {
	detail := detailOf(t, handlers.UnauthenticatedSignIn(errors.New("no such email")))
	if detail == nil {
		t.Fatal("no ErrorDetail: the gateway has nothing to render and falls back to the generic sentence")
	}
	if detail.GetCode() != handlers.CodeInvalidCredentials {
		t.Errorf("code = %q, want %q", detail.GetCode(), handlers.CodeInvalidCredentials)
	}
	// Anti-enumeration survives: the sentence names BOTH halves, so it says
	// nothing about whether the account exists.
	if !strings.Contains(detail.GetMessage(), "email or password") {
		t.Errorf("message = %q — it must not reveal which half was wrong", detail.GetMessage())
	}
	// And the operator's copy is untouched.
	st, _ := status.FromError(handlers.UnauthenticatedSignIn(errors.New("x")))
	if st.Message() != "invalid credentials" {
		t.Errorf("status message changed to %q; the opaque wire answer must stay", st.Message())
	}
}

// The four sign-in gates must be INDISTINGUISHABLE to a person, not just to a
// machine. A friendlier sentence for "no such account" than for "wrong
// password" is an email enumeration oracle — the exact leak the opaque status
// was built to close, reopened one layer up.
func TestUnauthenticatedSignIn_AllGatesRenderIdentically(t *testing.T) {
	causes := map[string]error{
		"no such account":  errors.New("user not found"),
		"wrong password":   errors.New("password mismatch"),
		"bot account":      errors.New("machine account may not sign in"),
		"disabled account": errors.New("account disabled"),
	}
	var first *w17pb.ErrorDetail
	for name, cause := range causes {
		got := detailOf(t, handlers.UnauthenticatedSignIn(cause))
		if got == nil {
			t.Fatalf("%s: no ErrorDetail", name)
		}
		if first == nil {
			first = got
			continue
		}
		if got.GetCode() != first.GetCode() || got.GetMessage() != first.GetMessage() {
			t.Errorf("%s renders %q/%q but another gate renders %q/%q — that difference enumerates accounts",
				name, got.GetCode(), got.GetMessage(), first.GetCode(), first.GetMessage())
		}
	}
}

// The GENERIC constructor serves 87 call sites — bearer headers, MFA codes,
// reset tokens, OAuth, API tokens, invites. It must not borrow sign-in's
// sentence: "Wrong email or password." for a missing bearer token or an
// expired reset link is simply false, and it is the failure this guard exists
// to catch, because attaching the pair in the shared constructor is the
// obvious-looking shortcut (caught in review on PR #6).
func TestUnauthenticated_GenericCarriesNoFlowSentence(t *testing.T) {
	if got := detailOf(t, handlers.Unauthenticated(errors.New("missing bearer header"))); got != nil {
		t.Errorf("generic refusal carried %q/%q; flows that did not ask for a sentence must get none",
			got.GetCode(), got.GetMessage())
	}
}

func TestUnauthenticated_OutageCarriesItsOwnCode(t *testing.T) {
	st, _ := status.FromError(handlers.Unauthenticated(status.Error(codes.Unavailable, "db down")))

	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			if ed.GetCode() != handlers.CodeAuthUnavailable {
				t.Errorf("code = %q, want %q", ed.GetCode(), handlers.CodeAuthUnavailable)
			}
			if strings.Contains(ed.GetMessage(), "password") {
				t.Errorf("an outage told the caller about their password: %q", ed.GetMessage())
			}
			// Reached from every flow, so it may not name one.
			if strings.Contains(strings.ToLower(ed.GetMessage()), "sign-in") {
				t.Errorf("the outage sentence names one flow (%q) but serves all of them", ed.GetMessage())
			}
			return
		}
	}
	t.Fatal("no ErrorDetail on the operational answer")
}
