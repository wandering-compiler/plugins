package handlers_test

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/auth/handlers"
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

// --- marb 2026-09-23: an outage is not a refusal --------------------------
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
