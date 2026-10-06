package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
	"github.com/wandering-compiler/platform/plugins/auth/lib/passwordhash"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// What a person is actually shown when a sign-in is refused, asserted by
// driving SignIn — not by calling the constructor.
//
// The constructor tests beside these prove UnauthenticatedSignIn builds the
// right pair. They cannot prove SignIn USES it: every one of the four gates
// would still compile, still refuse, and still return codes.Unauthenticated
// if it were switched back to the generic Unauthenticated, and the existing
// gate tests only assert "refused" or "code is Unauthenticated", so all of
// them stay green while the message a person reads silently disappears.
// Raised in review on w17 platform PR #8.
//
// This is also the anti-enumeration assertion that counts. The rule is about
// what a PROBER observes from the outside, and the outside is this seam.

// signInDetail drives SignIn and returns the ErrorDetail a gateway would
// render, failing the test if the call was not refused at all.
func signInDetail(t *testing.T, h *AuthServiceHandler, email, password string) *w17pb.ErrorDetail {
	t.Helper()
	_, err := h.SignIn(context.Background(), &pb.SignInReq{Email: email, Password: password})
	if err == nil {
		t.Fatal("SignIn succeeded where the test needs a refusal")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unauthenticated {
		t.Fatalf("refusal arrived as %v, not the opaque Unauthenticated", st.Code())
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok {
			return ed
		}
	}
	t.Fatal("no ErrorDetail reached the wire: the gateway falls back to " +
		"\"You are not signed in.\" beside the login form")
	return nil
}

// signInRefusalCases builds a handler for each of the four gates SignIn
// refuses a submitted credential at.
func signInRefusalCases(t *testing.T) map[string]func() (*AuthServiceHandler, string, string) {
	t.Helper()
	ps := testPasswordSettings()
	const password = "correct-horse-battery-staple"
	hash, err := ps.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	return map[string]func() (*AuthServiceHandler, string, string){
		"no such account": func() (*AuthServiceHandler, string, string) {
			s := newRoundTripStore()
			return &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: ps},
				"nobody@example.com", password
		},
		"wrong password": func() (*AuthServiceHandler, string, string) {
			s := newRoundTripStore()
			h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: ps}
			if _, err := h.SignUp(context.Background(), &pb.SignUpReq{
				Email: "a@b.c", Password: password,
			}); err != nil {
				t.Fatalf("SignUp: %v", err)
			}
			return h, "a@b.c", "something else"
		},
		"machine account": func() (*AuthServiceHandler, string, string) {
			s := passwordhash.DefaultSettings()
			botHash, err := s.Hash(password)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			return &AuthServiceHandler{
				Query:        signInBotQuery{kind: pb.AccountKind_BOT, hash: botHash},
				PasswordHash: s,
			}, "ci@example.com", password
		},
		"disabled account": func() (*AuthServiceHandler, string, string) {
			return &AuthServiceHandler{
				Query: disabledUserQuery{user: &pb.User{
					Id: "u1", Email: "u@example.com",
					PasswordHash: hash, DisabledAt: timestamppb.Now(),
				}},
				PasswordHash: ps,
			}, "u@example.com", password
		},
	}
}

// Each of the four gates must put a readable sentence on the wire. A gate
// quietly reverted to the generic constructor fails HERE and nowhere else.
func TestSignIn_EveryRefusalReachesTheWireWithAMessage(t *testing.T) {
	for name, build := range signInRefusalCases(t) {
		t.Run(name, func(t *testing.T) {
			pinConsoleActivation(t)
			h, email, password := build()
			d := signInDetail(t, h, email, password)
			if d.GetCode() != CodeInvalidCredentials {
				t.Errorf("code = %q, want %q", d.GetCode(), CodeInvalidCredentials)
			}
			if d.GetMessage() == "" {
				t.Error("empty message: nothing for a person to read")
			}
		})
	}
}

// And they must be INDISTINGUISHABLE from each other.
//
// This is the anti-enumeration rule asserted where it is actually exposed. A
// friendlier sentence for "no such account" than for "wrong password" is an
// email oracle, and so is a different code — the opaque status underneath
// does not help once a detail rides along with it.
func TestSignIn_TheFourRefusalsAreIndistinguishable(t *testing.T) {
	type seen struct{ code, msg string }
	got := map[string]seen{}
	for name, build := range signInRefusalCases(t) {
		pinConsoleActivation(t)
		h, email, password := build()
		d := signInDetail(t, h, email, password)
		got[name] = seen{d.GetCode(), d.GetMessage()}
	}

	var first string
	for name := range got {
		if first == "" || name < first {
			first = name
		}
	}
	want := got[first]
	for name, s := range got {
		if s != want {
			t.Errorf("%q renders %q/%q but %q renders %q/%q — that difference enumerates accounts",
				name, s.code, s.msg, first, want.code, want.msg)
		}
	}
}
