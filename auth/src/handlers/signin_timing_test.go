package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// signInNotFoundQuery embeds the generated client (nil) to satisfy
// pb.AuthQueryClient, overriding only GetUserByEmail to report "not found".
type signInNotFoundQuery struct{ pb.AuthQueryClient }

func (signInNotFoundQuery) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return nil, errors.New("user not found")
}

// B48-auth-1: SignIn must run a dummy password verification on the
// user-not-found path so its response time doesn't leak account existence
// (timing oracle → user enumeration). Without it, a non-existent email returns
// fast (no argon2) while a real email pays the derivation.
func TestSignIn_UserNotFound_RunsDummyVerify_B48(t *testing.T) {
	called := false
	orig := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) { called = true }
	t.Cleanup(func() { signInDummyVerify = orig })

	h := &AuthServiceHandler{Query: signInNotFoundQuery{}}
	if _, err := h.SignIn(context.Background(), &pb.SignInReq{Email: "nobody@example.com", Password: "pw"}); err == nil {
		t.Fatal("SignIn for an unknown user must return Unauthenticated")
	}
	if !called {
		t.Error("B48-auth-1: SignIn must run the dummy verify on the user-not-found path (anti-enumeration timing)")
	}
}

// B48-auth-2: SignIn must normalize (trim + lowercase) the email before the
// GetUserByEmail lookup, so a cross-case / whitespace sign-in matches the
// account stored at signup (type:EMAIL is a case-sensitive unique constraint).
type emailRecorderQuery struct {
	pb.AuthQueryClient
	gotEmail string
}

func (m *emailRecorderQuery) GetUserByEmail(_ context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	m.gotEmail = in.GetEmail()
	return nil, errors.New("not found")
}

func TestSignIn_NormalizesEmailForLookup_B48(t *testing.T) {
	orig := signInDummyVerify // stub out the argon2 dummy verify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = orig })

	m := &emailRecorderQuery{}
	h := &AuthServiceHandler{Query: m}
	_, _ = h.SignIn(context.Background(), &pb.SignInReq{Email: "  Foo@X.COM ", Password: "pw"})
	if m.gotEmail != "foo@x.com" {
		t.Errorf("GetUserByEmail email = %q, want normalized %q", m.gotEmail, "foo@x.com")
	}
}
