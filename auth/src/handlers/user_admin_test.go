package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// disabledUserQuery returns one canned user for GetUserByEmail, so SignIn
// reaches the disabled gate after a (successful) password verify.
type disabledUserQuery struct {
	pb.AuthQueryClient
	user *pb.User
}

func (q disabledUserQuery) GetUserByEmail(context.Context, *pb.GetUserByEmailReq, ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: q.user}, nil
}

// handlers/user_admin.go's init() installs the real signInDisabledGate
// override (this file compiles into the standalone test binary — feature
// gating happens at activation staging, not in the source tree), so these
// tests exercise the wired-up behaviour, not the base no-op.

// user_admin-1: the gate passes an active account (disabled_at nil) and
// rejects a disabled one (disabled_at set).
func TestSignInDisabledGate_SeamRejectsDisabledAllowsActive(t *testing.T) {
	if err := signInDisabledGate(&pb.User{}); err != nil {
		t.Fatalf("active account (disabled_at nil) must pass the gate, got %v", err)
	}
	if err := signInDisabledGate(&pb.User{DisabledAt: timestamppb.Now()}); err == nil {
		t.Fatal("disabled account (disabled_at set) must be rejected by the gate")
	}
}

// user_admin-2: SignIn rejects a disabled account even with the CORRECT
// password — the disabled gate fires after the password verify, so the
// only reason this login fails is the soft-disable.
func TestSignIn_RejectsDisabledAccount(t *testing.T) {
	ps := testPasswordSettings()
	hash, err := ps.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	h := &AuthServiceHandler{
		Query: disabledUserQuery{user: &pb.User{
			Id:           "u1",
			Email:        "u@example.com",
			PasswordHash: hash,
			DisabledAt:   timestamppb.Now(),
		}},
		PasswordHash: ps,
	}
	if _, err := h.SignIn(context.Background(), &pb.SignInReq{
		Email:    "u@example.com",
		Password: "correct-horse-battery-staple",
	}); err == nil {
		t.Fatal("SignIn must reject a disabled account even with the correct password")
	}
}
