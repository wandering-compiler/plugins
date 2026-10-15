package handlers

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// resetCallRecorder serves exactly the statements a reset is allowed to run
// and records them. Every other method is nil and panics if called — a reset
// that reached for the second factor, the address proof or a session mint
// fails here loudly.
type resetCallRecorder struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	calls []string
}

func (r *resetCallRecorder) ConsumePasswordResetToken(context.Context, *pb.ConsumePasswordResetTokenReq, ...grpc.CallOption) (*pb.ConsumePasswordResetTokenResp, error) {
	r.calls = append(r.calls, "ConsumePasswordResetToken")
	return &pb.ConsumePasswordResetTokenResp{UserId: "u1"}, nil
}

func (r *resetCallRecorder) UpdateUserPassword(_ context.Context, in *pb.UpdateUserPasswordReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordResp, error) {
	r.calls = append(r.calls, "UpdateUserPassword")
	return &pb.UpdateUserPasswordResp{UserId: in.GetUserId()}, nil
}

func (r *resetCallRecorder) SpendPasswordResetTokens(context.Context, *pb.SpendPasswordResetTokensReq, ...grpc.CallOption) (*pb.SpendPasswordResetTokensResp, error) {
	r.calls = append(r.calls, "SpendPasswordResetTokens")
	return &pb.SpendPasswordResetTokensResp{}, nil
}

func (r *resetCallRecorder) RevokeTokensForReset(context.Context, *pb.RevokeTokensForResetReq, ...grpc.CallOption) (*pb.RevokeTokensForResetResp, error) {
	r.calls = append(r.calls, "RevokeTokensForReset")
	return &pb.RevokeTokensForResetResp{}, nil
}

// A reset proves the mailbox and nothing more. It sets the password, spends
// the links and revokes the tokens; it issues no session, and it touches
// neither the second factor (the authenticator, its recovery codes, an open
// challenge) nor the address proof. So the next sign-in is challenged as
// before, a challenge opened before the reset is left to its TTL, and the
// address is no more verified than it was.
func TestResetPassword_TouchesThePasswordAndTokensOnly(t *testing.T) {
	r := &resetCallRecorder{}
	h := &AuthServiceHandler{Query: r, Mutation: r, PasswordHash: testPasswordSettings()}
	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "link", NewPassword: "a-new-long-password"})
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	want := "ConsumePasswordResetToken,UpdateUserPassword,SpendPasswordResetTokens,RevokeTokensForReset"
	if got := strings.Join(r.calls, ","); got != want {
		t.Errorf("a reset ran %s, want %s", got, want)
	}
	fields := resp.ProtoReflect().Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		if name := fields.Get(i).Name(); name != "sessions_revoked" {
			t.Errorf("ResetPasswordResp carries %q; a reset hands out nothing but the sweep's outcome", name)
		}
	}

	// And the statements behind those calls name nothing of the second factor
	// or of the address proof.
	src := readProto(t, filepath.Join("..", "..", "proto", "mutations", "auth_mutation.proto"))
	for _, rpc := range []string{"UpdateUserPassword", "ConsumePasswordResetToken", "SpendPasswordResetTokens", "RevokeTokensForReset"} {
		body := methodDQL(t, src, "rpc "+rpc+"(")
		for _, banned := range []string{"Totp", "RecoveryCode", "MfaChallenge", "email_verified_at", "email_proof"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s names %s:\n%s", rpc, banned, body)
			}
		}
	}
}
