package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// passwordChangeMock serves the one read ChangePassword makes and records the
// compare-and-swap it issues. `casErr` lets a test answer the way the
// generated mutation answers when the predicate matches nothing.
type passwordChangeMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	storedHash string

	casCalls  int
	lastCAS   *pb.UpdateUserPasswordIfUnchangedReq
	casErr    error
	plainCall int // UpdateUserPassword — the un-predicated write; must stay unused here
}

func (m *passwordChangeMock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), PasswordHash: m.storedHash}}, nil
}

func (m *passwordChangeMock) UpdateUserPasswordIfUnchanged(ctx context.Context, in *pb.UpdateUserPasswordIfUnchangedReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordIfUnchangedResp, error) {
	m.casCalls++
	m.lastCAS = in
	if m.casErr != nil {
		return nil, m.casErr
	}
	return &pb.UpdateUserPasswordIfUnchangedResp{UserId: in.GetUserId()}, nil
}

func (m *passwordChangeMock) UpdateUserPassword(ctx context.Context, in *pb.UpdateUserPasswordReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordResp, error) {
	m.plainCall++
	return &pb.UpdateUserPasswordResp{UserId: in.GetUserId()}, nil
}

func newPasswordChangeHandler(t *testing.T, current string) (*AuthServiceHandler, *passwordChangeMock) {
	t.Helper()
	ps := testPasswordSettings()
	hash, err := ps.Hash(current)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	m := &passwordChangeMock{storedHash: hash}
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: ps}, m
}

// The write must carry the hash the proof was verified AGAINST, so the
// database can refuse it if that value moved. Asserting the predicate's
// content is the point: a CAS that sends the wrong current_hash compiles,
// runs, and protects nothing — it would simply match zero rows forever, and
// the happy-path test would be the thing that noticed, at which point somebody
// "fixes" it by dropping the predicate again.
func TestChangePassword_WritesUnderTheVerifiedHash(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	stored := m.storedHash

	if _, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if m.casCalls != 1 {
		t.Fatalf("want exactly one compare-and-swap, got %d", m.casCalls)
	}
	if m.plainCall != 0 {
		t.Fatalf("the un-predicated UpdateUserPassword must not be used by a CHANGE (it serves resets), called %d time(s)", m.plainCall)
	}
	if got := m.lastCAS.GetCurrentHash(); got != stored {
		t.Fatalf("current_hash = %q, want the verified stored hash %q", got, stored)
	}
	if m.lastCAS.GetPasswordHash() == stored {
		t.Fatal("the new hash equals the old one — the write would be a no-op")
	}
	if m.lastCAS.GetUserId() != "u1" {
		t.Fatalf("user_id = %q, want the authenticated principal u1", m.lastCAS.GetUserId())
	}
}

// Somebody else changed the password between the read and the write, so the
// predicate matches nothing and the generated mutation answers NotFound. The
// caller must be refused — this is the case the CAS exists for: an attacker
// who knows the OLD password racing the owner's fresh rotation.
func TestChangePassword_RefusesWhenTheHashMovedUnderneath(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	m.casErr = status.Error(codes.NotFound, "no rows")

	_, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	})
	if err == nil {
		t.Fatal("a lost CAS must not report success — the password was NOT changed")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated (identical to the wrong-password refusal), got %v", status.Code(err))
	}
}

// A failure that is NOT the predicate missing keeps its own identity. Mapping
// every mutation error onto "wrong password" would tell somebody their password
// is wrong when the database is simply down, and would hide a real fault behind
// a message that invites them to retry forever.
func TestChangePassword_OtherWriteErrorsAreNotDisguised(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	boom := status.Error(codes.Unavailable, "db down")
	m.casErr = boom

	_, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable passed through, got %v", err)
	}
}

// The wrong current password is refused BEFORE anything is written. Without
// this, the tests above would all pass for a handler that verified nothing and
// leaned entirely on the database predicate — which would accept any caller who
// could guess the stored hash's own value.
func TestChangePassword_WrongCurrentPasswordWritesNothing(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")

	_, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "not-the-password",
		NewPassword:     "a-different-long-password",
	})
	if !errors.Is(err, errCurrentPasswordWrong) && status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want the wrong-password refusal, got %v", err)
	}
	if m.casCalls != 0 || m.plainCall != 0 {
		t.Fatalf("nothing may be written when the proof fails (cas=%d plain=%d)", m.casCalls, m.plainCall)
	}
}
