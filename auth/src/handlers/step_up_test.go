package handlers

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// stepUpMock serves the read ConfirmPassword makes and records the stamp.
type stepUpMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	storedHash string
	marks      []*pb.MarkSessionSteppedUpReq
	attempts   int64
	lockedTill *timestamppb.Timestamp
}

func (m *stepUpMock) RecordPasswordStepUpAttempt(_ context.Context, in *pb.RecordPasswordStepUpAttemptReq, _ ...grpc.CallOption) (*pb.RecordPasswordStepUpAttemptResp, error) {
	if m.lockedTill != nil && m.lockedTill.AsTime().After(time.Now()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.attempts++
	return &pb.RecordPasswordStepUpAttemptResp{Attempts: m.attempts}, nil
}

func (m *stepUpMock) LockPasswordStepUp(_ context.Context, in *pb.LockPasswordStepUpReq, _ ...grpc.CallOption) (*pb.LockPasswordStepUpResp, error) {
	m.attempts, m.lockedTill = 0, in.GetUntil()
	return &pb.LockPasswordStepUpResp{Id: in.GetTokenId()}, nil
}

func (m *stepUpMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), PasswordHash: m.storedHash}}, nil
}

func (m *stepUpMock) MarkSessionSteppedUp(_ context.Context, in *pb.MarkSessionSteppedUpReq, _ ...grpc.CallOption) (*pb.MarkSessionSteppedUpResp, error) {
	m.marks = append(m.marks, in)
	m.attempts = 0
	return &pb.MarkSessionSteppedUpResp{Id: in.GetTokenId(), SteppedUpAt: timestamppb.Now()}, nil
}

func newStepUpHandler(t *testing.T, password string) (*AuthServiceHandler, *stepUpMock) {
	t.Helper()
	ps := testPasswordSettings()
	hash, err := ps.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	m := &stepUpMock{storedHash: hash}
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: ps}, m
}

// The right password stamps the CALLER's own session, keyed on the
// authenticated user — never a session named by the request.
func TestConfirmPassword_StampsTheCallersSession(t *testing.T) {
	h, m := newStepUpHandler(t, "correct-horse-battery-staple")
	out, err := h.ConfirmPassword(sessionCallerCtx("u1", "tok-1"), &pb.ConfirmPasswordReq{Password: "correct-horse-battery-staple"})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.marks) != 1 || m.marks[0].GetTokenId() != "tok-1" || m.marks[0].GetUserId() != "u1" || out.GetSteppedUpAt() == nil {
		t.Fatalf("marks = %+v, out = %+v", m.marks, out)
	}
}

// A wrong password stamps nothing and says which field; an API token, which
// has no session, is refused before the password is even checked.
func TestConfirmPassword_RefusesAWrongPasswordAndAnAPIToken(t *testing.T) {
	h, m := newStepUpHandler(t, "correct-horse-battery-staple")
	_, err := h.ConfirmPassword(sessionCallerCtx("u1", "tok-1"), &pb.ConfirmPasswordReq{Password: "not-it"})
	if status.Code(err) != codes.PermissionDenied || func() bool { _, c := detailCode(t, err); return c != CodePasswordNotConfirmed }() {
		t.Fatalf("a wrong password: %v", err)
	}
	_, err = h.ConfirmPassword(sessionCallerCtx("u1", ""), &pb.ConfirmPasswordReq{Password: "correct-horse-battery-staple"})
	if _, c := detailCode(t, err); c != CodeSessionRequired {
		t.Fatalf("an API token: %v", err)
	}
	if len(m.marks) != 0 {
		t.Fatalf("stamped %d session(s)", len(m.marks))
	}
}

// Five wrong passwords in a row lock the step-up for fifteen minutes — even
// the right one is refused then — so a stolen session is no password oracle.
func TestConfirmPassword_LocksAfterFiveWrongPasswords(t *testing.T) {
	h, m := newStepUpHandler(t, "correct-horse-battery-staple")
	ctx := sessionCallerCtx("u1", "tok-1")
	for i := 0; i < maxPasswordStepUpAttempts; i++ {
		if _, err := h.ConfirmPassword(ctx, &pb.ConfirmPasswordReq{Password: "guess"}); func() bool { _, c := detailCode(t, err); return c != CodePasswordNotConfirmed }() {
			t.Fatalf("guess %d: %v", i+1, err)
		}
	}
	if _, err := h.ConfirmPassword(ctx, &pb.ConfirmPasswordReq{Password: "guess"}); func() bool { _, c := detailCode(t, err); return c != CodePasswordStepUpLocked }() {
		t.Fatalf("the sixth guess: %v", err)
	}
	if _, err := h.ConfirmPassword(ctx, &pb.ConfirmPasswordReq{Password: "correct-horse-battery-staple"}); func() bool { _, c := detailCode(t, err); return c != CodePasswordStepUpLocked }() {
		t.Fatalf("the right password while locked: %v", err)
	}
	if len(m.marks) != 0 || m.lockedTill == nil {
		t.Fatalf("marks %d, locked until %v", len(m.marks), m.lockedTill)
	}
}
