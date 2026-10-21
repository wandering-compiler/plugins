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
	"github.com/wandering-compiler/plugins/auth/lib/totp"
)

// stepUpCodeMock is the session row the step_up_code feature writes (the
// mailed code's hash and when it went out, the stamp, the guess budget) over
// mfaMock's authenticator and recovery codes.
type stepUpCodeMock struct {
	*mfaMock

	sessionGone bool
	codeHash    string
	sentAt      *timestamppb.Timestamp
	attempts    int64
	lockedTill  *timestamppb.Timestamp
	steppedUpAt *timestamppb.Timestamp

	sent     []*pb.SetStepUpCodeReq
	marks    []*pb.MarkSessionSteppedUpReq
	consumes []*pb.ConsumeStepUpCodeReq
}

func (m *stepUpCodeMock) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), Email: "ada@example.com"}}, nil
}

func (m *stepUpCodeMock) SetStepUpCode(_ context.Context, in *pb.SetStepUpCodeReq, _ ...grpc.CallOption) (*pb.SetStepUpCodeResp, error) {
	if m.sessionGone || (m.sentAt != nil && !m.sentAt.AsTime().Before(in.GetResendBefore().AsTime())) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.sent = append(m.sent, in)
	m.codeHash, m.sentAt = in.GetCodeHash(), timestamppb.Now()
	return &pb.SetStepUpCodeResp{TokenId: in.GetTokenId(), UserId: in.GetUserId(), SentAt: m.sentAt}, nil
}

func (m *stepUpCodeMock) GetSessionStepUp(_ context.Context, _ *pb.GetSessionStepUpReq, _ ...grpc.CallOption) (*pb.GetSessionStepUpResp, error) {
	if m.sessionGone {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetSessionStepUpResp{CodeHash: m.codeHash, SentAt: m.sentAt}, nil
}

func (m *stepUpCodeMock) ConsumeStepUpCode(_ context.Context, in *pb.ConsumeStepUpCodeReq, _ ...grpc.CallOption) (*pb.ConsumeStepUpCodeResp, error) {
	if m.sessionGone || m.codeHash == "" || m.codeHash != in.GetCodeHash() {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.consumes = append(m.consumes, in)
	m.codeHash, m.sentAt, m.attempts = "", nil, 0
	m.steppedUpAt = timestamppb.Now()
	return &pb.ConsumeStepUpCodeResp{Id: in.GetTokenId(), SteppedUpAt: m.steppedUpAt}, nil
}

func (m *stepUpCodeMock) RecordPasswordStepUpAttempt(_ context.Context, _ *pb.RecordPasswordStepUpAttemptReq, _ ...grpc.CallOption) (*pb.RecordPasswordStepUpAttemptResp, error) {
	if m.lockedTill != nil && m.lockedTill.AsTime().After(time.Now()) {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.attempts++
	return &pb.RecordPasswordStepUpAttemptResp{Attempts: m.attempts}, nil
}

func (m *stepUpCodeMock) LockPasswordStepUp(_ context.Context, in *pb.LockPasswordStepUpReq, _ ...grpc.CallOption) (*pb.LockPasswordStepUpResp, error) {
	m.attempts, m.lockedTill = 0, in.GetUntil()
	return &pb.LockPasswordStepUpResp{Id: in.GetTokenId()}, nil
}

func (m *stepUpCodeMock) MarkSessionSteppedUp(_ context.Context, in *pb.MarkSessionSteppedUpReq, _ ...grpc.CallOption) (*pb.MarkSessionSteppedUpResp, error) {
	m.marks = append(m.marks, in)
	m.attempts = 0
	m.steppedUpAt = timestamppb.Now()
	return &pb.MarkSessionSteppedUpResp{Id: in.GetTokenId(), SteppedUpAt: m.steppedUpAt}, nil
}

func (m *stepUpCodeMock) GetSessionSteppedUpAt(_ context.Context, _ *pb.GetSessionSteppedUpAtReq, _ ...grpc.CallOption) (*pb.GetSessionSteppedUpAtResp, error) {
	if m.sessionGone {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetSessionSteppedUpAtResp{SteppedUpAt: m.steppedUpAt}, nil
}

// testTotpSeed is a valid base32 seed, so the tests compute real codes.
const testTotpSeed = "JBSWY3DPEHPK3PXP"

func newStepUpCodeHandler(enrolled bool) (*AuthServiceHandler, *stepUpCodeMock) {
	inner := &mfaMock{}
	if enrolled {
		inner.totpSeed, inner.totpConfirmed = testTotpSeed, true
	}
	m := &stepUpCodeMock{mfaMock: inner}
	h := newMfaHandler(inner)
	h.Query, h.Mutation = m, m
	return h, m
}

func refusalCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return ""
	}
	_, c := detailCode(t, err)
	return c
}

// A person with an authenticator is asked for its code and nothing is
// mailed; anyone else gets a code mailed, its hash on THEIR session only.
func TestRequestStepUpCode_AuthenticatorOrMailedCode(t *testing.T) {
	h, m := newStepUpCodeHandler(true)
	out, err := h.RequestStepUpCode(sessionCallerCtx("u1", "tok-1"), &pb.RequestStepUpCodeReq{})
	if err != nil || out.GetMethod() != stepUpMethodAuthenticator || len(m.sent) != 0 {
		t.Fatalf("enrolled: out=%+v err=%v sent=%d", out, err, len(m.sent))
	}

	h, m = newStepUpCodeHandler(false)
	out, err = h.RequestStepUpCode(sessionCallerCtx("u1", "tok-1"), &pb.RequestStepUpCodeReq{})
	if err != nil || out.GetMethod() != stepUpMethodEmail || out.GetExpiresAt() == nil {
		t.Fatalf("not enrolled: out=%+v err=%v", out, err)
	}
	if len(m.sent) != 1 {
		t.Fatalf("sent %d codes", len(m.sent))
	}
	s := m.sent[0]
	if s.GetTokenId() != "tok-1" || s.GetUserId() != "u1" || s.GetEmail() != "ada@example.com" ||
		len(s.GetCode()) != mfaCodeDigits || s.GetCodeHash() == "" || s.GetCodeHash() == s.GetCode() {
		t.Fatalf("SetStepUpCode = %+v", s)
	}
}

// A second ask within a minute mails nothing new: it answers the code that
// is out, with that code's expiry — a stolen session cannot flood a mailbox.
func TestRequestStepUpCode_DoesNotResendWithinAMinute(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "tok-1")
	first, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{})
	if err != nil || again.GetMethod() != stepUpMethodEmail || len(m.sent) != 1 {
		t.Fatalf("again: out=%+v err=%v sent=%d", again, err, len(m.sent))
	}
	if d := again.GetExpiresAt().AsTime().Sub(first.GetExpiresAt().AsTime()); d > time.Second || d < -time.Second {
		t.Fatalf("expiry moved by %v", d)
	}
	// Past the gap a new code goes out.
	m.sentAt = timestamppb.New(time.Now().Add(-2 * stepUpCodeResendGap))
	if _, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{}); err != nil || len(m.sent) != 2 {
		t.Fatalf("after the gap: err=%v sent=%d", err, len(m.sent))
	}
}

// An API token has no session to step up.
func TestStepUpCode_RefusesAnAPIToken(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "")
	if _, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{}); refusalCode(t, err) != CodeSessionRequired {
		t.Fatalf("request: %v", err)
	}
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: "123456"}); refusalCode(t, err) != CodeSessionRequired {
		t.Fatalf("confirm: %v", err)
	}
	if len(m.sent) != 0 || m.attempts != 0 {
		t.Fatalf("sent %d, attempts %d", len(m.sent), m.attempts)
	}
}

// The mailed code stamps the session once; it is spent with the stamp.
func TestConfirmStepUp_MailedCode(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "tok-1")
	if _, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{}); err != nil {
		t.Fatal(err)
	}
	code := m.sent[0].GetCode()
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: wrongDigits(code)}); refusalCode(t, err) != CodeStepUpCodeWrong {
		t.Fatalf("a wrong code: %v", err)
	}
	out, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: code})
	if err != nil || out.GetSteppedUpAt() == nil || len(m.consumes) != 1 || m.consumes[0].GetTokenId() != "tok-1" {
		t.Fatalf("the right code: out=%+v err=%v consumes=%+v", out, err, m.consumes)
	}
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: code}); refusalCode(t, err) != CodeStepUpCodeWrong {
		t.Fatalf("the same code twice: %v", err)
	}
}

// A mailed code past mfa_code_ttl_seconds is refused even when it is right.
func TestConfirmStepUp_ExpiredMailedCode(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "tok-1")
	if _, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{}); err != nil {
		t.Fatal(err)
	}
	m.sentAt = timestamppb.New(time.Now().Add(-h.mfaTTL() - time.Second))
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: m.sent[0].GetCode()}); refusalCode(t, err) != CodeStepUpCodeWrong {
		t.Fatalf("expired: %v", err)
	}
	if len(m.consumes) != 0 {
		t.Fatal("an expired code was spent")
	}
}

// With an authenticator the proof is its code (claimed, so used once) or a
// recovery code; a mailed code is never what it takes.
func TestConfirmStepUp_Authenticator(t *testing.T) {
	h, m := newStepUpCodeHandler(true)
	ctx := sessionCallerCtx("u1", "tok-1")
	code, err := totp.Code(testTotpSeed, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: code})
	if err != nil || out.GetSteppedUpAt() == nil || len(m.marks) != 1 || m.marks[0].GetTokenId() != "tok-1" {
		t.Fatalf("authenticator code: out=%+v err=%v marks=%+v", out, err, m.marks)
	}
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: code}); refusalCode(t, err) != CodeStepUpCodeWrong {
		t.Fatalf("the same authenticator code again: %v", err)
	}
}

// Five wrong codes in a row lock the session's step-up — the right code is
// refused then too — the budget ConfirmPassword spends.
func TestConfirmStepUp_LocksAfterFiveWrongCodes(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "tok-1")
	if _, err := h.RequestStepUpCode(ctx, &pb.RequestStepUpCodeReq{}); err != nil {
		t.Fatal(err)
	}
	code := m.sent[0].GetCode()
	for i := 0; i < maxPasswordStepUpAttempts; i++ {
		if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: wrongDigits(code)}); refusalCode(t, err) != CodeStepUpCodeWrong {
			t.Fatalf("guess %d: %v", i+1, err)
		}
	}
	if _, err := h.ConfirmStepUp(ctx, &pb.ConfirmStepUpReq{Code: code}); refusalCode(t, err) != CodeStepUpLocked {
		t.Fatalf("the right code after five wrong: %v", err)
	}
	if len(m.consumes) != 0 || m.lockedTill == nil {
		t.Fatalf("consumes %d, locked until %v", len(m.consumes), m.lockedTill)
	}
}

// step_up_password=false: ConfirmPassword refuses before it reads anything,
// so the second factor is the only step-up.
func TestConfirmPassword_OffWhenTheSecondFactorIsTheOnlyProof(t *testing.T) {
	h, m := newStepUpHandler(t, "correct-horse-battery-staple")
	h.NoPasswordStepUp = true
	_, err := h.ConfirmPassword(sessionCallerCtx("u1", "tok-1"), &pb.ConfirmPasswordReq{Password: "correct-horse-battery-staple"})
	if refusalCode(t, err) != CodeStepUpPasswordOff || len(m.marks) != 0 || m.attempts != 0 {
		t.Fatalf("err=%v marks=%d attempts=%d", err, len(m.marks), m.attempts)
	}
}

// api_token_step_up_seconds: CreateApiToken's ask is a stamp on the CALLER's
// session no older than the setting.
func TestRequireRecentStepUp(t *testing.T) {
	h, m := newStepUpCodeHandler(false)
	ctx := sessionCallerCtx("u1", "tok-1")
	if err := requireRecentStepUp(ctx, h, "u1", "tok-1"); err != nil {
		t.Fatalf("off at 0: %v", err)
	}
	h.APITokenStepUpSeconds = 300
	if err := requireRecentStepUp(ctx, h, "u1", "tok-1"); refusalCode(t, err) != CodeCreateNeedsStepUp {
		t.Fatalf("never stepped up: %v", err)
	}
	m.steppedUpAt = timestamppb.New(time.Now().Add(-10 * time.Minute))
	if err := requireRecentStepUp(ctx, h, "u1", "tok-1"); refusalCode(t, err) != CodeCreateNeedsStepUp {
		t.Fatalf("stepped up too long ago: %v", err)
	}
	m.steppedUpAt = timestamppb.New(time.Now().Add(-time.Minute))
	if err := requireRecentStepUp(ctx, h, "u1", "tok-1"); err != nil {
		t.Fatalf("stepped up a minute ago: %v", err)
	}
	if err := requireRecentStepUp(ctx, h, "u1", ""); refusalCode(t, err) != CodeCreateNeedsStepUp {
		t.Fatalf("no session: %v", err)
	}
}

// wrongDigits returns a six-digit code that is not code.
func wrongDigits(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}
