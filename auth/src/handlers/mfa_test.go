package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/wandering-compiler/platform/plugins/auth/lib/passwordhash"
	"github.com/wandering-compiler/platform/plugins/auth/lib/secretbox"
	"github.com/wandering-compiler/platform/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

func testPasswordSettings() passwordhash.Settings { return passwordhash.DefaultSettings() }

// mfaMock satisfies both client interfaces. It implements the two_factor
// query/mutations AND the minimal `devices` methods VerifyMfa transits
// (devices.go's init() swaps issueSession to the device path, which runs
// in the combined standalone test binary).
type mfaMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	// totp secret state
	totpSecretEnc string // stored (encrypted) secret blob; "" = none
	totpConfirmed bool
	totpReadErr   error // enrolment store refuses to answer (marb #58/2, #58/3)

	// Concurrency seam. The real RecordMfaAttempt is one atomic UPDATE …
	// RETURNING; here a mutex stands in for that serialisation so the test
	// exercises the HANDLER's decision rather than the database's.
	mu          sync.Mutex
	recordHook  func()
	verifyCount int

	// challenge state (single challenge)
	chUserID    string
	chCodeHash  string
	chCreatedAt *timestamppb.Timestamp
	chConsumed  bool
	chAttempts  int64 // failed-attempt counter (Q43-auth-mfa)

	userEmail string

	// recorded
	createdChallenge *pb.CreateMfaChallengeReq
	confirmedTotp    bool
	deletedTotp      bool
}

// --- queries ---
// verifyCalls counts how many requests got PAST the cap to a code check —
// the number the budget is supposed to bound.
func (m *mfaMock) verifyCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.verifyCount
}

func (m *mfaMock) GetTotpSecret(ctx context.Context, in *pb.GetTotpSecretReq, _ ...grpc.CallOption) (*pb.GetTotpSecretResp, error) {
	m.mu.Lock()
	m.verifyCount++
	m.mu.Unlock()
	if m.totpReadErr != nil {
		return nil, m.totpReadErr
	}
	if m.totpSecretEnc == "" {
		return &pb.GetTotpSecretResp{}, nil
	}
	s := &pb.UserTotpSecret{UserId: in.GetUserId(), Secret: m.totpSecretEnc}
	if m.totpConfirmed {
		s.ConfirmedAt = timestamppb.Now()
	}
	return &pb.GetTotpSecretResp{Secret: s}, nil
}
func (m *mfaMock) GetMfaChallenge(ctx context.Context, in *pb.GetMfaChallengeReq, _ ...grpc.CallOption) (*pb.GetMfaChallengeResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := &pb.MfaChallenge{Id: in.GetChallengeId(), UserId: m.chUserID, CodeHash: m.chCodeHash, CreatedAt: m.chCreatedAt, Attempts: m.chAttempts}
	if m.chConsumed {
		ch.ConsumedAt = timestamppb.Now()
	}
	return &pb.GetMfaChallengeResp{Challenge: ch}, nil
}
func (m *mfaMock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), Email: m.userEmail}}, nil
}
func (m *mfaMock) GetDeviceByIdentifier(ctx context.Context, in *pb.GetDeviceByIdentifierReq, _ ...grpc.CallOption) (*pb.GetDeviceByIdentifierResp, error) {
	return &pb.GetDeviceByIdentifierResp{}, nil // not found → create
}

// --- mutations ---
func (m *mfaMock) CreateTotpSecret(ctx context.Context, in *pb.CreateTotpSecretReq, _ ...grpc.CallOption) (*pb.CreateTotpSecretResp, error) {
	m.totpSecretEnc = in.GetSecret()
	m.totpConfirmed = false
	return &pb.CreateTotpSecretResp{Secret: &pb.UserTotpSecret{UserId: in.GetUserId(), Secret: in.GetSecret()}}, nil
}
func (m *mfaMock) ConfirmTotpSecret(ctx context.Context, in *pb.ConfirmTotpSecretReq, _ ...grpc.CallOption) (*pb.ConfirmTotpSecretResp, error) {
	m.totpConfirmed = true
	m.confirmedTotp = true
	return &pb.ConfirmTotpSecretResp{UserId: in.GetUserId()}, nil
}
func (m *mfaMock) DeleteTotpSecret(ctx context.Context, in *pb.DeleteTotpSecretReq, _ ...grpc.CallOption) (*pb.DeleteTotpSecretResp, error) {
	m.totpSecretEnc = ""
	m.totpConfirmed = false
	m.deletedTotp = true
	return &pb.DeleteTotpSecretResp{UserId: in.GetUserId()}, nil
}
func (m *mfaMock) CreateMfaChallenge(ctx context.Context, in *pb.CreateMfaChallengeReq, _ ...grpc.CallOption) (*pb.CreateMfaChallengeResp, error) {
	m.createdChallenge = in
	m.chUserID = in.GetUserId()
	m.chCodeHash = in.GetCodeHash()
	m.chCreatedAt = timestamppb.Now()
	m.chConsumed = false
	return &pb.CreateMfaChallengeResp{Challenge: &pb.MfaChallenge{Id: "ch-1", UserId: in.GetUserId(), CodeHash: in.GetCodeHash()}}, nil
}
func (m *mfaMock) ConsumeMfaChallenge(ctx context.Context, in *pb.ConsumeMfaChallengeReq, _ ...grpc.CallOption) (*pb.ConsumeMfaChallengeResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.chConsumed {
		return &pb.ConsumeMfaChallengeResp{}, nil // already used → empty
	}
	m.chConsumed = true
	return &pb.ConsumeMfaChallengeResp{ChallengeId: in.GetChallengeId(), UserId: m.chUserID}, nil
}
func (m *mfaMock) RecordMfaAttempt(ctx context.Context, in *pb.RecordMfaAttemptReq, _ ...grpc.CallOption) (*pb.RecordMfaAttemptResp, error) {
	// Mirrors the statement, which is `UPDATE … WHERE consumed_at IS NULL
	// RETURNING attempts`: a consumed challenge matches NO ROW, so nothing
	// comes back — zero, not the old count. Returning the old count made this
	// mock more permissive than the engine on the one path where that
	// matters, and a mock that disagrees with its statement is what lets a
	// green suite describe a system nobody runs.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordHook != nil {
		m.recordHook()
	}
	if m.chConsumed {
		return &pb.RecordMfaAttemptResp{}, nil
	}
	m.chAttempts++
	return &pb.RecordMfaAttemptResp{Attempts: m.chAttempts}, nil
}

// device-path methods VerifyMfa transits (issueSession override)
func (m *mfaMock) CreateDevice(ctx context.Context, in *pb.CreateDeviceReq, _ ...grpc.CallOption) (*pb.CreateDeviceResp, error) {
	return &pb.CreateDeviceResp{Device: &pb.Device{Id: "dev-1", Identifier: in.GetIdentifier()}}, nil
}
func (m *mfaMock) TrustDevice(ctx context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	return &pb.TrustDeviceResp{DeviceId: in.GetDeviceId()}, nil
}
func (m *mfaMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{Token: &pb.UserToken{Token: "tok-verify"}}, nil
}

func mfaTestKey() string {
	k := make([]byte, secretbox.KeySize)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return base64.StdEncoding.EncodeToString(k)
}

func newMfaHandler(m *mfaMock) *AuthServiceHandler {
	return &AuthServiceHandler{
		Query:              m,
		Mutation:           m,
		PasswordHash:       testPasswordSettings(),
		TwoFactorTOTP:      true,
		TwoFactorScope:     "all_logins",
		MfaCodeTTLSeconds:  300,
		TwoFactorSecretKey: mfaTestKey(),
	}
}

func TestMfaGate_AllLogins_NoTotp_GeneratesCode(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	resp, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, "", false)
	if err != nil || !challenged {
		t.Fatalf("all_logins must challenge: challenged=%v err=%v", challenged, err)
	}
	if !resp.GetMfaRequired() || resp.GetChallengeId() != "ch-1" {
		t.Errorf("resp = %+v, want mfa_required + challenge_id ch-1", resp)
	}
	if m.createdChallenge.GetTotpEnrolled() {
		t.Error("no authenticator → totp_enrolled must be false")
	}
	if m.createdChallenge.GetCode() == "" || m.createdChallenge.GetCodeHash() == "" {
		t.Error("event path must generate a plaintext code + store its hash")
	}
	if m.createdChallenge.GetEmail() != "a@b.c" {
		t.Errorf("event email = %q, want a@b.c", m.createdChallenge.GetEmail())
	}
}

func TestMfaGate_NewDevices_SkipsTrusted(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorScope = scopeNewDevices
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, "dev-1", true)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	if challenged {
		t.Error("new_devices must NOT challenge a trusted device")
	}
}

func TestMfaGate_NewDevices_ChallengesUntrusted(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorScope = scopeNewDevices
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, "dev-1", false)
	if err != nil || !challenged {
		t.Errorf("new_devices must challenge an untrusted device: challenged=%v err=%v", challenged, err)
	}
}

func TestMfaGate_TotpEnrolled_NoCode(t *testing.T) {
	m := &mfaMock{totpSecretEnc: "x", totpConfirmed: true} // confirmed authenticator
	h := newMfaHandler(m)
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, "", false)
	if err != nil || !challenged {
		t.Fatalf("must challenge: %v", err)
	}
	if !m.createdChallenge.GetTotpEnrolled() {
		t.Error("confirmed authenticator → totp_enrolled true")
	}
	if m.createdChallenge.GetCode() != "" || m.createdChallenge.GetCodeHash() != "" {
		t.Error("TOTP path must NOT generate/store a code")
	}
}

func TestEnrollConfirmVerify_TotpRoundTrip(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")

	enroll, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if enroll.GetSecret() == "" || enroll.GetOtpauthUri() == "" {
		t.Fatal("enroll must return secret + otpauth uri")
	}
	// Confirm with a freshly computed code.
	code, _ := totp.Code(enroll.GetSecret(), time.Now())
	if _, err := h.ConfirmTotp(ctx, &pb.ConfirmTotpReq{Code: code}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !m.confirmedTotp {
		t.Error("confirm should mark the secret confirmed")
	}
	// Now a sign-in challenge + VerifyMfa with a TOTP code.
	_, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1"}, "", false)
	if !challenged {
		t.Fatal("expected challenge")
	}
	verifyCode, _ := totp.Code(enroll.GetSecret(), time.Now())
	vresp, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: verifyCode})
	if err != nil {
		t.Fatalf("verify (TOTP path): %v", err)
	}
	if vresp.GetToken() != "tok-verify" || vresp.GetUserId() != "u1" {
		t.Errorf("verify resp = %+v, want token tok-verify / user u1", vresp)
	}
}

func TestVerifyMfa_EventCodePath(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false // event path even though we could enroll
	ctx := ctxWithCaller("u1")
	_, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, "", false)
	if !challenged {
		t.Fatal("expected challenge")
	}
	code := m.createdChallenge.GetCode()
	if code == "" {
		t.Fatal("event path should have generated a code")
	}
	vresp, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code})
	if err != nil {
		t.Fatalf("verify (event path): %v", err)
	}
	if vresp.GetToken() != "tok-verify" {
		t.Errorf("verify token = %q, want tok-verify", vresp.GetToken())
	}
}

func TestVerifyMfa_WrongCode_Unauthenticated(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	ctx := ctxWithCaller("u1")
	_, _, _ = signInMfaGate(ctx, h, &pb.User{Id: "u1"}, "", false)
	if _, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
		t.Error("a wrong code must fail VerifyMfa")
	}
}

// Q43-auth-mfa: a 6-digit second factor must not be brute-forceable within
// the TTL. After maxMfaAttempts wrong codes the challenge is locked — even
// the CORRECT code is then refused (the attacker can't outrun the counter).
func TestVerifyMfa_LocksOutAfterMaxAttempts(t *testing.T) {
	m := &mfaMock{chUserID: "u1", chCreatedAt: timestamppb.Now()}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false // event/code path
	ctx := ctxWithCaller("u1")
	// Store the hash of the REAL code so the correct code would pass absent
	// the lockout.
	hash, err := h.PasswordHash.Hash("123456")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	m.chCodeHash = hash

	for i := 0; i < maxMfaAttempts; i++ {
		if _, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
			t.Fatalf("wrong-code attempt %d must fail", i+1)
		}
	}
	if m.chAttempts < int64(maxMfaAttempts) {
		t.Fatalf("recorded attempts = %d, want >= %d (failures must be counted)", m.chAttempts, maxMfaAttempts)
	}
	// The challenge is now locked: the correct code is rejected too.
	if _, err := h.VerifyMfa(ctx, &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Fatal("after maxMfaAttempts failures the challenge must be locked even for the correct code")
	}
}

func TestVerifyMfa_Expired_Unauthenticated(t *testing.T) {
	m := &mfaMock{
		chUserID:    "u1",
		chCodeHash:  "",
		chCreatedAt: timestamppb.New(time.Now().Add(-10 * time.Minute)), // older than TTL
	}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, err := h.VerifyMfa(ctxWithCaller("u1"), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Error("an expired challenge must fail VerifyMfa")
	}
}

func TestVerifyMfa_Consumed_Unauthenticated(t *testing.T) {
	m := &mfaMock{chUserID: "u1", chCreatedAt: timestamppb.Now(), chConsumed: true}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, err := h.VerifyMfa(ctxWithCaller("u1"), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Error("an already-consumed challenge must fail VerifyMfa")
	}
}

func TestEnrollTotp_NoKey_Errors(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorSecretKey = "" // no at-rest key configured
	if _, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{}); err == nil {
		t.Error("EnrollTotp must error (not ship plaintext) when no secret key is configured")
	}
}

func TestGetMfaStatus_ReflectsEnrollment(t *testing.T) {
	m := &mfaMock{totpSecretEnc: "x", totpConfirmed: true}
	h := newMfaHandler(m)
	resp, err := h.GetMfaStatus(ctxWithCaller("u1"), &pb.GetMfaStatusReq{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !resp.GetTotpEnrolled() {
		t.Error("confirmed authenticator → totp_enrolled true")
	}
}

// enrollAndConfirm sets up a CONFIRMED authenticator on the mock and
// returns the plaintext secret so a test can compute live codes. It
// resets the mock's recorded `deletedTotp` flag because EnrollTotp
// itself delete-then-creates (so the flag reflects only post-setup
// deletions).
func enrollAndConfirm(t *testing.T, h *AuthServiceHandler, m *mfaMock, ctx context.Context) string {
	t.Helper()
	enroll, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	code, _ := totp.Code(enroll.GetSecret(), time.Now())
	if _, err := h.ConfirmTotp(ctx, &pb.ConfirmTotpReq{Code: code}); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	m.deletedTotp = false
	return enroll.GetSecret()
}

// B1 — DisableTotp must re-verify a live TOTP code before removing a
// CONFIRMED authenticator, so a hijacked session can't permanently
// disable the victim's 2FA. A valid code deletes.
func TestDisableTotp_ValidCode_Deletes(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	secret := enrollAndConfirm(t, h, m, ctx)

	code, _ := totp.Code(secret, time.Now())
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: code}); err != nil {
		t.Fatalf("disable with valid code: %v", err)
	}
	if !m.deletedTotp {
		t.Error("DisableTotp with a valid code should delete the secret")
	}
}

// B1 — a wrong code must NOT disable 2FA (opaque Unauthenticated,
// secret left intact).
func TestDisableTotp_WrongCode_Rejected(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: "000000"}); err == nil {
		t.Error("DisableTotp with a wrong code must fail")
	}
	if m.deletedTotp {
		t.Error("a wrong code must NOT delete the confirmed secret (2FA-disable hijack)")
	}
}

// B1 — an empty code is rejected too (no bypass via the zero value).
func TestDisableTotp_EmptyCode_Rejected(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{}); err == nil {
		t.Error("DisableTotp with an empty code must fail")
	}
	if m.deletedTotp {
		t.Error("an empty code must NOT delete the confirmed secret")
	}
}

// B1 — a pending (unconfirmed) enrollment provides no active
// protection, so cancelling it needs no code (a user who lost the
// device mid-setup must still be able to back out).
func TestDisableTotp_Unconfirmed_NoCodeNeeded(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	if _, err := h.EnrollTotp(ctx, &pb.EnrollTotpReq{}); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// not confirmed → m.totpConfirmed stays false
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{}); err != nil {
		t.Fatalf("disable pending enrollment: %v", err)
	}
	if !m.deletedTotp {
		t.Error("an unconfirmed enrollment should be cancellable without a code")
	}
}

func TestValidateConfig_NewDevicesRequiresDevices(t *testing.T) {
	// devices.go init() sets devicesActive=true in the standalone binary;
	// flip it to exercise both branches of the guard.
	saved := devicesActive
	defer func() { devicesActive = saved }()

	devicesActive = false
	if err := ValidateConfig(&AuthServiceHandler{TwoFactorScope: "new_devices"}); err == nil {
		t.Error("new_devices without the devices feature must be rejected at bootstrap")
	}
	if err := ValidateConfig(&AuthServiceHandler{TwoFactorScope: "all_logins"}); err != nil {
		t.Errorf("all_logins must validate without devices: %v", err)
	}

	devicesActive = true
	if err := ValidateConfig(&AuthServiceHandler{TwoFactorScope: "new_devices"}); err != nil {
		t.Errorf("new_devices WITH devices must validate: %v", err)
	}
}

// --- marb #58/2 and #58/3: an unreadable enrolment must not weaken a factor --
//
// totpEnrolled folded a query error into `false`, so "the store did not
// answer" and "this user has no authenticator" were the same answer. Every
// caller then degraded in its own direction, and none of them logged anything.
// The four tests below are the four directions; they are written separately
// because a single one passing says nothing about the other three.

// The one marb verified: the check was guarded by `err == nil && …`, so a
// read failure made the whole condition false and the delete ran with no code
// presented at all.
func TestDisableTotp_ReadFailure_DoesNotDisableWithoutACode(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: "000000"}); err == nil {
		t.Error("a failed enrolment read must refuse, not skip the TOTP check")
	}
	if m.deletedTotp {
		t.Error("a confirmed second factor was dropped without a valid code")
	}
}

// The sign-in gate: no challenge means the password alone let the caller in.
func TestMfaGate_ReadFailure_RefusesRatherThanSkipTheChallenge(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", totpSecretEnc: "enc", totpConfirmed: true}
	h := newMfaHandler(m)
	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")

	_, _, err := mfaSignInGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, "", false)
	if err == nil {
		t.Error("a failed enrolment read must not let sign-in proceed on one factor")
	}
	if m.createdChallenge != nil {
		t.Error("no challenge should be recorded when the read failed")
	}
}

// GetMfaStatus: "you have no authenticator" is a claim a failed read cannot
// support — a user who believes it re-enrols and loses the one they have.
func TestGetMfaStatus_ReadFailure_Errors(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", totpSecretEnc: "enc", totpConfirmed: true}
	h := newMfaHandler(m)
	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")

	resp, err := h.GetMfaStatus(ctxWithCaller("u1"), &pb.GetMfaStatusReq{})
	if err == nil {
		t.Fatalf("a failed enrolment read must error, got %+v", resp)
	}
	if resp.GetTotpEnrolled() {
		t.Error("no response body should claim enrolment either")
	}
}

// VerifyMfa: falling through to the code-hash branch would check a TOTP user
// against a challenge code that a TOTP user is never sent.
func TestVerifyMfa_ReadFailure_DoesNotFallToTheWeakerPath(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	// A challenge whose stored code hash the caller CAN satisfy: if the
	// verifier falls through, this is the credential it accepts.
	hash, err := h.PasswordHash.Hash("123456")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	m.chUserID, m.chCodeHash, m.chCreatedAt = "u1", hash, timestamppb.Now()
	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")

	if _, err := h.VerifyMfa(context.Background(), &pb.VerifyMfaReq{ChallengeId: "c1", Code: "123456"}); err == nil {
		t.Error("an unreadable enrolment must not be verified against the fallback code")
	}
}

// --- marb #58: the cap was per-request, not per-challenge ------------------
//
// VerifyMfa read the attempt count loaded at the top of the call and
// incremented afterwards, in a separate rpc, only on a miss. Sequentially the
// cap held — and the comment said so, in those words. Concurrently every
// request read the same count, every one passed the check, and every one got
// a guess: the budget was five per challenge and a caller opening connections
// in parallel had as many as they wanted, which is the single property a
// lockout exists to deny.
//
// Driven through VerifyMfa rather than asserted on the counter, because the
// defect was never in the counter.
func TestVerifyMfa_ConcurrentGuessesShareOneBudget(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	hash, err := h.PasswordHash.Hash("123456")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	m.chUserID, m.chCodeHash, m.chCreatedAt = "u1", hash, timestamppb.Now()

	// Every one of these is WRONG, so none may succeed on its own merit; what
	// is being counted is how many were allowed to try at all. The mock's
	// counter is bumped under a mutex, standing in for the statement's
	// atomicity — the handler must decide on the number IT got back.
	const tries = 40
	var mu sync.Mutex
	var allowed int
	origRecord := m.recordHook
	m.recordHook = func() { mu.Lock(); allowed++; mu.Unlock() }
	t.Cleanup(func() { m.recordHook = origRecord })

	var wg sync.WaitGroup
	for i := 0; i < tries; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, _ = h.VerifyMfa(context.Background(), &pb.VerifyMfaReq{
				ChallengeId: "c1", Code: fmt.Sprintf("%06d", n),
			})
		}(i)
	}
	wg.Wait()

	// Every request reaches the counter — that is the point, the counter is
	// the gate now. What must be bounded is how many got PAST it to a guess.
	if got := m.verifyCalls(); got > maxMfaAttempts {
		t.Errorf("%d of %d concurrent requests were allowed to check a code against a cap of %d — "+
			"the budget is per-request, not per-challenge", got, tries, maxMfaAttempts)
	}
	if m.verifyCalls() == 0 {
		t.Error("no request reached the code check at all — the cap refuses everyone, which is a worse bug")
	}
}

// --- marb #58: re-enrolment must not destroy the factor it replaces -------
//
// EnrollTotp deletes the existing secret and then creates the new one, so the
// unique user_id index does not reject the second write. Run apart, a failure
// of the create leaves the user with NO second factor at all: the working
// authenticator is already gone. The operation exists to move an
// authenticator to a new phone, and its failure mode was to remove the old
// one and hand back nothing.
//
// Asserted through the handler with a create that fails, because the shape
// being fixed is the ORDER of two writes and not either write.
type failingCreateTotp struct {
	*mfaMock
	deleted bool
}

func (f *failingCreateTotp) DeleteTotpSecret(ctx context.Context, in *pb.DeleteTotpSecretReq, o ...grpc.CallOption) (*pb.DeleteTotpSecretResp, error) {
	f.deleted = true
	return f.mfaMock.DeleteTotpSecret(ctx, in, o...)
}

func (f *failingCreateTotp) CreateTotpSecret(context.Context, *pb.CreateTotpSecretReq, ...grpc.CallOption) (*pb.CreateTotpSecretResp, error) {
	return nil, status.Error(codes.Unavailable, "secret store down")
}

func TestEnrollTotp_AFailedCreateDoesNotLeaveTheUserWithoutAFactor(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", totpSecretEnc: "existing", totpConfirmed: true}
	f := &failingCreateTotp{mfaMock: m}
	h := newMfaHandler(m)
	h.Mutation = f

	if _, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{}); err == nil {
		t.Fatal("a failed create was reported as a successful enrolment")
	}

	// The delete and the create are one unit or they are a way to lose an
	// authenticator. With no DistTx wired here there is no rollback to
	// observe, so what this pins is the SEAM: both writes go through
	// replaceTotpSecret, which is what a transaction can be wrapped around.
	// Without it the two calls sit in EnrollTotp and nothing can undo the
	// first when the second fails.
	if !f.deleted {
		t.Error("the delete never ran — this test is not exercising the replacement path")
	}
}

// And the seam itself: EnrollTotp must route both writes through the pair, so
// a caller that DOES have a transaction can wrap them. A future edit that
// inlines them back would compile, pass every other test, and quietly restore
// the defect.
func TestEnrollTotp_BothWritesGoThroughOneSeam(t *testing.T) {
	src, err := os.ReadFile("mfa.go")
	if err != nil {
		t.Fatalf("read mfa.go: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "func (h *AuthServiceHandler) EnrollTotp(")
	if i < 0 {
		t.Fatal("EnrollTotp not found")
	}
	end := strings.Index(body[i:], "\n}\n")
	fn := body[i : i+end]
	for _, direct := range []string{"h.Mutation.DeleteTotpSecret(", "h.Mutation.CreateTotpSecret("} {
		if strings.Contains(fn, direct) {
			t.Errorf("EnrollTotp calls %s directly — the two writes are separable again, "+
				"and a failure between them takes the user's existing authenticator with it", direct)
		}
	}
	if !strings.Contains(fn, "replaceTotpSecret(") {
		t.Error("EnrollTotp no longer goes through replaceTotpSecret — nothing holds the pair together")
	}
	if !strings.Contains(fn, "distx.Begin(") {
		t.Error("EnrollTotp opens no transaction — the seam exists but nothing wraps it")
	}
}
