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

	"github.com/wandering-compiler/plugins/auth/lib/passwordhash"
	"github.com/wandering-compiler/plugins/auth/lib/secretbox"
	"github.com/wandering-compiler/plugins/auth/lib/totp"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

func testPasswordSettings() passwordhash.Settings { return passwordhash.DefaultSettings() }

// mfaMock satisfies both client interfaces. It implements the two_factor
// query/mutations AND the minimal `devices` methods VerifyMfa transits
// (devices.go's init() swaps issueSession to the device path, which runs
// in the combined standalone test binary).
type mfaMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	issuedHash string // the token_hash IssueToken was handed
	// the device IssueToken bound the session to, and the RegisterDevice
	// request that registered it
	issuedDevice     string
	registeredDevice *pb.RegisterDeviceReq

	// totp secret state
	totpSecretEnc string          // legacy `secret` (secretbox blob, rc.19 and earlier); "" = none
	totpSeed      string          // `seed` as the storage layer hands it back: plaintext
	movedSeed     string          // what MoveTotpSeed was given
	movedRow      string          // …and the enrolment row it was keyed by
	lastStep      int64           // UserTotpSecret.last_step (the replay guard)
	recovery      map[string]bool // code_hash → used, the LIVE set (revoked_at IS NULL)
	// The rows RevokeRecoveryCodes / RevokeTotpSecret ended: they stay, as
	// the statements keep them (nothing is deleted).
	revokedCodes   map[string]bool // code_hash of an unused code whose set was revoked
	revokedSecrets []revokedTotpRow
	claimErr       error     // ClaimTotpStep fails (store unreachable)
	stepUps        int64     // UserTotpSecret.stepup_attempts
	stepUpLocked   time.Time // UserTotpSecret.stepup_locked_until
	totpConfirmed  bool
	totpReadErr    error // enrolment store refuses to answer

	// Concurrency seam. The real RecordMfaAttempt is one atomic UPDATE …
	// RETURNING; here a mutex stands in for that serialisation so the test
	// exercises the HANDLER's decision rather than the database's.
	mu          sync.Mutex
	recordHook  func()
	verifyCount int

	// disabled: the account was disabled between the password step and this one.
	disabled bool

	// challenge state (single challenge)
	chUserID    string
	chThumb     string // the key the challenge was raised for
	chCodeHash  string
	chCreatedAt *timestamppb.Timestamp
	chConsumed  bool
	chAttempts  int64 // failed-attempt counter
	chPublic    bool  // the challenged sign-in asked for a public-computer session
	issuedReq   *pb.IssueTokenReq

	userEmail string

	// issuance cap + supersede state
	challengeCount int64                  // what CountRecentMfaChallenges reports
	countErr       error                  // the counter refuses to answer
	countedSince   *timestamppb.Timestamp // what the handler asked about
	supersedeErr   error
	ops            []string // ordered log of the writes issuance performs

	// recorded
	trustedDevice    *pb.TrustDeviceReq
	createdChallenge *pb.CreateMfaChallengeReq
	confirmedTotp    bool
	revokedTotp      bool
}

// revokedTotpRow is a UserTotpSecret row after RevokeTotpSecret: revoked_at
// stamped, seed and legacy secret cleared, confirmed_at kept.
type revokedTotpRow struct {
	seed, secret string
	confirmed    bool
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
	defer m.mu.Unlock()
	m.verifyCount++
	if m.totpReadErr != nil {
		return nil, m.totpReadErr
	}
	if m.totpSecretEnc == "" && m.totpSeed == "" {
		return &pb.GetTotpSecretResp{}, nil
	}
	s := &pb.UserTotpSecret{Id: "row-1", UserId: in.GetUserId(), Secret: m.totpSecretEnc, LastStep: m.lastStep}
	if m.totpConfirmed {
		s.ConfirmedAt = timestamppb.Now()
	}
	return &pb.GetTotpSecretResp{Secret: s, Seed: m.totpSeed}, nil
}
func (m *mfaMock) GetMfaChallenge(ctx context.Context, in *pb.GetMfaChallengeReq, _ ...grpc.CallOption) (*pb.GetMfaChallengeResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := &pb.MfaChallenge{Id: in.GetChallengeId(), UserId: m.chUserID, CodeHash: m.chCodeHash, CreatedAt: m.chCreatedAt, Attempts: m.chAttempts, Thumbprint: m.chThumb, PublicComputer: m.chPublic}
	if m.chConsumed {
		ch.ConsumedAt = timestamppb.Now()
	}
	return &pb.GetMfaChallengeResp{Challenge: ch}, nil
}
func (m *mfaMock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	u := &pb.User{Id: in.GetUserId(), Email: m.userEmail}
	if m.disabled {
		u.DisabledAt = timestamppb.Now()
	}
	return &pb.GetUserByIdResp{User: u}, nil
}

// --- mutations ---
func (m *mfaMock) CreateTotpSecret(ctx context.Context, in *pb.CreateTotpSecretReq, _ ...grpc.CallOption) (*pb.CreateTotpSecretResp, error) {
	m.totpSeed, m.totpSecretEnc = in.GetSeed(), ""
	m.totpConfirmed = false
	return &pb.CreateTotpSecretResp{Secret: &pb.UserTotpSecret{UserId: in.GetUserId()}}, nil
}
func (m *mfaMock) ClaimTotpStep(ctx context.Context, in *pb.ClaimTotpStepReq, _ ...grpc.CallOption) (*pb.ClaimTotpStepResp, error) {
	// Atomic, like the conditional UPDATE it stands for: without the lock,
	// concurrent claims of one step all saw it free and the concurrency test
	// failed on the fake, not on the handler.
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimErr != nil {
		return nil, m.claimErr
	}
	if in.GetStep() <= m.lastStep {
		return &pb.ClaimTotpStepResp{}, nil // the conditional UPDATE matched nothing
	}
	m.lastStep = in.GetStep()
	return &pb.ClaimTotpStepResp{Id: in.GetId()}, nil
}
func (m *mfaMock) RecordStepUpAttempt(ctx context.Context, in *pb.RecordStepUpAttemptReq, _ ...grpc.CallOption) (*pb.RecordStepUpAttemptResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if time.Now().Before(m.stepUpLocked) {
		return &pb.RecordStepUpAttemptResp{}, nil // the WHERE excludes a locked row
	}
	m.stepUps++
	return &pb.RecordStepUpAttemptResp{Attempts: m.stepUps}, nil
}
func (m *mfaMock) LockStepUp(ctx context.Context, in *pb.LockStepUpReq, _ ...grpc.CallOption) (*pb.LockStepUpResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stepUps, m.stepUpLocked = 0, in.GetUntil().AsTime()
	return &pb.LockStepUpResp{Id: in.GetId()}, nil
}
func (m *mfaMock) ResetStepUp(ctx context.Context, in *pb.ResetStepUpReq, _ ...grpc.CallOption) (*pb.ResetStepUpResp, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stepUps = 0
	return &pb.ResetStepUpResp{Id: in.GetId()}, nil
}
func (m *mfaMock) CreateRecoveryCode(ctx context.Context, in *pb.CreateRecoveryCodeReq, _ ...grpc.CallOption) (*pb.CreateRecoveryCodeResp, error) {
	if m.recovery == nil {
		m.recovery = map[string]bool{}
	}
	m.recovery[in.GetCodeHash()] = false
	return &pb.CreateRecoveryCodeResp{Id: "rc"}, nil
}

// RevokeRecoveryCodes: `SET revoked_at = NOW() WHERE user_id = :user_id AND
// used_at IS NULL AND revoked_at IS NULL` — the unused codes move to the
// revoked rows, the used ones keep their used_at; none stay live.
func (m *mfaMock) RevokeRecoveryCodes(ctx context.Context, in *pb.RevokeRecoveryCodesReq, _ ...grpc.CallOption) (*pb.RevokeRecoveryCodesResp, error) {
	for hash, used := range m.recovery {
		if !used {
			if m.revokedCodes == nil {
				m.revokedCodes = map[string]bool{}
			}
			m.revokedCodes[hash] = true
		}
	}
	m.recovery = nil
	return &pb.RevokeRecoveryCodesResp{}, nil
}
func (m *mfaMock) ConsumeRecoveryCode(ctx context.Context, in *pb.ConsumeRecoveryCodeReq, _ ...grpc.CallOption) (*pb.ConsumeRecoveryCodeResp, error) {
	used, ok := m.recovery[in.GetCodeHash()]
	if !ok || used {
		return &pb.ConsumeRecoveryCodeResp{}, nil
	}
	m.recovery[in.GetCodeHash()] = true
	return &pb.ConsumeRecoveryCodeResp{Id: "rc", UserId: in.GetUserId()}, nil
}
func (m *mfaMock) CountRecoveryCodes(ctx context.Context, in *pb.CountRecoveryCodesReq, _ ...grpc.CallOption) (*pb.CountRecoveryCodesResp, error) {
	var n int64
	for _, used := range m.recovery {
		if !used {
			n++
		}
	}
	return &pb.CountRecoveryCodesResp{Count: n}, nil
}
func (m *mfaMock) MoveTotpSeed(ctx context.Context, in *pb.MoveTotpSeedReq, _ ...grpc.CallOption) (*pb.MoveTotpSeedResp, error) {
	m.movedSeed, m.movedRow = in.GetSeed(), in.GetId()
	m.totpSeed, m.totpSecretEnc = in.GetSeed(), ""
	return &pb.MoveTotpSeedResp{UserId: in.GetUserId()}, nil
}
func (m *mfaMock) ConfirmTotpSecret(ctx context.Context, in *pb.ConfirmTotpSecretReq, _ ...grpc.CallOption) (*pb.ConfirmTotpSecretResp, error) {
	m.totpConfirmed = true
	m.confirmedTotp = true
	return &pb.ConfirmTotpSecretResp{UserId: in.GetUserId()}, nil
}

// RevokeTotpSecret: `SET revoked_at = NOW(), ended_key = id, seed = NULL,
// secret = NULL WHERE user_id = :user_id AND revoked_at IS NULL RETURNING
// user_id` — the live row is kept as a revoked one with its seed cleared; no
// live row is NotFound.
func (m *mfaMock) RevokeTotpSecret(ctx context.Context, in *pb.RevokeTotpSecretReq, _ ...grpc.CallOption) (*pb.RevokeTotpSecretResp, error) {
	if m.totpSecretEnc == "" && m.totpSeed == "" {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	m.revokedSecrets = append(m.revokedSecrets, revokedTotpRow{confirmed: m.totpConfirmed})
	m.totpSecretEnc, m.totpSeed = "", ""
	m.totpConfirmed = false
	m.revokedTotp = true
	return &pb.RevokeTotpSecretResp{UserId: in.GetUserId()}, nil
}
func (m *mfaMock) CreateMfaChallenge(ctx context.Context, in *pb.CreateMfaChallengeReq, _ ...grpc.CallOption) (*pb.CreateMfaChallengeResp, error) {
	m.ops = append(m.ops, "create")
	m.createdChallenge = in
	m.chUserID = in.GetUserId()
	m.chThumb = in.GetThumbprint()
	m.chPublic = in.GetPublicComputer()
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

// device-path methods VerifyMfa transits: the device the session is bound to
func (m *mfaMock) RegisterDevice(_ context.Context, in *pb.RegisterDeviceReq, _ ...grpc.CallOption) (*pb.RegisterDeviceResp, error) {
	m.registeredDevice = in
	return fakeRegisterDevice(in)
}
func (m *mfaMock) TrustDevice(ctx context.Context, in *pb.TrustDeviceReq, _ ...grpc.CallOption) (*pb.TrustDeviceResp, error) {
	m.trustedDevice = in
	return &pb.TrustDeviceResp{DeviceId: in.GetDeviceId()}, nil
}
func (m *mfaMock) IssueToken(ctx context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	m.issuedHash, m.issuedDevice, m.issuedReq = in.GetTokenHash(), in.GetDeviceId(), in
	return &pb.IssueTokenResp{Token: &pb.UserToken{}}, nil
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
	resp, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false)
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
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, "dev-1", true, false)
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
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, "dev-1", false, false)
	if err != nil || !challenged {
		t.Errorf("new_devices must challenge an untrusted device: challenged=%v err=%v", challenged, err)
	}
}

func TestMfaGate_TotpEnrolled_NoCode(t *testing.T) {
	m := &mfaMock{totpSeed: "x", totpConfirmed: true} // confirmed authenticator
	h := newMfaHandler(m)
	_, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1"}, testJKT, false, false)
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
	_, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1"}, testJKT, false, false)
	if !challenged {
		t.Fatal("expected challenge")
	}
	verifyCode := nextCode(t, enroll.GetSecret()) // the confirm spent this window's code
	vresp, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: verifyCode})
	if err != nil {
		t.Fatalf("verify (TOTP path): %v", err)
	}
	if vresp.GetToken() == "" || m.issuedHash != sha256Hex(vresp.GetToken()) || vresp.GetUserId() != "u1" {
		t.Errorf("verify resp = %+v, want a token whose sha256 was stored / user u1", vresp)
	}
}

func TestVerifyMfa_EventCodePath(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false // event path even though we could enroll
	ctx := ctxWithCaller("u1")
	_, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false)
	if !challenged {
		t.Fatal("expected challenge")
	}
	code := m.createdChallenge.GetCode()
	if code == "" {
		t.Fatal("event path should have generated a code")
	}
	vresp, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code})
	if err != nil {
		t.Fatalf("verify (event path): %v", err)
	}
	if vresp.GetToken() == "" || m.issuedHash != sha256Hex(vresp.GetToken()) {
		t.Errorf("verify token = %q: the store must get its sha256", vresp.GetToken())
	}
}

// The second factor completes the sign-in of the device that passed the
// password: the challenge records SignIn's key, and VerifyMfa signed by any
// other key is refused — even with the right code — as opaquely as a wrong
// code, spending an attempt (so probing is bounded) without consuming the
// challenge (which would record the factor as verified). The right key then
// still completes it.
func TestVerifyMfa_OnlyTheChallengedKeyCompletesTheSignIn(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	ctx := ctxWithCaller("u1")
	if _, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); !challenged {
		t.Fatal("expected challenge")
	}
	if m.createdChallenge.GetThumbprint() != testJKT {
		t.Fatalf("the challenge records key %q, want SignIn's", m.createdChallenge.GetThumbprint())
	}
	code := m.createdChallenge.GetCode()
	_, err := h.VerifyMfa(withJKT(ctx, otherJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code})
	// The same answer as a wrong code: Unauthenticated with the code-refused
	// pair, and nothing that says it was the key.
	if st, _ := status.FromError(err); st.Code() != codes.Unauthenticated {
		t.Fatalf("another key: err = %v, want the opaque refusal", err)
	}
	if d := errorDetailOf(t, err); d == nil || d.GetCode() != CodeMfaCodeRefused || d.GetMessage() != MsgMfaCodeRefused {
		t.Fatalf("another key: detail = %v, want the code-refused pair a wrong code gets", d)
	}
	if m.chConsumed || m.issuedHash != "" || m.chAttempts != 1 {
		t.Fatalf("another key: consumed=%v issued=%q attempts=%d, want an attempt spent and nothing else", m.chConsumed, m.issuedHash, m.chAttempts)
	}
	if _, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: code}); err != nil {
		t.Fatalf("the challenged key was refused after a probe: %v", err)
	}
}

func TestVerifyMfa_WrongCode_Unauthenticated(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	ctx := ctxWithCaller("u1")
	_, _, _ = signInMfaGate(ctx, h, &pb.User{Id: "u1"}, testJKT, false, false)
	if _, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
		t.Error("a wrong code must fail VerifyMfa")
	}
}

// A 6-digit second factor must not be brute-forceable within
// the TTL. After maxMfaAttempts wrong codes the challenge is locked — even
// the CORRECT code is then refused (the attacker can't outrun the counter).
func TestVerifyMfa_LocksOutAfterMaxAttempts(t *testing.T) {
	m := &mfaMock{chUserID: "u1", chThumb: testJKT, chCreatedAt: timestamppb.Now()}
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
		if _, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "000000"}); err == nil {
			t.Fatalf("wrong-code attempt %d must fail", i+1)
		}
	}
	if m.chAttempts < int64(maxMfaAttempts) {
		t.Fatalf("recorded attempts = %d, want >= %d (failures must be counted)", m.chAttempts, maxMfaAttempts)
	}
	// The challenge is now locked: the correct code is rejected too.
	if _, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Fatal("after maxMfaAttempts failures the challenge must be locked even for the correct code")
	}
}

func TestVerifyMfa_Expired_Unauthenticated(t *testing.T) {
	m := &mfaMock{
		chUserID:    "u1",
		chThumb:     testJKT,
		chCodeHash:  "",
		chCreatedAt: timestamppb.New(time.Now().Add(-10 * time.Minute)), // older than TTL
	}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Error("an expired challenge must fail VerifyMfa")
	}
}

func TestVerifyMfa_Consumed_Unauthenticated(t *testing.T) {
	m := &mfaMock{chUserID: "u1", chThumb: testJKT, chCreatedAt: timestamppb.Now(), chConsumed: true}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	if _, err := h.VerifyMfa(withJKT(ctxWithCaller("u1"), testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: "123456"}); err == nil {
		t.Error("an already-consumed challenge must fail VerifyMfa")
	}
}

// The seed is a CRYPTED_SECRET: enrolment hands the storage layer the
// plaintext and needs no plugin key — the field keyring is the bundle's, and a
// bundle without one does not boot.
func TestEnrollTotp_NeedsNoPluginKey(t *testing.T) {
	m := &mfaMock{}
	h := newMfaHandler(m)
	h.TwoFactorSecretKey = ""
	enroll, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{})
	if err != nil {
		t.Fatalf("enroll without two_factor_secret_key: %v", err)
	}
	if m.totpSeed != enroll.GetSecret() || m.totpSecretEnc != "" {
		t.Errorf("stored seed=%q legacy=%q, want the seed in `seed` and nothing in the legacy column", m.totpSeed, m.totpSecretEnc)
	}
}

// An authenticator enrolled by rc.19 (secretbox under two_factor_secret_key)
// keeps working, and its first use moves the seed into the encrypted column.
func TestLegacySeed_VerifiesAndMoves(t *testing.T) {
	seed, _ := totp.GenerateSecret()
	cipher, _ := secretbox.NewFromBase64(mfaTestKey())
	blob, _ := cipher.Seal(seed)
	m := &mfaMock{userEmail: "a@b.c", totpSecretEnc: blob, totpConfirmed: true}
	h := newMfaHandler(m)
	code, _ := totp.Code(seed, time.Now())
	if !h.verifyMfaCode(ctxWithCaller("u1"), "u1", "", code) {
		t.Fatal("a legacy authenticator no longer verifies")
	}
	if m.movedRow != "row-1" {
		t.Errorf("the move is keyed by %q, not by the enrolment row it read — a re-enrolment in between would get the old seed", m.movedRow)
	}
	if m.movedSeed != seed || m.totpSecretEnc != "" {
		t.Errorf("moved=%q legacy=%q, want the seed moved and the legacy column cleared", m.movedSeed, m.totpSecretEnc)
	}
	// Moved: the old key is no longer needed. (The next window's code: this
	// one was spent.)
	h.TwoFactorSecretKey = ""
	if !h.verifyMfaCode(ctxWithCaller("u1"), "u1", "", nextCode(t, seed)) {
		t.Error("a moved authenticator still needs the legacy key")
	}
}

// A legacy authenticator whose key is gone cannot be checked: a refusal the
// caller can read, not a 500 and not a pass.
func TestLegacySeed_KeyGone_Refuses(t *testing.T) {
	cipher, _ := secretbox.NewFromBase64(mfaTestKey())
	blob, _ := cipher.Seal("JBSWY3DPEHPK3PXP")
	m := &mfaMock{totpSecretEnc: blob, totpConfirmed: true}
	h := newMfaHandler(m)
	h.TwoFactorSecretKey = ""
	_, err := h.DisableTotp(ctxWithCaller("u1"), &pb.DisableTotpReq{Code: "123456"})
	if status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeTotpUnavailable {
		t.Errorf("want FailedPrecondition/%s, got %v", CodeTotpUnavailable, err)
	}
	if m.revokedTotp {
		t.Error("an authenticator that could not be checked was dropped")
	}
}

func TestGetMfaStatus_ReflectsEnrollment(t *testing.T) {
	m := &mfaMock{totpSeed: "x", totpConfirmed: true}
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
// resets the mock's recorded `revokedTotp` flag because EnrollTotp
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
	m.revokedTotp = false
	return enroll.GetSecret()
}

// DisableTotp must re-verify a live TOTP code before removing a
// CONFIRMED authenticator, so a hijacked session can't permanently
// disable the victim's 2FA. A valid code deletes.
func TestDisableTotp_ValidCode_Deletes(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	secret := enrollAndConfirm(t, h, m, ctx)

	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: nextCode(t, secret)}); err != nil {
		t.Fatalf("disable with valid code: %v", err)
	}
	if !m.revokedTotp {
		t.Error("DisableTotp with a valid code should delete the secret")
	}
}

// A wrong code must NOT disable 2FA (opaque Unauthenticated,
// secret left intact).
func TestDisableTotp_WrongCode_Rejected(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: "000000"}); err == nil {
		t.Error("DisableTotp with a wrong code must fail")
	}
	if m.revokedTotp {
		t.Error("a wrong code must NOT delete the confirmed secret (2FA-disable hijack)")
	}
}

// An empty code is rejected too (no bypass via the zero value).
func TestDisableTotp_EmptyCode_Rejected(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{}); err == nil {
		t.Error("DisableTotp with an empty code must fail")
	}
	if m.revokedTotp {
		t.Error("an empty code must NOT delete the confirmed secret")
	}
}

// A pending (unconfirmed) enrollment provides no active
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
	if !m.revokedTotp {
		t.Error("an unconfirmed enrollment should be cancellable without a code")
	}
}

// Device identity is base tier: every activation knows the device a sign-in
// comes from, so new_devices no longer needs the `devices` feature.
func TestValidateConfig_NewDevicesNeedsNoFeature(t *testing.T) {
	for _, scope := range []string{"new_devices", "all_logins"} {
		if err := ValidateConfig(&AuthServiceHandler{TwoFactorScope: scope}); err != nil {
			t.Errorf("%s must validate in every activation: %v", scope, err)
		}
	}
}

// --- an unreadable enrolment must not weaken a factor ---------------------
//
// totpEnrolled folded a query error into `false`, so "the store did not
// answer" and "this user has no authenticator" were the same answer. Every
// caller then degraded in its own direction, and none of them logged anything.
// The four tests below are the four directions; they are written separately
// because a single one passing says nothing about the other three.

// The direction that disables a factor: with the check guarded by
// `err == nil && …`, a read failure made the whole condition false and the
// delete ran with no code presented at all.
func TestDisableTotp_ReadFailure_DoesNotDisableWithoutACode(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	ctx := ctxWithCaller("u1")
	enrollAndConfirm(t, h, m, ctx)

	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")
	if _, err := h.DisableTotp(ctx, &pb.DisableTotpReq{Code: "000000"}); err == nil {
		t.Error("a failed enrolment read must refuse, not skip the TOTP check")
	}
	if m.revokedTotp {
		t.Error("a confirmed second factor was dropped without a valid code")
	}
}

// The sign-in gate: no challenge means the password alone let the caller in.
func TestMfaGate_ReadFailure_RefusesRatherThanSkipTheChallenge(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c", totpSeed: "enc", totpConfirmed: true}
	h := newMfaHandler(m)
	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")

	_, _, err := mfaSignInGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, "", false, false)
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
	m := &mfaMock{userEmail: "a@b.c", totpSeed: "enc", totpConfirmed: true}
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
	m.chUserID, m.chCodeHash, m.chCreatedAt, m.chThumb = "u1", hash, timestamppb.Now(), testJKT
	m.totpReadErr = status.Error(codes.Unavailable, "enrolment store down")

	if _, err := h.VerifyMfa(mintCtx(), &pb.VerifyMfaReq{ChallengeId: "c1", Code: "123456"}); err == nil {
		t.Error("an unreadable enrolment must not be verified against the fallback code")
	}
}

// --- the cap was per-request, not per-challenge -----------------------------
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
	m.chUserID, m.chCodeHash, m.chCreatedAt, m.chThumb = "u1", hash, timestamppb.Now(), testJKT

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
			_, _ = h.VerifyMfa(mintCtx(), &pb.VerifyMfaReq{
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

// --- re-enrolment must not destroy the factor it replaces -------------------
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

func (f *failingCreateTotp) RevokeTotpSecret(ctx context.Context, in *pb.RevokeTotpSecretReq, o ...grpc.CallOption) (*pb.RevokeTotpSecretResp, error) {
	f.deleted = true
	return f.mfaMock.RevokeTotpSecret(ctx, in, o...)
}

func (f *failingCreateTotp) CreateTotpSecret(context.Context, *pb.CreateTotpSecretReq, ...grpc.CallOption) (*pb.CreateTotpSecretResp, error) {
	return nil, status.Error(codes.Unavailable, "secret store down")
}

func TestEnrollTotp_AFailedCreateDoesNotLeaveTheUserWithoutAFactor(t *testing.T) {
	seed, _ := totp.GenerateSecret()
	m := &mfaMock{userEmail: "a@b.c", totpSeed: seed, totpConfirmed: true}
	f := &failingCreateTotp{mfaMock: m}
	h := newMfaHandler(m)
	h.Mutation = f

	code, _ := totp.Code(seed, time.Now()) // replacing a confirmed authenticator takes its code
	if _, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{Code: code}); err == nil {
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
	for _, direct := range []string{"h.Mutation.RevokeTotpSecret(", "h.Mutation.CreateTotpSecret("} {
		if strings.Contains(fn, direct) {
			t.Errorf("EnrollTotp calls %s directly — the two writes are separable again, "+
				"and a failure between them takes the user's existing authenticator with it", direct)
		}
	}
	if !strings.Contains(fn, "replaceTotpSecret(") {
		t.Error("EnrollTotp no longer goes through replaceTotpSecret — nothing holds the pair together")
	}
	if !strings.Contains(fn, "h.inTx(") {
		t.Error("EnrollTotp opens no transaction — the seam exists but nothing wraps it")
	}
	helper, err := os.ReadFile("signin_history.go")
	if err != nil {
		t.Fatalf("read signin_history.go: %v", err)
	}
	hb := string(helper)
	j := strings.Index(hb, "func (h *AuthServiceHandler) inTx(")
	if j < 0 || !strings.Contains(hb[j:j+strings.Index(hb[j:], "\n}\n")], "distx.Begin(") {
		t.Error("inTx begins no distributed transaction")
	}
}

// A challenge opened before the account was disabled does not finish into a
// session: the second step re-runs SignIn's account gates.
func TestVerifyMfa_ADisabledAccountGetsNoSession(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	ctx := ctxWithCaller("u1")
	if _, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); !challenged {
		t.Fatal("expected challenge")
	}
	m.disabled = true
	resp, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: m.createdChallenge.GetCode()})
	if status.Code(err) != codes.Unauthenticated || resp.GetToken() != "" {
		t.Fatalf("a disabled account finished its sign-in: %v %v", resp, err)
	}
}

// With the built-in authenticator off, or no seed key, enrolment is a clear
// refusal, not an authenticator VerifyMfa would never consult (TOTP off), or a
// 500 (no key).
func TestEnrollTotp_RefusedWhenTheAuthenticatorIsOff(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	for _, call := range []func() error{
		func() error { _, err := h.EnrollTotp(ctxWithCaller("u1"), &pb.EnrollTotpReq{}); return err },
		func() error {
			_, err := h.ConfirmTotp(ctxWithCaller("u1"), &pb.ConfirmTotpReq{Code: "123456"})
			return err
		},
	} {
		err := call()
		if status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeTotpUnavailable {
			t.Errorf("want FailedPrecondition/%s, got %v", CodeTotpUnavailable, err)
		}
	}
}

// nextCode is the authenticator's code for the NEXT time step — still inside
// the ±1 skew, and not the step a code earlier in the test already spent.
func nextCode(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.Code(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The trust VerifyMfa grants holds only if the account's device trust was not
// revoked since the challenge was raised: the password the SignIn checked may
// be one a password change replaced while the code was being typed. So the
// write is guarded by the challenge's creation, not by anything read later.
func TestVerifyMfa_TrustIsGuardedFromTheChallengeOn(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorTOTP = false
	ctx := ctxWithCaller("u1")
	if _, challenged, _ := signInMfaGate(ctx, h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); !challenged {
		t.Fatal("expected challenge")
	}
	m.chCreatedAt = timestamppb.New(time.Now().Add(-time.Minute))
	if _, err := h.VerifyMfa(withJKT(ctx, testJKT), &pb.VerifyMfaReq{ChallengeId: "ch-1", Code: m.createdChallenge.GetCode()}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.trustedDevice == nil {
		t.Fatal("VerifyMfa did not trust the device")
	}
	if got := m.trustedDevice.GetNotRevokedAfter(); !got.AsTime().Equal(m.chCreatedAt.AsTime()) {
		t.Errorf("trust cutoff = %v, want the challenge's creation %v", got, m.chCreatedAt)
	}
	// The device trusted, and the one the session is bound to, is the key that
	// signed THIS request — the one that passed the second factor.
	if m.registeredDevice.GetThumbprint() != testJKT || m.registeredDevice.GetUserId() != "u1" {
		t.Errorf("RegisterDevice = %+v, want (u1, the request's key)", m.registeredDevice)
	}
	if want := "dev-" + testJKT[:8]; m.issuedDevice != want || m.trustedDevice.GetDeviceId() != want {
		t.Errorf("bound to %q, trusted %q, want both %q", m.issuedDevice, m.trustedDevice.GetDeviceId(), want)
	}
}

// two_factor_scope=off spares the challenge on a development stack only:
// outside W17_ENV=dev the boot refuses it, and a handler built without that
// check challenges anyway.
func TestTwoFactorScopeOff_DevelopmentOnly(t *testing.T) {
	m := &mfaMock{userEmail: "a@b.c"}
	h := newMfaHandler(m)
	h.TwoFactorScope = scopeOff

	t.Setenv(envEnvironment, devEnvironment)
	if err := checkTwoFactorScope(h); err != nil {
		t.Fatalf("dev: %v", err)
	}
	if _, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil || challenged {
		t.Fatalf("dev must not challenge: challenged=%v err=%v", challenged, err)
	}

	for _, env := range []string{"production", ""} {
		t.Setenv(envEnvironment, env)
		if err := checkTwoFactorScope(h); err == nil {
			t.Fatalf("%q: off passed the boot", env)
		}
		if _, challenged, err := signInMfaGate(context.Background(), h, &pb.User{Id: "u1", Email: "a@b.c"}, testJKT, false, false); err != nil || !challenged {
			t.Fatalf("%q: off must still challenge: challenged=%v err=%v", env, challenged, err)
		}
	}
}
