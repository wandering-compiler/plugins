package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// e1Mock backs the password_reset + email_verification handlers (E1).
type e1Mock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	// query state
	userByEmail map[string]*pb.User // email -> user (nil = not found)
	userByID    map[string]*pb.User

	// recorded
	createdReset      *pb.CreatePasswordResetTokenReq
	consumedResetHash string
	consumeResetUser  string // user_id ConsumePasswordResetToken returns ("" = no live token)
	updatedPassword   *pb.UpdateUserPasswordReq
	revokedFor        string

	createdVerify      *pb.CreateEmailVerificationTokenReq
	consumedVerifyHash string
	consumeVerifyUser  string
	markedVerified     string
}

func (m *e1Mock) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: m.userByEmail[in.GetEmail()]}, nil
}
func (m *e1Mock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: m.userByID[in.GetUserId()]}, nil
}
func (m *e1Mock) CreatePasswordResetToken(ctx context.Context, in *pb.CreatePasswordResetTokenReq, _ ...grpc.CallOption) (*pb.CreatePasswordResetTokenResp, error) {
	m.createdReset = in
	return &pb.CreatePasswordResetTokenResp{Token: &pb.PasswordResetToken{Id: "prt-1", UserId: in.GetUserId(), TokenHash: in.GetTokenHash()}}, nil
}
func (m *e1Mock) ConsumePasswordResetToken(ctx context.Context, in *pb.ConsumePasswordResetTokenReq, _ ...grpc.CallOption) (*pb.ConsumePasswordResetTokenResp, error) {
	m.consumedResetHash = in.GetTokenHash()
	return &pb.ConsumePasswordResetTokenResp{UserId: m.consumeResetUser}, nil
}
func (m *e1Mock) UpdateUserPassword(ctx context.Context, in *pb.UpdateUserPasswordReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordResp, error) {
	m.updatedPassword = in
	return &pb.UpdateUserPasswordResp{UserId: in.GetUserId()}, nil
}
func (m *e1Mock) DeleteUserSessionsForReset(ctx context.Context, in *pb.DeleteUserSessionsForResetReq, _ ...grpc.CallOption) (*pb.DeleteUserSessionsForResetResp, error) {
	m.revokedFor = in.GetUserId()
	return &pb.DeleteUserSessionsForResetResp{UserId: in.GetUserId()}, nil
}
func (m *e1Mock) CreateEmailVerificationToken(ctx context.Context, in *pb.CreateEmailVerificationTokenReq, _ ...grpc.CallOption) (*pb.CreateEmailVerificationTokenResp, error) {
	m.createdVerify = in
	return &pb.CreateEmailVerificationTokenResp{Token: &pb.EmailVerificationToken{Id: "evt-1", UserId: in.GetUserId(), TokenHash: in.GetTokenHash()}}, nil
}
func (m *e1Mock) ConsumeEmailVerificationToken(ctx context.Context, in *pb.ConsumeEmailVerificationTokenReq, _ ...grpc.CallOption) (*pb.ConsumeEmailVerificationTokenResp, error) {
	m.consumedVerifyHash = in.GetTokenHash()
	return &pb.ConsumeEmailVerificationTokenResp{UserId: m.consumeVerifyUser}, nil
}
func (m *e1Mock) MarkEmailVerified(ctx context.Context, in *pb.MarkEmailVerifiedReq, _ ...grpc.CallOption) (*pb.MarkEmailVerifiedResp, error) {
	m.markedVerified = in.GetUserId()
	return &pb.MarkEmailVerifiedResp{UserId: in.GetUserId()}, nil
}

func newE1Handler(m *e1Mock) *AuthServiceHandler {
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
}

// ── password_reset ──────────────────────────────────────────

// E1 — an unknown email yields a uniform empty success with NO token
// minted (anti-enumeration: the caller can't tell a registered email from
// an unregistered one).
func TestRequestPasswordReset_UnknownEmail_NoOp(t *testing.T) {
	m := &e1Mock{userByEmail: map[string]*pb.User{}}
	h := newE1Handler(m)
	if _, err := h.RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "ghost@x.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if m.createdReset != nil {
		t.Error("an unknown email must NOT mint a reset token (would leak account existence)")
	}
}

// E1 — a known email mints a token, storing only its hash; the plaintext
// rides the event and is never the stored value.
func TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext(t *testing.T) {
	m := &e1Mock{userByEmail: map[string]*pb.User{"u@x.com": {Id: "u1", Email: "u@x.com"}}}
	h := newE1Handler(m)
	if _, err := h.RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "U@x.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if m.createdReset == nil {
		t.Fatal("a known email must mint a reset token")
	}
	if m.createdReset.GetUserId() != "u1" {
		t.Errorf("user_id = %q, want u1", m.createdReset.GetUserId())
	}
	plain, stored := m.createdReset.GetToken(), m.createdReset.GetTokenHash()
	if plain == "" || stored == "" {
		t.Fatal("both the plaintext (event) and the hash (stored) must be set")
	}
	if stored != sha256Hex(plain) {
		t.Error("stored token_hash must be sha256(plaintext)")
	}
	if stored == plain {
		t.Error("the plaintext token must never be the stored value")
	}
	if m.createdReset.GetEmail() != "u@x.com" {
		t.Errorf("event email = %q, want the canonical stored email", m.createdReset.GetEmail())
	}
}

// E1 — a valid reset token updates the password (hashed) and revokes
// existing sessions. The consume lookup is by HASH, never the plaintext.
func TestResetPassword_ValidToken_UpdatesAndRevokes(t *testing.T) {
	m := &e1Mock{consumeResetUser: "u1"}
	h := newE1Handler(m)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if m.consumedResetHash != sha256Hex("plain-tok") {
		t.Error("ConsumePasswordResetToken must be called with the HASH of the presented token")
	}
	if m.updatedPassword == nil || m.updatedPassword.GetUserId() != "u1" {
		t.Fatalf("UpdateUserPassword(u1) expected, got %+v", m.updatedPassword)
	}
	if m.updatedPassword.GetPasswordHash() == "new-secret-123" || m.updatedPassword.GetPasswordHash() == "" {
		t.Error("the new password must be stored hashed, never in plaintext")
	}
	if m.revokedFor != "u1" {
		t.Error("a successful reset must revoke the user's existing sessions")
	}
}

// E1 — an invalid/expired/used token (empty consume result) is an opaque
// failure that does NOT change the password.
func TestResetPassword_InvalidToken_Rejected(t *testing.T) {
	m := &e1Mock{consumeResetUser: ""} // no live token matched
	h := newE1Handler(m)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "bad", NewPassword: "whatever-123"}); err == nil {
		t.Error("an invalid reset token must fail")
	}
	if m.updatedPassword != nil {
		t.Error("an invalid token must NOT update any password")
	}
	if m.revokedFor != "" {
		t.Error("an invalid token must NOT revoke sessions")
	}
}

// ── email_verification ──────────────────────────────────────

// E1 — RequestEmailVerification mints a token for the caller, storing only
// its hash.
func TestRequestEmailVerification_StoresHash(t *testing.T) {
	m := &e1Mock{userByID: map[string]*pb.User{"u1": {Id: "u1", Email: "u@x.com"}}}
	h := newE1Handler(m)
	if _, err := h.RequestEmailVerification(ctxWithCaller("u1"), &pb.RequestEmailVerificationReq{}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if m.createdVerify == nil || m.createdVerify.GetUserId() != "u1" {
		t.Fatalf("CreateEmailVerificationToken(u1) expected, got %+v", m.createdVerify)
	}
	if m.createdVerify.GetTokenHash() != sha256Hex(m.createdVerify.GetToken()) {
		t.Error("stored token_hash must be sha256(plaintext)")
	}
}

// E1 — a valid verification token stamps email_verified_at; the consume is
// by hash.
func TestVerifyEmail_ValidToken_MarksVerified(t *testing.T) {
	m := &e1Mock{consumeVerifyUser: "u1"}
	h := newE1Handler(m)
	if _, err := h.VerifyEmail(context.Background(), &pb.VerifyEmailReq{Token: "plain-v"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.consumedVerifyHash != sha256Hex("plain-v") {
		t.Error("ConsumeEmailVerificationToken must be called with the token HASH")
	}
	if m.markedVerified != "u1" {
		t.Error("a valid token must mark the email verified")
	}
}

// E1 — an invalid verification token does NOT mark the email verified.
func TestVerifyEmail_InvalidToken_Rejected(t *testing.T) {
	m := &e1Mock{consumeVerifyUser: ""}
	h := newE1Handler(m)
	if _, err := h.VerifyEmail(context.Background(), &pb.VerifyEmailReq{Token: "bad"}); err == nil {
		t.Error("an invalid verification token must fail")
	}
	if m.markedVerified != "" {
		t.Error("an invalid token must NOT mark the email verified")
	}
}

// --- marb #58: the sweep that nobody was told had failed --------------------
//
// ResetPassword revokes every existing session and API token, because a reset
// is what somebody does when they think a credential is compromised. That
// sweep is best-effort by design — the password is already changed and a
// failure must not undo it — but its error was discarded with `_, _ =` under
// a comment saying it was "logged by the caller's interceptor". It was
// discarded before any interceptor could see it, and this plugin has no
// logging at all.
//
// So the one case the sweep exists for could leave the thief's session alive,
// report success, and end there. The outcome is reported now.
type resetSweepMock struct {
	*e1Mock
	sweepErr error
	swept    bool
}

func (m *resetSweepMock) DeleteUserSessionsForReset(ctx context.Context, in *pb.DeleteUserSessionsForResetReq, o ...grpc.CallOption) (*pb.DeleteUserSessionsForResetResp, error) {
	m.swept = true
	if m.sweepErr != nil {
		return nil, m.sweepErr
	}
	return m.e1Mock.DeleteUserSessionsForReset(ctx, in, o...)
}

func TestResetPassword_ReportsWhenTheSessionSweepDidNotRun(t *testing.T) {
	base := &e1Mock{consumeResetUser: "u1"}
	m := &resetSweepMock{e1Mock: base, sweepErr: status.Error(codes.Unavailable, "store down")}
	h := newE1Handler(base)
	h.Mutation = m

	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "tok", NewPassword: "n3wPassw0rd!"})
	if err != nil {
		t.Fatalf("a failed sweep must not fail the reset — the password is already changed: %v", err)
	}
	if !m.swept {
		t.Fatal("the sweep never ran — this test is not exercising the path")
	}
	if resp.GetSessionsRevoked() {
		t.Error("the response claims the sessions were revoked after the sweep failed — " +
			"this is the lie the discarded error used to tell silently")
	}
}

// And the other direction, or the assertion above passes for a response that
// always says false — which would tell every user to sign out everywhere
// after every reset, and get ignored within a week.
func TestResetPassword_ReportsASweepThatSucceeded(t *testing.T) {
	base := &e1Mock{consumeResetUser: "u1"}
	m := &resetSweepMock{e1Mock: base}
	h := newE1Handler(base)
	h.Mutation = m

	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "tok", NewPassword: "n3wPassw0rd!"})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !resp.GetSessionsRevoked() {
		t.Error("a successful sweep is reported as a failure — the field would be noise, not signal")
	}
}
