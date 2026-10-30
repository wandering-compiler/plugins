package handlers

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// tokenFlowMock backs the password_reset + email_verification handlers.
type tokenFlowMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	// query state
	userByEmail map[string]*pb.User // email -> user (nil = not found)
	userByID    map[string]*pb.User

	// recorded
	createdReset      *pb.CreatePasswordResetTokenReq
	createResetErr    error
	mintCtxErr        error
	consumedResetHash string
	consumeResetUser  string // user_id ConsumePasswordResetToken returns ("" = no live token)
	updatedPassword   *pb.UpdateUserPasswordReq
	// updatePasswordErr fails the write the reset token authorises — the
	// failure the transaction exists for. It is the SECOND half of the pair,
	// so a rollback here is what keeps the spent link recoverable.
	updatePasswordErr error
	revokedFor        string
	spentLinksFor     string
	spendErr          error

	createdVerify      *pb.CreateEmailVerificationTokenReq
	consumedVerifyHash string
	consumeVerifyUser  string
	markedVerified     string
}

func (m *tokenFlowMock) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	return &pb.GetUserByEmailResp{User: m.userByEmail[in.GetEmail()]}, nil
}
func (m *tokenFlowMock) GetUserById(ctx context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: m.userByID[in.GetUserId()]}, nil
}
func (m *tokenFlowMock) CreatePasswordResetToken(ctx context.Context, in *pb.CreatePasswordResetTokenReq, _ ...grpc.CallOption) (*pb.CreatePasswordResetTokenResp, error) {
	m.createdReset = in
	m.mintCtxErr = ctx.Err()
	if m.createResetErr != nil {
		return nil, m.createResetErr
	}
	return &pb.CreatePasswordResetTokenResp{Token: &pb.PasswordResetToken{Id: "prt-1", UserId: in.GetUserId(), TokenHash: in.GetTokenHash()}}, nil
}
func (m *tokenFlowMock) ConsumePasswordResetToken(ctx context.Context, in *pb.ConsumePasswordResetTokenReq, _ ...grpc.CallOption) (*pb.ConsumePasswordResetTokenResp, error) {
	m.consumedResetHash = in.GetTokenHash()
	return &pb.ConsumePasswordResetTokenResp{UserId: m.consumeResetUser}, nil
}
func (m *tokenFlowMock) UpdateUserPassword(ctx context.Context, in *pb.UpdateUserPasswordReq, _ ...grpc.CallOption) (*pb.UpdateUserPasswordResp, error) {
	if m.updatePasswordErr != nil {
		// Recorded even on the failure arm: a test has to be able to tell
		// "the write was attempted and refused" from "the write never ran".
		m.updatedPassword = in
		return nil, m.updatePasswordErr
	}
	m.updatedPassword = in
	return &pb.UpdateUserPasswordResp{UserId: in.GetUserId()}, nil
}
func (m *tokenFlowMock) SpendPasswordResetTokens(_ context.Context, in *pb.SpendPasswordResetTokensReq, _ ...grpc.CallOption) (*pb.SpendPasswordResetTokensResp, error) {
	m.spentLinksFor = in.GetUserId()
	if m.spendErr != nil {
		return nil, m.spendErr
	}
	return &pb.SpendPasswordResetTokensResp{}, nil
}
func (m *tokenFlowMock) RevokeTokensForReset(ctx context.Context, in *pb.RevokeTokensForResetReq, _ ...grpc.CallOption) (*pb.RevokeTokensForResetResp, error) {
	m.revokedFor = in.GetUserId()
	return &pb.RevokeTokensForResetResp{}, nil
}
func (m *tokenFlowMock) CreateEmailVerificationToken(ctx context.Context, in *pb.CreateEmailVerificationTokenReq, _ ...grpc.CallOption) (*pb.CreateEmailVerificationTokenResp, error) {
	m.createdVerify = in
	return &pb.CreateEmailVerificationTokenResp{Token: &pb.EmailVerificationToken{Id: "evt-1", UserId: in.GetUserId(), TokenHash: in.GetTokenHash()}}, nil
}
func (m *tokenFlowMock) ConsumeEmailVerificationToken(ctx context.Context, in *pb.ConsumeEmailVerificationTokenReq, _ ...grpc.CallOption) (*pb.ConsumeEmailVerificationTokenResp, error) {
	m.consumedVerifyHash = in.GetTokenHash()
	return &pb.ConsumeEmailVerificationTokenResp{UserId: m.consumeVerifyUser}, nil
}
func (m *tokenFlowMock) MarkEmailVerified(ctx context.Context, in *pb.MarkEmailVerifiedReq, _ ...grpc.CallOption) (*pb.MarkEmailVerifiedResp, error) {
	m.markedVerified = in.GetUserId()
	return &pb.MarkEmailVerifiedResp{UserId: in.GetUserId()}, nil
}

func newTokenFlowHandler(m *tokenFlowMock) *AuthServiceHandler {
	return &AuthServiceHandler{Query: m, Mutation: m, PasswordHash: testPasswordSettings()}
}

// ── password_reset ──────────────────────────────────────────

// An unknown email yields a uniform empty success with NO token
// minted (anti-enumeration: the caller can't tell a registered email from
// an unregistered one).
func TestRequestPasswordReset_UnknownEmail_NoOp(t *testing.T) {
	m := &tokenFlowMock{userByEmail: map[string]*pb.User{}}
	h := newTokenFlowHandler(m)
	if _, err := h.RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "ghost@x.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if m.createdReset != nil {
		t.Error("an unknown email must NOT mint a reset token (would leak account existence)")
	}
}

// A known email mints a token, storing only its hash; the plaintext
// rides the event and is never the stored value.
func TestRequestPasswordReset_KnownEmail_StoresHashEmitsPlaintext(t *testing.T) {
	m := &tokenFlowMock{userByEmail: map[string]*pb.User{"u@x.com": {Id: "u1", Email: "u@x.com"}}}
	h := newTokenFlowHandler(m)
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

// password_reset gap 3: a registered address answers BEFORE its link is
// minted — the mint is held here, and the answer still arrives — so the
// response takes the lookup's time for every address, registered or not.
// The held mint then runs, on a context the finished request no longer
// cancels.
func TestRequestPasswordReset_AnswersBeforeTheLinkIsMinted(t *testing.T) {
	var held func()
	prev := runDetached
	t.Cleanup(func() { runDetached = prev })
	runDetached = func(f func()) { held = f }

	m := &tokenFlowMock{userByEmail: map[string]*pb.User{"u@x.com": {Id: "u1", Email: "u@x.com"}}}
	h := newTokenFlowHandler(m)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := h.RequestPasswordReset(ctx, &pb.RequestPasswordResetReq{Email: "u@x.com"}); err != nil {
		t.Fatalf("request: %v", err)
	}
	if m.createdReset != nil {
		t.Fatal("the link was minted before the answer — a registered address answers slower than an unknown one")
	}
	if held == nil {
		t.Fatal("nothing was scheduled for a registered address")
	}
	cancel() // the request is over
	held()
	if m.createdReset == nil || m.createdReset.GetUserId() != "u1" {
		t.Fatalf("the detached mint did not run to completion after the request ended: %+v", m.createdReset)
	}
	if m.mintCtxErr != nil {
		t.Errorf("the mint ran on the request's cancelled context: %v", m.mintCtxErr)
	}

	// An unknown address schedules nothing at all.
	held = nil
	if _, err := h.RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "ghost@x.com"}); err != nil || held != nil {
		t.Fatalf("unknown address: %v, scheduled %v", err, held != nil)
	}
}

// The error channel is closed too: a mint that fails (only a registered
// address ever reaches it) answers exactly what an unknown address answers.
func TestRequestPasswordReset_AFailedMintAnswersLikeAnUnknownAddress(t *testing.T) {
	known := &tokenFlowMock{userByEmail: map[string]*pb.User{"u@x.com": {Id: "u1", Email: "u@x.com"}}, createResetErr: status.Error(codes.Internal, "insert failed")}
	unknown := &tokenFlowMock{userByEmail: map[string]*pb.User{}}
	a, errA := newTokenFlowHandler(known).RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "u@x.com"})
	b, errB := newTokenFlowHandler(unknown).RequestPasswordReset(context.Background(), &pb.RequestPasswordResetReq{Email: "ghost@x.com"})
	if errA != nil || errB != nil {
		t.Fatalf("known-with-failed-mint %v, unknown %v — both must be a plain success", errA, errB)
	}
	if !proto.Equal(a, b) {
		t.Errorf("the answers differ: %v vs %v", a, b)
	}
	if known.createdReset == nil {
		t.Error("the failing mint never ran — this arm is not exercising the error")
	}
}

// A valid reset token updates the password (hashed) and revokes
// existing sessions. The consume lookup is by HASH, never the plaintext.
func TestResetPassword_ValidToken_UpdatesAndRevokes(t *testing.T) {
	m := &tokenFlowMock{consumeResetUser: "u1"}
	h := newTokenFlowHandler(m)
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

// An invalid/expired/used token (empty consume result) is an opaque
// failure that does NOT change the password.
func TestResetPassword_InvalidToken_Rejected(t *testing.T) {
	m := &tokenFlowMock{consumeResetUser: ""} // no live token matched
	h := newTokenFlowHandler(m)
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

// RequestEmailVerification mints a token for the caller, storing only
// its hash.
func TestRequestEmailVerification_StoresHash(t *testing.T) {
	m := &tokenFlowMock{userByID: map[string]*pb.User{"u1": {Id: "u1", Email: "u@x.com"}}}
	h := newTokenFlowHandler(m)
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

// A valid verification token stamps email_verified_at; the consume is
// by hash.
func TestVerifyEmail_ValidToken_MarksVerified(t *testing.T) {
	m := &tokenFlowMock{consumeVerifyUser: "u1"}
	h := newTokenFlowHandler(m)
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

// An invalid verification token does NOT mark the email verified.
func TestVerifyEmail_InvalidToken_Rejected(t *testing.T) {
	m := &tokenFlowMock{consumeVerifyUser: ""}
	h := newTokenFlowHandler(m)
	if _, err := h.VerifyEmail(context.Background(), &pb.VerifyEmailReq{Token: "bad"}); err == nil {
		t.Error("an invalid verification token must fail")
	}
	if m.markedVerified != "" {
		t.Error("an invalid token must NOT mark the email verified")
	}
}

// --- the sweep that nobody was told had failed ------------------------------
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
	*tokenFlowMock
	sweepErr error
	swept    bool
	// tx, when set, is read at the sweep: whether the reset's transaction
	// was still open when the sessions were revoked.
	tx          *recordingDistTx
	sweptInOpen bool
}

func (m *resetSweepMock) RevokeTokensForReset(ctx context.Context, in *pb.RevokeTokensForResetReq, o ...grpc.CallOption) (*pb.RevokeTokensForResetResp, error) {
	m.swept = true
	if m.tx != nil {
		m.sweptInOpen = m.tx.settled() == "left open"
	}
	if m.sweepErr != nil {
		return nil, m.sweepErr
	}
	return m.tokenFlowMock.RevokeTokensForReset(ctx, in, o...)
}

func TestResetPassword_ReportsWhenTheSessionSweepDidNotRun(t *testing.T) {
	base := &tokenFlowMock{consumeResetUser: "u1"}
	m := &resetSweepMock{tokenFlowMock: base, sweepErr: status.Error(codes.Unavailable, "store down")}
	h := newTokenFlowHandler(base)
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
	base := &tokenFlowMock{consumeResetUser: "u1"}
	m := &resetSweepMock{tokenFlowMock: base}
	h := newTokenFlowHandler(base)
	h.Mutation = m

	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "tok", NewPassword: "n3wPassw0rd!"})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !resp.GetSessionsRevoked() {
		t.Error("a successful sweep is reported as a failure — the field would be noise, not signal")
	}
}

// ── the reset transaction, driven rather than read ──────────────────────

// newTokenFlowHandlerTx is newTokenFlowHandler with the transaction coordinator
// the GENERATED bundle always supplies. Kept separate so the existing arms keep
// proving what they proved, and the transaction gets arms of its own.
func newTokenFlowHandlerTx(m *tokenFlowMock, tx *recordingDistTx) *AuthServiceHandler {
	h := newTokenFlowHandler(m)
	h.DistTx = tx
	h.Connection = "app-postgres"
	return h
}

// A successful reset must COMMIT, and it must have opened the transaction on
// the handler's own connection — a Begin on the wrong connection would hold a
// transaction the password write never joins, so both writes would land
// outside it and the rollback path would undo nothing.
func TestResetPassword_Success_CommitsOnTheHandlersConnection(t *testing.T) {
	tx := &recordingDistTx{}
	m := &tokenFlowMock{consumeResetUser: "u1"}
	h := newTokenFlowHandlerTx(m, tx)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if got := tx.settled(); got != "committed" {
		t.Fatalf("a successful reset left its transaction %s, want committed", got)
	}
	if len(tx.begun) != 1 || tx.begun[0] != "app-postgres" {
		t.Errorf("Begin connections = %v, want exactly one on the handler's connection", tx.begun)
	}
	if len(tx.committed) != 1 || tx.committed[0] != fakeTxID {
		t.Errorf("Commit tx ids = %v, want one %q — the handle's own id must be the one finished", tx.committed, fakeTxID)
	}
}

// The arm the fix exists for. The consume is the CHECK, so it must come
// first — which means a failure after it has spent a valid link while the
// password is unchanged, leaving the person with neither. That is only
// survivable if the pair rolls back together.
//
// Without this, deleting `distx.Begin` from ResetPassword leaves the suite
// green: every other reset arm builds a handler with no coordinator at all.
func TestResetPassword_FailureAfterConsume_RollsBack(t *testing.T) {
	tx := &recordingDistTx{}
	m := &tokenFlowMock{consumeResetUser: "u1", updatePasswordErr: errTestUpdateFailed}
	h := newTokenFlowHandlerTx(m, tx)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); err == nil {
		t.Fatal("a failed password write must fail the reset")
	}
	if got := tx.settled(); got != "rolled back" {
		t.Fatalf("a failed password write left its transaction %s, want rolled back — the reset link is spent and the password never changed", got)
	}
	if len(tx.committed) != 0 {
		t.Errorf("nothing may be committed on the failure path; got %v", tx.committed)
	}
}

// A coordinator that refuses to open the transaction must fail the reset
// BEFORE the token is spent. Proceeding without one would silently restore
// the pre-fix behaviour on exactly the day the coordinator is unhealthy.
func TestResetPassword_BeginRefused_SpendsNothing(t *testing.T) {
	tx := &recordingDistTx{beginErr: errTestBeginRefused}
	m := &tokenFlowMock{consumeResetUser: "u1"}
	h := newTokenFlowHandlerTx(m, tx)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); err == nil {
		t.Fatal("a refused Begin must fail the reset")
	}
	if m.consumedResetHash != "" {
		t.Error("the reset token was consumed despite there being no transaction to protect the pair")
	}
	if m.updatedPassword != nil {
		t.Error("the password was written with no transaction open")
	}
}

// password_reset gap 4: with a coordinator the session sweep runs INSIDE the
// reset's transaction — before the commit — so the reset and the end of every
// old session land together. The answer then says the sessions were revoked,
// and it is true.
func TestResetPassword_SweepsSessionsInsideTheTransaction(t *testing.T) {
	tx := &recordingDistTx{}
	base := &tokenFlowMock{consumeResetUser: "u1"}
	m := &resetSweepMock{tokenFlowMock: base, tx: tx}
	h := newTokenFlowHandlerTx(base, tx)
	h.Mutation = m
	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"})
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if !m.swept || !m.sweptInOpen {
		t.Fatalf("the sweep ran %v, inside the open transaction %v — it must run before the commit", m.swept, m.sweptInOpen)
	}
	if base.revokedFor != "u1" {
		t.Errorf("swept %q, want u1", base.revokedFor)
	}
	if got := tx.settled(); got != "committed" || !resp.GetSessionsRevoked() {
		t.Errorf("transaction %s, sessions_revoked %v — want committed and true", got, resp.GetSessionsRevoked())
	}
}

// The arm the move exists for: a sweep that fails rolls the WHOLE reset back.
// Committing the new password while the thief's session lives on is the
// outcome a reset must never have; refused, the person retries with the same
// link (it was not spent) and the old password still stands.
func TestResetPassword_AFailedSweepRollsTheResetBack(t *testing.T) {
	tx := &recordingDistTx{}
	base := &tokenFlowMock{consumeResetUser: "u1"}
	m := &resetSweepMock{tokenFlowMock: base, tx: tx, sweepErr: status.Error(codes.Unavailable, "store down")}
	h := newTokenFlowHandlerTx(base, tx)
	h.Mutation = m
	resp, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"})
	if err == nil || resp != nil {
		t.Fatalf("a failed sweep: %v, %v — want the reset refused", resp, err)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("the refusal is %v, want the sweep's own Unavailable (retry), not a bad-token answer", status.Code(err))
	}
	if got := tx.settled(); got != "rolled back" || len(tx.committed) != 0 {
		t.Fatalf("transaction %s (committed %v), want rolled back — the new password must not land without the sweep", got, tx.committed)
	}
	if base.updatedPassword == nil {
		t.Error("the password write never ran — this arm is not past the consume")
	}
}

// Distinct sentinels: a single shared "test error" would let an arm pass on a
// failure that came from somewhere else entirely.
var (
	errTestUpdateFailed = errors.New("test: the password write failed")
	errTestBeginRefused = errors.New("test: the coordinator refused to begin")
	errTestSpendFailed  = errors.New("test: spending the other reset links failed")
)

// Every other live reset link of the account is spent with the one used: a
// second link would set the password again.
func TestResetPassword_SpendsEveryOtherResetLink(t *testing.T) {
	m := &tokenFlowMock{consumeResetUser: "u1"}
	h := newTokenFlowHandler(m)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if m.spentLinksFor != "u1" {
		t.Errorf("the account's other reset links were not spent (spent for %q)", m.spentLinksFor)
	}
}

// Spending the other links is part of the reset's unit of work: when it
// fails, the reset fails and nothing commits, so the person is not told the
// password changed while older links still work.
func TestResetPassword_AFailedSpendRollsBackTheReset(t *testing.T) {
	tx := &recordingDistTx{}
	m := &tokenFlowMock{consumeResetUser: "u1", spendErr: errTestSpendFailed}
	h := newTokenFlowHandlerTx(m, tx)
	if _, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "plain-tok", NewPassword: "new-secret-123"}); !errors.Is(err, errTestSpendFailed) {
		t.Fatalf("want the spend's failure, got %v", err)
	}
	if got := tx.settled(); got != "rolled back" {
		t.Fatalf("a failed spend left its transaction %s, want rolled back", got)
	}
	if len(tx.committed) != 0 {
		t.Errorf("nothing may be committed on the failure path; got %v", tx.committed)
	}
}
