package handlers

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
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

	sweeps   []*pb.DeleteOtherSessionTokensReq
	sweepErr error

	spentLinksFor string // user whose reset links SpendPasswordResetTokens spent
	spendErr      error
}

func (m *passwordChangeMock) SpendPasswordResetTokens(_ context.Context, in *pb.SpendPasswordResetTokensReq, _ ...grpc.CallOption) (*pb.SpendPasswordResetTokensResp, error) {
	m.spentLinksFor = in.GetUserId()
	if m.spendErr != nil {
		return nil, m.spendErr
	}
	return &pb.SpendPasswordResetTokensResp{}, nil
}

func (m *passwordChangeMock) DeleteOtherSessionTokens(ctx context.Context, in *pb.DeleteOtherSessionTokensReq, _ ...grpc.CallOption) (*pb.DeleteOtherSessionTokensResp, error) {
	m.sweeps = append(m.sweeps, in)
	if m.sweepErr != nil {
		return nil, m.sweepErr
	}
	return &pb.DeleteOtherSessionTokensResp{}, nil
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

// A password change signs the person out everywhere ELSE: every other
// session of theirs is deleted, the one they changed it from is kept, and
// their API tokens are not touched (only sessions are named).
func TestChangePassword_EndsEveryOtherSession(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	if _, err := h.ChangePassword(ctxWithEnvelope(t, "u1", "11111111-1111-4111-8111-111111111111"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if len(m.sweeps) != 1 {
		t.Fatalf("other sessions swept %d times, want once", len(m.sweeps))
	}
	sw := m.sweeps[0]
	if sw.GetUserId() != "u1" || sw.GetKeepTokenId() != "11111111-1111-4111-8111-111111111111" {
		t.Errorf("sweep = %+v, want u1's sessions but the caller's own", sw)
	}

	// An API-token caller has no session to keep: every session goes.
	m.sweeps = nil
	if _, err := h.ChangePassword(ctxWithEnvelope(t, "u1", ""), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-third-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword (API token): %v", err)
	}
	if len(m.sweeps) != 1 || m.sweeps[0].GetKeepTokenId() != nilUUID {
		t.Errorf("an API-token caller kept a session: %+v", m.sweeps)
	}
}

// A sign-out that fails fails the change: the person must not be told the
// password changed while the other sessions live on.
func TestChangePassword_AFailedSignOutFailsTheChange(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	m.sweepErr = status.Error(codes.Unavailable, "db down")
	_, err := h.ChangePassword(ctxWithEnvelope(t, "u1", "11111111-1111-4111-8111-111111111111"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want the sweep's failure, got %v", err)
	}
}

// A reset link asked for before a password change would undo the change; it
// is spent in the same unit of work.
func TestChangePassword_SpendsTheAccountsResetLinks(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	if _, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if m.spentLinksFor != "u1" {
		t.Errorf("reset links not spent on a password change (spent for %q)", m.spentLinksFor)
	}
}

// A spend that fails fails the change: the person must not be told the
// password changed while a reset link could still undo it.
func TestChangePassword_AFailedSpendFailsTheChange(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	m.spendErr = status.Error(codes.Unavailable, "db down")
	_, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want the spend's failure, got %v", err)
	}
}

// The sweep spares API tokens by naming the session realm in the statement,
// behind ?feature(api_token): the token_type column exists only with that
// feature, so an ungated filter would break every activation of
// password_change without it, and no filter at all would delete API tokens.
func TestChangePassword_TheSweepSparesAPITokensOnlyWhereTheyExist(t *testing.T) {
	body := mutationRPCBody(t, "DeleteOtherSessionTokens")
	if !strings.Contains(body, `"AND ?feature(api_token) token_type = 1"`) {
		t.Errorf("DeleteOtherSessionTokens does not filter the session realm behind ?feature(api_token):\n%s", body)
	}
}

// A password change ends the trust of every device of the account, in the
// statement that writes the new password: whoever held the old password may
// have signed in from a device that would otherwise keep skipping the second
// factor under two_factor_scope=new_devices. Behind ?feature(devices), because
// the column exists only with that feature; ungated, every activation of
// password_change without devices would stop generating.
func TestChangePassword_RevokesDeviceTrustInTheSameStatement(t *testing.T) {
	body := mutationRPCBody(t, "UpdateUserPasswordIfUnchanged")
	if !strings.Contains(body, `"?feature(devices) device_trust_revoked_at = NOW() "`) {
		t.Errorf("UpdateUserPasswordIfUnchanged does not revoke device trust behind ?feature(devices):\n%s", body)
	}
}

// mutationRPCBody returns the declaration of one AuthMutation rpc, from its
// `rpc Name(` to its closing brace, for a test that pins its statement.
func mutationRPCBody(t *testing.T, rpc string) string {
	t.Helper()
	raw, err := os.ReadFile("../../proto/mutations/auth_mutation.proto")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "rpc "+rpc+"(")
	if i < 0 {
		t.Fatalf("%s not found", rpc)
	}
	end := strings.Index(src[i:], "\n  }\n")
	if end < 0 {
		t.Fatalf("%s has no closing brace", rpc)
	}
	return src[i : i+end]
}

// The new hash is derived BEFORE the transaction opens: a deliberately slow
// derivation inside it would hold the row lock the compare-and-swap takes for
// as long as the hash runs. Observed through a hash that fails (an empty
// password is refused by the hasher): a derivation inside the transaction
// would have begun one first and rolled it back.
func TestChangePassword_HashesBeforeTheTransactionOpens(t *testing.T) {
	h, m := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	tx := &recordingDistTx{}
	h.DistTx, h.Connection = tx, "main"

	if _, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "",
	}); err == nil {
		t.Fatal("an empty new password was accepted")
	}
	if len(tx.begun) != 0 || m.casCalls != 0 {
		t.Fatalf("a failed derivation opened a transaction (%s) or wrote (%d) — the hash ran inside it", tx.settled(), m.casCalls)
	}

	// The control: a derivation that succeeds goes on to one committed
	// transaction, so the assertion above is not met by a handler that never
	// opens one.
	if _, err := h.ChangePassword(orgAuthedCtx("u1"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if tx.settled() != "committed" || len(tx.begun) != 1 {
		t.Fatalf("the change ran in %d transaction(s), %s; want one, committed", len(tx.begun), tx.settled())
	}
}

// The current password is the whole proof: a change asks for no second-factor
// step-up, also for an account with an authenticator. The request carries no
// field for a code, and the handler reads nothing of the second factor —
// passwordChangeMock serves no two_factor query, so a read of one panics.
// Documented behaviour: a session that knows the password can rotate it.
func TestChangePassword_AsksForNoSecondFactor(t *testing.T) {
	fields := (&pb.ChangePasswordReq{}).ProtoReflect().Descriptor().Fields()
	var names []string
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	if strings.Join(names, ",") != "current_password,new_password" {
		t.Errorf("ChangePasswordReq fields = %v, want current_password and new_password only", names)
	}

	h, _ := newPasswordChangeHandler(t, "correct-horse-battery-staple")
	h.TwoFactorTOTP = true
	if _, err := h.ChangePassword(ctxWithEnvelope(t, "u1", "11111111-1111-4111-8111-111111111111"), &pb.ChangePasswordReq{
		CurrentPassword: "correct-horse-battery-staple",
		NewPassword:     "a-different-long-password",
	}); err != nil {
		t.Fatalf("ChangePassword with the current password alone: %v", err)
	}
}
