package handlers

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// ── a failed erasure, retried, without a transaction coordinator ───────────

// flakyEraser fails the two_factor eraser the first `failures` times.
type flakyEraser struct {
	*revocationStore
	failures int
}

func (f *flakyEraser) EraseTwoFactorData(ctx context.Context, in *pb.EraseTwoFactorDataReq, o ...grpc.CallOption) (*pb.EraseTwoFactorDataResp, error) {
	if f.failures > 0 {
		f.failures--
		return nil, status.Error(codes.Unavailable, "db down")
	}
	return f.revocationStore.EraseTwoFactorData(ctx, in, o...)
}

// Without DistTx every statement commits on its own. An eraser that fails must
// not leave the account marked erased with personal data still in place: the
// erasers run before EraseUser, so the account is not yet erased and the retry
// (the operator sees the error) does the whole erasure.
func TestEraseUsers_ARetryCompletesAFailedErasureWithoutATransaction(t *testing.T) {
	f := &flakyEraser{revocationStore: aliceStore(), failures: 1}
	h := &AuthServiceHandler{Query: f, Mutation: f} // no DistTx
	ctx := sessionCallerCtx("admin", "t-admin")
	if _, err := h.EraseUsers(ctx, &pb.EraseUsersReq{Ids: []string{"u1"}}); err == nil {
		t.Fatal("a failed eraser was reported as an erasure")
	}
	if f.users["u1"].erasedAt != nil {
		t.Fatal("the account was marked erased although an eraser failed — a retry would skip the rest")
	}
	f.erased = nil
	if _, err := h.EraseUsers(ctx, &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if f.users["u1"].erasedAt == nil || !containsPrefix(f.erased, "two_factor:u1") || !containsPrefix(f.erased, "oauth:u1") {
		t.Errorf("the retry did not complete the erasure: erased_at %v, erasers %v", f.users["u1"].erasedAt, f.erased)
	}
}

// An account already erased (by an attempt whose erasers did not all finish)
// still has every eraser run; only EraseUser is skipped.
func TestEraseUsers_AnErasedAccountStillGetsEveryEraser(t *testing.T) {
	s := aliceStore()
	s.users["u1"].erasedAt = timestamppb.Now()
	s.users["u1"].email = erasedAddress("u1")
	counted := &countingErase{revocationStore: s}
	h := &AuthServiceHandler{Query: counted, Mutation: counted}
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if counted.eraseUserCalls != 0 {
		t.Errorf("EraseUser ran %d time(s) for an account already erased", counted.eraseUserCalls)
	}
	for _, want := range []string{"two_factor:u1", "oauth:u1", "email_verification:u1", "password_reset:u1"} {
		if !containsPrefix(s.erased, want) {
			t.Errorf("eraser %s did not run for an erased account: %v", want, s.erased)
		}
	}
	// The invitation and pending-registration erasers have no old address
	// left: they must not re-address the placeholder to itself (or anything
	// else).
	for _, e := range s.erased {
		if strings.HasPrefix(e, "org_invite:") || strings.HasPrefix(e, "sign_up_confirmation:") {
			t.Errorf("an address eraser ran with the placeholder: %s", e)
		}
	}
}

func containsPrefix(list []string, prefix string) bool {
	for _, s := range list {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// ── the invitation eraser normalises the address ───────────────────────────

// Invitations store the address normalised; an account's may not be (an admin
// edit writes it as given). The eraser compares the normalised form.
func TestEraseUsers_TheInvitationEraserNormalisesTheAddress(t *testing.T) {
	s := aliceStore()
	s.users["u1"].email = "  Alice@Example.COM "
	h := eraseHandler(s)
	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("erase: %v", err)
	}
	want := "org_invite:alice@example.com"
	if !containsPrefix(s.erased, want) {
		t.Errorf("invitation eraser ran %v, want %s", s.erased, want)
	}
}

// ── the erased-account domain is refused everywhere an address is set ──────

func assertReservedRefused(t *testing.T, path string, err error) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("%s with an erased.invalid address: %v, want InvalidArgument", path, err)
		return
	}
	if d := detailOf(t, err); d.GetCode() != CodeEmailInvalid || d.GetField() != "email" || d.GetMessage() != MsgEmailInvalid {
		t.Errorf("%s: detail %v, want %s on email", path, d, CodeEmailInvalid)
	}
}

// Every address in erasedEmailDomain is refused, in any case and spacing;
// every other address passes.
func TestRefuseReservedEmail(t *testing.T) {
	for email, refused := range map[string]bool{
		"erased-u1@erased.invalid":   true,
		" Erased-U1@ERASED.invalid ": true,
		"anyone@erased.invalid":      true,
		"alice@example.com":          false,
		"alice@not-erased.invalid":   false,
		"erased.invalid@example.com": false,
	} {
		if got := refuseReservedEmail(context.Background(), email) != nil; got != refused {
			t.Errorf("refuseReservedEmail(%q) refused = %v, want %v", email, got, refused)
		}
	}
}

// Plain SignUp: refused before any write.
func TestSignUp_RefusesTheErasedDomain(t *testing.T) {
	pinConsoleActivation(t)
	s := newConfirmStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
	_, err := h.SignUp(mintCtx(), &pb.SignUpReq{Email: "erased-u1@erased.invalid", Password: "pw"})
	assertReservedRefused(t, "SignUp", err)
	if len(s.users) != 0 {
		t.Errorf("a refused sign-up created %v", s.users)
	}
}

// Under sign_up_confirmation SignUp refuses before parking; a registration
// parked before that refusal existed is refused at confirmation.
func TestConfirmSignUp_RefusesTheErasedDomain(t *testing.T) {
	h, s := confirmHandler(t)
	_, err := h.SignUp(withJKT(context.Background(), testJKT), &pb.SignUpReq{Email: "erased-u1@erased.invalid", Password: "pw"})
	assertReservedRefused(t, "SignUp (confirmation)", err)
	if len(s.pending) != 0 {
		t.Errorf("a refused registration was parked: %v", s.pending)
	}

	codeHash, err := testPasswordSettings().Hash("ABCD2345")
	if err != nil {
		t.Fatal(err)
	}
	s.pending["p-old"] = &pendingRow{email: "erased-u1@erased.invalid", passwordHash: codeHash, codeHash: codeHash, expiresAt: time.Now().Add(time.Hour)}
	_, err = h.ConfirmSignUp(withJKT(context.Background(), testJKT), &pb.ConfirmSignUpReq{PendingId: "p-old", Code: "ABCD2345"})
	assertReservedRefused(t, "ConfirmSignUp", err)
	if len(s.users) != 0 {
		t.Errorf("a refused confirmation created %v", s.users)
	}
}

// An OAuth provider may assert any address: the account creation refuses the
// erased domain before any gate or write.
func TestOAuthAccountCreation_RefusesTheErasedDomain(t *testing.T) {
	h := &AuthServiceHandler{} // no store: a call into one would panic
	_, err := h.createOAuthAccount(context.Background(), "p1", "sub-1", "Erased-U1@Erased.Invalid", true, "", "")
	assertReservedRefused(t, "OAuth account creation", err)
}

// The admin's update goes through UpdateAccount, which refuses it; any other
// address reaches UpdateUser.
func TestUpdateAccount_RefusesTheErasedDomain(t *testing.T) {
	m := &updateUserRecorder{current: "u2@example.com"}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	ctx := sessionCallerCtx("admin", "t-admin")
	_, err := h.UpdateAccount(ctx, &pb.UpdateAccountReq{UserId: "u2", Email: "erased-u1@erased.invalid"})
	assertReservedRefused(t, "UpdateAccount", err)
	if m.req != nil {
		t.Errorf("a refused update reached UpdateUser: %v", m.req)
	}
	resp, err := h.UpdateAccount(ctx, &pb.UpdateAccountReq{UserId: "u2", Email: "bob@example.com"})
	if err != nil || m.req.GetEmail() != "bob@example.com" || resp.GetEmail() != "bob@example.com" {
		t.Errorf("an ordinary update: %v, %v, reached %v", resp, err, m.req)
	}
}

// SignIn looks an address up lower-cased; an address stored as typed in the
// admin could never sign in, and would sit beside its lower-case twin past the
// case-sensitive unique index.
func TestUpdateAccount_NormalizesTheAddress(t *testing.T) {
	m := &updateUserRecorder{current: "u2@example.com"}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	if _, err := h.UpdateAccount(sessionCallerCtx("admin", "t-admin"), &pb.UpdateAccountReq{UserId: "u2", Email: "  Bob@Example.COM "}); err != nil {
		t.Fatal(err)
	}
	if got := m.req.GetEmail(); got != "bob@example.com" {
		t.Errorf("UpdateUser got %q, want bob@example.com", got)
	}
}

// An address change spends the links mailed to the old address, in the
// change's transaction: a verification link would verify the new address, a
// reset link would let the old mailbox set the password.
func TestUpdateAccount_SpendsTheOldAddressLinks(t *testing.T) {
	m := &updateUserRecorder{current: "old@example.com"}
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: m, Mutation: m, DistTx: tx}
	if _, err := h.UpdateAccount(sessionCallerCtx("admin", "t-admin"), &pb.UpdateAccountReq{UserId: "u2", Email: "new@example.com"}); err != nil {
		t.Fatal(err)
	}
	if m.resetSpent != "u2" || m.verifySpent != "u2" {
		t.Errorf("links spent: reset %q, verification %q, want both u2", m.resetSpent, m.verifySpent)
	}
	if got := tx.settled(); got != "committed" {
		t.Errorf("the change was %s, want committed", got)
	}
}

// A spend that fails rolls the address change back with it.
func TestUpdateAccount_AFailedSpendRollsTheChangeBack(t *testing.T) {
	m := &updateUserRecorder{current: "old@example.com", spendErr: status.Error(codes.Unavailable, "db down")}
	tx := &recordingDistTx{}
	h := &AuthServiceHandler{Query: m, Mutation: m, DistTx: tx}
	if _, err := h.UpdateAccount(sessionCallerCtx("admin", "t-admin"), &pb.UpdateAccountReq{UserId: "u2", Email: "new@example.com"}); err == nil {
		t.Fatal("a failed spend was reported as a change")
	}
	if got := tx.settled(); got != "rolled back" {
		t.Errorf("the change was %s, want rolled back", got)
	}
}

// Saving the address the account has (as typed, in another case) writes
// nothing, so the address keeps its verification and proof.
func TestUpdateAccount_TheSameAddressWritesNothing(t *testing.T) {
	m := &updateUserRecorder{current: "bob@example.com"}
	h := &AuthServiceHandler{Query: m, Mutation: m}
	resp, err := h.UpdateAccount(sessionCallerCtx("admin", "t-admin"), &pb.UpdateAccountReq{UserId: "u2", Email: "Bob@Example.com"})
	if err != nil || resp.GetEmail() != "bob@example.com" {
		t.Fatalf("UpdateAccount: %v, %v", resp, err)
	}
	if m.req != nil || m.resetSpent != "" || m.verifySpent != "" {
		t.Errorf("an unchanged address wrote: update %v, reset %q, verification %q", m.req, m.resetSpent, m.verifySpent)
	}
}

type updateUserRecorder struct {
	pb.AuthMutationClient
	pb.AuthQueryClient
	current     string
	req         *pb.UpdateUserReq
	resetSpent  string
	verifySpent string
	spendErr    error
}

func (u *updateUserRecorder) GetUserById(_ context.Context, in *pb.GetUserByIdReq, _ ...grpc.CallOption) (*pb.GetUserByIdResp, error) {
	return &pb.GetUserByIdResp{User: &pb.User{Id: in.GetUserId(), Email: u.current}}, nil
}

func (u *updateUserRecorder) UpdateUser(_ context.Context, in *pb.UpdateUserReq, _ ...grpc.CallOption) (*pb.UpdateUserResp, error) {
	u.req = in
	return &pb.UpdateUserResp{UserId: in.GetUserId(), Email: in.GetEmail()}, nil
}

func (u *updateUserRecorder) SpendPasswordResetTokens(_ context.Context, in *pb.SpendPasswordResetTokensReq, _ ...grpc.CallOption) (*pb.SpendPasswordResetTokensResp, error) {
	u.resetSpent = in.GetUserId()
	return &pb.SpendPasswordResetTokensResp{}, u.spendErr
}

func (u *updateUserRecorder) SpendEmailVerificationTokens(_ context.Context, in *pb.SpendEmailVerificationTokensReq, _ ...grpc.CallOption) (*pb.SpendEmailVerificationTokensResp, error) {
	u.verifySpent = in.GetUserId()
	return &pb.SpendEmailVerificationTokensResp{}, u.spendErr
}

// A machine account's address is the operator's input too.
func TestCreateBot_RefusesTheErasedDomain(t *testing.T) {
	h := &AuthServiceHandler{} // refused before any store call
	_, err := h.CreateBot(sessionCallerCtx("admin", "t-admin"), &pb.CreateBotReq{Email: "erased-u1@erased.invalid", RoleId: "r1"})
	assertReservedRefused(t, "CreateBot", err)
}

// ── registering a revoked client pair ──────────────────────────────────────

type registerCollision struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	clients []*pb.AuthClient
}

func (r *registerCollision) RegisterAuthClient(context.Context, *pb.RegisterAuthClientReq, ...grpc.CallOption) (*pb.RegisterAuthClientResp, error) {
	return nil, status.Error(codes.AlreadyExists, "duplicate key")
}

// GetAuthClientRevocation answers by the unique pair, as the query does.
func (r *registerCollision) GetAuthClientRevocation(_ context.Context, in *pb.GetAuthClientRevocationReq, _ ...grpc.CallOption) (*pb.GetAuthClientRevocationResp, error) {
	for _, c := range r.clients {
		if c.GetClientId() == in.GetClientId() && c.GetRedirectUri() == in.GetRedirectUri() {
			return &pb.GetAuthClientRevocationResp{Id: c.GetId(), RevokedAt: c.GetRevokedAt()}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

// The unique (client_id, redirect_uri) index is full, so a revoked pair stays
// taken. Registering it again is a clear refusal naming the remedy — not a
// revival, not the generic AlreadyExists. A live duplicate keeps the
// AlreadyExists it always had.
func TestRegisterClient_ARevokedPairIsRefusedClearly(t *testing.T) {
	const redirect = "https://app.example.com/cb"
	r := &registerCollision{clients: []*pb.AuthClient{{ClientId: "app", RedirectUri: redirect, RevokedAt: timestamppb.Now()}}}
	h := &AuthServiceHandler{Query: r, Mutation: r, PasswordHash: testPasswordSettings()}
	ctx := sessionCallerCtx("admin", "t-admin")
	_, err := h.RegisterClient(ctx, &pb.RegisterClientReq{ClientId: "app", RedirectUri: redirect})
	if status.Code(err) != codes.FailedPrecondition || detailOf(t, err).GetCode() != CodeClientRevoked {
		t.Fatalf("registering a revoked pair: %v, want FailedPrecondition / %s", err, CodeClientRevoked)
	}
	r.clients[0].RevokedAt = nil
	_, err = h.RegisterClient(ctx, &pb.RegisterClientReq{ClientId: "app", RedirectUri: redirect})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("registering a live pair again: %v, want AlreadyExists", err)
	}
}

// ── the probe decides that a token ended, not the app clock ────────────────

// The miss-path probe found the row expired by the database's NOW(). An app
// clock behind the database must not turn that into the plain refusal: the
// token is SESSION_EXPIRED all the same.
func TestAuthenticate_AnExpiredTokenSaysSoWhateverTheAppClock(t *testing.T) {
	ahead := timestamppb.New(time.Now().Add(2 * time.Minute)) // the app clock lags
	q := &expiryLookupQuery{expiredAt: ahead, kind: pb.TokenType_TOKEN_TYPE_SESSION}
	_, err := bareAuthenticate(t, &AuthServiceHandler{Query: q, Mutation: &touchRecorder{}}, "skewed-tok")
	if d := detailOf(t, err); d.GetCode() != CodeSessionExpired {
		t.Fatalf("an expired token under clock skew answered %v (detail %v), want %s", err, d, CodeSessionExpired)
	}
}

// When it ended, from the probe's two instants alone.
func TestEndedAt(t *testing.T) {
	t1 := timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := timestamppb.New(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	for name, tc := range map[string]struct {
		tok  endedToken
		want *timestamppb.Timestamp
	}{
		"expired, not revoked":           {endedToken{expiresAt: t2}, t2},
		"revoked, never expires":         {endedToken{revokedAt: t1}, t1},
		"revoked before it expired":      {endedToken{expiresAt: t2, revokedAt: t1}, t1},
		"revoked after it had expired":   {endedToken{expiresAt: t1, revokedAt: t2}, t1},
		"neither (the probe never says)": {endedToken{}, nil},
	} {
		if got := tc.tok.endedAt(); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: endedAt = %v, want %v", name, got, tc.want)
		}
	}
}

// ── an erasure stopped part-way leaves no usable account ───────────────────

// Access ends FIRST. An erasure that fails after it — and that nobody
// retries — leaves the account disabled, its password unusable and every
// token and device revoked, its address still in place for the retry. It
// used to run the erasers first: a failure then left a usable account (a
// password sign-in, live sessions) with its authenticator already wiped.
func TestEraseUsers_APartialErasureLeavesNoUsableAccount(t *testing.T) {
	f := &flakyEraser{revocationStore: aliceStore(), failures: 1}
	hash, err := testPasswordSettings().Hash("alice-password")
	if err != nil {
		t.Fatal(err)
	}
	f.users["u1"].hash = hash
	h := &AuthServiceHandler{Query: f, Mutation: f, PasswordHash: testPasswordSettings()} // no DistTx
	prev := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) {}
	t.Cleanup(func() { signInDummyVerify = prev })

	if _, err := h.EraseUsers(sessionCallerCtx("admin", "t-admin"), &pb.EraseUsersReq{Ids: []string{"u1"}}); err == nil {
		t.Fatal("a failed eraser was reported as an erasure")
	}
	u := f.users["u1"]
	if u.disabledAt == nil || u.hash != "!" || u.erasedAt != nil || u.email != "alice@example.com" {
		t.Errorf("after a partial erasure the account is %+v, want disabled, password unusable, not yet erased, address kept", u)
	}
	for _, id := range []string{"t-session", "t-other", "t-api"} {
		assertRevoked(t, f.revocationStore, id, "admin", pb.RevokeReason_REVOKE_REASON_USER_ERASED)
	}
	for _, d := range f.devices {
		if d.revokedAt == nil {
			t.Errorf("device %s is live after a partial erasure", d.id)
		}
	}
	if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "alice@example.com", Password: "alice-password"}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("a password sign-in after a partial erasure: %v, want refused", err)
	}
	if _, err := refuseUnsignableAccount(context.Background(), h, "u1"); status.Code(err) != codes.Unauthenticated {
		t.Errorf("the account gates passed a partially erased account: %v", err)
	}
}

// ── rotating a registered client's secret ──────────────────────────────────

type secretRegistry struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	rows map[string]*clientRow
	hash map[string]string // id -> stored secret hash
}

// RotateAuthClientSecret: id AND revoked_at IS NULL.
func (r *secretRegistry) RotateAuthClientSecret(_ context.Context, in *pb.RotateAuthClientSecretReq, _ ...grpc.CallOption) (*pb.RotateAuthClientSecretResp, error) {
	c := r.rows[in.GetId()]
	if c == nil || c.revokedAt != nil {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.hash[c.id] = in.GetClientSecret()
	return &pb.RotateAuthClientSecretResp{Id: c.id}, nil
}

// A client that lost its secret keeps its client_id: the live registration
// gets a new secret, returned once, stored only hashed, and the old one stops
// verifying. A revoked registration is refused and keeps what it had; an API
// token cannot rotate (the secret is a credential).
func TestRotateClientSecret_KeepsTheClientIDAndRefusesARevokedOne(t *testing.T) {
	ps := testPasswordSettings()
	old, err := ps.Hash("old-secret")
	if err != nil {
		t.Fatal(err)
	}
	r := &secretRegistry{
		rows: map[string]*clientRow{
			"c1": {id: "c1", clientID: "app", redirect: "https://app.example.com/cb", enabled: true},
			"c2": {id: "c2", clientID: "app", redirect: "https://old.example.com/cb", revokedAt: timestamppb.Now()},
		},
		hash: map[string]string{"c1": old, "c2": old},
	}
	h := &AuthServiceHandler{Query: r, Mutation: r, PasswordHash: ps}
	ctx := sessionCallerCtx("admin", "t-admin")

	resp, err := h.RotateClientSecret(ctx, &pb.RotateClientSecretReq{Id: "c1"})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if resp.GetClientSecret() == "" || r.hash["c1"] == resp.GetClientSecret() {
		t.Fatalf("the new secret is missing or stored in the clear: %q / %q", resp.GetClientSecret(), r.hash["c1"])
	}
	if ok, _, _ := ps.VerifyAndRotate(r.hash["c1"], resp.GetClientSecret(), nil); !ok {
		t.Error("the stored hash does not verify the secret handed out")
	}
	if ok, _, _ := ps.VerifyAndRotate(r.hash["c1"], "old-secret", nil); ok {
		t.Error("the old secret still verifies after a rotation")
	}

	if _, err := h.RotateClientSecret(ctx, &pb.RotateClientSecretReq{Id: "c2"}); status.Code(err) != codes.NotFound {
		t.Errorf("rotating a revoked registration: %v, want NotFound", err)
	}
	if r.hash["c2"] != old {
		t.Error("a revoked registration's secret was replaced")
	}
	if _, err := h.RotateClientSecret(sessionCallerCtx("admin", ""), &pb.RotateClientSecretReq{Id: "c1"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an API-token caller rotated a client secret: %v", err)
	}
}
