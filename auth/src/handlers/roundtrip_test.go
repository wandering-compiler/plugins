package handlers

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/auth/gen/pb"
)

// --- register, then sign in ------------------------------------------------
//
// The most basic loop this plugin has, and nothing covered it. There are tests
// for SignUp's roles, SignUp's invite gate, SignIn's timing, SignIn's gates —
// and not one that registers an account and then logs into it with the
// password it registered with.
//
// That gap is why a colleague being onboarded could not be told, from here,
// whether the login was broken or their password was wrong: nothing in the
// suite asserted the two halves agree (2026-09-23).
//
// The store is a map rather than a canned response on purpose. A mock that
// answers GetUserByEmail with a hash of its own choosing proves the two halves
// agree with the MOCK; only one that keeps what SignUp wrote and returns it
// unchanged can prove they agree with each other.

type roundTripStore struct {
	pb.AuthQueryClient
	pb.AuthMutationClient

	users map[string]*pb.User // email (as stored) -> row
	next  int
}

func newRoundTripStore() *roundTripStore {
	return &roundTripStore{users: map[string]*pb.User{}}
}

func (s *roundTripStore) CreateUser(_ context.Context, in *pb.CreateUserReq, _ ...grpc.CallOption) (*pb.CreateUserResp, error) {
	s.next++
	u := &pb.User{
		Id:           "u-" + string(rune('0'+s.next)),
		Email:        in.GetEmail(),
		PasswordHash: in.GetPasswordHash(),
	}
	s.users[in.GetEmail()] = u
	return &pb.CreateUserResp{User: u}, nil
}

// Keyed on the email EXACTLY as CreateUser stored it, which is what the
// unique index does. If the two halves normalise differently, the lookup
// misses and this is where it shows.
func (s *roundTripStore) GetUserByEmail(_ context.Context, in *pb.GetUserByEmailReq, _ ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	u, ok := s.users[in.GetEmail()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.GetUserByEmailResp{User: u}, nil
}

func (s *roundTripStore) IssueToken(_ context.Context, in *pb.IssueTokenReq, _ ...grpc.CallOption) (*pb.IssueTokenResp, error) {
	return &pb.IssueTokenResp{Token: &pb.UserToken{Id: "t-1", Token: "bearer", UserId: in.GetUserId()}}, nil
}
func (s *roundTripStore) AssignRoleToUser(context.Context, *pb.AssignRoleToUserReq, ...grpc.CallOption) (*pb.AssignRoleToUserResp, error) {
	return &pb.AssignRoleToUserResp{}, nil
}
func (s *roundTripStore) CountUsers(context.Context, *pb.CountUsersReq, ...grpc.CallOption) (*pb.CountUsersResp, error) {
	return &pb.CountUsersResp{Count: 1}, nil
}
func (s *roundTripStore) GetDefaultRoles(context.Context, *pb.GetDefaultRolesReq, ...grpc.CallOption) (*pb.GetDefaultRolesResp, error) {
	return &pb.GetDefaultRolesResp{}, nil
}

// pinConsoleActivation makes these tests describe the console's ACTIVATION
// rather than the test binary's accidental union of every feature.
//
// Every feature's file compiles into this binary, so every init() seam is
// installed — tenant_scope's create path, devices' resolver, two_factor's
// gate. A real activation stages only the files its features name. Without
// pinning, a sign-in here walks through `devices` (which the console does not
// enable) and panics on a store that has no reason to implement it, and the
// test says nothing about the deployment anybody actually runs.
//
// Console features, for the record: rbac, authenticate_turnkey,
// sign_in_turnkey, sign_up_turnkey, cli_login, org_membership, org_invite,
// password_change, api_token, user_admin, service_account. No devices, no
// two_factor, no tenant_scope, no sign_up_confirmation.
func pinConsoleActivation(t *testing.T) {
	t.Helper()
	origDevice := resolveSignInDevice
	resolveSignInDevice = func(context.Context, *AuthServiceHandler, string) (string, bool, error) {
		return "", true, nil
	}
	t.Cleanup(func() { resolveSignInDevice = origDevice })

	origMfa := signInMfaGate
	signInMfaGate = func(context.Context, *AuthServiceHandler, *pb.User, string, bool) (*pb.SignInResp, bool, error) {
		return nil, false, nil
	}
	t.Cleanup(func() { signInMfaGate = origMfa })

	// No sign_up_confirmation on the console: SignUp creates the account.
	origConfirm := signUpConfirmation
	signUpConfirmation = nil
	t.Cleanup(func() { signUpConfirmation = origConfirm })

	pinTenantlessSignup(t)
}

// pinTenantlessSignup fixes the create seam to the plain variant.
//
// Every feature's file is compiled into the test binary, so tenant_scope's
// init() has replaced the seam — an activation that does not enable it would
// never have that. Pinning is what makes these tests describe the console's
// activation (no tenant_scope) rather than the test binary's accidental union
// of all of them.
func pinTenantlessSignup(t *testing.T) {
	t.Helper()
	orig := signupCreateUser
	signupCreateUser = func(ctx context.Context, h *AuthServiceHandler, _ *pb.SignUpReq, email, passwordHash string) (string, error) {
		resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{Email: email, PasswordHash: passwordHash})
		if err != nil {
			return "", err
		}
		return resp.GetUser().GetId(), nil
	}
	t.Cleanup(func() { signupCreateUser = orig })
}

func TestSignUpThenSignIn_TheSamePasswordWorks(t *testing.T) {
	pinConsoleActivation(t)
	s := newRoundTripStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	const (
		email    = "jaroslav@example.com"
		password = "correct horse battery staple"
	)
	if _, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: email, Password: password}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := h.SignIn(context.Background(), &pb.SignInReq{Email: email, Password: password}); err != nil {
		t.Fatalf("an account could not sign in with the password it registered with: %v", err)
	}
}

// The email the two halves agree on. A registration that stores one spelling
// and a sign-in that looks up another is a login nobody can complete and a
// password nobody can debug — and the asymmetry is invisible in any test that
// uses the same literal on both sides.
func TestSignUpThenSignIn_EmailSpellingDoesNotSplitTheAccount(t *testing.T) {
	for _, tc := range []struct{ registered, typed string }{
		{"Jaroslav@Example.com", "jaroslav@example.com"},
		{"jaroslav@example.com", "  Jaroslav@EXAMPLE.com "},
		{" jaroslav@example.com ", "jaroslav@example.com"},
	} {
		pinConsoleActivation(t)
		s := newRoundTripStore()
		h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}
		const password = "correct horse battery staple"

		if _, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: tc.registered, Password: password}); err != nil {
			t.Fatalf("SignUp %q: %v", tc.registered, err)
		}
		if _, err := h.SignIn(context.Background(), &pb.SignInReq{Email: tc.typed, Password: password}); err != nil {
			t.Errorf("registered as %q, typed %q — refused: %v", tc.registered, tc.typed, err)
		}
	}
}

// And the control: a wrong password must still be refused. Without it the two
// tests above pass for a SignIn that accepts anything.
func TestSignUpThenSignIn_AWrongPasswordIsStillRefused(t *testing.T) {
	pinConsoleActivation(t)
	s := newRoundTripStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}

	if _, err := h.SignUp(context.Background(), &pb.SignUpReq{
		Email: "a@b.c", Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if _, err := h.SignIn(context.Background(), &pb.SignInReq{Email: "a@b.c", Password: "something else"}); err == nil {
		t.Error("a wrong password signed in")
	}
}

// --- a consumer: a bad token must not be distinguishable -------------------
//
// The consume statements carry RETURNING, so "no live row" arrives as an
// ERROR (NotFound), not as an empty response. All three handlers returned it
// raw, which told a caller apart "this token is unknown / used / expired" from
// every other outcome — the enumeration the opaque refusal exists to prevent.
// It also made the `userID == ""` branch below each of them unreachable: it
// was written for a shape the mutation never produces.
//
// Asserted on the WIRE CODE, because that is what a prober sees. And with an
// outage beside it: the same constructor must keep calling a dead store a
// dead store rather than dressing it as a bad token.

type consumeMock struct {
	pb.AuthQueryClient
	pb.AuthMutationClient
	err error
}

func (m consumeMock) ConsumePasswordResetToken(context.Context, *pb.ConsumePasswordResetTokenReq, ...grpc.CallOption) (*pb.ConsumePasswordResetTokenResp, error) {
	return nil, m.err
}
func (m consumeMock) ConsumeEmailVerificationToken(context.Context, *pb.ConsumeEmailVerificationTokenReq, ...grpc.CallOption) (*pb.ConsumeEmailVerificationTokenResp, error) {
	return nil, m.err
}
func (m consumeMock) ConsumeCliAuthCode(context.Context, *pb.ConsumeCliAuthCodeReq, ...grpc.CallOption) (*pb.ConsumeCliAuthCodeResp, error) {
	return nil, m.err
}

func TestConsumePaths_ABadTokenIsAlwaysTheSameOpaqueRefusal(t *testing.T) {
	notFound := status.Error(codes.NotFound, "no rows")
	for _, tc := range []struct {
		what string
		call func(*AuthServiceHandler) error
	}{
		{"password reset", func(h *AuthServiceHandler) error {
			_, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "t", NewPassword: "n3wPassw0rd!"})
			return err
		}},
		{"email verification", func(h *AuthServiceHandler) error {
			_, err := h.VerifyEmail(context.Background(), &pb.VerifyEmailReq{Token: "t"})
			return err
		}},
		{"cli code exchange", func(h *AuthServiceHandler) error {
			_, err := h.CliToken(context.Background(), &pb.CliTokenReq{
				Code: "c", CodeVerifier: strings.Repeat("a", 64),
			})
			return err
		}},
	} {
		h := &AuthServiceHandler{
			Query:        consumeMock{err: notFound},
			Mutation:     consumeMock{err: notFound},
			PasswordHash: testPasswordSettings(),
		}
		err := tc.call(h)
		if err == nil {
			t.Errorf("%s: an unknown token was accepted", tc.what)
			continue
		}
		if got := status.Code(err); got != codes.Unauthenticated {
			t.Errorf("%s: an unknown token came back as %v — a prober can tell it apart from a wrong one", tc.what, got)
		}
	}
}

// The other half of the same constructor: a store that is down is not a bad
// token, and saying so is what makes the opaque answer above trustworthy
// rather than a blanket.
func TestConsumePaths_AnOutageIsStillAnOutage(t *testing.T) {
	down := status.Error(codes.Unavailable, "store down")
	h := &AuthServiceHandler{
		Query:        consumeMock{err: down},
		Mutation:     consumeMock{err: down},
		PasswordHash: testPasswordSettings(),
	}
	_, err := h.ResetPassword(context.Background(), &pb.ResetPasswordReq{Token: "t", NewPassword: "n3wPassw0rd!"})
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("a dead store was reported as %v — the user is told their reset link is bad while the service is down", got)
	}
}

// The machine-account writes are pairs, and the pairing is the fix. Asserted
// on the source because that is where it can be undone: inlining the calls
// back into the handler compiles, passes every behavioural test, and silently
// restores the failure mode.
//
//   - IssueBotToken: a token minted and then narrowed leaves a LIVE token with
//     a partial subset on failure — or none, which the resolver reads as
//     all_permissions. The caller asked for a narrow credential, got an error,
//     and may have left a wider one behind.
//   - CreateBot: an account created without its membership is an orphan whose
//     address is now taken, so the operator's retry fails on a conflict with
//     an account they were told was never created.
func TestServiceAccount_TheWritesThatMustNotSeparate(t *testing.T) {
	src, err := os.ReadFile("service_account.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body := string(src)

	for _, tc := range []struct {
		fn    string
		seam  string
		apart []string
	}{
		{"IssueBotToken", "issueApiTokenTx(", []string{"h.Mutation.IssueApiToken(", "h.Mutation.AddTokenPermission("}},
		{"CreateBot", "createBotUserTx(", []string{"h.Mutation.CreateBotUser(", "h.Mutation.AddOrgMembership(", "h.Mutation.AssignRoleToUser("}},
	} {
		i := strings.Index(body, "func (h *AuthServiceHandler) "+tc.fn+"(")
		if i < 0 {
			t.Errorf("%s not found", tc.fn)
			continue
		}
		end := strings.Index(body[i:], "\n}\n")
		fn := body[i : i+end]

		if !strings.Contains(fn, tc.seam) {
			t.Errorf("%s no longer goes through %s — nothing holds its writes together", tc.fn, tc.seam)
		}
		if !strings.Contains(fn, "distx.Begin(") {
			t.Errorf("%s opens no transaction — the seam exists but nothing wraps it", tc.fn)
		}
		if !strings.Contains(fn, "tx.Rollback(") {
			t.Errorf("%s never rolls back — a failure keeps what it wrote", tc.fn)
		}
		for _, direct := range tc.apart {
			if strings.Contains(fn, direct) {
				t.Errorf("%s calls %s directly — its writes are separable again", tc.fn, direct)
			}
		}
	}
}

// The single-use token and the write it authorises are pairs too. Apart, a
// failure between them burns a valid link and leaves the state unchanged: the
// person is left with neither the reset nor the link they asked for, and they
// asked because they could not get in. Asserted on the source for the same
// reason as the machine-account pair — inlining compiles and passes.
func TestConsumePaths_TheTokenAndItsWriteDoNotSeparate(t *testing.T) {
	for _, tc := range []struct {
		file, fn, seam string
		apart          []string
	}{
		{"reset.go", "ResetPassword", "consumeAndSetPassword(",
			[]string{"h.Mutation.ConsumePasswordResetToken(", "h.Mutation.UpdateUserPassword("}},
		{"emailverify.go", "VerifyEmail", "consumeAndMarkVerified(",
			[]string{"h.Mutation.ConsumeEmailVerificationToken(", "h.Mutation.MarkEmailVerified("}},
	} {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		body := string(src)
		i := strings.Index(body, "func (h *AuthServiceHandler) "+tc.fn+"(")
		if i < 0 {
			t.Errorf("%s not found in %s", tc.fn, tc.file)
			continue
		}
		fn := body[i : i+strings.Index(body[i:], "\n}\n")]

		if !strings.Contains(fn, tc.seam) {
			t.Errorf("%s no longer goes through %s", tc.fn, tc.seam)
		}
		if !strings.Contains(fn, "distx.Begin(") || !strings.Contains(fn, "tx.Rollback(") {
			t.Errorf("%s does not consume the token inside a transaction it can roll back", tc.fn)
		}
		for _, direct := range tc.apart {
			if strings.Contains(fn, direct) {
				t.Errorf("%s calls %s directly — the token can be spent without the write landing", tc.fn, direct)
			}
		}
	}
}
