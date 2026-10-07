package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// --- sign_up_confirmation ---------------------------------------------------
//
// The store keeps what the handler wrote and applies the same conditions the
// DQL does (expiry in the WHERE, DELETE … RETURNING as the claim, the UPSERT's
// window arithmetic), so a test proves the handler against those rules rather
// than against canned answers.

type pendingRow struct {
	email, passwordHash, codeHash string
	attempts                      int64
	expiresAt                     time.Time
}

type confirmStore struct {
	*roundTripStore
	pending   map[string]*pendingRow
	codes     map[string]string // pending id -> plaintext code, as the event carried it
	confirmed []string          // user ids markEmailConfirmed was called for
	nextID    int
}

func newConfirmStore() *confirmStore {
	return &confirmStore{
		roundTripStore: newRoundTripStore(),
		pending:        map[string]*pendingRow{},
		codes:          map[string]string{},
	}
}

func (s *confirmStore) PurgeExpiredPendingSignUps(_ context.Context, in *pb.PurgeExpiredPendingSignUpsReq, _ ...grpc.CallOption) (*pb.PurgeExpiredPendingSignUpsResp, error) {
	for id, r := range s.pending {
		if r.email == in.GetEmail() && !r.expiresAt.After(time.Now()) {
			delete(s.pending, id)
		}
	}
	return &pb.PurgeExpiredPendingSignUpsResp{}, nil
}

func (s *confirmStore) CreatePendingSignUp(_ context.Context, in *pb.CreatePendingSignUpReq, _ ...grpc.CallOption) (*pb.CreatePendingSignUpResp, error) {
	s.nextID++
	id := "p-" + string(rune('0'+s.nextID))
	s.pending[id] = &pendingRow{email: in.GetEmail(), passwordHash: in.GetPasswordHash(), codeHash: in.GetCodeHash(), expiresAt: in.GetExpiresAt().AsTime()}
	s.codes[id] = in.GetCode()
	return &pb.CreatePendingSignUpResp{Pending: &pb.PendingSignUp{Id: id, Email: in.GetEmail()}}, nil
}

func (s *confirmStore) live(id string) (*pendingRow, bool) {
	r, ok := s.pending[id]
	return r, ok && r.expiresAt.After(time.Now())
}

func (s *confirmStore) RecordPendingSignUpAttempt(_ context.Context, in *pb.RecordPendingSignUpAttemptReq, _ ...grpc.CallOption) (*pb.RecordPendingSignUpAttemptResp, error) {
	r, ok := s.live(in.GetPendingId())
	if !ok {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	r.attempts++
	return &pb.RecordPendingSignUpAttemptResp{Attempts: r.attempts, CodeHash: r.codeHash, Email: r.email}, nil
}

func (s *confirmStore) ClaimPendingSignUp(_ context.Context, in *pb.ClaimPendingSignUpReq, _ ...grpc.CallOption) (*pb.ClaimPendingSignUpResp, error) {
	r, ok := s.live(in.GetPendingId())
	if !ok {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	delete(s.pending, in.GetPendingId())
	return &pb.ClaimPendingSignUpResp{Email: r.email, PasswordHash: r.passwordHash}, nil
}

func (s *confirmStore) DeletePendingSignUpsForEmail(_ context.Context, in *pb.DeletePendingSignUpsForEmailReq, _ ...grpc.CallOption) (*pb.DeletePendingSignUpsForEmailResp, error) {
	for id, r := range s.pending {
		if r.email == in.GetEmail() {
			delete(s.pending, id)
		}
	}
	return &pb.DeletePendingSignUpsForEmailResp{}, nil
}

// CreateUser refuses a taken address the way a REAL store does: the unique
// index surfaces as InvalidArgument + ErrorDetail{UNIQUE_VIOLATION, email}
// (grpcerr C-3). It used to answer AlreadyExists, which no store sends — so
// the handlers' AlreadyExists branch passed here and never fired live.
func (s *confirmStore) CreateUser(ctx context.Context, in *pb.CreateUserReq, opts ...grpc.CallOption) (*pb.CreateUserResp, error) {
	if _, taken := s.users[in.GetEmail()]; taken {
		return nil, storeUniqueViolation("email")
	}
	return s.roundTripStore.CreateUser(ctx, in, opts...)
}

// pinConfirmationActivation is pinConsoleActivation with sign_up_confirmation
// on, and markEmailConfirmed recording into the store instead of needing the
// email_verification columns.
func pinConfirmationActivation(t *testing.T, s *confirmStore) {
	t.Helper()
	pinConsoleActivation(t)
	signUpConfirmation = startSignUpConfirmation
	origConfirmCreate, origStamp, origMark := confirmCreateUser, pendingSignUpTenant, markEmailConfirmed
	confirmCreateUser = func(ctx context.Context, h *AuthServiceHandler, claimed *pb.ClaimPendingSignUpResp) (string, error) {
		resp, err := h.Mutation.CreateUser(ctx, &pb.CreateUserReq{Email: claimed.GetEmail(), PasswordHash: claimed.GetPasswordHash()})
		if err != nil {
			return "", err
		}
		return resp.GetUser().GetId(), nil
	}
	pendingSignUpTenant = func(context.Context, *AuthServiceHandler, *pb.SignUpReq, *pb.CreatePendingSignUpReq) error {
		return nil
	}
	markEmailConfirmed = func(_ context.Context, _ *AuthServiceHandler, userID string) error {
		s.confirmed = append(s.confirmed, userID)
		return nil
	}
	t.Cleanup(func() {
		confirmCreateUser, pendingSignUpTenant, markEmailConfirmed = origConfirmCreate, origStamp, origMark
	})
}

func confirmHandler(t *testing.T) (*AuthServiceHandler, *confirmStore) {
	s := newConfirmStore()
	pinConfirmationActivation(t, s)
	return &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings()}, s
}

func TestSignUpConfirmation_SignUpParksAndConfirmCreates(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()

	resp, err := h.SignUp(ctx, &pb.SignUpReq{Email: "Ceo@Example.com", Password: "pw-owner"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	if !resp.GetConfirmationRequired() || resp.GetPendingId() == "" || resp.GetToken() != "" || resp.GetUserId() != "" {
		t.Fatalf("SignUp must park the registration and hand out no session, got %+v", resp)
	}
	if len(s.users) != 0 {
		t.Fatalf("SignUp created an account before the address was proved: %v", s.users)
	}
	code := s.codes[resp.GetPendingId()]
	if len(code) != signUpCodeLength || strings.Trim(code, signUpCodeAlphabet) != "" {
		t.Fatalf("the event carried %q, want %d characters of Crockford base32", code, signUpCodeLength)
	}
	if s.pending[resp.GetPendingId()].codeHash == code {
		t.Fatal("the code was stored in plaintext")
	}

	done, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: code})
	if err != nil {
		t.Fatalf("ConfirmSignUp: %v", err)
	}
	if done.GetUserId() == "" || done.GetToken() == "" {
		t.Fatalf("ConfirmSignUp must create the account and a session, got %+v", done)
	}
	if len(s.confirmed) != 1 || s.confirmed[0] != done.GetUserId() {
		t.Errorf("the confirmed address was not recorded as proved: %v", s.confirmed)
	}
	if _, err := h.SignIn(ctx, &pb.SignInReq{Email: "ceo@example.com", Password: "pw-owner"}); err != nil {
		t.Errorf("the confirmed account cannot sign in with its password: %v", err)
	}
}

// The case the feature exists for: a stranger who knows the address starts a
// registration and walks away. The owner registers anyway, confirms, and the
// account is theirs — with their password, not the stranger's.
func TestSignUpConfirmation_AnAbandonedRegistrationBlocksNobody(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()

	squat, err := h.SignUp(ctx, &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-stranger"})
	if err != nil {
		t.Fatalf("stranger's SignUp: %v", err)
	}
	own, err := h.SignUp(ctx, &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-owner"})
	if err != nil {
		t.Fatalf("the owner could not register an address somebody else had started: %v", err)
	}
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: own.GetPendingId(), Code: s.codes[own.GetPendingId()]}); err != nil {
		t.Fatalf("owner's ConfirmSignUp: %v", err)
	}
	if _, err := h.SignIn(ctx, &pb.SignInReq{Email: "ceo@example.com", Password: "pw-stranger"}); err == nil {
		t.Error("the stranger's password signs in to the owner's account")
	}
	if _, ok := s.pending[squat.GetPendingId()]; ok {
		t.Error("the stranger's registration survived the owner's confirmation")
	}
	// And it cannot be confirmed afterwards either — the code the stranger never
	// received is not the point; the row is gone.
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: squat.GetPendingId(), Code: s.codes[squat.GetPendingId()]}); err == nil {
		t.Error("a second account was created for a confirmed address")
	}
}

func TestSignUpConfirmation_WrongCodesAreRefusedAndExhaustTheRow(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	resp, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	for i := 0; i < maxSignUpConfirmAttempts; i++ {
		if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: "00000000"}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("wrong code %d: want InvalidArgument, got %v", i+1, err)
		}
	}
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]}); err == nil {
		t.Fatal("the right code was accepted after the attempt budget was spent")
	}
	if len(s.users) != 0 {
		t.Fatalf("an account was created: %v", s.users)
	}
}

func TestSignUpConfirmation_ACodeIsSingleUse(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	resp, _ := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	req := &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]}
	if _, err := h.ConfirmSignUp(ctx, req); err != nil {
		t.Fatalf("first ConfirmSignUp: %v", err)
	}
	if _, err := h.ConfirmSignUp(ctx, req); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a spent registration confirmed again: %v", err)
	}
}

func TestSignUpConfirmation_AnExpiredRegistrationIsRefused(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	resp, _ := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	s.pending[resp.GetPendingId()].expiresAt = time.Now().Add(-time.Second)
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an expired registration: want InvalidArgument, got %v", err)
	}
}

// SignUp must not tell a stranger which addresses have accounts: a taken
// address gets the same answer as a new one, and its code goes to the
// address. Only whoever confirms with that code — the owner — learns the
// account exists, and nothing is created.
func TestSignUpConfirmation_ATakenAddressIsNotRevealedBySignUp(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	s.users["a@example.com"] = &pb.User{Id: "u-x", Email: "a@example.com"}

	taken, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if err != nil {
		t.Fatalf("SignUp for a taken address answered %v — that tells a stranger the address is registered", err)
	}
	fresh, err := h.SignUp(ctx, &pb.SignUpReq{Email: "b@example.com", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if taken.GetConfirmationRequired() != fresh.GetConfirmationRequired() || taken.GetToken() != "" || taken.GetPendingId() == "" {
		t.Fatalf("taken %+v vs new %+v — the answers must have the same shape", taken, fresh)
	}
	code, mailed := s.codes[taken.GetPendingId()]
	if !mailed {
		t.Fatal("no code went to the taken address — the owner would never hear of the attempt, and the answer's timing differs")
	}
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: taken.GetPendingId(), Code: code}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("confirming a taken address: want AlreadyExists (sign in instead), got %v", err)
	}
	if s.users["a@example.com"].GetId() != "u-x" {
		t.Fatal("the existing account was replaced")
	}
}

// There is no per-address cap: a cap is a lever anybody can pull to refuse the
// owner. However many registrations a stranger starts, the owner's still gets
// a code and still confirms.
func TestSignUpConfirmation_NoNumberOfStrangersRefusesTheOwner(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, err := h.SignUp(ctx, &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-stranger"}); err != nil {
			t.Fatalf("stranger's SignUp %d: %v", i+1, err)
		}
	}
	own, err := h.SignUp(ctx, &pb.SignUpReq{Email: "ceo@example.com", Password: "pw-owner"})
	if err != nil {
		t.Fatalf("the owner was refused after strangers registered the address: %v", err)
	}
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: own.GetPendingId(), Code: s.codes[own.GetPendingId()]}); err != nil {
		t.Fatalf("owner's ConfirmSignUp: %v", err)
	}
	if len(s.pending) != 0 {
		t.Errorf("%d strangers' registrations survived the owner's confirmation", len(s.pending))
	}
}

// A code read off a mail is typed however the person types it.
func TestSignUpConfirmation_TheCodeIsReadForgivingly(t *testing.T) {
	h, s := confirmHandler(t)
	ctx := context.Background()
	resp, _ := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	code := s.codes[resp.GetPendingId()]
	typed := strings.ToLower(code[:4]) + "-" + strings.ToLower(code[4:])
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: typed}); err != nil {
		t.Fatalf("%q typed as %q was refused: %v", code, typed, err)
	}
}

func TestNormalizeSignUpCode(t *testing.T) {
	for in, want := range map[string]string{
		"abcd-efgh":  "ABCDEFGH",
		" AB CD EF ": "ABCDEF",
		"O0IL":       "0011",
	} {
		if got := normalizeSignUpCode(in); got != want {
			t.Errorf("normalizeSignUpCode(%q) = %q, want %q", in, got, want)
		}
	}
	for i := 0; i < 200; i++ {
		c, err := generateSignUpCode()
		if err != nil {
			t.Fatal(err)
		}
		if normalizeSignUpCode(c) != c {
			t.Fatalf("a generated code %q does not survive normalisation", c)
		}
	}
}

// --- sign_up_allowlist -------------------------------------------------------

func TestParseSignUpAllowlist(t *testing.T) {
	got, err := parseSignUpAllowlist(" CEO@Example.com, @firma.cz\n@b.io ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Join(got, "|") != "ceo@example.com|@firma.cz|@b.io" {
		t.Errorf("parsed %q", got)
	}
	for _, bad := range []string{"example.com", "@", "@localhost", "a@b@c.cz", "ceo@"} {
		if _, err := parseSignUpAllowlist(bad); err == nil {
			t.Errorf("%q was accepted as an allowlist entry", bad)
		}
	}
	if err := ValidateConfig(&AuthServiceHandler{SignUpAllowlist: "example.com"}); err == nil {
		t.Error("a malformed allowlist did not fail the boot")
	}
}

func TestSignUpAllowlistGate(t *testing.T) {
	h := &AuthServiceHandler{SignUpAllowlist: "ceo@example.com, @firma.cz"}
	for email, want := range map[string]bool{
		"ceo@example.com":      true,
		"CEO@Example.com":      true,
		"cfo@example.com":      false,
		"jana@firma.cz":        true,
		"jana@sub.firma.cz":    false, // a domain entry is that domain, not its subdomains
		"jana@notfirma.cz":     false,
		"firma.cz@evil.com":    false,
		"ceo@example.com.evil": false,
	} {
		err := signUpAllowlistGate(h, email)
		if (err == nil) != want {
			t.Errorf("%s: allowed=%v, want %v", email, err == nil, want)
		}
	}
	if err := signUpAllowlistGate(&AuthServiceHandler{}, "anyone@anywhere.com"); err != nil {
		t.Errorf("an empty allowlist refused: %v", err)
	}
}

// SignUp refuses before writing or mailing anything, and ConfirmSignUp checks
// the list again: an address removed from it after its code was sent does not
// become an account.
func TestSignUpAllowlist_GatesBothSteps(t *testing.T) {
	h, s := confirmHandler(t)
	h.SignUpAllowlist = "@example.com"
	ctx := context.Background()

	if _, err := h.SignUp(ctx, &pb.SignUpReq{Email: "x@elsewhere.com", Password: "pw"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an address outside the list: want PermissionDenied, got %v", err)
	}
	if len(s.codes) != 0 {
		t.Fatal("a refused address still reached the store")
	}

	resp, err := h.SignUp(ctx, &pb.SignUpReq{Email: "a@example.com", Password: "pw"})
	if err != nil {
		t.Fatalf("SignUp inside the list: %v", err)
	}
	h.SignUpAllowlist = "@other.com"
	if _, err := h.ConfirmSignUp(ctx, &pb.ConfirmSignUpReq{PendingId: resp.GetPendingId(), Code: s.codes[resp.GetPendingId()]}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("confirming an address the list no longer names: want PermissionDenied, got %v", err)
	}
	if len(s.users) != 0 {
		t.Fatal("an account was created outside the list")
	}
}

// Without sign_up_confirmation the allowlist still gates the plain SignUp.
func TestSignUpAllowlist_GatesThePlainSignUp(t *testing.T) {
	pinConsoleActivation(t)
	s := newRoundTripStore()
	h := &AuthServiceHandler{Query: s, Mutation: s, PasswordHash: testPasswordSettings(), SignUpAllowlist: "@example.com"}
	if _, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: "x@elsewhere.com", Password: "pw"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	if _, err := h.SignUp(context.Background(), &pb.SignUpReq{Email: "a@example.com", Password: "pw"}); err != nil {
		t.Fatalf("an allowed address was refused: %v", err)
	}
}

// storeUniqueViolation is the error a generated store returns for a unique
// index: InvalidArgument with the structured detail, exactly as
// grpcerr.Wrap renders a Postgres 23505.
func storeUniqueViolation(field string) error {
	st, _ := status.New(codes.InvalidArgument, "unique violation").WithDetails(
		protoadapt.MessageV1Of(&w17pb.ErrorDetail{Field: field, Code: "UNIQUE_VIOLATION", Message: "already exists"}))
	return st.Err()
}
