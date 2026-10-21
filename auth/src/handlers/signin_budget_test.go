package handlers

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// budgetStore is a SignIn store that keeps the guess budget the way the
// statements do: a count and a window start per account and per live
// signed-in device, a window older than the cutoff starting over at 1.
type budgetStore struct {
	*signInStore
	mu      sync.Mutex
	account map[string]*budgetRow // by user id
	device  map[string]*budgetRow // by devKey
	resets  int
}

type budgetRow struct {
	n     int64
	since time.Time
}

func (*budgetStore) keepsSignInBudget() {}

func newBudgetStore(t *testing.T, users ...string) (*budgetStore, *AuthServiceHandler) {
	t.Helper()
	m, h := newSignInStore(t, users...)
	b := &budgetStore{signInStore: m, account: map[string]*budgetRow{}, device: map[string]*budgetRow{}}
	h.Mutation = b
	return b, h
}

func count(rows map[string]*budgetRow, key string, now, cutoff time.Time) int64 {
	r := rows[key]
	if r == nil {
		r = &budgetRow{}
		rows[key] = r
	}
	if r.since.IsZero() || r.since.Before(cutoff) {
		r.n, r.since = 1, now
	} else {
		r.n++
	}
	return r.n
}

func (b *budgetStore) CountSignInAttempt(_ context.Context, in *pb.CountSignInAttemptReq, _ ...grpc.CallOption) (*pb.CountSignInAttemptResp, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return &pb.CountSignInAttemptResp{Attempts: count(b.account, in.GetUserId(), in.GetNow().AsTime(), in.GetCutoff().AsTime())}, nil
}

func (b *budgetStore) CountDeviceSignInAttempt(_ context.Context, in *pb.CountDeviceSignInAttemptReq, _ ...grpc.CallOption) (*pb.CountDeviceSignInAttemptResp, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := devKey(in.GetUserId(), in.GetThumbprint())
	d := b.rows[key]
	if d == nil || d.GetRevokedAt() != nil || d.GetApiKey() {
		return nil, status.Error(codes.NotFound, "no rows")
	}
	return &pb.CountDeviceSignInAttemptResp{Attempts: count(b.device, key, in.GetNow().AsTime(), in.GetCutoff().AsTime())}, nil
}

func (b *budgetStore) ResetSignInAttempts(_ context.Context, in *pb.ResetSignInAttemptsReq, _ ...grpc.CallOption) (*pb.ResetSignInAttemptsResp, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.resets++
	delete(b.account, in.GetUserId())
	delete(b.device, devKey(in.GetUserId(), in.GetThumbprint()))
	return &pb.ResetSignInAttemptsResp{}, nil
}

func signIn(h *AuthServiceHandler, jkt, password string) error {
	_, err := h.SignIn(withJKT(context.Background(), jkt), &pb.SignInReq{Email: "u1@example.com", Password: password})
	return err
}

// wantThrottled asserts err is the budget's refusal, answered exactly as a
// wrong password is.
func wantThrottled(t *testing.T, err error, what string) {
	t.Helper()
	if !errors.Is(err, errSignInThrottled) {
		t.Fatalf("%s: %v, want the budget's refusal", what, err)
	}
	if status.Code(err) != codes.Unauthenticated || detailOf(t, err).GetCode() != CodeInvalidCredentials {
		t.Fatalf("%s: %v, want the wrong-password refusal (%s)", what, err, CodeInvalidCredentials)
	}
}

// sign-in/failure-budget: once the account's budget is spent, a key that
// never signed in to it is refused, the right password included — and as a
// wrong password is, with the throwaway verify.
func TestSignIn_BudgetSpent_AnUnknownDeviceIsRefused(t *testing.T) {
	noSecondFactor(t)
	_, h := newBudgetStore(t, "u1")
	h.SignInFailureBudget = 3
	for i := range 3 {
		if err := signIn(h, otherJKT, "wrong-password"); errors.Is(err, errSignInThrottled) || err == nil {
			t.Fatalf("attempt %d: %v, want a wrong password", i+1, err)
		}
	}
	dummy := false
	orig := signInDummyVerify
	signInDummyVerify = func(*AuthServiceHandler, string) { dummy = true }
	t.Cleanup(func() { signInDummyVerify = orig })

	wantThrottled(t, signIn(h, otherJKT, devicePassword), "the right password over the budget")
	if !dummy {
		t.Error("a refusal by the budget must run the throwaway verify, as an unknown address does")
	}
}

// sign-in/failure-budget: the account is not locked — a device that signed
// in to it before still signs in, and that resets the budget.
func TestSignIn_BudgetSpent_AKnownDeviceStillSignsIn(t *testing.T) {
	noSecondFactor(t)
	m, h := newBudgetStore(t, "u1")
	h.SignInFailureBudget = 3
	m.put("u1", testJKT, &pb.Device{})
	for range 5 {
		_ = signIn(h, otherJKT, "wrong-password")
	}
	if err := signIn(h, testJKT, devicePassword); err != nil {
		t.Fatalf("the owner's own device was refused: %v", err)
	}
	if m.account["u1"] != nil || m.resets != 1 {
		t.Fatalf("a correct password did not reset the budget: %+v, %d resets", m.account["u1"], m.resets)
	}
	if err := signIn(h, otherJKT, devicePassword); err != nil {
		t.Fatalf("after the reset a new device is refused: %v", err)
	}
}

// sign-in/failure-budget: a known device has a budget of its own while the
// account's is spent, so a stolen device key is no unlimited oracle.
func TestSignIn_BudgetSpent_AKnownDeviceHasItsOwnBudget(t *testing.T) {
	noSecondFactor(t)
	m, h := newBudgetStore(t, "u1")
	h.SignInFailureBudget, h.SignInDeviceFailureBudget = 2, 2
	m.put("u1", testJKT, &pb.Device{})
	for range 2 {
		_ = signIn(h, otherJKT, "wrong-password")
	}
	for i := range 2 {
		if err := signIn(h, testJKT, "wrong-password"); errors.Is(err, errSignInThrottled) {
			t.Fatalf("device attempt %d refused by the budget: %v", i+1, err)
		}
	}
	wantThrottled(t, signIn(h, testJKT, devicePassword), "the device's budget spent")

	// A revoked device or a program's key is no known device.
	m.put("u1", testJKT, &pb.Device{RevokedAt: timestamppb.Now()})
	wantThrottled(t, signIn(h, testJKT, devicePassword), "a revoked device")
}

// sign-in/failure-budget: the budget is a window — an old one starts over.
func TestSignIn_BudgetWindowStartsOver(t *testing.T) {
	noSecondFactor(t)
	m, h := newBudgetStore(t, "u1")
	h.SignInFailureBudget = 1
	m.account["u1"] = &budgetRow{n: 50, since: time.Now().Add(-time.Hour)}
	if err := signIn(h, otherJKT, devicePassword); err != nil {
		t.Fatalf("an hour-old window still refused: %v", err)
	}
}

// sign-in/failure-budget: an attempt the store could not count is refused
// (as the outage it is), before its password is checked.
func TestSignIn_UncountedAttemptIsRefused(t *testing.T) {
	noSecondFactor(t)
	m, h := newBudgetStore(t, "u1")
	h.Mutation = failingBudget{m}
	if err := signIn(h, testJKT, devicePassword); err == nil {
		t.Fatal("an uncounted attempt was granted")
	}
	if len(m.issued) != 0 || len(m.registered) != 0 {
		t.Fatalf("an uncounted attempt got past the password: %+v issued, %+v registered", m.issued, m.registered)
	}
}

type failingBudget struct{ *budgetStore }

func (failingBudget) CountSignInAttempt(context.Context, *pb.CountSignInAttemptReq, ...grpc.CallOption) (*pb.CountSignInAttemptResp, error) {
	return nil, status.Error(codes.Unavailable, "down")
}

// The history records the budget's refusal as THROTTLED.
func TestSignInOutcome_Throttled(t *testing.T) {
	if got := signInOutcome(UnauthenticatedSignIn(errSignInThrottled)); got != pb.SignInOutcome_SIGN_IN_OUTCOME_THROTTLED {
		t.Fatalf("outcome = %v, want THROTTLED", got)
	}
}
