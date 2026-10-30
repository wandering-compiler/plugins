package handlers

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
	"github.com/wandering-compiler/plugins/auth/lib/passwordhash"
)

// rehashStore is the sign-in store with the RehashUserPassword statement:
// compare-and-swap on the stored hash, as the DQL does.
type rehashStore struct {
	*signInStore
	calls   []*pb.RehashUserPasswordReq
	failErr error
}

func (s *rehashStore) RehashUserPassword(_ context.Context, in *pb.RehashUserPasswordReq, _ ...grpc.CallOption) (*pb.RehashUserPasswordResp, error) {
	s.calls = append(s.calls, in)
	if s.failErr != nil {
		return nil, s.failErr
	}
	for _, u := range s.users {
		if u.GetId() == in.GetUserId() && u.GetPasswordHash() == in.GetCurrentHash() {
			u.PasswordHash = in.GetPasswordHash()
			return &pb.RehashUserPasswordResp{UserId: u.GetId()}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "no rows")
}

// weakHash is devicePassword under a setting the current one outranks: a
// different algorithm (bcrypt where the default is argon2id) at a low cost.
func weakHash(t *testing.T) string {
	t.Helper()
	h, err := passwordhash.Settings{Algo: passwordhash.Bcrypt, Params: passwordhash.Params{BcryptCost: 4}}.Hash(devicePassword)
	if err != nil {
		t.Fatal(err)
	}
	if ok, needs := testPasswordSettings().Verify(h, devicePassword); !ok || !needs {
		t.Fatalf("the fixture is not a weak hash of the password: ok %v needsRehash %v", ok, needs)
	}
	return h
}

func newRehashStore(t *testing.T, stored string) (*rehashStore, *AuthServiceHandler) {
	t.Helper()
	m, h := newSignInStore(t, "u1")
	m.users["u1@example.com"].PasswordHash = stored
	s := &rehashStore{signInStore: m}
	h.Query, h.Mutation = s, s
	return s, h
}

// A sign-in with a hash weaker than the current settings stores the same
// password under them (base gap 2). Without it a project that raised its cost,
// or moved from bcrypt to argon2id, kept every existing account on the old
// hash for as long as the account lived.
func TestSignIn_RehashesAWeakHash(t *testing.T) {
	noSecondFactor(t)
	old := weakHash(t)
	s, h := newRehashStore(t, old)
	if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if len(s.calls) != 1 || s.calls[0].GetUserId() != "u1" || s.calls[0].GetCurrentHash() != old {
		t.Fatalf("rehash calls %v, want one for u1 guarded on the verified hash", s.calls)
	}
	now := s.users["u1@example.com"].GetPasswordHash()
	if now == old {
		t.Fatal("the weak hash is still stored")
	}
	if ok, needs := testPasswordSettings().Verify(now, devicePassword); !ok || needs {
		t.Fatalf("the stored hash after the sign-in: verifies %v, still weak %v", ok, needs)
	}
	// And the next sign-in has nothing left to do.
	if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatalf("second SignIn: %v", err)
	}
	if len(s.calls) != 1 {
		t.Errorf("a current hash was rehashed again: %d calls", len(s.calls))
	}
}

// A hash already under the current settings is left alone, and a wrong
// password rehashes nothing — the rehash happens only after a verified
// password, so it can neither be triggered nor timed by someone without it.
func TestSignIn_RehashesOnlyAWeakHashAfterTheRightPassword(t *testing.T) {
	noSecondFactor(t)
	s, h := newSignInStore(t, "u1")
	r := &rehashStore{signInStore: s}
	h.Query, h.Mutation = r, r
	if _, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("a current hash was rehashed: %v", r.calls)
	}

	w, hw := newRehashStore(t, weakHash(t))
	if _, err := hw.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: "not-the-password"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong password: %v", err)
	}
	if len(w.calls) != 0 {
		t.Errorf("a wrong password rehashed: %v", w.calls)
	}
}

// The rehash is best effort: a storage failure while writing it, or a hash
// changed since the read (a password change or reset racing the sign-in — the
// compare-and-swap matches no row), never fails a sign-in whose password was
// verified. And the racing change is never overwritten with the old password's
// rehash.
func TestSignIn_ARehashThatCannotBeWrittenStillSignsIn(t *testing.T) {
	noSecondFactor(t)
	s, h := newRehashStore(t, weakHash(t))
	s.failErr = status.Error(codes.Unavailable, "db down")
	if resp, err := h.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil || resp.GetToken() == "" {
		t.Fatalf("a failed rehash failed the sign-in: %v, %v", resp, err)
	}

	r, hr := newRehashStore(t, weakHash(t))
	// The read saw the weak hash; by the write, a change stored another.
	changed := "changed-meanwhile"
	hr.Query = racingRead{rehashStore: r, swapTo: changed}
	if resp, err := hr.SignIn(mintCtx(), &pb.SignInReq{Email: "u1@example.com", Password: devicePassword}); err != nil || resp.GetToken() == "" {
		t.Fatalf("a racing change failed the sign-in: %v, %v", resp, err)
	}
	if got := r.users["u1@example.com"].GetPasswordHash(); got != changed {
		t.Errorf("the racing change was overwritten: stored %q", got)
	}
}

// racingRead answers the sign-in's lookup with the stored row, then stores
// another hash, as a password change committing between the read and the
// rehash would.
type racingRead struct {
	*rehashStore
	swapTo string
}

func (q racingRead) GetUserByEmail(ctx context.Context, in *pb.GetUserByEmailReq, o ...grpc.CallOption) (*pb.GetUserByEmailResp, error) {
	resp, err := q.rehashStore.GetUserByEmail(ctx, in, o...)
	if err != nil {
		return nil, err
	}
	read := &pb.User{Id: resp.GetUser().GetId(), Email: resp.GetUser().GetEmail(), PasswordHash: resp.GetUser().GetPasswordHash()}
	q.users[in.GetEmail()].PasswordHash = q.swapTo
	return &pb.GetUserByEmailResp{User: read}, nil
}

// The statement is a compare-and-swap that touches the hash and nothing else:
// a rehash is not a password change, so it must not end device trust, revoke
// a session or stamp anything a change stamps.
func TestRehashUserPassword_IsAGuardedHashOnlyWrite(t *testing.T) {
	dql := methodDQL(t, readProto(t, filepath.Join("..", "..", "proto", "mutations", "auth_mutation.proto")), "rpc RehashUserPassword(")
	for _, want := range []string{"UPDATE @module.User SET", "password_hash = :password_hash", "WHERE id = :user_id AND password_hash = :current_hash"} {
		if !strings.Contains(dql, want) {
			t.Errorf("RehashUserPassword lacks %q:\n%s", want, dql)
		}
	}
	for _, never := range []string{"device_trust_revoked_at", "UserToken", "revoked_at", "email_verified_at"} {
		if strings.Contains(dql, never) {
			t.Errorf("RehashUserPassword writes %q — a rehash is not a password change:\n%s", never, dql)
		}
	}
	if strings.Count(dql, "dql:") > 1 {
		t.Errorf("RehashUserPassword is more than one statement:\n%s", dql)
	}
}
