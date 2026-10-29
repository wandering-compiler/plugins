package handlers

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"

	pb "github.com/wandering-compiler/plugins/auth/gen/pb"
)

// lockoutStore is alice (u1) plus u2 and u3, with the given wildcard holders.
func lockoutStore(admins ...string) *revocationStore {
	s := aliceStore()
	s.addUser("u2", "bob@example.com")
	s.addUser("u3", "carol@example.com")
	s.admins = admins
	return s
}

func wantRefusal(t *testing.T, err error, c codes.Code, code string) {
	t.Helper()
	if got, detail := detailCode(t, err); got != c || detail != code {
		t.Fatalf("got %v (%s), want %v %s", got, detail, c, code)
	}
}

// An operator cannot disable their own account: it would sign them out in the
// middle of the action, and it is another administrator's call. Nothing in the
// selection is disabled.
func TestDisableAccounts_RefusesTheOperatorsOwnAccount(t *testing.T) {
	s := lockoutStore("u1", "u2")
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.DisableAccounts(sessionCallerCtx("u2", "t-u2"), &pb.DisableAccountsReq{Ids: []string{"u1", "u2"}})
	wantRefusal(t, err, codes.FailedPrecondition, CodeOwnAccount)
	if s.users["u1"].disabledAt != nil || s.users["u2"].disabledAt != nil {
		t.Fatal("a refused selection disabled an account")
	}
}

// The realm keeps an account that can administer it: disabling the last
// active wildcard holder is refused, and an administrator who is already
// disabled does not count as the one left.
func TestDisableAccounts_KeepsTheLastAdministrator(t *testing.T) {
	s := lockoutStore("u1", "u3")
	s.users["u3"].disabledAt = now() // can administer nothing
	h := &AuthServiceHandler{Query: s, Mutation: s}
	_, err := h.DisableAccounts(sessionCallerCtx("op", "t-op"), &pb.DisableAccountsReq{Ids: []string{"u1"}})
	wantRefusal(t, err, codes.FailedPrecondition, CodeLastAdmin)
	if s.users["u1"].disabledAt != nil {
		t.Fatal("the last administrator was disabled")
	}

	// The administrators were locked before the decision (both, in id order),
	// so a concurrent change to either waits for this transaction.
	if !slices.Equal(s.locked, []string{"u1"}) {
		t.Errorf("locked %v, want the active administrators [u1]", s.locked)
	}

	// With another active administrator, the same disable goes through.
	s.admins = append(s.admins, "u2")
	if _, err := h.DisableAccounts(sessionCallerCtx("op", "t-op"), &pb.DisableAccountsReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("disable with another administrator left: %v", err)
	}
	if s.users["u1"].disabledAt == nil {
		t.Fatal("u1 was not disabled")
	}
}

// A realm with no wildcard holder — or no rbac at all — refuses nothing: there
// is no administrator the rule could keep.
func TestDisableAccounts_ARealmWithoutAdministratorsRefusesNothing(t *testing.T) {
	s := lockoutStore()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	if _, err := h.DisableAccounts(sessionCallerCtx("op", "t-op"), &pb.DisableAccountsReq{Ids: []string{"u1"}}); err != nil {
		t.Fatalf("no administrators: %v", err)
	}

	prev := realmAdmins
	t.Cleanup(func() { realmAdmins = prev })
	realmAdmins = func(context.Context, *AuthServiceHandler) ([]string, bool, error) { return nil, false, nil }
	s.admins = []string{"u2"}
	if _, err := h.DisableAccounts(sessionCallerCtx("op", "t-op"), &pb.DisableAccountsReq{Ids: []string{"u2"}}); err != nil {
		t.Fatalf("without rbac: %v", err)
	}
}

// Disable and enable each emit one event per account they change, with the
// operator; an account already in that state emits nothing, and an erased one
// is not enabled.
func TestDisableAndEnableAccounts_EmitPerAccountChanged(t *testing.T) {
	s := lockoutStore()
	s.users["u3"].disabledAt = now()
	h := &AuthServiceHandler{Query: s, Mutation: s}
	ctx := sessionCallerCtx("op", "t-op")
	if _, err := h.DisableAccounts(ctx, &pb.DisableAccountsReq{Ids: []string{"u1", "u3"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.emitted, "UserDisabled:u1:op") || slices.Contains(s.emitted, "UserDisabled:u3:op") {
		t.Errorf("disable events %v, want u1 only", s.emitted)
	}
	if !(s.tokens["t-session"].revokedAt != nil) {
		t.Error("disabling u1 left its session live")
	}

	s.users["u3"].erasedAt = now()
	s.emitted = nil
	if _, err := h.EnableAccounts(ctx, &pb.EnableAccountsReq{Ids: []string{"u1", "u2", "u3"}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.emitted, []string{"UserEnabled:u1:op"}) {
		t.Errorf("enable events %v, want u1 only (u2 was enabled, u3 is erased)", s.emitted)
	}
	if s.users["u3"].disabledAt == nil {
		t.Error("an erased account was enabled")
	}
	if _, err := h.EnableAccounts(ctx, &pb.EnableAccountsReq{}); err != errEmptySelection {
		t.Errorf("an empty selection: %v", err)
	}
}

// The erasure is held to the same rule: not the operator's own account, not
// the realm's last administrator — both refused before anything is ended.
func TestEraseUsers_KeepsTheOperatorAndTheLastAdministrator(t *testing.T) {
	s := lockoutStore("u1")
	h := &AuthServiceHandler{Query: s, Mutation: s}

	_, err := h.EraseAccount(sessionCallerCtx("u1", "t-session"), &pb.EraseAccountReq{UserId: "u1"})
	wantRefusal(t, err, codes.FailedPrecondition, CodeOwnAccount)

	_, err = h.EraseUsers(sessionCallerCtx("op", "t-op"), &pb.EraseUsersReq{Ids: []string{"u1"}})
	wantRefusal(t, err, codes.FailedPrecondition, CodeLastAdmin)
	if s.users["u1"].erasedAt != nil || s.users["u1"].disabledAt != nil || (s.tokens["t-session"].revokedAt != nil) {
		t.Fatal("a refused erasure ended the account's access")
	}
}
