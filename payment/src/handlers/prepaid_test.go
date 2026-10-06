package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// constraintErr builds the InvalidArgument + ErrorDetail{code} shape
// storage returns for a constraint violation.
func constraintErr(t *testing.T, code string) error {
	t.Helper()
	st, err := status.New(codes.InvalidArgument, "constraint").WithDetails(&w17pb.ErrorDetail{Code: code})
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	return st.Err()
}

func prepaidHandler(q *fakeQuery, m *fakeMutation) *PaymentServiceHandler {
	return &PaymentServiceHandler{Query: q, Mutation: m, Backend: &fakeBackend{}}
}

func TestGrantCredit(t *testing.T) {
	m := &fakeMutation{}
	h := prepaidHandler(&fakeQuery{}, m)
	view, err := h.GrantCredit(context.Background(), &pb.GrantCreditReq{UserId: "u1", Amount: "10.00", IdempotencyKey: "g1"})
	if err != nil {
		t.Fatalf("GrantCredit: %v", err)
	}
	if m.lastApply.GetDelta() != "10.00" {
		t.Errorf("grant delta = %q, want 10.00 (positive)", m.lastApply.GetDelta())
	}
	if m.lastApply.GetReason() != "grant" {
		t.Errorf("default reason = %q, want grant", m.lastApply.GetReason())
	}
	if view.GetBalance() != "10.00" {
		t.Errorf("balance = %q", view.GetBalance())
	}
}

func TestSpendCredit_NegatesDelta(t *testing.T) {
	m := &fakeMutation{}
	h := prepaidHandler(&fakeQuery{}, m)
	if _, err := h.SpendCredit(context.Background(), &pb.SpendCreditReq{UserId: "u1", Amount: "5.00", IdempotencyKey: "s1"}); err != nil {
		t.Fatalf("SpendCredit: %v", err)
	}
	if m.lastApply.GetDelta() != "-5.00" {
		t.Errorf("spend delta = %q, want -5.00", m.lastApply.GetDelta())
	}
}

func TestSpendCredit_Insufficient(t *testing.T) {
	m := &fakeMutation{applyErr: constraintErr(t, "INVALID_VALUE")} // balance CHECK
	h := prepaidHandler(&fakeQuery{}, m)
	_, err := h.SpendCredit(context.Background(), &pb.SpendCreditReq{UserId: "u1", Amount: "999", IdempotencyKey: "s2"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition (insufficient), got %v", err)
	}
}

func TestApplyCredit_IdempotentOnDuplicate(t *testing.T) {
	// UNIQUE on idempotency_key ⇒ already applied; return current balance.
	m := &fakeMutation{applyErr: constraintErr(t, "UNIQUE_VIOLATION")}
	q := &fakeQuery{balance: &pb.CreditBalance{UserId: "u1", Balance: "42.00"}}
	h := prepaidHandler(q, m)
	view, err := h.GrantCredit(context.Background(), &pb.GrantCreditReq{UserId: "u1", Amount: "10", IdempotencyKey: "dup"})
	if err != nil {
		t.Fatalf("idempotent grant should not error: %v", err)
	}
	if view.GetBalance() != "42.00" {
		t.Errorf("idempotent grant should return current balance, got %q", view.GetBalance())
	}
}

func TestGrantCredit_ValidatesAmount(t *testing.T) {
	h := prepaidHandler(&fakeQuery{}, &fakeMutation{})
	for _, amt := range []string{"", "0", "0.00", "-5", "abc", "1.2.3"} {
		_, err := h.GrantCredit(context.Background(), &pb.GrantCreditReq{UserId: "u1", Amount: amt, IdempotencyKey: "k"})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("amount %q: want InvalidArgument, got %v", amt, err)
		}
	}
}

func TestApplyCredit_RequiresIdempotencyKey(t *testing.T) {
	h := prepaidHandler(&fakeQuery{}, &fakeMutation{})
	_, err := h.GrantCredit(context.Background(), &pb.GrantCreditReq{UserId: "u1", Amount: "1.00"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for missing idempotency_key, got %v", err)
	}
}

// Note: reading the balance is now a direct storage query
// (PaymentQuery.GetCreditBalance via REST preset) — no business handler
// to test. The currentBalance helper is still covered via the
// idempotent-grant path (TestApplyCredit_IdempotentOnDuplicate).

// rc.2 and earlier stored the caller's RAW key in the ledger. A grant or
// spend made by one of them and retried after the upgrade is not found under
// the scoped key, and used to land a second time — credit granted twice, a
// service paid for twice. It is looked up under the raw key too, and is the
// same apply when principal, direction and amount all match.
func TestFlow_Credit_ApplyRetriedAcrossTheUpgrade_AppliesOnce(t *testing.T) {
	r := newRig(t)
	// What rc.2 wrote: raw caller keys.
	for _, row := range []*pb.ApplyCreditReq{
		{UserId: "user-a", Delta: "10", Reason: "grant", IdempotencyKey: "order-1"},
		{UserId: "user-a", Delta: "-2", Reason: "spend", IdempotencyKey: "use-1"},
		{UserId: "user-a", Delta: "3", Reason: "topup", Ref: "pi_legacy", IdempotencyKey: "topup:pi_legacy"},
	} {
		if _, err := r.store.ApplyCredit(bg, row); err != nil {
			t.Fatal(err)
		}
	}
	applies := r.store.callCount("ApplyCredit")

	// The retries: same principal, direction and amount (amount by value).
	if v, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "10.00", IdempotencyKey: "order-1"}); err != nil || v.GetBalance() != "11.0000" {
		t.Errorf("grant retried across the upgrade = %v / %v, want balance 11.0000 (applied once)", v, err)
	}
	if v, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "2", IdempotencyKey: "use-1"}); err != nil || v.GetBalance() != "11.0000" {
		t.Errorf("spend retried across the upgrade = %v / %v, want balance 11.0000 (applied once)", v, err)
	}
	if n := r.store.callCount("ApplyCredit"); n != applies {
		t.Errorf("a retry of an rc.2 apply reached ApplyCredit (%d → %d)", applies, n)
	}

	// Not the same apply — the collisions the scoped key exists to fix:
	// another principal, the other direction, another amount, and a key in
	// the top-up namespace. Each applies.
	for _, c := range []struct {
		what string
		call func() error
	}{
		{"user-b under user-a's key", func() error {
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-b", Amount: "10", IdempotencyKey: "order-1"})
			return err
		}},
		{"a spend under a grant's key", func() error {
			_, err := r.h.SpendCredit(bg, &pb.SpendCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "order-1"})
			return err
		}},
		{"another amount under the key", func() error {
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "4", IdempotencyKey: "order-1"})
			return err
		}},
		{"a caller grant under a top-up's key", func() error {
			_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "3", IdempotencyKey: "topup:pi_legacy"})
			return err
		}},
	} {
		before := r.store.count("ledger")
		if err := c.call(); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if r.store.count("ledger") != before+1 {
			t.Errorf("%s: not applied — a silent no-op", c.what)
		}
	}
	if b := r.store.balance(t, "user-a"); b != "17.0000" {
		t.Errorf("user-a balance = %s, want 17.0000 (11 − 1 + 4 + 3)", b)
	}
	if b := r.store.balance(t, "user-b"); b != "10.0000" {
		t.Errorf("user-b balance = %s, want 10.0000", b)
	}

	// A failing lookup surfaces; nothing is applied blind.
	r.store.injectBefore("GetCreditLedgerByKey", errTransient)
	before := r.store.count("ledger")
	_, err := r.h.GrantCredit(bg, &pb.GrantCreditReq{UserId: "user-a", Amount: "1", IdempotencyKey: "fresh"})
	wantCode(t, err, codes.Unavailable, "legacy lookup failure")
	if r.store.count("ledger") != before {
		t.Error("applied although the legacy lookup failed")
	}
}
