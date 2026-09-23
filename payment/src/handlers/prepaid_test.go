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
