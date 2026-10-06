package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

func usageHandler(q *fakeQuery, m *fakeMutation) *PaymentServiceHandler {
	return &PaymentServiceHandler{Query: q, Mutation: m, Backend: &fakeBackend{}}
}

func TestReportUsage(t *testing.T) {
	m := &fakeMutation{}
	h := usageHandler(&fakeQuery{}, m)
	view, err := h.ReportUsage(context.Background(), &pb.ReportUsageReq{
		UserId: "u1", Meter: "api_calls", Period: "2026-06", Quantity: 5, ItemRef: "order-9", IdempotencyKey: "r1",
	})
	if err != nil {
		t.Fatalf("ReportUsage: %v", err)
	}
	if m.lastRecord.GetQuantity() != 5 || m.lastRecord.GetMeter() != "api_calls" {
		t.Errorf("recorded = %+v", m.lastRecord)
	}
	if m.lastRecord.GetItemRef() != "order-9" {
		t.Errorf("item_ref lost: %q", m.lastRecord.GetItemRef())
	}
	if view.GetTotal() != 5 {
		t.Errorf("total = %d, want 5", view.GetTotal())
	}
}

func TestReportUsage_Validates(t *testing.T) {
	h := usageHandler(&fakeQuery{}, &fakeMutation{})
	cases := []*pb.ReportUsageReq{
		{Meter: "m", Period: "p", Quantity: 1, IdempotencyKey: "k"},               // no user
		{UserId: "u", Period: "p", Quantity: 1, IdempotencyKey: "k"},              // no meter
		{UserId: "u", Meter: "m", Quantity: 1, IdempotencyKey: "k"},               // no period
		{UserId: "u", Meter: "m", Period: "p", Quantity: 0, IdempotencyKey: "k"},  // non-positive
		{UserId: "u", Meter: "m", Period: "p", Quantity: -3, IdempotencyKey: "k"}, // negative
		{UserId: "u", Meter: "m", Period: "p", Quantity: 1},                       // no idem key
	}
	for i, req := range cases {
		if _, err := h.ReportUsage(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("case %d: want InvalidArgument, got %v", i, err)
		}
	}
}

func TestReportUsage_IdempotentOnDuplicate(t *testing.T) {
	m := &fakeMutation{recordErr: constraintErr(t, "UNIQUE_VIOLATION")}
	q := &fakeQuery{usageMeter: &pb.UsageMeter{UserId: "u1", Meter: "api_calls", Period: "2026-06", Total: 100}}
	h := usageHandler(q, m)
	view, err := h.ReportUsage(context.Background(), &pb.ReportUsageReq{
		UserId: "u1", Meter: "api_calls", Period: "2026-06", Quantity: 5, IdempotencyKey: "dup",
	})
	if err != nil {
		t.Fatalf("idempotent report should not error: %v", err)
	}
	if view.GetTotal() != 100 {
		t.Errorf("idempotent report should return current total, got %d", view.GetTotal())
	}
}

// Note: reading the meter is now a direct storage query
// (PaymentQuery.GetUsageMeter via REST preset). The currentMeter helper
// is still covered via the idempotent-report path
// (TestReportUsage_IdempotentOnDuplicate).
