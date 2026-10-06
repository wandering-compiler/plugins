package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
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

// rc.2 and earlier stored the caller's RAW key on the UsageRecord. A report
// made by one of them and retried after the upgrade is not found under the
// scoped key, and used to be counted a second time (a meter of 7 became 14).
// It is looked up under the raw key too, and is the same report when
// principal, meter, period and quantity all match.
func TestFlow_Usage_ReportRetriedAcrossTheUpgrade_CountsOnce(t *testing.T) {
	r := newRig(t)
	// What rc.2 wrote: the raw caller key.
	if _, err := r.store.RecordUsage(bg, &pb.RecordUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"}); err != nil {
		t.Fatal(err)
	}
	records := r.store.callCount("RecordUsage")

	v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"})
	if err != nil || v.GetTotal() != 7 {
		t.Errorf("report retried across the upgrade = %v / %v, want total 7 (counted once)", v, err)
	}
	if n := r.store.callCount("RecordUsage"); n != records {
		t.Errorf("a retry of an rc.2 report reached RecordUsage (%d → %d)", records, n)
	}

	// Not the same report — the collisions the scoped key exists to fix.
	// Each is recorded.
	for _, c := range []struct {
		what string
		req  *pb.ReportUsageReq
	}{
		{"user-b under user-a's key", &pb.ReportUsageReq{UserId: "user-b", Meter: "api_calls", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"}},
		{"another meter under the key", &pb.ReportUsageReq{UserId: "user-a", Meter: "storage_gb", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"}},
		{"another period under the key", &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-07", Quantity: 7, IdempotencyKey: "batch-1"}},
		{"another quantity under the key", &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 8, IdempotencyKey: "batch-1"}},
	} {
		before := r.store.count("usage")
		if _, err := r.h.ReportUsage(bg, c.req); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if r.store.count("usage") != before+1 {
			t.Errorf("%s: not recorded — a silent no-op", c.what)
		}
	}
	if v, _ := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 7, IdempotencyKey: "batch-1"}); v.GetTotal() != 15 {
		t.Errorf("user-a api_calls 2026-06 total = %d, want 15 (7 + 8)", v.GetTotal())
	}

	// A failing lookup surfaces; nothing is recorded blind.
	r.store.injectBefore("GetUsageRecordByKey", errTransient)
	before := r.store.count("usage")
	_, err = r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 1, IdempotencyKey: "fresh"})
	wantCode(t, err, codes.Unavailable, "legacy lookup failure")
	if r.store.count("usage") != before {
		t.Error("recorded although the legacy lookup failed")
	}
}

// A caller key shaped like a scoped key ("v2:" + hex) is not looked up raw:
// it can equal ANOTHER report's stored scoped key, and matching that row
// would answer a new report as a retry and never count it.
func TestFlow_Usage_CallerKeyShapedLikeAScopedKey_IsNotAMatch(t *testing.T) {
	r := newRig(t)
	if _, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 3, IdempotencyKey: "x"}); err != nil {
		t.Fatal(err)
	}
	stored := scopedKey("usage", "user-a", "api_calls", "2026-06", "x")
	v, err := r.h.ReportUsage(bg, &pb.ReportUsageReq{UserId: "user-a", Meter: "api_calls", Period: "2026-06", Quantity: 3, IdempotencyKey: stored})
	if err != nil {
		t.Fatal(err)
	}
	if v.GetTotal() != 6 {
		t.Errorf("total = %d, want 6 — a report under a key equal to another's stored scoped key was taken for a retry", v.GetTotal())
	}
}
