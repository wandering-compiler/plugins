package handlers

import (
	"context"
	"strings"

	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// ReportUsage records metered consumption: append a UsageRecord and
// increment the materialized UsageMeter atomically. Idempotent on the
// key — a retried report (same idempotency_key) is a no-op that returns
// the current meter total.
func (h *PaymentServiceHandler) ReportUsage(ctx context.Context, req *pb.ReportUsageReq) (*pb.UsageView, error) {
	if req.GetUserId() == "" {
		return nil, invalidArg("user_id is required")
	}
	if strings.TrimSpace(req.GetMeter()) == "" {
		return nil, invalidArg("meter is required")
	}
	if strings.TrimSpace(req.GetPeriod()) == "" {
		return nil, invalidArg("period is required (the billing-window key, e.g. \"2026-06\")")
	}
	if req.GetQuantity() <= 0 {
		return nil, invalidArg("quantity must be positive")
	}
	if req.GetIdempotencyKey() == "" {
		return nil, invalidArg("idempotency_key is required (the report must be idempotent)")
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	// The stored key is scoped by (principal, meter, period):
	// UsageRecord.idempotency_key is one table-wide UNIQUE, and a duplicate
	// is answered with success. With the raw key stored, a report for
	// user-b (or for another meter) under a key already used elsewhere
	// recorded nothing and still succeeded — usage silently never billed.
	resp, err := h.Mutation.RecordUsage(ctx, &pb.RecordUsageReq{
		UserId:         req.GetUserId(),
		Meter:          req.GetMeter(),
		Period:         req.GetPeriod(),
		Quantity:       req.GetQuantity(),
		ItemRef:        req.GetItemRef(),
		Metadata:       req.GetMetadata(),
		IdempotencyKey: scopedKey("usage", req.GetUserId(), req.GetMeter(), req.GetPeriod(), req.GetIdempotencyKey()),
	})
	if err != nil {
		if constraintCode(err) == codeUniqueViolation {
			// Already recorded under this key → idempotent: return the
			// current meter total.
			return h.currentMeter(ctx, req.GetUserId(), req.GetMeter(), req.GetPeriod())
		}
		return nil, err
	}
	return &pb.UsageView{
		UserId: resp.GetUserId(),
		Meter:  resp.GetMeter(),
		Period: resp.GetPeriod(),
		Total:  resp.GetTotal(),
	}, nil
}

func (h *PaymentServiceHandler) currentMeter(ctx context.Context, userID, meter, period string) (*pb.UsageView, error) {
	got, err := h.Query.GetUsageMeter(ctx, &pb.GetUsageMeterReq{UserId: userID, Meter: meter, Period: period})
	if err != nil {
		return nil, err
	}
	view := &pb.UsageView{UserId: userID, Meter: meter, Period: period}
	if m := got.GetMeter(); m != nil {
		view.Total = m.GetTotal()
	}
	return view, nil
}
