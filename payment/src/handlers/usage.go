package handlers

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
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
	// One window, one spelling (canonicalPeriod): everything below — the
	// meter, the stored key, the raw-key lookup — sees the canonical one.
	period, err := canonicalPeriod(req.GetPeriod())
	if err != nil {
		return nil, invalidArg(err.Error())
	}
	req = proto.Clone(req).(*pb.ReportUsageReq)
	req.Period = period
	if req.GetQuantity() <= 0 {
		return nil, invalidArg("quantity must be positive")
	}
	if req.GetIdempotencyKey() == "" {
		return nil, invalidArg("idempotency_key is required (the report must be idempotent)")
	}
	if err := idempotencyKeyTooLong(req.GetIdempotencyKey()); err != nil {
		return nil, err
	}

	dup, err := h.reportedUnderRawKey(ctx, req)
	if err != nil {
		return nil, err
	}
	if dup {
		return h.currentMeter(ctx, req.GetUserId(), req.GetMeter(), req.GetPeriod())
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
		switch constraintCode(err) {
		case codeUniqueViolation:
			// Already recorded under this key → idempotent: return the
			// current meter total.
			return h.currentMeter(ctx, req.GetUserId(), req.GetMeter(), req.GetPeriod())
		case codeValueOutOfRange:
			// The meter's total + quantity overflowed its 64-bit column
			// (usage gap 2). Nothing was recorded (the record and the
			// meter are one transaction); say what, not "a value does not
			// fit the column".
			return nil, status.Error(codes.FailedPrecondition, "the meter's total would exceed its maximum; nothing was recorded")
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

// reportedUnderRawKey reports whether this report was already recorded by a
// version that stored the caller's RAW key (rc.2 and earlier).
//
// The scoped key cannot find such a record: a report made before the upgrade
// and retried after it would be counted a second time — usage billed twice.
// So before recording under the scoped key the records are read under the
// raw key too (one extra single-row read per report), and a row there is
// THIS report when it is the same principal, meter, period and quantity. A
// row that differs in any of them is the cross-principal / cross-meter
// collision the scoped key exists to fix, and the report proceeds under the
// scoped key.
//
// Keys shaped "v2:…" are not looked up: that is the scoped-key namespace
// (scopedKey), so a row there is some other report's scoped record and never
// a raw key an earlier version stored for this one.
func (h *PaymentServiceHandler) reportedUnderRawKey(ctx context.Context, req *pb.ReportUsageReq) (bool, error) {
	if strings.HasPrefix(req.GetIdempotencyKey(), scopedKeyPrefix) {
		return false, nil
	}
	got, err := h.Query.GetUsageRecordByKey(ctx, &pb.GetUsageRecordByKeyReq{IdempotencyKey: req.GetIdempotencyKey()})
	if err != nil {
		if absent(err) {
			return false, nil
		}
		return false, err
	}
	r := got.GetRecord()
	return r != nil &&
		r.GetUserId() == req.GetUserId() &&
		r.GetMeter() == req.GetMeter() &&
		r.GetPeriod() == req.GetPeriod() &&
		r.GetQuantity() == req.GetQuantity(), nil
}

func (h *PaymentServiceHandler) currentMeter(ctx context.Context, userID, meter, period string) (*pb.UsageView, error) {
	got, err := h.Query.GetUsageMeter(ctx, &pb.GetUsageMeterReq{UserId: userID, Meter: meter, Period: period})
	if err != nil && !absent(err) { // nothing metered yet: zero
		return nil, err
	}
	view := &pb.UsageView{UserId: userID, Meter: meter, Period: period}
	if m := got.GetMeter(); m != nil {
		view.Total = m.GetTotal()
	}
	return view, nil
}

// GetMyUsageMeter returns the signed-in caller's meter for (meter, period).
func (h *PaymentServiceHandler) GetMyUsageMeter(ctx context.Context, req *pb.GetMyUsageMeterReq) (*pb.GetUsageMeterResp, error) {
	caller, err := signedInCaller(ctx)
	if err != nil {
		return nil, err
	}
	// Read under the spelling the meter is stored under; a window that is
	// none of the accepted ones has no meter to read.
	period, err := canonicalPeriod(req.GetPeriod())
	if err != nil {
		return nil, invalidArg(err.Error())
	}
	got, err := h.Query.GetUsageMeter(ctx, &pb.GetUsageMeterReq{UserId: caller, Meter: req.GetMeter(), Period: period})
	if absent(err) {
		// Nothing reported yet: the meter row appears with the first report.
		return &pb.GetUsageMeterResp{Meter: &pb.UsageMeter{UserId: caller, Meter: req.GetMeter(), Period: period}}, nil
	}
	return got, err
}
