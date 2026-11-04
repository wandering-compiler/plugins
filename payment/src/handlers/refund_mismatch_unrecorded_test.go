package handlers

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
)

// received_amount / received_currency are NULL-able (they describe only a
// mismatch), so a row held at AMOUNT_MISMATCH that records neither must be
// refused, not judged against an empty amount.
func TestRefundAllowed_MismatchWithoutReceivedAmountIsRefused(t *testing.T) {
	h := &PaymentServiceHandler{}
	ctx := context.Background()
	err := h.refundAllowed(ctx, ctx, &pb.Payment{Id: "p1", Currency: "EUR"},
		&pb.LockPaymentForRefundResp{Id: "p1", Amount: 100000, Status: int32(pb.Payment_AMOUNT_MISMATCH)}, 10000)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for a mismatch with no received amount, got %v", err)
	}
}
