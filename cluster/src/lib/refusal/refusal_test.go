package refusal

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The reason survives the round trip a client actually performs: a status
// error, possibly wrapped by whoever passed it along.
func TestReasonOf_ReadsTheReasonBack(t *testing.T) {
	err := New(codes.PermissionDenied, TicketNotRedeemable, "spent")
	if got := ReasonOf(err); got != TicketNotRedeemable {
		t.Fatalf("ReasonOf = %q, want %q", got, TicketNotRedeemable)
	}
	if got := ReasonOf(fmt.Errorf("placing: %w", err)); got != TicketNotRedeemable {
		t.Errorf("a wrapped refusal lost its reason: %q", got)
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("code = %s — annotating changed the code", status.Code(err))
	}
}

// A reason from another domain is somebody else's vocabulary, and a client
// that classified by it would be reading a word it never agreed on.
func TestReasonOf_IgnoresOtherDomainsAndPlainErrors(t *testing.T) {
	st, _ := status.New(codes.Unavailable, "x").WithDetails(
		&errdetails.ErrorInfo{Domain: "elsewhere", Reason: NoWorker})
	if got := ReasonOf(st.Err()); got != "" {
		t.Errorf("a foreign domain's reason was read as ours: %q", got)
	}
	if got := ReasonOf(errors.New("boom")); got != "" {
		t.Errorf("a plain error has reason %q", got)
	}
	if got := ReasonOf(status.Error(codes.Unavailable, "transport")); got != "" {
		t.Errorf("a bare status has reason %q", got)
	}
	if got := ReasonOf(nil); got != "" {
		t.Errorf("nil has reason %q", got)
	}
}
