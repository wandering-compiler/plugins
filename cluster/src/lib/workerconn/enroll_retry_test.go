package workerconn

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
)

// A relay that holds no ban set yet answers an enrolment Unavailable with a
// reason. The worker waits it out with the same code; every other reasoned
// refusal (a code that is not valid, a banned key) ends Run, because no retry
// fixes it.
func TestEnrolmentFinal_ABanSetNotYetReceivedIsRetried(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("workerconn: enrolling: %w", err) }
	for name, tc := range map[string]struct {
		err   error
		final bool
	}{
		"no ban set yet": {wrap(refusal.New(codes.Unavailable, refusal.BanSetUnknown, "x")), false},
		"unreachable":    {errors.New("dial tcp: connection refused"), false},
		"code invalid":   {wrap(refusal.New(codes.PermissionDenied, refusal.RegistrationCodeInvalid, "x")), true},
		"banned key":     {wrap(refusal.New(codes.PermissionDenied, refusal.WorkerBanned, "x")), true},
		"no code":        {ErrNeedsRegistration, true},
		"bad claim":      {fmt.Errorf("%w: x", ErrInvalidClaim), true},
	} {
		if got := enrolmentFinal(tc.err); got != tc.final {
			t.Errorf("%s: final = %v, want %v", name, got, tc.final)
		}
	}
}
