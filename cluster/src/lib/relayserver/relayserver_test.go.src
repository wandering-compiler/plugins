package relayserver

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
)

// events is a ScheduleTask stream the test reads back.
type events struct {
	grpc.ServerStream
	ctx context.Context
	got []*pb.ScheduleTaskEvent
}

func (e *events) Context() context.Context { return e.ctx }
func (e *events) Send(ev *pb.ScheduleTaskEvent) error {
	e.got = append(e.got, ev)
	return nil
}

func newPool(t *testing.T) *relaycore.Pool {
	t.Helper()
	p, err := relaycore.New(relaycore.Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A relay that cannot say where its work endpoint is refuses — and says it is
// a CONFIGURATION problem, so a control plane falls through to another relay
// instead of handing the caller an error that is nobody's fault but the
// operator's.
func TestScheduleTask_AMisconfiguredRelayRefusesWithAReason(t *testing.T) {
	s := &Server{Pool: newPool(t)}
	err := s.ScheduleTask(&pb.ScheduleTaskReq{}, &events{ctx: t.Context()})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition", status.Code(err))
	}
	if got := refusal.ReasonOf(err); got != refusal.RelayMisconfigured {
		t.Errorf("reason = %q, want %q", got, refusal.RelayMisconfigured)
	}
}

func TestExchangeWorkers_NoRegistryRefusesWithAReason(t *testing.T) {
	_, err := (&Server{}).ExchangeWorkers(t.Context(), &pb.ExchangeWorkersReq{})
	if got := refusal.ReasonOf(err); got != refusal.RelayMisconfigured {
		t.Errorf("reason = %q, want %q", got, refusal.RelayMisconfigured)
	}
}
