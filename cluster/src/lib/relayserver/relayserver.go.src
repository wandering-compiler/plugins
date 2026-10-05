// Package relayserver is the relay's control-plane-facing half: the
// ClusterService a control plane calls to place work here.
//
// It is the SAME service the project serves, which is what makes the control
// plane a stream proxy rather than a translator. What differs is the answer:
// the project decides WHICH relay, this decides WHEN and hands out the ticket.
package relayserver

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
)

// Server serves one relay's scheduling.
type Server struct {
	pb.UnimplementedClusterServiceServer

	// Pool is this relay's capacity and queue.
	Pool *relaycore.Pool

	// Workers is this relay's admission state. Never nil in a running relay.
	Workers *workeradmit.Registry

	// Backends is the attached fleet, read for the worker count RelayStats
	// reports to an operator. Optional.
	Backends *Backends

	// Codes holds the registration codes this relay mints for new workers.
	// The same store the enrolment server redeems them from.
	Codes *regcode.Store

	// ProxyFingerprint is the lowercase hex SHA-256 of the certificate the
	// PROXY presents, handed to the caller so it can pin what answers at
	// ProxyAddress.
	//
	// Without it the caller sends a bearer ticket and its work to whatever
	// holds that address; it has no other way to know what should be there,
	// because it learned the address from the control plane a moment ago.
	ProxyFingerprint string

	// ProxyAddress is `host:port` of the half a CALLER connects to, as the
	// outside world reaches it.
	//
	// Local configuration, and it has to be: a process behind NAT cannot
	// discover how it is addressed, and the management address the control
	// plane dialled is a different port. This is the one fact about itself a
	// relay can only be told.
	ProxyAddress string

	// PollInterval is what a polled reservation is told as poll_after_ms.
	// Zero uses relaycore.DefaultPollInterval. Keep it well inside the pool's
	// PollTimeout, or obedient clients get abandoned.
	PollInterval time.Duration
}

// misconfigured refuses before any slot is taken when the relay cannot name
// its own work endpoint.
//
// Refused rather than answered with an empty address: a grant the caller
// cannot connect to is worse than no grant, because it consumes a slot and
// fails later somewhere with less context.
func (s *Server) misconfigured() error {
	if s.ProxyAddress == "" || s.ProxyFingerprint == "" {
		return refusal.New(codes.FailedPrecondition, refusal.RelayMisconfigured,
			"relay: the work endpoint is not fully described (address + certificate fingerprint), "+
				"so a grant would name somewhere the caller cannot verify")
	}
	return nil
}

// granted is a grant as the wire carries it: where to go, what to pin, what
// to present, and by when.
func (s *Server) granted(g relaycore.Grant) *pb.TaskGranted {
	return &pb.TaskGranted{
		Address:         s.ProxyAddress,
		CertFingerprint: s.ProxyFingerprint,
		Ticket:          g.Ticket,
		ExpiresAt:       timestamppb.New(g.ExpiresAt),
	}
}

// ScheduleTask holds a queue place for as long as the caller holds the stream.
func (s *Server) ScheduleTask(
	req *pb.ScheduleTaskReq,
	srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent],
) error {
	if err := s.misconfigured(); err != nil {
		return err
	}

	// `relay` is left EMPTY on every event below. A relay has never been told
	// its name in the control plane's registry, and inventing one — its
	// hostname, say — would put a second, disagreeing identity on the wire.
	// The control plane stamps it as the events pass through.
	grant, err := s.Pool.Wait(srv.Context(), func(pos int) error {
		return srv.Send(&pb.ScheduleTaskEvent{
			Event: &pb.ScheduleTaskEvent_Queued{
				Queued: &pb.TaskQueued{Position: int32(pos)},
			},
		})
	})
	switch {
	case errors.Is(err, relaycore.ErrDraining):
		// Draining, with the reason a control plane falls through on: this
		// relay will not place anything, and another one may.
		return refusal.New(codes.Unavailable, refusal.RelayDraining, "relay: draining — place elsewhere")
	case err != nil:
		// Context errors land here — the caller left, or its deadline passed.
		// Both are the caller's own status, not a failure of this relay.
		return status.FromContextError(err).Err()
	}

	return srv.Send(&pb.ScheduleTaskEvent{
		Event: &pb.ScheduleTaskEvent_Granted{
			Granted: s.granted(grant),
		},
	})
}

// ExchangeWorkers reports every worker this relay has met. The ban set the
// call carries was already applied by the management server's interceptor —
// as on every call — so there is nothing left for the body to say.
func (s *Server) ExchangeWorkers(context.Context, *pb.ExchangeWorkersReq) (*pb.ExchangeWorkersResp, error) {
	if s.Workers == nil {
		return nil, refusal.New(codes.FailedPrecondition, refusal.RelayMisconfigured, "relay: no worker registry is wired")
	}
	known := s.Workers.Known()
	out := make([]*pb.KnownWorker, 0, len(known))
	for _, w := range known {
		out = append(out, &pb.KnownWorker{CertFingerprint: w.ID, Name: w.Name, DeviceId: w.DeviceID})
	}
	return &pb.ExchangeWorkersResp{Workers: out}, nil
}

// IssueRegistrationCode mints a one-time code for a new worker. `ids` is the
// control plane's to read; whoever reached this method chose the relay by
// dialling it.
//
// The relay's own fingerprint travels with the code, so the operator hands a
// worker everything it needs to trust this relay in one go.
func (s *Server) IssueRegistrationCode(context.Context, *pb.IssueRegistrationCodeReq) (*pb.IssueRegistrationCodeResp, error) {
	if s.Codes == nil {
		return nil, refusal.New(codes.FailedPrecondition, refusal.RelayMisconfigured,
			"relay: no registration-code store is wired — this relay cannot enrol workers")
	}
	code, expires, err := s.Codes.Issue()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay: minting a registration code: %v", err)
	}
	return &pb.IssueRegistrationCodeResp{
		Code:             code,
		ExpiresAt:        timestamppb.New(expires),
		RelayFingerprint: s.ProxyFingerprint,
	}, nil
}

// RelayStats reports this relay's load, which is what a control plane ranks
// relays by.
func (s *Server) RelayStats(context.Context, *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	st := s.Pool.Stats()
	workers := 0
	if s.Backends != nil {
		workers = s.Backends.Count()
	}
	return &pb.RelayStatsResp{
		InUse:    int32(st.InUse),
		Reserved: int32(st.Reserved),
		Queued:   int32(st.Queued),
		Capacity: int32(st.Capacity),
		Draining: st.Draining,
		Workers:  int32(workers),
	}, nil
}

// DrainRelay drains THIS relay. `ids` is the control plane's to read — a
// relay has never been told its registry id, and whoever reached this method
// already chose which relay they meant by dialling it.
func (s *Server) DrainRelay(context.Context, *pb.DrainRelayReq) (*pb.DrainRelayResp, error) {
	s.Pool.Drain()
	return &pb.DrainRelayResp{}, nil
}

// CheckWorkers is the PROJECT's method. A relay has no registry to sweep and
// no other relay to ask, so it says so rather than answering for a side it is
// not.
func (s *Server) CheckWorkers(context.Context, *pb.CheckWorkersReq) (*pb.CheckWorkersResp, error) {
	return nil, status.Error(codes.Unimplemented,
		"relay: CheckWorkers is answered by the control plane, not by a relay")
}
