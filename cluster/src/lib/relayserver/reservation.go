package relayserver

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
)

// ReserveTask takes a place in this relay's queue and answers at once.
//
// A draining relay REFUSES rather than answering `expired`: nothing was
// reserved, and the control plane placing this request falls through to
// another relay on that reason, as it does on ScheduleTask.
func (s *Server) ReserveTask(context.Context, *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	if err := s.misconfigured(); err != nil {
		return nil, err
	}
	r, err := s.Pool.Reserve()
	if errors.Is(err, relaycore.ErrDraining) {
		return nil, refusal.New(codes.Unavailable, refusal.RelayDraining, "relay: draining — place elsewhere")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay: reserving: %v", err)
	}
	return s.reservationState(r.ID, r.State), nil
}

// GetReservation is the poll. An unknown reservation and one drained out of
// the queue are both `expired` — the place is gone and the answer is to place
// again — with the reason telling an operator which.
func (s *Server) GetReservation(_ context.Context, req *pb.GetReservationReq) (*pb.ReservationState, error) {
	id := req.GetReservation()
	st, err := s.Pool.Poll(id)
	switch {
	case errors.Is(err, relaycore.ErrDraining):
		return s.expired(id, refusal.RelayDraining), nil
	case errors.Is(err, relaycore.ErrNoSuchReservation):
		return s.expired(id, refusal.ReservationUnknown), nil
	case err != nil:
		return nil, status.Errorf(codes.Internal, "relay: polling: %v", err)
	}
	return s.reservationState(id, st), nil
}

// CancelReservation gives the place back. Idempotent: cancelling something
// already gone has the outcome the caller wanted.
func (s *Server) CancelReservation(_ context.Context, req *pb.CancelReservationReq) (*pb.CancelReservationResp, error) {
	s.Pool.Cancel(req.GetReservation())
	return &pb.CancelReservationResp{}, nil
}

func (s *Server) pollAfterMs() int32 {
	d := s.PollInterval
	if d <= 0 {
		d = relaycore.DefaultPollInterval
	}
	return int32(d.Milliseconds())
}

func (s *Server) reservationState(id string, st relaycore.State) *pb.ReservationState {
	out := &pb.ReservationState{Reservation: id, PollAfterMs: s.pollAfterMs()}
	if st.Grant != nil {
		out.State = &pb.ReservationState_Granted{Granted: s.granted(*st.Grant)}
	} else {
		// `relay` left empty for the control plane to stamp, as on the stream.
		out.State = &pb.ReservationState_Queued{Queued: &pb.TaskQueued{Position: int32(st.Position)}}
	}
	return out
}

func (s *Server) expired(id, reason string) *pb.ReservationState {
	return &pb.ReservationState{
		Reservation: id,
		State:       &pb.ReservationState_Expired{Expired: &pb.ReservationExpired{Reason: reason}},
		PollAfterMs: s.pollAfterMs(),
	}
}
