package relayserver

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
)

// ReserveTask takes a place in this relay's queue and answers at once.
//
// A draining relay REFUSES rather than answering `expired`: nothing was
// reserved, and the control plane placing this request falls through to
// another relay on that reason, as it does on ScheduleTask.
//
// The place is recorded under the owner the control plane sends
// (resowner.Header), and only a poll or cancel carrying the same owner reaches
// it. The response header confirms that, so a control plane can tell this
// relay from one too old to bind.
func (s *Server) ReserveTask(ctx context.Context, _ *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	if err := s.misconfigured(); err != nil {
		return nil, err
	}
	owner := resowner.From(ctx)
	r, err := s.Pool.Reserve(owner)
	if errors.Is(err, relaycore.ErrDraining) {
		return nil, refusal.New(codes.Unavailable, refusal.RelayDraining, "relay: draining — place elsewhere")
	}
	if errors.Is(err, relaycore.ErrQueueFull) {
		return nil, refusal.New(codes.ResourceExhausted, refusal.QueueFull, "relay: the queue is full — place elsewhere or retry later")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay: reserving: %v", err)
	}
	if owner != "" {
		if err := resowner.Confirm(ctx); err != nil {
			s.Pool.Cancel(r.ID, owner)
			return nil, status.Errorf(codes.Internal, "relay: confirming the reservation's owner: %v", err)
		}
	}
	return s.reservationState(r.ID, r.State), nil
}

// GetReservation is the poll. An unknown reservation and one drained out of
// the queue are both `expired` — the place is gone and the answer is to place
// again — with the reason telling an operator which. So is a reservation
// owned by someone other than the caller the control plane names: nothing in
// the answer says the id was real.
func (s *Server) GetReservation(ctx context.Context, req *pb.GetReservationReq) (*pb.ReservationState, error) {
	id := req.GetReservation()
	st, err := s.Pool.Poll(id, resowner.From(ctx))
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
// already gone has the outcome the caller wanted. Another owner's reservation
// answers the same, and stays.
func (s *Server) CancelReservation(ctx context.Context, req *pb.CancelReservationReq) (*pb.CancelReservationResp, error) {
	s.Pool.Cancel(req.GetReservation(), resowner.From(ctx))
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
