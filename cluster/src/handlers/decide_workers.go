package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// BanWorkers bans the selected workers; see the proto.
func (h *ClusterServiceHandler) BanWorkers(ctx context.Context, req *pb.DecideWorkersActionReq) (*pb.DecideWorkersActionResp, error) {
	return h.decide(ctx, req, true)
}

// UnbanWorkers lifts the ban on the selected workers; see the proto.
func (h *ClusterServiceHandler) UnbanWorkers(ctx context.Context, req *pb.DecideWorkersActionReq) (*pb.DecideWorkersActionResp, error) {
	return h.decide(ctx, req, false)
}

// decide records the decision under the CALLER's id. Who let a machine back in
// is the first question in an incident, so it is read from the verified
// principal and never taken from the request: a field the client filled could
// name anyone.
func (h *ClusterServiceHandler) decide(ctx context.Context, req *pb.DecideWorkersActionReq, ban bool) (*pb.DecideWorkersActionResp, error) {
	if len(req.GetIds()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cluster: select at least one worker")
	}
	var who pb.Caller
	if err := principal.Envelope(ctx, &who); err != nil || who.GetUserId() == "" {
		return nil, status.Error(codes.Unauthenticated, "cluster: a ban is recorded under the signed-in operator, and there is none")
	}
	if err := h.Workers.Decide(ctx, req.GetIds(), ban, who.GetUserId()); err != nil {
		return nil, err
	}
	return &pb.DecideWorkersActionResp{}, nil
}
