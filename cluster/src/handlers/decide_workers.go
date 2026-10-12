package handlers

import (
	"context"
	"log"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
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
	h.pushBans(ctx)
	return &pb.DecideWorkersActionResp{}, nil
}

// pushBans delivers the new ban set to every registered relay now, rather
// than with the next call that happens to reach each one. An enabled relay
// would have it before its next placement anyway; a disabled one would
// otherwise never hear of it and go on renewing the banned worker's
// certificate. Best effort: the decision is recorded, and a relay that
// cannot be reached gets the set with its next call.
func (h *ClusterServiceHandler) pushBans(ctx context.Context) {
	if h.Relays == nil || h.Dial == nil {
		return
	}
	ctx, err := h.withBans(context.WithoutCancel(ctx))
	if err != nil {
		return
	}
	relays, err := h.Relays.ListAll(ctx)
	if err != nil {
		log.Printf("cluster: cannot list relays to deliver the ban set: %v", err)
		return
	}
	// In parallel, so the operator waits at most one dial timeout however
	// many relays there are, not one per unreachable relay.
	var wg sync.WaitGroup
	for _, r := range relays {
		wg.Add(1)
		go func(r Relay) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, h.dialTimeout())
			defer cancel()
			conn, err := h.dialReady(pctx, r)
			if err == nil {
				_, err = newRelayClient(conn).RelayStats(pctx, &pb.RelayStatsReq{})
				_ = conn.Close()
			}
			if err != nil {
				log.Printf("cluster: relay %q did not take the new ban set now (it gets it with its next call): %v", r.Name, err)
			}
		}(r)
	}
	wg.Wait()
}
