package handlers

import (
	"context"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// relayService is the wire name of ClusterService ON A RELAY: the plugin's own
// proto package, as written, never the activation's.
//
// The relay is a separate binary built from this plugin's source, so it serves
// ClusterService under `w17.contrib.cluster`. The control plane is not: its
// copy of the contract is STAGED into the activating project, and staging
// renames the proto package to `<domain package>.<registered_as>` — so the
// generated client of an activation called `codegen` in domain `console` dials
// `/console.codegen.ClusterService/…`, a service no relay has. The messages are
// unaffected (protobuf encodes field numbers, not names); only the method path
// carries the package. Every call to a relay goes through relayClient, which
// names the relay's path. (Found live: the first activated control plane
// answered every reservation "0 placeable" — unknown service.)
const relayService = "/w17.contrib.cluster.ClusterService/"

var scheduleTaskStream = grpc.StreamDesc{StreamName: "ScheduleTask", ServerStreams: true}

// relayClient is ClusterService as a relay serves it.
type relayClient struct{ cc grpc.ClientConnInterface }

func newRelayClient(cc grpc.ClientConnInterface) relayClient { return relayClient{cc: cc} }

func (c relayClient) RelayStats(ctx context.Context, in *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	out := new(pb.RelayStatsResp)
	return out, c.cc.Invoke(ctx, relayService+"RelayStats", in, out)
}

func (c relayClient) DrainRelay(ctx context.Context, in *pb.DrainRelayReq) (*pb.DrainRelayResp, error) {
	out := new(pb.DrainRelayResp)
	return out, c.cc.Invoke(ctx, relayService+"DrainRelay", in, out)
}

func (c relayClient) ExchangeWorkers(ctx context.Context, in *pb.ExchangeWorkersReq) (*pb.ExchangeWorkersResp, error) {
	out := new(pb.ExchangeWorkersResp)
	return out, c.cc.Invoke(ctx, relayService+"ExchangeWorkers", in, out)
}

func (c relayClient) IssueRegistrationCode(ctx context.Context, in *pb.IssueRegistrationCodeReq) (*pb.IssueRegistrationCodeResp, error) {
	out := new(pb.IssueRegistrationCodeResp)
	return out, c.cc.Invoke(ctx, relayService+"IssueRegistrationCode", in, out)
}

func (c relayClient) ReserveTask(ctx context.Context, in *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	out := new(pb.ReservationState)
	return out, c.cc.Invoke(ctx, relayService+"ReserveTask", in, out)
}

func (c relayClient) GetReservation(ctx context.Context, in *pb.GetReservationReq) (*pb.ReservationState, error) {
	out := new(pb.ReservationState)
	return out, c.cc.Invoke(ctx, relayService+"GetReservation", in, out)
}

func (c relayClient) CancelReservation(ctx context.Context, in *pb.CancelReservationReq) (*pb.CancelReservationResp, error) {
	out := new(pb.CancelReservationResp)
	return out, c.cc.Invoke(ctx, relayService+"CancelReservation", in, out)
}

func (c relayClient) ScheduleTask(ctx context.Context, in *pb.ScheduleTaskReq) (grpc.ServerStreamingClient[pb.ScheduleTaskEvent], error) {
	stream, err := c.cc.NewStream(ctx, &scheduleTaskStream, relayService+"ScheduleTask")
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[pb.ScheduleTaskReq, pb.ScheduleTaskEvent]{ClientStream: stream}
	if err := x.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}
