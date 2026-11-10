package tunnel

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// panicky panics in a unary and in a server-streaming method.
type panicky struct {
	pb.UnimplementedClusterServiceServer
}

func (panicky) RelayStats(context.Context, *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	panic("a handler bug")
}

func (panicky) ScheduleTask(*pb.ScheduleTaskReq, grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
	panic("a handler bug")
}

func serveWith(t *testing.T, opts []grpc.ServerOption, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(opts...)
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// A handler's panic on a server built with RecoverServerOptions is answered
// Internal without its value, and the process — here the test binary, on a
// relay every queue and tunnel — survives to answer the next call. Without
// the net grpc-go lets the panic end the process.
func TestRecoverServerOptions_APanicIsInternalAndTheServerLives(t *testing.T) {
	for name, opts := range map[string][]grpc.ServerOption{
		"recover":                        RecoverServerOptions(),
		"work (proxy and worker tunnel)": WorkServerOptions(),
	} {
		cc := serveWith(t, opts, func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, panicky{}) })
		c := pb.NewClusterServiceClient(cc)
		for range 2 {
			_, err := c.RelayStats(bounded(t), &pb.RelayStatsReq{})
			if st := status.Convert(err); st.Code() != codes.Internal || st.Message() == "a handler bug" {
				t.Fatalf("%s: unary panic answered %v %q, want Internal without the value", name, st.Code(), st.Message())
			}
		}
		stream, err := c.ScheduleTask(bounded(t), &pb.ScheduleTaskReq{})
		if err == nil {
			_, err = stream.Recv()
		}
		if status.Code(err) != codes.Internal {
			t.Errorf("%s: streaming panic answered %v, want Internal", name, err)
		}
	}
}

// The proxy's picker runs inside the proxy's stream handler: a panic there is
// Internal for that caller, not the end of the relay.
func TestProxy_APanickingPickerIsInternal(t *testing.T) {
	cc := proxy(t, func(context.Context, string) (Backend, error) { panic("a picker bug") })
	c := pb.NewClusterServiceClient(cc)
	for range 2 {
		if _, err := c.RelayStats(bounded(t), &pb.RelayStatsReq{}); status.Code(err) != codes.Internal {
			t.Fatalf("a panicking picker answered %v, want Internal", err)
		}
	}
}
