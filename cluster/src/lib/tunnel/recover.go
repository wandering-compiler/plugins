package tunnel

import (
	"context"
	"log"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoverServerOptions are the panic net every gRPC server in the cluster is
// built with, FIRST among its options so it is the outermost chained
// interceptor: a panic in a handler or in any interceptor after it (the ban
// set's, a project's own on the worker) is logged with its stack and answered
// Internal, the panic value never reaching the peer.
//
// These servers are built by hand, not by the w17 runtime, so nothing else
// gives them the recovery a generated server has — and grpc-go does not
// recover a handler's panic: it ends the PROCESS. On a relay that is every
// queue, ticket, reservation, attached worker and running call at once, for
// one bad request.
//
// Only the recovery is taken from the w17 server chain, and implemented here
// rather than imported: the SDK's interceptor reports through its telemetry
// package, which would pull the SDK's whole runtime (database drivers,
// exporters) into the relay binary. These are infrastructure ports, not
// product surfaces: the management port's peer is the pinned control plane,
// the worker ports authenticate by this relay's CA and the proxy by ticket —
// none carries a principal (the proxy strips the gateway-owned metadata), so
// there is no principal to read; the relay's peers dial without a retry
// policy, so there is no replay to mark against; and the relay keeps its own
// shutdown (drain, then bounded stops) and its own log.
func RecoverServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(recoverUnary),
		grpc.ChainStreamInterceptor(recoverStream),
	}
}

func recoverUnary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
	defer recovered(info.FullMethod, &err)
	return handler(ctx, req)
}

func recoverStream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer recovered(info.FullMethod, &err)
	return handler(srv, ss)
}

// recovered turns a panic in flight into a logged stack and an Internal
// answer naming only the method.
func recovered(method string, err *error) {
	r := recover()
	if r == nil {
		return
	}
	log.Printf("PANIC serving %s: %v\n%s", method, r, debug.Stack())
	*err = status.Errorf(codes.Internal, "%s: internal error", method)
}
