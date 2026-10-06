package relayserver

import (
	"context"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
)

// BanInterceptors apply the ban set the control plane sends on EVERY call to
// the management server, before the call itself runs.
//
// An interceptor rather than a field on each request, because the rule is
// "every call carries it" and a field is a promise each new method has to
// remember to keep. A relay holds bans in memory only; with them on every call,
// one that restarted is corrected by the first contact — which, since every
// placement begins with one, comes before any work is placed on it.
//
// A call WITHOUT the header changes nothing (workeradmit.BansFrom): absent is
// not "nobody is banned", and reading it that way would let any call that
// happened to lack the header lift every ban at once.
func BanInterceptors(reg *workeradmit.Registry) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	apply := func(ctx context.Context) {
		if bans, ok := workeradmit.BansFrom(ctx); ok {
			reg.SetBanned(bans)
		}
	}
	unary := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		apply(ctx)
		return h(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		apply(ss.Context())
		return h(srv, ss)
	}
	return unary, stream
}

// BanServerOptions installs BanInterceptors on a server.
func BanServerOptions(reg *workeradmit.Registry) []grpc.ServerOption {
	u, s := BanInterceptors(reg)
	return []grpc.ServerOption{grpc.ChainUnaryInterceptor(u), grpc.ChainStreamInterceptor(s)}
}
