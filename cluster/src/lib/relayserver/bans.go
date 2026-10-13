package relayserver

import (
	"context"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// BanInterceptors apply the ban set the control plane sends on EVERY call to
// the management server, before the call itself runs.
//
// An interceptor rather than a field on each request, because the rule is
// "every call carries it" and a field is a promise each new method has to
// remember to keep. With it on every contact, a relay that restarted without
// its saved set is corrected by the first one — which, since every placement
// begins with one, comes before any work is placed on it.
//
// A call carries either the complete set with its version, or — to a relay
// that confirmed holding that version — the version alone. A version alone
// that is newer than the set held is REFUSED with BAN_SET_NEEDED before the
// call runs, and the control plane sends it again with the set: the call is
// never served under a set older than the one the control plane knows of.
// Either way the answer names the version now held (BannedHeldHeader).
//
// A call WITHOUT either header changes nothing (workeradmit.BansFrom): absent
// is not "nobody is banned", and reading it that way would let any call that
// happened to lack the header lift every ban at once.
func BanInterceptors(reg *workeradmit.Registry) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	apply := func(ctx context.Context, setHeader func(metadata.MD) error) error {
		version := workeradmit.BanVersionFrom(ctx)
		bans, sent := workeradmit.BansFrom(ctx)
		switch {
		case sent:
			reg.SetBannedAt(bans, version)
		case version == 0:
			return nil
		case !reg.Current(version):
			return refusal.New(codes.FailedPrecondition, refusal.BanSetNeeded,
				"relay: the ban set named is newer than the one held — send it")
		}
		// Best effort: a header that cannot be set costs the control plane
		// the complete set on its next call, nothing else.
		_ = setHeader(metadata.Pairs(workeradmit.BannedHeldHeader, strconv.FormatInt(reg.Version(), 10)))
		return nil
	}
	unary := func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if err := apply(ctx, func(md metadata.MD) error { return grpc.SetHeader(ctx, md) }); err != nil {
			return nil, err
		}
		return h(ctx, req)
	}
	stream := func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		if err := apply(ss.Context(), ss.SetHeader); err != nil {
			return err
		}
		return h(srv, ss)
	}
	return unary, stream
}

// BanServerOptions installs BanInterceptors on a server.
func BanServerOptions(reg *workeradmit.Registry) []grpc.ServerOption {
	u, s := BanInterceptors(reg)
	return []grpc.ServerOption{grpc.ChainUnaryInterceptor(u), grpc.ChainStreamInterceptor(s)}
}
