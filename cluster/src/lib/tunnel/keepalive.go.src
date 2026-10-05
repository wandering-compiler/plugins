package tunnel

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// MaxMessage is the largest single message any hop of a relay carries, in
// either direction: 256 MiB, what w17ctl allows itself.
//
// gRPC's default is 4 MiB and it is enforced PER MESSAGE — a stream does not
// lift it, because a stream is a sequence of messages and each is checked. The
// caller's limit is not the one that matters if any hop between it and the
// worker is lower, so one constant feeds every hop: the proxy server, the
// relay's client over a tunnel, and the worker's server on it.
const MaxMessage = 256 << 20

// Keepalive timing, ONE set for every connection in the cluster.
//
// Without it a peer that vanishes without a RST — a spot VM reclaimed, a cable
// pulled, a NAT that forgot the mapping — leaves the other end holding an
// ESTABLISHED socket that nothing will ever read EOF from. A tunnel would stay
// a selectable backend, a caller's stream would hang until its own deadline.
//
// The two halves are related and live together for that reason: a client that
// pings faster than the server's enforcement allows collects strikes and is
// cut with GOAWAY "too_many_pings" — every idle connection torn down on a loop.
// KeepaliveMinTime must stay at or below KeepaliveTime, and an outside client
// (w17ctl dialling a relay's proxy) must ping no faster than KeepaliveMinTime.
const (
	// KeepaliveTime is how long a connection may be silent before a ping.
	KeepaliveTime = 30 * time.Second
	// KeepaliveTimeout is how long a ping may go unanswered before the
	// connection is declared dead.
	KeepaliveTimeout = 10 * time.Second
	// KeepaliveMinTime is the shortest ping interval a server tolerates: 10 s,
	// the floor grpc-go clamps every client to, so no grpc-go client can be cut
	// for pinging too often whatever it configured. Well below KeepaliveTime.
	KeepaliveMinTime = 10 * time.Second
)

// ClientKeepalive is the dial option every client in the cluster uses.
//
// PermitWithoutStream because the connections that most need watching are
// idle ones: a tunnel with no call on it, a worker's attach stream between
// status changes.
func ClientKeepalive() grpc.DialOption {
	return grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                KeepaliveTime,
		Timeout:             KeepaliveTimeout,
		PermitWithoutStream: true,
	})
}

// ServerKeepalive is what every server in the cluster is built with: it pings
// its peer on the same schedule, and it ACCEPTS the clients' pings — including
// on a connection with no active stream, which gRPC's default refuses.
func ServerKeepalive() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    KeepaliveTime,
			Timeout: KeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             KeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	}
}

// WorkServerOptions are what a server CARRYING WORK is built with — the
// relay's proxy and the worker's server on its tunnel: keepalive, and the
// message cap in both directions.
func WorkServerOptions() []grpc.ServerOption {
	return append(ServerKeepalive(),
		grpc.MaxRecvMsgSize(MaxMessage),
		grpc.MaxSendMsgSize(MaxMessage),
	)
}

// workDialOptions are the client half of WorkServerOptions, for the relay's
// client over a tunnel.
func workDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		ClientKeepalive(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxMessage),
			grpc.MaxCallSendMsgSize(MaxMessage),
		),
	}
}
