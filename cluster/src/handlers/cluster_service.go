package handlers

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// Relay is what the scheduler needs to know about one registered relay. A
// narrow struct rather than the generated row, so this package does not depend
// on the shape of a table it does not own.
type Relay struct {
	ID          string
	Name        string
	URL         string
	Fingerprint string
}

// ErrRelayNotFound is RelayStore.Get's answer for an id the registry does not
// hold.
var ErrRelayNotFound = errors.New("cluster: no relay with that id")

// RelayStore is the seam onto the plugin's own tables, wired by
// RegisterPlugin. An interface rather than the generated client directly,
// because scheduling is worth testing against a store that cannot fail in
// ways a real database would never produce.
type RelayStore interface {
	// ListEnabled returns the relays scheduling may consider, in any order.
	ListEnabled(ctx context.Context) ([]Relay, error)
	// Get returns one relay by registry id, enabled or not, or
	// ErrRelayNotFound. Used where an id arrives from outside — an operator's
	// selection, a reservation handle — rather than from a listing.
	Get(ctx context.Context, id string) (Relay, error)
	// RecordReached and RecordFailed maintain the observed-state CACHE on the
	// row. Both are best-effort: a scheduling decision that succeeded must not
	// be failed because bookkeeping about it could not be written.
	RecordReached(ctx context.Context, id string) error
	RecordFailed(ctx context.Context, id, msg string) error
}

// Dialer opens a pinned connection to one relay. Injected so a test can stand
// a relay up in-process without certificates.
type Dialer func(target, fingerprint string) (*grpc.ClientConn, error)

// ClusterServiceHandler serves the project's side of ClusterService.
//
// # The relay speaks the SAME contract
//
// A relay implements ClusterService too, and this handler is a STREAM PROXY
// over it: it chooses a relay and forwards that relay's events to the caller.
// One contract describes both hops.
//
// The alternative — a second, relay-facing proto — was considered and is
// worse: two contracts describing one conversation drift, and the drift shows
// up as a scheduling bug rather than a compile error. The only thing the relay
// cannot fill in is its own registry NAME, which it has never been told; this
// handler stamps it on the way past.
//
// # It holds no load of its own
//
// Which relay to use is decided from each relay's own RelayStats, asked fresh
// for every placement. An earlier version counted the callers THIS process was
// holding open per relay; a grant ends that hold at once, so on a pool below
// capacity every relay read zero, and no console replica knew what any other
// had placed. The relay is the one place that sees all of its load.
type ClusterServiceHandler struct {
	pb.UnimplementedClusterServiceServer

	// Relays is the registry. Never nil after RegisterPlugin.
	Relays RelayStore

	// Workers is the worker registry. Never nil after RegisterPlugin.
	Workers WorkerStore

	// Dial opens the management connection. Never nil after RegisterPlugin.
	Dial Dialer

	// DialTimeout bounds how long ONE relay may take to answer before it is
	// treated as unreachable and the next is tried. Zero means a default.
	//
	// It exists because grpc.NewClient is LAZY: without waiting for the
	// connection to come up, "dial" returns instantly for a black-holed relay
	// and the failure surfaces as the caller's own deadline expiring, with the
	// pool never falling through to a healthy one.
	DialTimeout time.Duration

	// rotate breaks ties, and carries the spread on an idle pool.
	//
	// The tiebreak used to be the relay NAME, which is stable and therefore
	// always picks the same relay — so below capacity, where every load is
	// zero, the alphabetically first relay took every task and the rest idled
	// (a consumer, 2026-09-25). For a pool whose POINT is spreading work over
	// several machines and addresses, that turned the feature off during
	// exactly the conditions it is normally in.
	rotate atomic.Uint64
}

func (h *ClusterServiceHandler) dialTimeout() time.Duration {
	if h.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return h.DialTimeout
}
