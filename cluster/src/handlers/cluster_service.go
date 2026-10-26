package handlers

import (
	"context"
	"errors"
	"sync"
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
	// ListAll returns every registered relay, enabled or not. A ban is sent
	// to all of them: a disabled relay takes no placements, but its workers
	// still renew their certificates there.
	ListAll(ctx context.Context) ([]Relay, error)
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
// a relay up in-process without certificates. The handler keeps what it
// returns open and shares it between calls (see relayConn).
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
	// zero, the alphabetically first relay took every task and the rest idled.
	// For a pool whose POINT is spreading work over
	// several machines and addresses, that turned the feature off during
	// exactly the conditions it is normally in.
	rotate atomic.Uint64

	// bans caches the ban set for banCacheTTL. Every call to a relay carries
	// the set, and reading it from the registry each time put two queries on
	// the hot path of every placement and poll. A decision made through this
	// replica drops the cache at once (forgetBans); one made through another
	// replica reaches it within the TTL, and the deciding replica has already
	// pushed the new set to every relay.
	//
	// bansGen counts decisions through this replica. A read that began before
	// one is not cached: it may hold the set from before the decision, and
	// caching it would undo forgetBans for a whole TTL.
	bansMu   sync.Mutex
	bans     []string
	bansVer  int64
	bansAt   time.Time
	bansFull bool
	bansGen  uint64

	// BanReadTimeout bounds the registry reads of one ban-set delivery (the
	// set and the relay list). Zero means banReadTimeout.
	BanReadTimeout time.Duration

	// delivered is the outcome of the last ban-set delivery, per relay id and
	// for the registry reads (see delivery), so the periodic delivery
	// logs a change of state — a relay or the registry failing, and
	// recovering — and not the same failure every few minutes.
	deliveredMu sync.Mutex
	delivered   map[string]delivery

	// written remembers what this replica last wrote onto each relay's row,
	// and when, so an unchanged state is written at most once per
	// reachedEvery instead of on every placement (see record).
	writtenMu sync.Mutex
	written   map[string]writtenState

	// conns is one shared management connection per relay (see relayConn).
	connsMu     sync.Mutex
	conns       map[string]*relayConn
	connsClosed bool

	// obs* queue the observed state for the background flush (see observe).
	obsMu      sync.Mutex
	obsPending map[string]observation
	obsRunning bool
	obsIdle    *sync.Cond
}

// banCacheTTL bounds how stale the ban set this replica sends may be when
// another replica made the decision.
const banCacheTTL = 2 * time.Second

// reachedEvery is how often an unchanged observed state — a reachable relay's
// last_seen_at, or an unreachable one's error — is written again.
const reachedEvery = 30 * time.Second

// cachedBans returns the ban set and its version, from the cache while fresh.
// A read error is returned, never a stale set in its place: the caller refuses
// the call (see withBans).
//
// Once the cache is older than banCacheTTL, the version alone is read first:
// a decision always moves it forward (WorkerStore.Decide), so an unchanged
// version is an unchanged set, and the set — which grows with every ban ever
// taken — is read again only when it changed.
func (h *ClusterServiceHandler) cachedBans(ctx context.Context) ([]string, int64, error) {
	h.bansMu.Lock()
	if h.bansFull && time.Since(h.bansAt) < banCacheTTL {
		bans, v := h.bans, h.bansVer
		h.bansMu.Unlock()
		return bans, v, nil
	}
	full, cachedVer, gen := h.bansFull, h.bansVer, h.bansGen
	h.bansMu.Unlock()
	if full && cachedVer != 0 {
		v, err := h.Workers.BanVersion(ctx)
		if err != nil {
			return nil, 0, err
		}
		if v == cachedVer {
			h.bansMu.Lock()
			if h.bansFull && h.bansGen == gen && h.bansVer == v {
				h.bansAt = time.Now()
				bans := h.bans
				h.bansMu.Unlock()
				return bans, v, nil
			}
			h.bansMu.Unlock()
		}
	}
	return h.readBans(ctx)
}

// readBans reads the ban set from the registry and caches it, unless a
// decision through this replica happened while it was being read, or the
// cache already holds a newer version.
func (h *ClusterServiceHandler) readBans(ctx context.Context) ([]string, int64, error) {
	h.bansMu.Lock()
	gen := h.bansGen
	h.bansMu.Unlock()
	bans, v, err := h.Workers.Banned(ctx)
	if err != nil {
		return nil, 0, err
	}
	h.bansMu.Lock()
	if gen == h.bansGen && (!h.bansFull || v >= h.bansVer) {
		h.bans, h.bansVer, h.bansAt, h.bansFull = bans, v, time.Now(), true
	}
	h.bansMu.Unlock()
	return bans, v, nil
}

// forgetBans drops the cached ban set, after a decision through this replica.
func (h *ClusterServiceHandler) forgetBans() {
	h.bansMu.Lock()
	h.bansFull = false
	h.bansGen++
	h.bansMu.Unlock()
}

func (h *ClusterServiceHandler) dialTimeout() time.Duration {
	if h.DialTimeout <= 0 {
		return 5 * time.Second
	}
	return h.DialTimeout
}
