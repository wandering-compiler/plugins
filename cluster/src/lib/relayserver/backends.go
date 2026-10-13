package relayserver

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// TicketHeader carries the grant a caller redeems at the proxy.
//
// Lowercase because gRPC metadata keys are, and named without the `x-w17-`
// prefix on purpose: that namespace is for metadata the gateway has VERIFIED,
// and a value the caller supplies must not look like one.
const TicketHeader = "w17-cluster-ticket"

// Backends is the set of workers currently attached to this relay.
//
// A worker holds ONE tunnel connection and HTTP/2 multiplexes every call over
// it, so a socket is not a slot. How much a worker can take is what IT said on
// its attach stream, and this is where the two halves meet: the tunnel gives a
// fingerprint a connection, the attach stream gives the same fingerprint a
// capacity and a readiness.
//
// It is therefore also the relay's capacity model. The sum over workers that
// are connected AND ready is what the pool may grant, which is what stops an
// empty relay handing out tickets against nobody.
type Backends struct {
	mu sync.Mutex
	// pubMu orders capacity publishes (see publishLocked). Taken BEFORE mu,
	// never inside it.
	pubMu sync.Mutex
	conns map[string]*backend // fingerprint → tunnel
	// retired holds tunnels that take no new work but still carry running
	// work: replaced by a newer tunnel from the same key (a worker that
	// renewed reconnects), or past their certificate's expiry. Each closes
	// when its last call ends, or at the end of its grace (see ExpireAt).
	retired  map[string][]*backend
	profiles map[string]workerProfile // fingerprint → what the worker said
	order    []string                 // rotation cursor over conns
	next     int

	// gen numbers every tunnel and every attach stream, monotonically.
	//
	// A fingerprint is a MACHINE, not a connection, and the same machine
	// reconnects. Without a generation, a late unwind of the old attachment
	// erases the new one's profile, and a proxy call still finishing on the
	// old tunnel releases a slot booked on the new one — both of which look
	// like a worker that mysteriously went quiet or overfilled. Every write
	// carries the generation it belongs to and is dropped if it is stale.
	gen uint64

	// onCapacity is told the new total whenever it changes. The relay wires
	// this to the pool, so a worker attaching promotes whoever is queued
	// instead of making them wait for the next arrival.
	onCapacity func(int)

	// expiryGrace is how long work already running on a tunnel whose
	// certificate expired may go on before the tunnel is closed under it
	// (see ExpireAt). Zero closes it at expiry.
	expiryGrace time.Duration
}

// backend is one tunnel and the work booked on it. Counted per CONNECTION so
// a reconnect starts at zero rather than inheriting the old socket's bookings.
type backend struct {
	conn     *grpc.ClientConn
	gen      uint64
	inflight int

	// graceStarted: the certificate the tunnel was opened with has expired
	// while work ran on it, and the grace timer is running (ExpireAt).
	graceStarted bool
	// timers fire on this tunnel's expiry and grace; stopped when it leaves.
	timers []*time.Timer
}

func (be *backend) stopTimers() {
	for _, t := range be.timers {
		t.Stop()
	}
}

// workerProfile is what a worker claimed about itself on its attach stream.
// Absent until it says something: a tunnel with no profile yet contributes no
// capacity, which is the safe direction.
type workerProfile struct {
	slots uint32
	ready bool
	gen   uint64
}

func NewBackends() *Backends {
	return &Backends{
		conns:    map[string]*backend{},
		retired:  map[string][]*backend{},
		profiles: map[string]workerProfile{},
	}
}

// NewAttachment issues the generation one attach stream writes under.
func (b *Backends) NewAttachment() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gen++
	return b.gen
}

// OnCapacityChange registers the sink for capacity updates and reports the
// current value once, so a caller wiring this at boot starts in step.
func (b *Backends) OnCapacityChange(f func(int)) {
	b.mu.Lock()
	b.onCapacity = f
	n := b.capacityLocked()
	b.mu.Unlock()
	if f != nil {
		f(n)
	}
}

// capacityLocked sums what the attached, ready workers can take.
//
// A worker counts only with BOTH halves present: a tunnel (it can be reached)
// and a profile saying ready (it wants work). Draining and unhealthy workers
// fall out here, which is what makes a drain take effect without dropping the
// socket that the work already running is travelling over.
func (b *Backends) capacityLocked() int {
	total := 0
	for fp := range b.conns {
		if pr, ok := b.profiles[fp]; ok && pr.ready {
			total += int(pr.slots)
		}
	}
	return total
}

// removeLocked drops a worker's current tunnel. The single place a current
// tunnel leaves, so nothing can forget to republish the capacity.
func (b *Backends) removeLocked(fingerprint string) {
	if be, ok := b.conns[fingerprint]; ok {
		be.stopTimers()
	}
	b.detachLocked(fingerprint)
}

// detachLocked takes fingerprint's current tunnel out of the selectable set,
// leaving its timers running.
func (b *Backends) detachLocked(fingerprint string) {
	delete(b.conns, fingerprint)
	for i, f := range b.order {
		if f == fingerprint {
			b.order = append(b.order[:i], b.order[i+1:]...)
			break
		}
	}
}

// retireLocked keeps be, a tunnel already out of the selectable set, for the
// work running on it, or returns its connection to close now when nothing
// runs on it.
func (b *Backends) retireLocked(fingerprint string, be *backend) *grpc.ClientConn {
	if be.inflight == 0 {
		be.stopTimers()
		return be.conn
	}
	b.retired[fingerprint] = append(b.retired[fingerprint], be)
	return nil
}

// retiredLocked finds a retired tunnel by its connection or, with conn nil,
// by its generation.
func (b *Backends) retiredLocked(fingerprint string, conn *grpc.ClientConn, gen uint64) *backend {
	for _, be := range b.retired[fingerprint] {
		if (conn != nil && be.conn == conn) || (conn == nil && be.gen == gen) {
			return be
		}
	}
	return nil
}

// dropRetiredLocked forgets a retired tunnel and stops its timers.
func (b *Backends) dropRetiredLocked(fingerprint string, be *backend) {
	be.stopTimers()
	list := b.retired[fingerprint]
	for i, x := range list {
		if x == be {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(b.retired, fingerprint)
	} else {
		b.retired[fingerprint] = list
	}
}

// publishLocked recomputes and hands the total out, OUTSIDE the lock.
//
// The sink is the pool, and the pool promotes queued callers synchronously.
// Calling it while holding this mutex would run pool code under a relay lock
// for no reason and invites an ordering nobody can see.
//
// The returned func re-reads the total when it runs, under pubMu, rather than
// carrying the value computed here: publishes run AFTER b.mu is released and
// from different goroutines (attach streams, tunnel watchers), and a value
// captured early could reach the pool after a newer one — leaving it at, say,
// capacity 0 with a ready worker attached, and nothing queued ever promoted.
// Serialised and re-read, the last publish always carries the current total.
func (b *Backends) publishLocked() func() {
	if b.onCapacity == nil {
		return func() {}
	}
	return func() {
		b.pubMu.Lock()
		defer b.pubMu.Unlock()
		b.mu.Lock()
		n, f := b.capacityLocked(), b.onCapacity
		b.mu.Unlock()
		f(n)
	}
}

// SetProfile records what a worker says it can take and whether it wants work.
//
// Called from the attach stream, on the announcement and on every status
// change after it. Idempotent, and safe before the tunnel exists — a worker
// that announces and then opens its tunnel arrives in that order, and the
// capacity simply appears when the second half does.
func (b *Backends) SetProfile(fingerprint string, gen uint64, slots uint32, ready bool) {
	b.mu.Lock()
	// A write from a SUPERSEDED attachment is dropped. The same machine
	// reconnecting gets a higher generation, and the old stream unwinding
	// afterwards must not overwrite what the new one said.
	if cur, ok := b.profiles[fingerprint]; ok && cur.gen > gen {
		b.mu.Unlock()
		return
	}
	b.profiles[fingerprint] = workerProfile{slots: slots, ready: ready, gen: gen}
	publish := b.publishLocked()
	b.mu.Unlock()
	publish()
}

// ClearProfile forgets what a worker claimed, when its attach stream ends.
//
// Separate from Remove because the two connections are separate: a worker
// whose attach stream dropped is no longer declaring itself available even if
// its tunnel is briefly still up, and it must stop attracting new work.
func (b *Backends) ClearProfile(fingerprint string, gen uint64) {
	b.mu.Lock()
	// Only the CURRENT attachment may clear. Without this, a reconnect that
	// beats the old stream's unwind has its brand-new profile deleted by the
	// dying one, and a healthy worker drops out of the capacity sum until it
	// happens to send another status.
	if cur, ok := b.profiles[fingerprint]; !ok || cur.gen != gen {
		b.mu.Unlock()
		return
	}
	delete(b.profiles, fingerprint)
	publish := b.publishLocked()
	b.mu.Unlock()
	publish()
}

// Add registers a worker's tunnel. A second tunnel from the same fingerprint
// REPLACES the first for new work — a worker that reconnected has a live
// socket and possibly a dead one, and keeping both selectable would send half
// the work into the dead one. The old tunnel is closed at once if nothing runs
// on it; otherwise it is retired and closes when its last call ends. A worker
// that renewed its certificate opens a new tunnel with it while work is still
// running on the old one, and closing the old one would cut that work.
//
// It also WATCHES the connection. Without that the entry outlives the socket:
// the worker hangs up, the fingerprint stays selectable, and later tickets are
// sent into a dead connection while Count still reports a worker. The failure
// looks like a flaky relay and points nowhere near the cause.
func (b *Backends) Add(fingerprint string, conn *grpc.ClientConn) uint64 {
	b.mu.Lock()
	var replaced *grpc.ClientConn
	if old, ok := b.conns[fingerprint]; ok {
		replaced = b.retireLocked(fingerprint, old)
	} else {
		b.order = append(b.order, fingerprint)
	}
	b.gen++
	gen := b.gen
	// inflight counts THIS connection's calls. The old tunnel's bookings stay
	// with it (retired, released when its calls end), and the machine's room
	// is counted across both (busyLocked).
	b.conns[fingerprint] = &backend{conn: conn, gen: gen}
	publish := b.publishLocked()
	b.mu.Unlock()
	// Closed AFTER unlocking, like every Close here: closing runs the tunnel's
	// close hook, which takes b.mu (RemoveConn), and gRPC's own locks sit in
	// between — holding b.mu across a Close is a lock-order inversion that
	// deadlocked the relay live.
	if replaced != nil {
		_ = replaced.Close()
	}
	publish()
	// Connect eagerly. grpc.NewClient is LAZY, so without this the conn sits
	// in Idle until the first call goes through it — and a tunnel that dies
	// before any work arrives would never have left Idle for the watcher to
	// notice it leaving Ready. The socket is already open; this only makes the
	// state machine say so.
	conn.Connect()
	go b.watch(fingerprint, conn, gen)
	return gen
}

// watch drops a backend once its tunnel can no longer carry anything.
//
// A tunnel is SINGLE USE by construction — the socket was the worker's, the
// dialer hands it over once, and a reconnect is refused — so the connection
// can never recover. The signal is therefore leaving Ready for anything but a
// transient Connecting.
//
// Two shapes were tried first and are recorded so nobody repeats them.
// Waiting for Shutdown waits forever: a broken tunnel parks in
// TransientFailure retrying a dial that is refused by construction. And
// hanging removal on the socket's Close never fires: gRPC keeps its end open
// and goes on redialling, so the close hook the worker side relies on has no
// counterpart here.
func (b *Backends) watch(fingerprint string, conn *grpc.ClientConn, gen uint64) {
	ctx := context.Background()
	ready := false
	for {
		st := conn.GetState()
		if st == connectivity.Ready {
			ready = true
		} else if ready && st != connectivity.Connecting {
			break
		} else if st == connectivity.Shutdown {
			break
		}
		if !conn.WaitForStateChange(ctx, st) {
			break
		}
	}
	b.mu.Lock()
	// Only if it is still THE SAME connection: a worker that reconnected has
	// already replaced this entry, and dropping the new tunnel because the old
	// one finally noticed it was dead would disconnect a healthy worker.
	// Only if it is still the worker's CURRENT tunnel. A retired one is
	// already out of the selectable set and closes with its last call.
	cur, ok := b.conns[fingerprint]
	if !ok || cur.gen != gen {
		b.mu.Unlock()
		return
	}
	// RETIRED, not closed under its calls. Leaving Ready is also what a
	// worker stopping gracefully looks like (GOAWAY): the calls still
	// running on it go on, and closing the connection here would cancel
	// them. On a socket that really died they fail on their own, and the
	// last one to end closes it (release).
	b.detachLocked(fingerprint)
	closing := b.retireLocked(fingerprint, cur)
	// Republished HERE too. This is the path a dead tunnel actually takes —
	// Remove is the deliberate one — and without it the pool kept the departed
	// worker's slots and went on granting tickets that failed at the proxy
	// until some unrelated attach happened to refresh the total.
	publish := b.publishLocked()
	b.mu.Unlock()
	if closing != nil {
		_ = closing.Close() // outside b.mu — see Add
	}
	publish()
}

// SetExpiryGrace sets how long running work may finish on a tunnel whose
// certificate expired; see ExpireAt. The relay wires its --drain-timeout.
func (b *Backends) SetExpiryGrace(d time.Duration) {
	b.mu.Lock()
	b.expiryGrace = d
	b.mu.Unlock()
}

// ExpireAt retires conn, fingerprint's tunnel, at notAfter — when the
// certificate it was opened with stops being valid.
//
// The handshake checked the certificate once, and a tunnel can stay open for
// longer than any certificate lasts, so without this an expired credential
// kept a connected backend for as long as the worker held the socket. At
// expiry the tunnel takes no new work at once and stops counting toward
// capacity; the work already running on it may finish within the expiry grace,
// after which the tunnel is closed and whatever is still running ends as
// WORKER_LOST. A worker that renewed has already opened a new tunnel with the
// new certificate (see Add), so this normally finds the old one idle or
// already gone.
//
// Expiry is routine, so running work gets the grace; a ban is not, and
// DropWhere cuts at once.
func (b *Backends) ExpireAt(fingerprint string, conn *grpc.ClientConn, notAfter time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	be, ok := b.conns[fingerprint]
	if !ok || be.conn != conn {
		if be = b.retiredLocked(fingerprint, conn, 0); be == nil {
			return
		}
	}
	be.timers = append(be.timers, time.AfterFunc(time.Until(notAfter), func() {
		b.expire(fingerprint, conn)
	}))
}

// expire stops conn taking work, and closes it now if nothing runs on it or
// after the grace if something does.
func (b *Backends) expire(fingerprint string, conn *grpc.ClientConn) {
	b.mu.Lock()
	var be *backend
	var closing *grpc.ClientConn
	if cur, ok := b.conns[fingerprint]; ok && cur.conn == conn {
		be = cur
		b.detachLocked(fingerprint)
		closing = b.retireLocked(fingerprint, be)
	} else if be = b.retiredLocked(fingerprint, conn, 0); be == nil {
		b.mu.Unlock()
		return
	}
	if closing == nil && !be.graceStarted {
		be.graceStarted = true
		if b.expiryGrace <= 0 {
			b.dropRetiredLocked(fingerprint, be)
			closing = conn
		} else {
			be.timers = append(be.timers, time.AfterFunc(b.expiryGrace, func() {
				b.RemoveConn(fingerprint, conn)
			}))
		}
	}
	publish := b.publishLocked()
	b.mu.Unlock()
	if closing != nil {
		_ = closing.Close() // outside b.mu — see Add
	}
	publish()
}

// DropWhere closes and forgets the tunnels of every worker drop selects —
// used when a worker is banned. Its current tunnel and any retired one alike:
// closing a connection ends the calls still running on it too, so a ban stops
// the work, not only the next piece of it.
//
// drop runs under b.mu, so it must not call back into Backends.
//
// The PROFILE stays. It belongs to the attach stream, which ends on its own
// at its next poll and clears it under its own generation. Deleting it here
// left a worker banned and unbanned within one poll permanently out of the
// capacity sum: its attach stream never ended, so it never announced again,
// and the tunnel it reopened carried nothing. Without a tunnel the profile
// counts for nothing anyway (capacityLocked, take).
func (b *Backends) DropWhere(drop func(fingerprint string) bool) {
	b.mu.Lock()
	var closing []*grpc.ClientConn
	for fp, be := range b.conns {
		if drop(fp) {
			closing = append(closing, be.conn)
			b.removeLocked(fp)
		}
	}
	for fp, list := range b.retired {
		if drop(fp) {
			for _, be := range list {
				be.stopTimers()
				closing = append(closing, be.conn)
			}
			delete(b.retired, fp)
		}
	}
	if len(closing) == 0 {
		b.mu.Unlock()
		return
	}
	publish := b.publishLocked()
	b.mu.Unlock()
	for _, c := range closing {
		_ = c.Close() // outside b.mu — see Add
	}
	publish()
}

// RemoveConn drops a worker's tunnel when THAT connection ends — it hung up,
// or was denied while attached. Called from the tunnel's own close hook, which
// is the only signal that is both prompt and true for a single-use connection.
//
// Only if conn is still the worker's CURRENT tunnel: a worker opens a fresh
// tunnel for every run, so the old one's hook fires while its replacement is
// already serving, and removing by fingerprint alone disconnected a healthy
// worker.
func (b *Backends) RemoveConn(fingerprint string, conn *grpc.ClientConn) {
	b.mu.Lock()
	if cur, ok := b.conns[fingerprint]; ok && cur.conn == conn {
		b.removeLocked(fingerprint)
	} else if old := b.retiredLocked(fingerprint, conn, 0); old != nil {
		b.dropRetiredLocked(fingerprint, old)
	} else {
		b.mu.Unlock()
		return
	}
	publish := b.publishLocked()
	b.mu.Unlock()
	if conn != nil {
		_ = conn.Close() // outside b.mu — see Add
	}
	publish()
}

// Count reports how many workers are attached, ready or not. For an operator
// reading a screen; scheduling uses Capacity.
func (b *Backends) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.conns)
}

// Retiring reports how many tunnels take no new work but still carry calls:
// replaced by a newer tunnel from the same worker, or past their
// certificate's expiry. For an operator reading a screen, and for tests.
func (b *Backends) Retiring() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, list := range b.retired {
		n += len(list)
	}
	return n
}

// Capacity is what the attached, ready workers add up to.
func (b *Backends) Capacity() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capacityLocked()
}

// release records that a piece of work finished on ONE TUNNEL.
//
// Keyed by generation, not by fingerprint alone. A call still unwinding on a
// replaced tunnel would otherwise give back a slot booked on the replacement,
// and the new connection could then be overfilled past what the machine said
// it could take. A retired tunnel's last call closes it.
func (b *Backends) release(fingerprint string, gen uint64) {
	b.mu.Lock()
	if be, ok := b.conns[fingerprint]; ok && be.gen == gen {
		if be.inflight > 0 {
			be.inflight--
		}
		b.mu.Unlock()
		return
	}
	be := b.retiredLocked(fingerprint, nil, gen)
	if be == nil || be.inflight == 0 {
		b.mu.Unlock()
		return
	}
	be.inflight--
	if be.inflight > 0 {
		b.mu.Unlock()
		return
	}
	// The last call on a retired tunnel: nothing is left to wait for.
	b.dropRetiredLocked(fingerprint, be)
	publish := b.publishLocked()
	b.mu.Unlock()
	_ = be.conn.Close() // outside b.mu — see Add
	publish()
}

var errNoWorker = errors.New("no worker attached")

// busyLocked is how many calls a worker is running: on its current tunnel
// and on any retired one still finishing work. The slots it declared are the
// MACHINE's, so a worker that renewed and holds two tunnels is not given its
// slots twice.
func (b *Backends) busyLocked(fingerprint string) int {
	n := 0
	if be, ok := b.conns[fingerprint]; ok {
		n += be.inflight
	}
	for _, be := range b.retired[fingerprint] {
		n += be.inflight
	}
	return n
}

// take returns the attached worker with the most room, and books a slot on it.
//
// Admission is re-checked here and not only when the tunnel opened, because
// approval can be withdrawn while a worker is connected. Checking once at
// accept would leave a revoked machine receiving work until it happened to
// reconnect — which is to say, until it felt like it.
//
// MOST FREE SLOTS, not round-robin. A plain cursor moved one step per call
// whatever each machine was already carrying, so a four-slot box and a
// one-slot box were handed the same amount and the small one thrashed while
// the big one idled. Free slots weights the choice by what
// each machine actually said it can take.
//
// Draining and unhealthy workers are skipped: they keep their tunnel so the
// work already travelling over it can finish, and they take no more.
func (b *Backends) take(admitted func(string) bool) (*grpc.ClientConn, string, uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.order) == 0 {
		return nil, "", 0, errNoWorker
	}

	best, bestFree := "", 0
	for i := range b.order {
		// Start one past the last pick so equal-room workers alternate rather
		// than always resolving to the same one.
		fp := b.order[(b.next+1+i)%len(b.order)]
		pr, ok := b.profiles[fp]
		if !ok || !pr.ready {
			continue
		}
		if admitted != nil && !admitted(fp) {
			continue
		}
		if free := int(pr.slots) - b.busyLocked(fp); free > bestFree {
			best, bestFree = fp, free
		}
	}
	if best == "" {
		return nil, "", 0, errNoWorker
	}
	for i, fp := range b.order {
		if fp == best {
			b.next = i
			break
		}
	}
	be := b.conns[best]
	be.inflight++
	return be.conn, best, be.gen, nil
}

// TicketPicker is the proxy's admission: it redeems the caller's ticket and
// then hands back a worker.
//
// THE TICKET IS REDEEMED HERE, not when it was granted. A grant reserves a
// slot; redeeming converts the reservation into running work. Doing it at the
// proxy is what makes the reservation real — a caller that never arrives loses
// the slot to the TTL, and one that arrives twice with the same ticket finds
// it already spent.
func TicketPicker(pool *relaycore.Pool, backends *Backends, workers *workeradmit.Registry) tunnel.Picker {
	return func(ctx context.Context, _ string) (tunnel.Backend, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		vals := md.Get(TicketHeader)
		if len(vals) == 0 || vals[0] == "" {
			return tunnel.Backend{}, refusal.New(codes.Unauthenticated, refusal.TicketMissing,
				"relay: no "+TicketHeader+" — ask the control plane to schedule a task and send the ticket it grants")
		}
		if err := pool.Claim(vals[0]); err != nil {
			// Deliberately does not distinguish expired from spent from
			// invented: see relaycore.ErrNoSuchTicket.
			return tunnel.Backend{}, refusal.New(codes.PermissionDenied, refusal.TicketNotRedeemable,
				"relay: that ticket is not redeemable — it may have expired, or already been used")
		}

		admitted := func(string) bool { return true }
		if workers != nil {
			admitted = workers.Admitted
		}
		conn, fp, gen, err := backends.take(admitted)
		if err != nil {
			// The slot was claimed and there is nobody to run the work, so it
			// goes back immediately rather than waiting out the call.
			pool.Done()
			return tunnel.Backend{}, refusal.New(codes.Unavailable, refusal.NoWorker,
				"relay: the ticket was valid but no admitted worker is attached right now")
		}
		// Done exactly once, however the call ends: the slot is held by the
		// CONNECTION from here, and a leak would shrink the pool silently
		// until a restart.
		var once sync.Once
		return tunnel.Backend{
			Conn: conn,
			Release: func() {
				once.Do(func() {
					// Both books, exactly once: the pool's slot AND the
					// worker's. Releasing only the pool would leave the machine
					// looking permanently busy to take(), so it would stop
					// being chosen while being perfectly idle.
					backends.release(fp, gen)
					pool.Done()
				})
			},
		}, nil
	}
}
