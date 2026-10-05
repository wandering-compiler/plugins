// Package relaycore is a relay's scheduling core: capacity, a queue, and
// tickets. It holds no storage and survives nothing — a restart drops every
// queue place and every outstanding ticket, which is correct, because the
// slots those tickets named are gone too.
//
// Split out from the gRPC server so the rules below can be tested as rules. A
// queue whose only test is "the RPC worked" is a queue whose race conditions
// are discovered in production.
//
// # One queue, two ways to stand in it
//
// A RESERVATION is a place in the queue with an id. Its holder learns how it
// stands by asking (Poll), and its presence is that asking: a reservation not
// polled within PollTimeout is abandoned, so a client that crashed holds
// nothing. That is the shape a control plane needs when it must answer in
// short unary calls — it reserves, returns at once, and polls on its client's
// behalf.
//
// Wait is the other shape — block until granted, presence held by a live
// connection — and it is a reservation too: the same queue, the same grant,
// with the open call standing in for the polls.
package relaycore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Grant is one slot, held for whoever was at the head of the queue.
type Grant struct {
	Ticket    string
	ExpiresAt time.Time
}

// State is where a reservation stands: granted, or queued at Position.
type State struct {
	// Position is the 1-based place in the queue; 0 once granted.
	Position int
	// Grant is set once a slot is this reservation's.
	Grant *Grant
}

// Reservation is a place taken by Reserve, and how it stood when taken.
type Reservation struct {
	ID string
	State
}

var (
	// ErrNoSuchTicket covers redeemed, expired and invented tickets with ONE
	// error on purpose. Telling a caller which of the three it was tells an
	// attacker whether a guessed ticket ever existed.
	ErrNoSuchTicket = errors.New("relaycore: no such ticket")
	// ErrNoSuchReservation is the same rule for reservations: abandoned,
	// cancelled, redeemed, expired and invented all read alike. The answer to
	// every one of them is to place again.
	ErrNoSuchReservation = errors.New("relaycore: no such reservation")
	// ErrDraining is a relay taking no new work. It is not a failure of the
	// caller's request: another relay may take it now.
	ErrDraining = errors.New("relaycore: relay is draining")
)

// reservation is one place in the queue, and later the slot it was granted.
type reservation struct {
	id string

	// changed is poked (never blocking) whenever this reservation's state
	// moves: a new position, a grant, an eviction. Only Wait listens.
	changed chan struct{}
	// lastPos is the position last announced, so a notification fires on a
	// CHANGE rather than on every queue mutation.
	lastPos int

	grant *Grant
	// seen is whether the grant has been RETURNED to anyone yet. Until it
	// has, its ticket has no expiry running — see Poll.
	seen bool

	// abandon fires when a polled reservation was not polled within the
	// pool's PollTimeout. Nil for a Wait, whose open call is its presence.
	abandon *time.Timer

	// evicted marks a reservation drained out of the queue. It stays in the
	// map as a tombstone until its next poll answers ErrDraining once — "place
	// again" rather than an unexplained "no such reservation".
	evicted bool
}

// Pool is one relay's capacity and the queue in front of it.
type Pool struct {
	// ceiling is the relay's own upper bound, or 0 for none. The EFFECTIVE
	// capacity is what the attached workers add up to, capped by this.
	ceiling     int
	ttl         time.Duration
	pollTimeout time.Duration
	now         func() time.Time
	newID       func() string

	mu sync.Mutex
	// capacity is DERIVED: SetCapacity is called by whatever tracks the
	// attached workers, and it starts at zero because a relay with nobody
	// attached can run nothing.
	//
	// It used to be a static RELAY_CAPACITY, which meant a relay with zero
	// workers happily granted its full complement of slots. Every one of those
	// callers was told TaskGranted — success, by the contract — and only found
	// out at the proxy, with "the ticket was valid but no admitted worker is
	// attached right now". A grant is supposed to BE a slot; for a pool whose
	// machines come and go, that was not an edge case but the normal morning
	// (a consumer, 2026-09-25).
	capacity int
	// inUse counts every slot spoken for: granted (redeemed or not).
	inUse int
	// tickets are granted and not yet redeemed. The timer is the claim
	// window; NIL while the grant has not been returned to anyone.
	tickets map[string]*time.Timer
	// byTicket finds the reservation a ticket belongs to, so redeeming or
	// expiring it also retires the reservation.
	byTicket     map[string]*reservation
	reservations map[string]*reservation
	queue        []*reservation
	// draining is one-way for the life of the process. A relay is drained to
	// be taken away; bringing it back is a restart, which is also what clears
	// every other piece of state it holds.
	draining bool
}

// Options configures a Pool.
//
// A zero TTL is still refused — a ticket that expires before it can be used is
// almost certainly a config that did not load. Capacity is different now: it
// is a CEILING, it is optional, and zero means "whatever the workers add up
// to". A relay that wants to cap itself below its fleet (bandwidth, a shared
// box) sets it; most do not.
type Options struct {
	// Capacity is the relay's own upper bound, or 0 for none. It is not the
	// capacity — SetCapacity supplies that from the attached workers.
	Capacity  int
	TicketTTL time.Duration
	// PollTimeout is how long a polled reservation survives without a poll
	// before it is abandoned. Zero uses DefaultPollTimeout. Size it at a few
	// poll intervals: one late poll must not cost a client its place.
	PollTimeout time.Duration
	// Now and NewID are seams for tests. Nil uses the real ones.
	Now   func() time.Time
	NewID func() string
}

// DefaultPollInterval is how often a polling client is asked to come back,
// and DefaultPollTimeout how long a reservation lives without it: about three
// missed polls.
const (
	DefaultPollInterval = 3 * time.Second
	DefaultPollTimeout  = 10 * time.Second
)

func New(o Options) (*Pool, error) {
	if o.Capacity < 0 {
		return nil, fmt.Errorf("relaycore: capacity ceiling cannot be negative, got %d", o.Capacity)
	}
	if o.TicketTTL <= 0 {
		return nil, fmt.Errorf("relaycore: ticket TTL must be positive, got %s", o.TicketTTL)
	}
	if o.PollTimeout < 0 {
		return nil, fmt.Errorf("relaycore: poll timeout cannot be negative, got %s", o.PollTimeout)
	}
	p := &Pool{
		ceiling:      o.Capacity,
		ttl:          o.TicketTTL,
		pollTimeout:  o.PollTimeout,
		now:          o.Now,
		newID:        o.NewID,
		tickets:      map[string]*time.Timer{},
		byTicket:     map[string]*reservation{},
		reservations: map[string]*reservation{},
	}
	if p.pollTimeout == 0 {
		p.pollTimeout = DefaultPollTimeout
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.newID == nil {
		p.newID = randomID
	}
	return p, nil
}

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A ticket that is not unpredictable is not a credential. There is no
		// degraded mode worth having here.
		panic("relaycore: no entropy for a ticket: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// Reserve takes a place in the queue and returns AT ONCE — granted when there
// is room, queued with a position otherwise. The holder learns what happens
// next by polling, and keeps the place only by polling.
//
// A reservation ID is a bearer credential like a ticket: it is 32 random
// bytes, and whoever holds it can collect the grant.
func (p *Pool) Reserve() (Reservation, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.draining {
		return Reservation{}, ErrDraining
	}
	r := p.enqueueLocked()
	r.abandon = time.AfterFunc(p.pollTimeout, func() { p.abandonReservation(r) })
	st, err := p.pollLocked(r)
	return Reservation{ID: r.id, State: st}, err
}

// Poll reports how a reservation stands, and is what keeps it alive.
//
// # The claim window starts HERE
//
// A slot granted to a reservation is held without a ticket expiry until a
// poll first returns the grant. Before that nobody can redeem it — the ticket
// exists in this process and nowhere else — so a TTL started at the grant
// would burn while the client sleeps until its next poll, and any TTL shorter
// than the poll interval would hand out tickets dead on arrival. The slot is
// not held forever meanwhile: the abandonment timer still runs, so a client
// that vanished gives it back.
//
// A repeated poll after that returns the SAME grant, so a client whose first
// answer was lost in transit does not lose its slot to it.
func (p *Pool) Poll(id string) (State, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.reservations[id]
	if !ok {
		return State{}, ErrNoSuchReservation
	}
	return p.pollLocked(r)
}

func (p *Pool) pollLocked(r *reservation) (State, error) {
	if r.evicted {
		// One-shot: the place-again answer is given once, then the
		// reservation is forgotten like any other.
		p.forgetLocked(r)
		return State{}, ErrDraining
	}
	if r.grant != nil {
		if !r.seen {
			r.seen = true
			if r.abandon != nil {
				// From here the ticket's own window governs the slot.
				r.abandon.Stop()
			}
			r.grant.ExpiresAt = p.now().Add(p.ttl)
			ticket := r.grant.Ticket
			p.tickets[ticket] = time.AfterFunc(p.ttl, func() { p.expire(ticket) })
		}
		g := *r.grant
		return State{Grant: &g}, nil
	}
	if r.abandon != nil {
		r.abandon.Reset(p.pollTimeout)
	}
	return State{Position: p.positionLocked(r)}, nil
}

// Cancel gives a reservation up: its queue place, or the slot it was granted
// if the ticket has not been redeemed. Idempotent, and silent about ids it
// does not know — the outcome the caller wants is already true.
func (p *Pool) Cancel(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.reservations[id]; ok {
		p.retireLocked(r)
	}
}

// Wait joins the queue and blocks until a slot is granted to THIS caller, or
// ctx ends.
//
// onPosition is called with a 1-based queue position whenever it changes, and
// never when the grant is immediate — a caller that is served at once should
// see one event, not a position followed by a grant.
//
// It is a reservation whose presence is the open call instead of polls: no
// abandonment timer, and leaving (ctx ending) cancels it.
//
// # Why the grant is targeted rather than announced
//
// The pool does not publish "a slot is free" and let waiters race for it. It
// picks the head of the queue and hands the slot to that waiter alone. There
// is therefore no race to lose: a second waiter never sees the slot, so it
// cannot take one that was already given away, and no compare-and-swap is
// needed to make that true.
func (p *Pool) Wait(ctx context.Context, onPosition func(int) error) (Grant, error) {
	p.mu.Lock()
	if p.draining {
		p.mu.Unlock()
		return Grant{}, ErrDraining
	}
	r := p.enqueueLocked()
	p.mu.Unlock()

	if onPosition == nil {
		onPosition = func(int) error { return nil }
	}
	reported := 0
	for {
		st, err := p.Poll(r.id)
		switch {
		case err != nil:
			return Grant{}, err
		case st.Grant != nil:
			return *st.Grant, nil
		case st.Position != reported:
			// Every CHANGE, not just the first. A caller watching a queue
			// sees it shorten as the places ahead are granted or give up;
			// reporting only the initial number would have it stare at a
			// position that stopped being true seconds later.
			reported = st.Position
			if err := onPosition(st.Position); err != nil {
				p.Cancel(r.id)
				return Grant{}, err
			}
		}
		select {
		case <-r.changed:
		case <-ctx.Done():
			// The caller left. Its place goes away with it — which is the
			// whole reason the queue is held by a live connection and not by a
			// row with a timeout somebody has to sweep. A grant that crossed
			// the cancellation goes back too.
			p.Cancel(r.id)
			return Grant{}, ctx.Err()
		}
	}
}

func (p *Pool) enqueueLocked() *reservation {
	r := &reservation{id: p.newID(), changed: make(chan struct{}, 1)}
	p.reservations[r.id] = r
	p.queue = append(p.queue, r)
	p.promoteLocked()
	return r
}

func (p *Pool) positionLocked(r *reservation) int {
	for i, q := range p.queue {
		if q == r {
			return i + 1
		}
	}
	return 0
}

func poke(r *reservation) {
	select {
	case r.changed <- struct{}{}:
	default:
	}
}

// notifyLocked tells every queued reservation that its place moved.
//
// Called after ANY queue mutation — an enqueue, a promotion, a departure —
// because all three move somebody. Pokes never block: a listener that has not
// consumed the last one reads the newest state when it does.
func (p *Pool) notifyLocked() {
	for i, q := range p.queue {
		if pos := i + 1; q.lastPos != pos {
			q.lastPos = pos
			poke(q)
		}
	}
}

// promoteLocked hands slots to the head of the queue while capacity allows.
func (p *Pool) promoteLocked() {
	for p.inUse < p.capacity && len(p.queue) > 0 {
		r := p.queue[0]
		p.queue = p.queue[1:]
		p.inUse++
		ticket := p.newID()
		r.grant = &Grant{Ticket: ticket}
		// Reserved, with NO claim window yet: the window starts when the
		// grant is first returned (pollLocked). Until then the slot is held
		// by the reservation — and released by its abandonment if nobody
		// comes for it.
		p.tickets[ticket] = nil
		p.byTicket[ticket] = r
		poke(r)
	}
	p.notifyLocked()
}

// abandonReservation is a polled reservation's timer: nobody asked about it
// in time, so it goes — queue place, unseen grant, or tombstone alike.
func (p *Pool) abandonReservation(r *reservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if cur, ok := p.reservations[r.id]; !ok || cur != r || r.seen {
		// Already gone, or its grant was returned and the ticket's own window
		// governs now.
		return
	}
	p.retireLocked(r)
}

// retireLocked removes a reservation in whatever state it is in, giving back
// what it held.
func (p *Pool) retireLocked(r *reservation) {
	for i, q := range p.queue {
		if q == r {
			p.queue = append(p.queue[:i], p.queue[i+1:]...)
			p.notifyLocked()
			break
		}
	}
	if r.grant != nil {
		// Still unredeemed, or nothing: releaseLocked ignores a ticket that
		// is no longer outstanding.
		p.releaseLocked(r.grant.Ticket)
	}
	p.forgetLocked(r)
}

func (p *Pool) forgetLocked(r *reservation) {
	if r.abandon != nil {
		r.abandon.Stop()
	}
	if r.grant != nil {
		delete(p.byTicket, r.grant.Ticket)
	}
	delete(p.reservations, r.id)
}

// SetCapacity reports how much the attached workers can take right now.
//
// Called on every change to the fleet — a worker attaches, leaves, drains or
// reports itself unhealthy — and it promotes immediately, so a queued caller
// is granted the moment a machine shows up rather than on the next arrival.
//
// Shrinking below what is in use is normal and safe: the loop below only ever
// promotes while there is room, so a shrunk pool simply stops granting until
// the work in flight drains. Nothing is revoked — a ticket already handed out
// is a promise, and taking it back would break the contract to fix an estimate.
func (p *Pool) SetCapacity(n int) {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ceiling > 0 && n > p.ceiling {
		n = p.ceiling
	}
	if n == p.capacity {
		return
	}
	p.capacity = n
	p.promoteLocked()
}

func (p *Pool) expire(ticket string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.byTicket[ticket]; ok {
		p.forgetLocked(r)
	}
	p.releaseLocked(ticket)
}

// Claim redeems a ticket, converting a time-bounded reservation into a slot
// held by the caller's work. Single use: the ticket is forgotten here, so a
// replay finds nothing — and the reservation it came from is finished.
func (p *Pool) Claim(ticket string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.tickets[ticket]
	if !ok {
		return ErrNoSuchTicket
	}
	if t == nil {
		// Never returned to anyone, so nobody can be holding it legitimately.
		// Unreachable for a ticket of 32 random bytes; refused rather than
		// assumed.
		return ErrNoSuchTicket
	}
	t.Stop()
	delete(p.tickets, ticket)
	if r, ok := p.byTicket[ticket]; ok {
		p.forgetLocked(r)
	}
	// inUse is NOT decremented: the slot moves from "reserved" to "running".
	// It comes back through Done.
	return nil
}

// Done returns a slot held by running work.
func (p *Pool) Done() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inUse > 0 {
		p.inUse--
	}
	p.promoteLocked()
}

// releaseLocked returns a slot still held by an unredeemed ticket.
func (p *Pool) releaseLocked(ticket string) {
	t, ok := p.tickets[ticket]
	if !ok {
		return
	}
	if t != nil {
		t.Stop()
	}
	delete(p.tickets, ticket)
	if p.inUse > 0 {
		p.inUse--
	}
	p.promoteLocked()
}

// Drain stops the relay taking new work: every place still queued is given
// up at once — a Wait returns ErrDraining, a polled reservation answers it on
// its next poll — and every later Wait or Reserve is refused with it.
//
// What it does NOT touch is the point of draining rather than stopping. A
// grant already made stays good — its holder was promised a slot and may be on
// its way — and work already running keeps its slot until it ends. An operator
// (or a SIGTERM) drains, waits for Stats().Held() to reach zero, and only then
// takes the relay away, so servers come and go without an outage.
//
// Idempotent, and one-way: see the `draining` field.
func (p *Pool) Drain() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.draining {
		return
	}
	p.draining = true
	for _, r := range p.queue {
		r.evicted = true
		poke(r)
	}
	p.queue = nil
}

// Stats is what a relay is doing, for the control plane choosing a relay and
// for an operator waiting on a drain. Point-in-time and immediately stale,
// like every such number.
type Stats struct {
	// InUse is slots held by RUNNING work — a ticket was redeemed and its
	// connection has not ended.
	InUse int
	// Reserved is slots granted and not yet redeemed. They are spoken for: a
	// control plane must count them as load, and a drain must wait for them
	// (or their expiry).
	Reserved int
	// Queued is places waiting for a slot, held open or polled.
	Queued int
	// Capacity is what the attached, ready workers add up to (capped by the
	// relay's ceiling).
	Capacity int
	// Draining — the relay takes no new work.
	Draining bool
}

// Held is every slot spoken for, running or promised.
func (s Stats) Held() int { return s.InUse + s.Reserved }

// Stats reports the pool's current state.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	// inUse counts a slot from the GRANT, because that is when it stops being
	// available; the tickets map is the part of it nobody has redeemed yet.
	reserved := len(p.tickets)
	return Stats{
		InUse:    p.inUse - reserved,
		Reserved: reserved,
		Queued:   len(p.queue),
		Capacity: p.capacity,
		Draining: p.draining,
	}
}
