package relaycore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// newPool builds a pool with `capacity` worth of attached workers.
//
// A Pool is EMPTY until SetCapacity says otherwise, so this stands in for the
// relay wiring that sums up the attached fleet. Tests that care about the
// empty state build their own.
func newPool(t *testing.T, capacity int, ttl time.Duration) *Pool {
	t.Helper()
	p, err := New(Options{TicketTTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(capacity)
	return p
}

// A zero TTL is a config that did not load: defaulting it would hand out
// tickets that are dead on arrival.
//
// Capacity is NOT in that list any more. It became an optional ceiling when
// the real capacity started coming from the attached workers, so zero is the
// ordinary case — a relay nobody has attached to yet — and refusing it would
// refuse every relay at boot.
func TestNew_RefusesAConfigThatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		o          Options
	}{
		{"no ttl", "TTL must be positive", Options{Capacity: 1}},
		{"negative ceiling", "cannot be negative", Options{Capacity: -1, TicketTTL: time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.o); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one saying %q", err, tc.want)
			}
		})
	}
}

// Room available: one grant, and NO position event. A caller served
// immediately that still saw "you are 1st in the queue" would report a wait
// that never happened.
func TestWait_ImmediateGrantReportsNoPosition(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	positions := 0
	g, err := p.Wait(t.Context(), func(int) error { positions++; return nil })
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if g.Ticket == "" || g.ExpiresAt.IsZero() {
		t.Fatalf("grant is incomplete: %+v", g)
	}
	if positions != 0 {
		t.Errorf("an immediate grant reported %d position(s)", positions)
	}
}

// The slot moves reserved → running → free, and the next waiter gets it.
func TestWait_QueuesThenGrantsWhenTheSlotComesBack(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	first, err := p.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	got := make(chan Grant, 1)
	seen := make(chan int, 4)
	go func() {
		g, err := p.Wait(t.Context(), func(pos int) error { seen <- pos; return nil })
		if err == nil {
			got <- g
		}
	}()

	if pos := <-seen; pos != 1 {
		t.Fatalf("queued at position %d, want 1", pos)
	}
	select {
	case g := <-got:
		t.Fatalf("granted while the only slot was held: %+v", g)
	case <-time.After(50 * time.Millisecond):
	}

	if err := p.Claim(first.Ticket); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	p.Done()

	select {
	case g := <-got:
		if g.Ticket == first.Ticket {
			t.Error("the second waiter was handed the FIRST waiter's ticket")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the freed slot never reached the waiter")
	}
}

// The property the whole design rests on: a freed slot is handed to ONE
// waiter, not announced to all of them. Two waiters, one slot — exactly one
// moves, and it is the one that has been waiting longest.
func TestWait_AFreedSlotGoesToExactlyOneWaiter(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	held, _ := p.Wait(t.Context(), nil)
	if err := p.Claim(held.Ticket); err != nil {
		t.Fatal(err)
	}

	type res struct {
		who int
		g   Grant
	}
	out := make(chan res, 2)
	ready := make(chan struct{}, 2)
	for i := 1; i <= 2; i++ {
		go func() {
			g, err := p.Wait(t.Context(), func(int) error { ready <- struct{}{}; return nil })
			if err == nil {
				out <- res{who: i, g: g}
			}
		}()
		<-ready // serialise entry so "longest waiting" is well defined
	}

	p.Done()

	select {
	case r := <-out:
		if r.who != 1 {
			t.Errorf("waiter %d was served first — the queue is not FIFO", r.who)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nobody was served")
	}
	select {
	case r := <-out:
		t.Fatalf("a second waiter was also granted the same slot: %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}

// An unclaimed ticket must return its slot on its own. Otherwise a caller that
// died between the grant and the connection holds capacity forever, and
// nothing in the system is watching for it.
func TestWait_AnUnclaimedTicketReturnsItsSlot(t *testing.T) {
	p := newPool(t, 1, 40*time.Millisecond)
	if _, err := p.Wait(t.Context(), nil); err != nil { // granted, never claimed
		t.Fatal(err)
	}
	got := make(chan Grant, 1)
	go func() {
		if g, err := p.Wait(t.Context(), nil); err == nil {
			got <- g
		}
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("the slot never came back from an unclaimed ticket")
	}
}

// A caller that gives up releases its place, and it does so without leaking
// the slot if the grant and the cancellation cross.
func TestWait_ACancelledWaiterLeavesNothingBehind(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	held, _ := p.Wait(t.Context(), nil)
	_ = p.Claim(held.Ticket)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	queued := make(chan struct{})
	go func() {
		_, err := p.Wait(ctx, func(int) error { close(queued); return nil })
		done <- err
	}()
	<-queued
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	if queuedN := p.Stats().Queued; queuedN != 0 {
		t.Errorf("the queue still holds %d place(s) for a caller that left", queuedN)
	}
	p.Done()
	if inUse := p.Stats().Held(); inUse != 0 {
		t.Errorf("inUse = %d after everyone left — a slot leaked", inUse)
	}
}

// A ticket is single use, and every way of failing to redeem one reports the
// SAME error. Distinguishing "expired" from "never existed" tells an attacker
// whether a guess was ever a real ticket.
func TestClaim_IsSingleUseAndIndiscriminate(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	g, _ := p.Wait(t.Context(), nil)
	if err := p.Claim(g.Ticket); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	replay := p.Claim(g.Ticket)
	invented := p.Claim("deadbeef")
	if !errors.Is(replay, ErrNoSuchTicket) {
		t.Errorf("replaying a ticket: %v, want ErrNoSuchTicket", replay)
	}
	if !errors.Is(invented, ErrNoSuchTicket) {
		t.Errorf("inventing a ticket: %v, want ErrNoSuchTicket", invented)
	}
	if replay.Error() != invented.Error() {
		t.Errorf("a replayed ticket and an invented one report differently:\n %v\n %v", replay, invented)
	}
}

// A caller watching a queue must see it SHORTEN. Reporting only the position
// it joined at leaves it staring at a number that stopped being true seconds
// later — and there is no other signal it could use, because the whole design
// says the stream is the progress.
func TestWait_PositionUpdatesAsTheQueueShortens(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	held, _ := p.Wait(t.Context(), nil)
	if err := p.Claim(held.Ticket); err != nil {
		t.Fatal(err)
	}

	// Two ahead of the watcher, entered one at a time so the order is defined.
	var ahead []context.CancelFunc
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(t.Context())
		ahead = append(ahead, cancel)
		in := make(chan struct{})
		// Once: positions now update whenever the queue moves, so this
		// callback fires more than once for the same waiter.
		var entered sync.Once
		go func() {
			_, _ = p.Wait(ctx, func(int) error { entered.Do(func() { close(in) }); return nil })
		}()
		<-in
	}

	seen := make(chan int, 8)
	go func() {
		_, _ = p.Wait(t.Context(), func(pos int) error { seen <- pos; return nil })
	}()
	if got := <-seen; got != 3 {
		t.Fatalf("joined at position %d, want 3", got)
	}

	// One ahead gives up: the watcher moves to 2 without anything being granted.
	ahead[0]()
	select {
	case got := <-seen:
		if got != 2 {
			t.Errorf("after one ahead left, position = %d, want 2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the position never updated when a place ahead disappeared")
	}
}

// An empty relay grants NOTHING.
//
// This is the defect a consumer reported: capacity was a static RELAY_CAPACITY with
// no relationship to the attached fleet, so a relay with zero workers handed
// out its full complement of tickets. Each caller was told TaskGranted —
// success, by the contract — and discovered at the proxy that there was nobody
// to run it. A grant is supposed to BE a slot.
func TestWait_AnEmptyRelayGrantsNothing(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := p.Wait(ctx, nil); err == nil {
		t.Fatal("a relay with no attached worker granted a slot — " +
			"the caller is promised a slot and gets a failure at the proxy instead")
	}
}

// And the queue drains the moment a machine shows up: a caller already waiting
// is granted by the attach, not by the next arrival.
func TestSetCapacity_AttachingAWorkerPromotesTheQueue(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	granted := make(chan Grant, 1)
	go func() {
		g, err := p.Wait(t.Context(), nil)
		if err == nil {
			granted <- g
		}
	}()
	// Let the caller reach the queue before the worker arrives.
	waitFor(t, func() bool { return p.Stats().Queued == 1 })

	p.SetCapacity(1)
	select {
	case <-granted:
	case <-time.After(2 * time.Second):
		t.Fatal("a worker attached and the queued caller was not promoted")
	}
}

// A shrinking fleet stops granting; it does NOT revoke.
//
// A ticket already handed out is a promise, and withdrawing it to correct an
// estimate would break the contract the caller is holding.
func TestSetCapacity_ShrinkingStopsGrantingAndRevokesNothing(t *testing.T) {
	p := newPool(t, 2, time.Minute)
	g, err := p.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(0)

	if err := p.Claim(g.Ticket); err != nil {
		t.Errorf("a ticket granted before the fleet shrank was refused: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	if _, err := p.Wait(ctx, nil); err == nil {
		t.Error("a pool whose workers all left still granted a slot")
	}
}

// The ceiling caps a fleet bigger than the relay itself can carry.
func TestSetCapacity_CeilingCapsTheFleet(t *testing.T) {
	p, err := New(Options{Capacity: 2, TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(10)
	if capacity := p.Stats().Capacity; capacity != 2 {
		t.Fatalf("capacity = %d, want the ceiling of 2 — a relay may be smaller than its fleet", capacity)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition never became true")
}
