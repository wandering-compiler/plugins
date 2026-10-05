package relaycore

import (
	"errors"
	"testing"
	"time"
)

func newPolledPool(t *testing.T, capacity int, ttl, pollTimeout time.Duration) *Pool {
	t.Helper()
	p, err := New(Options{TicketTTL: ttl, PollTimeout: pollTimeout})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(capacity)
	return p
}

// occupy takes every slot with claimed work, so whatever comes next queues.
func occupy(t *testing.T, p *Pool, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		g, err := p.Wait(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Claim(g.Ticket); err != nil {
			t.Fatal(err)
		}
	}
}

func mustPoll(t *testing.T, p *Pool, id string) State {
	t.Helper()
	st, err := p.Poll(id)
	if err != nil {
		t.Fatalf("Poll(%s): %v", id, err)
	}
	return st
}

// Room available: the reservation IS the grant, and it is redeemable.
func TestReserve_GrantsAtOnceWhenThereIsRoom(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	if r.Grant == nil || r.Grant.Ticket == "" || r.Grant.ExpiresAt.IsZero() {
		t.Fatalf("reservation on an idle relay = %+v, want a grant with a ticket and an expiry", r)
	}
	if err := p.Claim(r.Grant.Ticket); err != nil {
		t.Fatalf("the granted ticket is not redeemable: %v", err)
	}
	// Redeemed is done: the reservation has nothing left to report.
	if _, err := p.Poll(r.ID); !errors.Is(err, ErrNoSuchReservation) {
		t.Errorf("polling a redeemed reservation: %v, want ErrNoSuchReservation", err)
	}
}

// No room: the reservation queues, RETURNS AT ONCE, and a poll reports the
// place — then the grant, when a slot frees.
func TestReserve_QueuesAndPollReportsPositionThenGrant(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	occupy(t, p, 1)

	first, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	if first.Position != 1 || second.Position != 2 || first.Grant != nil {
		t.Fatalf("positions %d and %d (grant %v), want 1 and 2 with no grant", first.Position, second.Position, first.Grant)
	}
	if st := p.Stats(); st.Queued != 2 {
		t.Errorf("queued = %d, want 2 — a polled reservation is as much load as a stream", st.Queued)
	}

	p.Done()
	if st := mustPoll(t, p, first.ID); st.Grant == nil {
		t.Fatalf("the head of the queue was not granted the freed slot: %+v", st)
	}
	if st := mustPoll(t, p, second.ID); st.Position != 1 {
		t.Errorf("the second reservation reports position %d, want 1", st.Position)
	}
}

// A client that stops polling ABANDONS its place — a crashed w17ctl holds
// nothing.
func TestPoll_AnUnpolledReservationIsAbandoned(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, 60*time.Millisecond)
	occupy(t, p, 1)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return p.Stats().Queued == 0 })
	if _, err := p.Poll(r.ID); !errors.Is(err, ErrNoSuchReservation) {
		t.Errorf("polling an abandoned reservation: %v, want ErrNoSuchReservation", err)
	}
}

// …and one that keeps polling keeps its place, however long the queue takes.
func TestPoll_KeepsAReservationAlive(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, 60*time.Millisecond)
	occupy(t, p, 1)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end); {
		if st := mustPoll(t, p, r.ID); st.Position != 1 {
			t.Fatalf("position = %d while polling, want 1", st.Position)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// The claim window starts when a poll first RETURNS the grant, not when the
// slot was assigned.
//
// A grant nobody has seen cannot be claimed — the ticket is in the relay's
// memory and nowhere else — so burning its TTL while the client sleeps until
// its next poll would hand out tickets that are dead on arrival whenever the
// TTL is shorter than the poll interval.
func TestPoll_TheClaimWindowStartsWhenTheGrantIsFirstReturned(t *testing.T) {
	p := newPolledPool(t, 1, 80*time.Millisecond, time.Minute)
	occupy(t, p, 1)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	p.Done() // granted, unseen

	time.Sleep(200 * time.Millisecond) // well past the TTL, before anyone looks
	st := mustPoll(t, p, r.ID)
	if st.Grant == nil {
		t.Fatalf("the reservation lost its grant while nobody had seen it: %+v", st)
	}
	if left := time.Until(st.Grant.ExpiresAt); left < 40*time.Millisecond {
		t.Errorf("the ticket has %s left on first sight — its window started before it was returned", left)
	}
	// A second poll answers the SAME grant: a client whose first response was
	// lost must not lose its slot to that.
	if again := mustPoll(t, p, r.ID); again.Grant == nil || again.Grant.Ticket != st.Grant.Ticket {
		t.Errorf("a repeated poll answered %+v, want the same ticket", again)
	}
	if err := p.Claim(st.Grant.Ticket); err != nil {
		t.Errorf("a ticket returned a moment ago is not redeemable: %v", err)
	}
}

// …and once returned, the window DOES run: an unredeemed ticket gives its slot
// back and the reservation is gone.
func TestPoll_AReturnedGrantExpiresUnclaimed(t *testing.T) {
	p := newPolledPool(t, 1, 50*time.Millisecond, time.Minute)
	r, err := p.Reserve()
	if err != nil || r.Grant == nil {
		t.Fatalf("setup: %+v %v", r, err)
	}
	waitFor(t, func() bool { return p.Stats().Held() == 0 })
	if _, err := p.Poll(r.ID); !errors.Is(err, ErrNoSuchReservation) {
		t.Errorf("polling after the claim window passed: %v, want ErrNoSuchReservation", err)
	}
}

// A grant whose client vanished before seeing it comes back by abandonment —
// otherwise its slot would be held by a ticket nobody can ever redeem.
func TestPoll_AnUnseenGrantIsReturnedWhenItsClientStopsPolling(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, 60*time.Millisecond)
	occupy(t, p, 1)
	if _, err := p.Reserve(); err != nil {
		t.Fatal(err)
	}
	p.Done() // granted to a client that is never heard from again
	waitFor(t, func() bool { return p.Stats().Held() == 0 })

	// The slot is free again: a new caller gets it at once.
	r, err := p.Reserve()
	if err != nil || r.Grant == nil {
		t.Fatalf("the abandoned grant's slot did not come back: %+v %v", r, err)
	}
}

// Cancel gives the place back — queued or granted — and is idempotent.
func TestCancel_ReleasesTheSlotOrThePlace(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	granted, err := p.Reserve()
	if err != nil || granted.Grant == nil {
		t.Fatalf("setup: %+v %v", granted, err)
	}
	queued, err := p.Reserve()
	if err != nil || queued.Position != 1 {
		t.Fatalf("setup: %+v %v", queued, err)
	}

	p.Cancel(granted.ID)
	if st := mustPoll(t, p, queued.ID); st.Grant == nil {
		t.Fatalf("cancelling a granted reservation did not free its slot for the next: %+v", st)
	}
	p.Cancel(queued.ID)
	p.Cancel(queued.ID)
	p.Cancel("never-existed")
	if st := p.Stats(); st.Held() != 0 || st.Queued != 0 {
		t.Errorf("stats after cancelling everything = %+v, want nothing held or queued", st)
	}
}

// A reservation queued on a relay that starts draining is told to PLACE AGAIN
// on its next poll — not "unknown", which would read as a lost reservation,
// and not left queued, where nothing will ever be granted.
func TestDrain_AQueuedReservationIsToldToPlaceAgain(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	occupy(t, p, 1)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	p.Drain()
	if _, err := p.Poll(r.ID); !errors.Is(err, ErrDraining) {
		t.Fatalf("polling a drained-out reservation: %v, want ErrDraining", err)
	}
	if _, err := p.Poll(r.ID); !errors.Is(err, ErrNoSuchReservation) {
		t.Errorf("the place-again answer was not one-shot: %v", err)
	}
	if _, err := p.Reserve(); !errors.Is(err, ErrDraining) {
		t.Errorf("a draining relay accepted a reservation: %v", err)
	}
}

// But a reservation already GRANTED keeps its grant through a drain: it is a
// promise, exactly like a ticket handed out on a stream.
func TestDrain_AGrantedReservationKeepsItsGrant(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	occupy(t, p, 1)
	r, err := p.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	p.Done()
	p.Drain()
	if st := mustPoll(t, p, r.ID); st.Grant == nil {
		t.Fatalf("a reservation granted before the drain lost its grant: %+v", st)
	}
}
