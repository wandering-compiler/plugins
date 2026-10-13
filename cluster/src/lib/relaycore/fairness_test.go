package relaycore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// One owner holds at most MaxQueuePerOwner places in the queue; other owners
// still queue behind it, a place that leaves the queue (granted, cancelled)
// frees the share, and the empty owner — a control plane from before owners —
// is not counted.
func TestReserve_OneOwnerHoldsAtMostItsShare(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute, PollTimeout: time.Minute, MaxQueue: 10, MaxQueuePerOwner: 2})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(1)
	if _, err := p.Reserve(me); err != nil { // granted at once: not queued, not counted
		t.Fatal(err)
	}
	var mine []Reservation
	for i := 0; i < 2; i++ {
		r, err := p.Reserve(me)
		if err != nil {
			t.Fatalf("place %d: %v", i, err)
		}
		mine = append(mine, r)
	}
	if _, err := p.Reserve(me); !errors.Is(err, ErrOwnerQueueFull) {
		t.Fatalf("a third place for one owner: %v, want ErrOwnerQueueFull", err)
	}
	if _, err := p.Reserve("owner-other"); err != nil {
		t.Fatalf("another owner was refused behind a full share: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := p.Reserve(""); err != nil {
			t.Fatalf("the empty owner was counted: %v", err)
		}
	}
	p.Cancel(mine[0].ID, me)
	if _, err := p.Reserve(me); err != nil {
		t.Fatalf("a cancelled place did not free the share: %v", err)
	}
	// A grant moves a place out of the queue: the share frees with it.
	p.SetCapacity(3)
	if st, err := p.Poll(mine[1].ID, me); err != nil || st.Grant == nil {
		t.Fatalf("the oldest place was not granted: %v, %v", st, err)
	}
	if _, err := p.Reserve(me); err != nil {
		t.Fatalf("a granted place still counted against the share: %v", err)
	}
}

// A streaming waiter counts against its owner's share like a reservation.
func TestWaitFor_CountsAgainstTheOwnersShare(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute, PollTimeout: time.Minute, MaxQueue: 10, MaxQueuePerOwner: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(me); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := p.WaitFor(ctx, me, nil); !errors.Is(err, ErrOwnerQueueFull) {
		t.Fatalf("a stream past the owner's share: %v, want ErrOwnerQueueFull", err)
	}
	queued := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := p.WaitFor(ctx, "owner-other", func(int) error { close(queued); return nil })
		done <- err
	}()
	<-queued
	p.SetCapacity(2)
	if err := <-done; err != nil {
		t.Fatalf("another owner's stream: %v", err)
	}
}

// The share defaults to half the queue, and a configured one must fit in it.
func TestNew_PerOwnerShare(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if p.maxPerOwner != DefaultMaxQueue/2 {
		t.Errorf("default share %d, want half of %d", p.maxPerOwner, DefaultMaxQueue)
	}
	if got := DefaultMaxQueuePerOwner(1); got != 1 {
		t.Errorf("share of a one-place queue = %d, want 1", got)
	}
	for _, o := range []Options{
		{TicketTTL: time.Minute, MaxQueuePerOwner: -1},
		{TicketTTL: time.Minute, MaxQueue: 4, MaxQueuePerOwner: 5},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("New(%+v) accepted a share that cannot work", o)
		}
	}
}

// Drain empties the queue, and with it every owner's count.
func TestDrain_ForgetsEveryShare(t *testing.T) {
	p, err := New(Options{TicketTTL: time.Minute, PollTimeout: time.Minute, MaxQueue: 4, MaxQueuePerOwner: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Reserve(me); err != nil {
		t.Fatal(err)
	}
	p.Drain()
	p.mu.Lock()
	n := len(p.queuedBy)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("%d owners still counted after a drain", n)
	}
}
