package relaycore

import (
	"errors"
	"testing"
	"time"
)

// Stats separates what is RUNNING from what is only PROMISED.
//
// A granted ticket holds a slot before its caller connects, and a control
// plane sorting relays by load has to count it — but a drain waiting for work
// to finish must not confuse a ticket with a job. Both read here, apart.
func TestStats_SeparatesRunningFromReserved(t *testing.T) {
	p := newPool(t, 2, time.Minute)
	running, _ := p.Wait(t.Context(), nil)
	if err := p.Claim(running.Ticket); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Wait(t.Context(), nil); err != nil { // granted, not claimed
		t.Fatal(err)
	}
	queuedIn := make(chan struct{})
	go func() { _, _ = p.Wait(t.Context(), func(int) error { close(queuedIn); return nil }) }()
	<-queuedIn

	st := p.Stats()
	if st.InUse != 1 || st.Reserved != 1 || st.Queued != 1 || st.Capacity != 2 || st.Draining {
		t.Fatalf("stats = %+v, want 1 running, 1 reserved, 1 queued, capacity 2, not draining", st)
	}
	if st.Held() != 2 {
		t.Errorf("Held = %d, want running + reserved = 2", st.Held())
	}
}

// Draining takes no new work, sends the queue elsewhere, and keeps every
// promise already made.
//
// The queue is told at once rather than left to wait: on a draining relay
// nothing will ever be granted, so a caller kept in its queue would wait out
// its whole deadline for a slot that cannot come — while another relay may
// have one now.
func TestDrain_RefusesNewWorkReleasesTheQueueAndKeepsPromises(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	promised, err := p.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	queued := make(chan error, 1)
	in := make(chan struct{})
	go func() {
		_, err := p.Wait(t.Context(), func(int) error { close(in); return nil })
		queued <- err
	}()
	<-in

	p.Drain()

	select {
	case err := <-queued:
		if !errors.Is(err, ErrDraining) {
			t.Fatalf("the queued caller got %v, want ErrDraining", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a caller queued on a draining relay was left waiting")
	}
	if _, err := p.Wait(t.Context(), nil); !errors.Is(err, ErrDraining) {
		t.Errorf("a new caller on a draining relay got %v, want ErrDraining", err)
	}
	// A ticket granted before the drain is a promise: its caller is already on
	// its way to the proxy.
	if err := p.Claim(promised.Ticket); err != nil {
		t.Errorf("a ticket granted before the drain was refused: %v", err)
	}
	// And capacity arriving during a drain grants nothing to nobody.
	p.SetCapacity(5)
	st := p.Stats()
	if !st.Draining || st.Queued != 0 || st.Held() != 1 {
		t.Errorf("stats after drain = %+v, want draining, empty queue, the one claimed slot held", st)
	}
}

// Drain is idempotent: an operator pressing it twice, or a SIGTERM after the
// button, must not panic or reset anything.
func TestDrain_Twice(t *testing.T) {
	p := newPool(t, 1, time.Minute)
	p.Drain()
	p.Drain()
	if !p.Stats().Draining {
		t.Fatal("not draining after Drain")
	}
}
