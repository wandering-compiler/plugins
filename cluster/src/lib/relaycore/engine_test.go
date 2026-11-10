package relaycore

import (
	"errors"
	"testing"
	"time"
)

// A ticket taken for an engine redeems for a call naming that engine, and for
// one naming none — a client from before engines — and reports the engine.
func TestClaimEngine_RedeemsForTheSameEngineOrNone(t *testing.T) {
	for _, named := range []string{"v0.1.0-rc.71", ""} {
		p := newPolledPool(t, 1, time.Minute, time.Minute)
		r, err := p.ReserveEngine(me, "v0.1.0-rc.71")
		if err != nil {
			t.Fatal(err)
		}
		got, err := p.ClaimEngine(r.Grant.Ticket, named)
		if err != nil {
			t.Fatalf("ClaimEngine(named %q): %v", named, err)
		}
		if got != "v0.1.0-rc.71" {
			t.Errorf("ClaimEngine(named %q) = engine %q, want the reservation's", named, got)
		}
	}
}

// A call naming ANOTHER engine is refused, and the ticket is not spent: the
// place is still the reservation's, and the right call redeems it after.
func TestClaimEngine_AnotherEngineIsRefusedWithoutSpendingTheTicket(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	r, err := p.ReserveEngine(me, "v0.1.0-rc.71")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ClaimEngine(r.Grant.Ticket, "v0.2.0-rc.1"); !errors.Is(err, ErrEngineMismatch) {
		t.Fatalf("ClaimEngine with another engine: %v, want ErrEngineMismatch", err)
	}
	if _, err := p.ClaimEngine(r.Grant.Ticket, "v0.1.0-rc.71"); err != nil {
		t.Errorf("the ticket was spent by a refused call: %v", err)
	}
}

// A reservation that binds no engine redeems for any call, named or not, as
// every reservation did before engines.
func TestClaimEngine_AnUnboundReservationTakesAnyCall(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	r, err := p.Reserve(me)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.ClaimEngine(r.Grant.Ticket, "v0.1.0-rc.71")
	if err != nil {
		t.Fatalf("an unbound reservation refused a named call: %v", err)
	}
	if got != "" {
		t.Errorf("engine = %q for a reservation that bound none", got)
	}
}

// A queued reservation carries its engine to the grant it is promoted to.
func TestReserveEngine_AQueuedPlaceKeepsItsEngine(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	occupy(t, p, 1)
	r, err := p.ReserveEngine(me, "v0.1.0-rc.71")
	if err != nil {
		t.Fatal(err)
	}
	if r.Grant != nil {
		t.Fatal("granted on a full pool")
	}
	p.Done()
	st := mustPoll(t, p, r.ID)
	if st.Grant == nil {
		t.Fatal("not granted after a slot came back")
	}
	if _, err := p.ClaimEngine(st.Grant.Ticket, "v0.2.0-rc.1"); !errors.Is(err, ErrEngineMismatch) {
		t.Errorf("the promoted grant lost its engine: %v", err)
	}
}

// A ticket given back (cancelled, expired) leaves no engine behind.
func TestClaimEngine_ARetiredTicketLeavesNothing(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	r, err := p.ReserveEngine(me, "v0.1.0-rc.71")
	if err != nil {
		t.Fatal(err)
	}
	p.Cancel(r.ID, me)
	p.mu.Lock()
	n := len(p.ticketEngine)
	p.mu.Unlock()
	if n != 0 {
		t.Errorf("%d ticket engine(s) left after the reservation was cancelled", n)
	}
}
