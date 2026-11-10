package relaycore

import (
	"testing"
	"time"
)

const (
	engOld = "v0.1.0-rc.73"
	engNew = "v0.2.0-rc.1"
)

// A worker's slots count for the engines it runs: with one slot running the
// old engine and one the new, a second reservation for the old engine waits
// while one for the new engine — later in the queue — is granted.
func TestEngineCapacity_AFullEngineWaitsWhileAnotherGoesAhead(t *testing.T) {
	p := newPolledPool(t, 2, time.Minute, time.Minute)
	p.SetEngineCapacity(0, map[string]int{engOld: 1, engNew: 1})

	first, err := p.ReserveEngine(me, engOld)
	if err != nil || first.Grant == nil {
		t.Fatalf("first old-engine reservation not granted: %+v %v", first, err)
	}
	second, err := p.ReserveEngine(me, engOld)
	if err != nil {
		t.Fatal(err)
	}
	if second.Grant != nil {
		t.Fatal("a second old-engine reservation was granted beyond the old engine's one slot")
	}
	third, err := p.ReserveEngine(me, engNew)
	if err != nil {
		t.Fatal(err)
	}
	if third.Grant == nil {
		t.Fatal("a new-engine reservation waited behind a full old engine")
	}
	// The old engine's slot coming back promotes the waiting old-engine place.
	if _, err := p.ClaimEngine(first.Grant.Ticket, engOld); err != nil {
		t.Fatal(err)
	}
	p.DoneEngine(engOld)
	if st := mustPoll(t, p, second.ID); st.Grant == nil {
		t.Error("the waiting old-engine place was not granted when an old-engine slot came back")
	}
}

// A worker that names no engine runs any, so its slots count for every engine.
func TestEngineCapacity_AWorkerNamingNoneCountsForEvery(t *testing.T) {
	p := newPolledPool(t, 2, time.Minute, time.Minute)
	p.SetEngineCapacity(1, map[string]int{engNew: 1})
	a, _ := p.ReserveEngine(me, engOld)
	b, _ := p.ReserveEngine(me, engNew)
	if a.Grant == nil || b.Grant == nil {
		t.Fatalf("granted old=%v new=%v, want both (one any-worker slot + one new-engine slot)", a.Grant != nil, b.Grant != nil)
	}
}

// An engine nobody runs is never granted, however much other room there is:
// the reservation queues (the relay refuses it up front when its fleet is
// present and runs other engines — relayserver.ReserveTask).
func TestEngineCapacity_AnEngineNobodyRunsIsNotGranted(t *testing.T) {
	p := newPolledPool(t, 4, time.Minute, time.Minute)
	p.SetEngineCapacity(0, map[string]int{engOld: 4})
	r, err := p.ReserveEngine(me, engNew)
	if err != nil {
		t.Fatal(err)
	}
	if r.Grant != nil {
		t.Error("a reservation for an engine no worker runs was granted")
	}
}

// Before any per-engine capacity is reported the pool is one queue, as before
// engines: a relay whose workers announce nothing behaves as it always did.
func TestEngineCapacity_NoneReportedIsOneQueue(t *testing.T) {
	p := newPolledPool(t, 2, time.Minute, time.Minute)
	a, _ := p.ReserveEngine(me, engOld)
	b, _ := p.ReserveEngine(me, engOld)
	if a.Grant == nil || b.Grant == nil {
		t.Error("an engine was limited with no per-engine capacity reported")
	}
}

// Every way a slot comes back gives the engine its share back: a cancelled
// grant, an expired ticket, and a run ending.
func TestEngineCapacity_EveryReturnFreesTheEngine(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	p.SetEngineCapacity(0, map[string]int{engOld: 1})
	r, _ := p.ReserveEngine(me, engOld)
	p.Cancel(r.ID, me)
	r2, _ := p.ReserveEngine(me, engOld)
	if r2.Grant == nil {
		t.Fatal("a cancelled grant kept the engine's slot")
	}
	if _, err := p.ClaimEngine(r2.Grant.Ticket, ""); err != nil {
		t.Fatal(err)
	}
	p.DoneEngine(engOld)
	p.mu.Lock()
	held := p.engineInUse[engOld]
	p.mu.Unlock()
	if held != 0 {
		t.Errorf("engine %s still holds %d slot(s) after its run ended", engOld, held)
	}
}

// A place counts only the places of its own engine ahead of it: it does not
// wait behind another engine's queue.
func TestEngineCapacity_PositionIsWithinTheEnginesQueue(t *testing.T) {
	p := newPolledPool(t, 1, time.Minute, time.Minute)
	p.SetEngineCapacity(0, map[string]int{engOld: 1, engNew: 1})
	occupy(t, p, 1)
	o1, _ := p.ReserveEngine(me, engOld)
	n1, _ := p.ReserveEngine(me, engNew)
	o2, _ := p.ReserveEngine(me, engOld)
	if got := o1.State.Position; got != 1 {
		t.Errorf("first old-engine place = %d, want 1", got)
	}
	if got := n1.State.Position; got != 1 {
		t.Errorf("first new-engine place = %d, want 1 (it does not wait behind the old engine)", got)
	}
	if got := o2.State.Position; got != 2 {
		t.Errorf("second old-engine place = %d, want 2", got)
	}
}
