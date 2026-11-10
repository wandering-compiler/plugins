package relayserver

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
)

// Work for an engine goes only to a worker that runs it, or to one that named
// no engines (a worker from before engines takes anything).
func TestBackends_TakeForPicksAWorkerRunningTheEngine(t *testing.T) {
	b := NewBackends()
	genOld := attach(t, b, "old", 4, true)
	genNew := attach(t, b, "new", 1, true)
	b.SetEngines("old", genOld, []string{"v0.1.0-rc.71"})
	b.SetEngines("new", genNew, []string{"v0.2.0-rc.1"})

	_, fp, _, err := b.takeFor(nil, "v0.2.0-rc.1")
	if err != nil {
		t.Fatal(err)
	}
	if fp != "new" {
		t.Errorf("work for v0.2.0-rc.1 went to %q, which runs v0.1.0-rc.71 only", fp)
	}
	if _, _, _, err := b.takeFor(nil, "v0.2.0-rc.1"); err == nil {
		t.Error("a second task for v0.2.0-rc.1 was placed though its only worker is full")
	}
	if _, fp, _, err := b.takeFor(nil, ""); err != nil || fp != "old" {
		t.Errorf("unbound work = %q, %v; want the worker with room", fp, err)
	}
}

func TestBackends_AWorkerNamingNoEnginesTakesAnyEngine(t *testing.T) {
	b := NewBackends()
	attach(t, b, "legacy", 1, true)
	if _, fp, _, err := b.takeFor(nil, "v0.1.0-rc.71"); err != nil || fp != "legacy" {
		t.Errorf("takeFor on a worker naming no engines = %q, %v; want it taken", fp, err)
	}
}

// Carries decides whether a relay takes a reservation at all: yes while
// nobody is attached (it queues, as any reservation does), yes when a worker
// runs the engine or names none, no when the fleet runs only other engines.
func TestBackends_Carries(t *testing.T) {
	b := NewBackends()
	if !b.Carries("v0.1.0-rc.71") {
		t.Error("an empty relay turned a reservation away instead of queueing it")
	}
	gen := attach(t, b, "w", 1, true)
	b.SetEngines("w", gen, []string{"v0.1.0-rc.71"})
	if !b.Carries("v0.1.0-rc.71") {
		t.Error("the relay does not carry the engine its worker announced")
	}
	if b.Carries("v0.2.0-rc.1") {
		t.Error("the relay claims an engine no attached worker runs")
	}
	if !b.Carries("") {
		t.Error("unbound work was turned away")
	}
}

// The engines go with the attachment: a stale stream cannot overwrite them,
// and the stream ending forgets them.
func TestBackends_EnginesFollowTheAttachment(t *testing.T) {
	b := NewBackends()
	old := attach(t, b, "w", 1, true)
	cur := b.NewAttachment()
	b.SetProfile("w", cur, 1, true)
	b.SetEngines("w", cur, []string{"v0.2.0-rc.1"})
	b.SetEngines("w", old, []string{"v0.1.0-rc.71"})
	if b.Carries("v0.1.0-rc.71") {
		t.Error("a superseded attachment overwrote the engines of the current one")
	}
	b.ClearProfile("w", cur)
	if !b.Carries("v0.1.0-rc.71") {
		t.Error("the engines outlived the attachment that announced them")
	}
}

// pickNaming is pickWith for a call that also names the engine it expects.
func pickNaming(pick tunnel.Picker, ticket, engine string) (tunnel.Backend, error) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(TicketHeader, ticket, EngineHeader, engine))
	return pick(ctx, "/acme.Work/Run")
}

// The proxy refuses a call naming another engine than its reservation, with
// the reason that sends the client to place again, and the ticket survives
// it: the right call still redeems.
func TestTicketPicker_AnotherEngineIsRefusedAndTheTicketSurvives(t *testing.T) {
	b := NewBackends()
	pool := poolWith(t, 1)
	srv := tunnelTo(t, b, "w")
	defer srv.Stop()
	r, err := pool.ReserveEngine("", "v0.1.0-rc.71")
	if err != nil {
		t.Fatal(err)
	}
	pick := TicketPicker(pool, b, nil)
	_, err = pickNaming(pick, r.Grant.Ticket, "v0.2.0-rc.1")
	wantRefusal(t, err, codes.FailedPrecondition, refusal.EngineMismatch)
	be, err := pickNaming(pick, r.Grant.Ticket, "v0.1.0-rc.71")
	if err != nil {
		t.Fatalf("the reservation's own engine was refused after a wrong one: %v", err)
	}
	be.Release()
}

// A client from before engines sends no header; its call still goes through.
func TestTicketPicker_ACallNamingNoEngineIsLetThrough(t *testing.T) {
	b := NewBackends()
	pool := poolWith(t, 1)
	srv := tunnelTo(t, b, "w")
	defer srv.Stop()
	r, err := pool.ReserveEngine("", "v0.1.0-rc.71")
	if err != nil {
		t.Fatal(err)
	}
	be, err := pickWith(TicketPicker(pool, b, nil), r.Grant.Ticket)
	if err != nil {
		t.Fatalf("a call without the engine header was refused: %v", err)
	}
	be.Release()
}

// ReserveTask for an engine the attached fleet does not run is refused with
// the reason a control plane falls through on; one it runs is granted.
func TestServer_ReserveTaskRefusesAnEngineNoWorkerRuns(t *testing.T) {
	pool := poolWith(t, 1)
	s := configured(t, pool)
	s.Backends = NewBackends()
	gen := attach(t, s.Backends, "w", 1, true)
	s.Backends.SetEngines("w", gen, []string{"v0.1.0-rc.71"})
	c := serveManagement(t, s)

	_, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{Engine: "v0.2.0-rc.1"})
	wantRefusal(t, err, codes.Unavailable, refusal.EngineNotCarried)
	if st := pool.Stats(); st.Held() != 0 {
		t.Errorf("a refused reservation took a slot: %+v", st)
	}
	r, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{Engine: "v0.1.0-rc.71"})
	if err != nil || r.GetGranted() == nil {
		t.Fatalf("ReserveTask for the engine the worker runs = %v, %v; want a grant", r, err)
	}
}
