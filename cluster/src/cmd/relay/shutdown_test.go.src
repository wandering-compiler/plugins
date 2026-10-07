package main

import (
	"sync"
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
)

// fakeServer records how it was stopped; GracefulStop blocks until released,
// the way a real one does while a call is running.
type fakeServer struct {
	rec      *recorder
	name     string
	graceful chan struct{} // closed to let GracefulStop return; nil returns at once
}

func (f *fakeServer) GracefulStop() {
	f.record(f.name + ".graceful")
	if f.graceful != nil {
		<-f.graceful
	}
}

func (f *fakeServer) Stop() {
	f.record(f.name + ".stop")
	if f.graceful != nil {
		select {
		case <-f.graceful:
		default:
			close(f.graceful)
		}
	}
}

func (f *fakeServer) record(s string) {
	f.rec.add(s)
}

type recorder struct {
	mu  sync.Mutex
	log []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, s)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

type closer struct{ closed bool }

func (c *closer) Close() error { c.closed = true; return nil }

func busyPool(t *testing.T) (*relaycore.Pool, string) {
	t.Helper()
	p, err := relaycore.New(relaycore.Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(1)
	g, err := p.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return p, g.Ticket
}

// A relay that is told to stop DRAINS first and waits for the work it is
// carrying, and only then stops serving it.
//
// It used to GracefulStop the proxy straight away, which was also unbounded: a
// codegen run takes minutes, so a SIGTERM either waited forever or — under a
// container runtime's kill timeout — cut the run anyway, with no new placement
// refused in the meantime.
func TestShutdown_DrainsWaitsForTheWorkThenStops(t *testing.T) {
	pool, ticket := busyPool(t)
	if err := pool.Claim(ticket); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	plan := shutdownPlan{
		pool:         pool,
		proxy:        &fakeServer{rec: rec, name: "proxy"},
		management:   &fakeServer{rec: rec, name: "management"},
		attach:       &fakeServer{rec: rec, name: "attach"},
		tunnels:      &closer{},
		drainTimeout: time.Minute,
		stopTimeout:  time.Second,
		poll:         5 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() { plan.run(); close(done) }()

	time.Sleep(50 * time.Millisecond)
	if !pool.Stats().Draining {
		t.Fatal("the relay is not draining while it shuts down — new work is still placed on it")
	}
	stoppedEarly := len(rec.snapshot()) > 0
	if stoppedEarly {
		t.Fatalf("servers were stopped while work was still running: %v", rec.snapshot())
	}

	pool.Done() // the run finishes
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish after the last run ended")
	}
	if !plan.tunnels.(*closer).closed {
		t.Error("the tunnel listener was never closed")
	}
}

// The wait is BOUNDED: a run that never ends does not keep a relay up forever,
// and a GracefulStop that would hang is cut short.
func TestShutdown_IsBounded(t *testing.T) {
	pool, ticket := busyPool(t)
	if err := pool.Claim(ticket); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	proxy := &fakeServer{rec: rec, name: "proxy", graceful: make(chan struct{})}
	plan := shutdownPlan{
		pool:         pool,
		proxy:        proxy,
		management:   &fakeServer{rec: rec, name: "management"},
		attach:       &fakeServer{rec: rec, name: "attach"},
		tunnels:      &closer{},
		drainTimeout: 50 * time.Millisecond,
		stopTimeout:  50 * time.Millisecond,
		poll:         5 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() { plan.run(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown waited past both bounds")
	}
	found := false
	for _, l := range rec.snapshot() {
		if l == "proxy.stop" {
			found = true
		}
	}
	if !found {
		t.Errorf("a GracefulStop that hung was never cut short with Stop: %v", rec.snapshot())
	}
}
