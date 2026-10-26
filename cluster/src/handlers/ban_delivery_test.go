package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// stallingWorkers is a worker registry whose ban-set reads hang until their
// context ends while stall is set — a database that stopped answering, as on
// a full disk — and answer normally once it is cleared.
type stallingWorkers struct {
	*workerStore
	stall atomic.Bool
}

func (w *stallingWorkers) Banned(ctx context.Context) ([]string, int64, error) {
	if w.stall.Load() {
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	return w.workerStore.Banned(ctx)
}

// A registry read that never returns must not stop the periodic delivery.
// The reads ran on a context with no deadline, so one stalled statement held
// the delivery under way — and the loop waits for it before the next — for
// good: the relay went on refusing every worker ("no ban set received")
// until the control plane was restarted, and nothing was logged. Bounded,
// the stalled round gives up, and the first round after the database
// answers again delivers.
func TestKeepBansDelivered_AStalledRegistryReadDoesNotStopTheSchedule(t *testing.T) {
	reg, dial := serveRelayWithWorkers(t)
	ws := &stallingWorkers{workerStore: &workerStore{banned: []string{"bb"}, banVersion: 3}}
	ws.stall.Store(true)
	h := &ClusterServiceHandler{
		Relays:         &store{relays: []Relay{{ID: "1", Name: "only", URL: "live"}}},
		Workers:        ws,
		Dial:           dial,
		BanReadTimeout: 20 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { h.KeepBansDelivered(ctx, 10*time.Millisecond); close(done) }()
	defer func() { cancel(); <-done }()

	time.Sleep(100 * time.Millisecond) // several stalled rounds
	if reg.HoldsBanSet() {
		t.Fatal("a ban set was delivered while the registry could not be read")
	}
	ws.stall.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for !reg.HoldsBanSet() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !reg.HoldsBanSet() || reg.Admitted("bb") {
		t.Fatal("the delivery never recovered once the registry answered again")
	}
}

// The periodic delivery logs a change of state, not every round: a relay
// that starts failing is logged once with the error, its recovery once, and
// a relay deliberately down is not repeated every few minutes. The registry
// read the same way. Silent, a control plane that could deliver nothing left
// the only line anywhere on the relay, which was not at fault.
func TestPushBans_LogsAChangeOfState(t *testing.T) {
	reg, dial := serveRelayWithWorkers(t)
	var down atomic.Bool
	down.Store(true)
	ws := &workerStore{banned: []string{"bb"}, banVersion: 3}
	h := &ClusterServiceHandler{
		Relays:      &store{relays: []Relay{{ID: "1", Name: "edge", URL: "live"}}},
		Workers:     ws,
		DialTimeout: 200 * time.Millisecond,
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			if down.Load() {
				return nil, errors.New("connection refused")
			}
			return dial(target, fp)
		},
	}
	buf := captureLog(t)
	logged := buf.String

	for range 3 {
		h.pushBans(t.Context(), false)
	}
	if got := strings.Count(logged(), `relay "edge" did not take the ban set`); got != 1 {
		t.Fatalf("a relay failing three rounds running was logged %d times, want once:\n%s", got, logged())
	}
	if !strings.Contains(logged(), "connection refused") {
		t.Errorf("the failure was logged without its error:\n%s", logged())
	}

	down.Store(false)
	h.pushBans(t.Context(), false)
	h.pushBans(t.Context(), false)
	if !reg.HoldsBanSet() {
		t.Fatal("the relay did not get the set once reachable")
	}
	if got := strings.Count(logged(), `relay "edge" takes the ban set again`); got != 1 {
		t.Errorf("the recovery was logged %d times, want once:\n%s", got, logged())
	}

	ws.mu.Lock()
	ws.bannedErr = errors.New("pq: could not extend file: No space left on device")
	ws.mu.Unlock()
	h.forgetBans()
	h.pushBans(t.Context(), false)
	h.pushBans(t.Context(), false)
	if got := strings.Count(logged(), "so no relay is handed one"); got != 1 {
		t.Errorf("a registry that cannot be read was logged %d times, want once:\n%s", got, logged())
	}
	if !strings.Contains(logged(), "No space left on device") {
		t.Errorf("the registry failure was logged without its error:\n%s", logged())
	}
	ws.mu.Lock()
	ws.bannedErr = nil
	ws.mu.Unlock()
	h.pushBans(t.Context(), false)
	if !strings.Contains(logged(), "read again") {
		t.Errorf("the registry's recovery was not logged:\n%s", logged())
	}

	// A decision's push logs every relay it did not reach, as before.
	down.Store(true)
	h.retireRelay("1")
	before := strings.Count(logged(), `relay "edge" did not take the ban set`)
	h.pushBans(t.Context(), true)
	h.pushBans(t.Context(), true)
	if got := strings.Count(logged(), `relay "edge" did not take the ban set`) - before; got != 2 {
		t.Errorf("a decision's push logged an unreached relay %d times over two pushes, want 2", got)
	}
}

// A relay that stays down with an error naming an ephemeral port — a new one
// every round — is one failure, not a new one each round. And a relay no
// longer registered leaves no recorded outcome behind.
func TestPushBans_AnEphemeralPortIsNotANewFailure(t *testing.T) {
	var port atomic.Int32
	port.Store(50000)
	relays := &store{relays: []Relay{{ID: "1", Name: "edge", URL: "live"}}}
	h := &ClusterServiceHandler{
		Relays:      relays,
		Workers:     &workerStore{banned: []string{"bb"}, banVersion: 3},
		DialTimeout: 200 * time.Millisecond,
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			return nil, fmt.Errorf("read tcp 10.0.0.2:%d->10.0.0.5:443: connection reset by peer", port.Add(1))
		},
	}
	buf := captureLog(t)
	for range 3 {
		h.pushBans(t.Context(), false)
	}
	if got := strings.Count(buf.String(), `relay "edge" did not take the ban set`); got != 1 {
		t.Fatalf("a relay down three rounds, each on another local port, was logged %d times, want once:\n%s", got, buf.String())
	}

	relays.relays = nil
	h.pushBans(t.Context(), false)
	h.deliveredMu.Lock()
	_, kept := h.delivered["1"]
	h.deliveredMu.Unlock()
	if kept {
		t.Error("the outcome of a relay no longer registered was kept")
	}
}
