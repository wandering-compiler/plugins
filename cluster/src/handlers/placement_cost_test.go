package handlers

import (
	"context"
	"errors"
	"testing"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// The ban set is read once per banCacheTTL, not on every relay-bound call,
// and a decision through this replica reads it again at once.
func TestWithBans_CachesTheSetAndADecisionRefreshesIt(t *testing.T) {
	ws := &workerStore{banned: []string{"aa"}}
	h := &ClusterServiceHandler{Workers: ws}
	for i := 0; i < 3; i++ {
		if _, err := h.withBans(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if ws.bannedCalls != 1 {
		t.Fatalf("ban set read %d times for three calls, want 1", ws.bannedCalls)
	}
	if _, err := h.BanWorkers(signedIn("op"), &pb.DecideWorkersActionReq{Ids: []string{"x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.withBans(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ws.bannedCalls != 2 {
		t.Errorf("after a decision the cached set was sent (reads = %d, want 2)", ws.bannedCalls)
	}
}

// The observed state is throttled: an unchanged state — reached, or failed
// with the same message — is written once per reachedEvery, a change is
// written at once, and an operator action writes every time.
func TestObserve_IsThrottledAndAChangeWritesAtOnce(t *testing.T) {
	s := &store{}
	h := &ClusterServiceHandler{Relays: s}
	r := Relay{ID: "r-1", Name: "one"}
	settle := func() {
		t.Helper()
		if err := h.waitObserved(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	h.observe(t.Context(), r, nil)
	settle()
	h.observe(t.Context(), r, nil)
	settle()
	if len(s.reached) != 1 {
		t.Fatalf("reached written %d times in a row, want 1", len(s.reached))
	}
	down := errors.New("down")
	h.observe(t.Context(), r, down)
	settle()
	h.observe(t.Context(), r, down)
	settle()
	if len(s.failed) != 1 {
		t.Fatalf("the same failure written %d times in a row, want 1", len(s.failed))
	}
	h.observe(t.Context(), r, errors.New("refused"))
	settle()
	h.observe(t.Context(), r, nil)
	settle()
	if len(s.failed) != 2 || len(s.reached) != 2 {
		t.Errorf("reached=%v failed=%v; want a new failure and the success after it recorded", s.reached, s.failed)
	}
	// An operator action records every time, throttle or not.
	h.noteOK(t.Context(), r)
	h.note(t.Context(), r, errors.New("refused"))
	h.note(t.Context(), r, errors.New("refused"))
	if len(s.reached) != 3 || len(s.failed) != 4 {
		t.Errorf("reached=%d failed=%d; an operator action must always record", len(s.reached), len(s.failed))
	}
}

// A read that began before a decision through this replica must not be
// cached over it, or the push after the decision would send the old set.
func TestCachedBans_AReadOverlappingADecisionIsNotCached(t *testing.T) {
	ws := &workerStore{banned: []string{"old"}, banVersion: 5}
	h := &ClusterServiceHandler{Workers: ws}
	slow := &decidingDuringRead{workerStore: ws, during: func() {
		ws.mu.Lock()
		ws.banned, ws.banVersion = []string{"old", "new"}, 6
		ws.mu.Unlock()
		h.forgetBans()
	}}
	h.Workers = slow
	if _, _, err := h.cachedBans(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.Workers = ws
	bans, v, err := h.cachedBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v != 6 || len(bans) != 2 {
		t.Errorf("served %v at version %d after the decision, want the new set at 6", bans, v)
	}
}

// decidingDuringRead returns the set as it was, then runs a decision before
// the read completes, the way a concurrent decision lands mid-read.
type decidingDuringRead struct {
	*workerStore
	during func()
}

func (d *decidingDuringRead) Banned(ctx context.Context) ([]string, int64, error) {
	bans, v, err := d.workerStore.Banned(ctx)
	d.during()
	return bans, v, err
}
