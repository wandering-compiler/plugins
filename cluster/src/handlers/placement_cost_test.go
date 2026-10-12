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

// A reachable relay's row is written once per reachedEvery; a failure is
// written every time and makes the next success write again.
func TestNoteOK_IsThrottledAndAFailureResetsIt(t *testing.T) {
	s := &store{}
	h := &ClusterServiceHandler{Relays: s}
	r := Relay{ID: "r-1", Name: "one"}
	h.noteOK(context.Background(), r)
	h.noteOK(context.Background(), r)
	if len(s.reached) != 1 {
		t.Fatalf("reached written %d times in a row, want 1", len(s.reached))
	}
	h.note(context.Background(), r, errors.New("down"))
	h.noteOK(context.Background(), r)
	if len(s.reached) != 2 || len(s.failed) != 1 {
		t.Errorf("reached=%v failed=%v; want the success after a failure recorded", s.reached, s.failed)
	}
}
