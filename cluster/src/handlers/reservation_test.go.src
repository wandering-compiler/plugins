package handlers

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
)

// twoRelays stands two REAL relays up and a control plane over both, routed by
// url.
func twoRelays(t *testing.T, capA, capB int) (h *ClusterServiceHandler, a, b *relaycore.Pool) {
	t.Helper()
	a, dialA := serveRelay(t, capA, time.Minute, "a-net:9000")
	b, dialB := serveRelay(t, capB, time.Minute, "b-net:9000")
	h = &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays: &store{relays: []Relay{
			{ID: "11111111-1111-1111-1111-111111111111", Name: "a", URL: "a-url", Fingerprint: "fa"},
			{ID: "22222222-2222-2222-2222-222222222222", Name: "b", URL: "b-url", Fingerprint: "fb"},
		}},
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			if target == "a-url" {
				return dialA(target, fp)
			}
			return dialB(target, fp)
		},
	}
	return h, a, b
}

// The handle names the relay, so a poll reaching ANY console replica is routed
// with no memory of its own — and what it routes to is the relay that holds
// the place.
func TestReserveTask_TheHandleRoutesThePollToTheRelayHoldingThePlace(t *testing.T) {
	h, a, b := twoRelays(t, 1, 0) // only a has room; b has no workers
	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{Label: "codegen"})
	if err != nil {
		t.Fatalf("ReserveTask: %v", err)
	}
	g := st.GetGranted()
	if g == nil {
		t.Fatalf("an idle relay with room did not grant at once: %v", st)
	}
	relayID, _, ok := strings.Cut(st.GetReservation(), ".")
	if !ok || relayID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("handle %q does not name relay a", st.GetReservation())
	}
	if g.GetRelay() != "a" || g.GetAddress() != "a-net:9000" {
		t.Errorf("grant = %v, want relay a's name and address", g)
	}
	if st.GetPollAfterMs() <= 0 {
		t.Errorf("poll_after_ms = %d, want the relay's interval", st.GetPollAfterMs())
	}

	again, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: st.GetReservation()})
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if again.GetGranted().GetTicket() != g.GetTicket() {
		t.Errorf("a poll answered %v, want the same grant", again)
	}
	if err := a.Claim(g.GetTicket()); err != nil {
		t.Fatalf("the ticket is not redeemable at the relay that granted it: %v", err)
	}
	if b.Stats().Queued != 0 {
		t.Error("the other relay was touched")
	}
}

// Queued, then granted by a later poll; the relay name is stamped on both.
func TestGetReservation_QueuedThenGranted(t *testing.T) {
	h, a, _ := twoRelays(t, 1, 0)
	// Saturate a so the next reservation queues there (b, with no capacity,
	// sorts after it either way).
	first, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || first.GetGranted() == nil {
		t.Fatalf("setup: %v %v", first, err)
	}
	if err := a.Claim(first.GetGranted().GetTicket()); err != nil {
		t.Fatal(err)
	}
	h.Relays.(*store).relays = h.Relays.(*store).relays[:1] // only a from here

	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatalf("ReserveTask: %v", err)
	}
	if q := st.GetQueued(); q == nil || q.GetPosition() != 1 || q.GetRelay() != "a" {
		t.Fatalf("state = %v, want queued at 1 on a", st)
	}
	a.Done()
	got, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: st.GetReservation()})
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if got.GetGranted() == nil || got.GetGranted().GetRelay() != "a" {
		t.Fatalf("after the slot freed, poll = %v, want a grant stamped with a", got)
	}
	if got.GetReservation() != st.GetReservation() {
		t.Errorf("the poll changed the handle: %q → %q", st.GetReservation(), got.GetReservation())
	}
}

// A place that is gone is EXPIRED — an answer, not an error — with a reason.
// A relay row that no longer exists is the same answer: the place cannot be
// collected.
func TestGetReservation_GoneIsExpired(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	for _, handle := range []string{
		"11111111-1111-1111-1111-111111111111.deadbeef",
		"99999999-9999-9999-9999-999999999999.deadbeef",
	} {
		st, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: handle})
		if err != nil {
			t.Fatalf("GetReservation(%s): %v", handle, err)
		}
		if got := st.GetExpired().GetReason(); got != refusal.ReservationUnknown {
			t.Errorf("%s: state = %v, want expired with %s", handle, st, refusal.ReservationUnknown)
		}
	}
}

// A handle that is not one is the caller's bug and says so.
func TestGetReservation_AMalformedHandleIsInvalid(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	_, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: "no-dot-here"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}

// A draining relay is skipped for a new reservation, and a reservation queued
// on it is told to place again.
func TestReserveTask_DrainingRelaysAreSkippedAndTheirQueueExpires(t *testing.T) {
	h, a, b := twoRelays(t, 1, 1)
	// Fill both, so the next reservation queues on one of them.
	for i := 0; i < 2; i++ {
		st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
		if err != nil || st.GetGranted() == nil {
			t.Fatalf("setup %d: %v %v", i, st, err)
		}
	}
	queued, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || queued.GetQueued() == nil {
		t.Fatalf("setup: %v %v", queued, err)
	}
	holder, other := a, b
	if queued.GetQueued().GetRelay() == "b" {
		holder, other = b, a
	}
	holder.Drain()

	st, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: queued.GetReservation()})
	if err != nil {
		t.Fatalf("GetReservation: %v", err)
	}
	if st.GetExpired().GetReason() != refusal.RelayDraining {
		t.Fatalf("a reservation on a drained relay = %v, want expired with %s", st, refusal.RelayDraining)
	}
	// Placing again lands on the relay that is not draining.
	again, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatalf("ReserveTask after a drain: %v", err)
	}
	if other.Stats().Queued != 1 {
		t.Errorf("the new reservation did not land on the relay still taking work: %v", again)
	}
}

// Cancel reaches the relay and frees the place there.
func TestCancelReservation_FreesThePlace(t *testing.T) {
	h, a, _ := twoRelays(t, 1, 0)
	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || st.GetGranted() == nil {
		t.Fatalf("setup: %v %v", st, err)
	}
	if _, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: st.GetReservation()}); err != nil {
		t.Fatalf("CancelReservation: %v", err)
	}
	if held := a.Stats().Held(); held != 0 {
		t.Errorf("held = %d after cancelling the only grant", held)
	}
	// Idempotent.
	if _, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: st.GetReservation()}); err != nil {
		t.Errorf("a second cancel failed: %v", err)
	}
}

// With every relay out of play the refusal says so in the cluster's own words:
// NO_RELAY. A bare Unavailable reads, to a client, as its CONSOLE being down.
func TestReserveTask_NoPlaceableRelayIsNoRelay(t *testing.T) {
	h, a, b := twoRelays(t, 1, 1)
	a.Drain()
	b.Drain()
	_, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == refusal.Domain && info.GetReason() == refusal.NoRelay {
			if st.Code() != codes.Unavailable {
				t.Fatalf("code = %s, want Unavailable", st.Code())
			}
			return
		}
	}
	t.Fatalf("err = %v, want ErrorInfo{%s, %s}", err, refusal.Domain, refusal.NoRelay)
}
