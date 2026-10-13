package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
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
		handleFor("11111111-1111-1111-1111-111111111111", "deadbeef"),
		handleFor("99999999-9999-9999-9999-999999999999", "deadbeef"),
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

// handleFor is the handle ReserveTask would hand a caller with no signed-in
// principal (the project's own code) for this relay and reservation.
func handleFor(relayID, local string) string {
	return relayID + handleSep + local + handleSep + holderTag(internalHolder, relayID, local)
}

// A handle works only for the caller it was handed to: another signed-in
// caller holding it reads it as expired and cancels nothing, and neither does
// a call with no principal at all.
func TestReservationHandle_BelongsToItsHolder(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	alice, bob := signedIn("alice"), signedIn("bob")
	st, err := h.ReserveTask(alice, &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if got, err := h.GetReservation(alice, &pb.GetReservationReq{Reservation: st.GetReservation()}); err != nil || got.GetExpired() != nil {
		t.Fatalf("the holder's poll: %v, %v", got, err)
	}
	for name, other := range map[string]context.Context{"another user": bob, "no principal": context.Background()} {
		got, err := h.GetReservation(other, &pb.GetReservationReq{Reservation: st.GetReservation()})
		if err != nil || got.GetExpired().GetReason() != refusal.ReservationUnknown {
			t.Errorf("%s's poll = %v, %v; want expired as unknown", name, got, err)
		}
		if _, err := h.CancelReservation(other, &pb.CancelReservationReq{Reservation: st.GetReservation()}); err != nil {
			t.Fatalf("%s's cancel: %v", name, err)
		}
	}
	if got, err := h.GetReservation(alice, &pb.GetReservationReq{Reservation: st.GetReservation()}); err != nil || got.GetExpired() != nil {
		t.Errorf("another caller's cancel took the holder's place: %v, %v", got, err)
	}
}

// The tag covers the whole handle: the holder's own tag does not carry over to
// a handle naming a different relay.
func TestReservationHandle_TagCoversTheRelay(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	parts := strings.Split(st.GetReservation(), handleSep)
	parts[0] = "99999999-9999-9999-9999-999999999999"
	if holderTag(internalHolder, parts[0], parts[1]) == parts[2] {
		t.Fatal("the tag does not depend on the relay")
	}
}

// An envelope that is present but unreadable is refused, never read as "no
// principal": that would give every such caller the one identity they share.
func TestReservationHandle_AnUnreadableEnvelopeIsRefused(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-w17-user", "not base64!"))
	if _, err := h.ReserveTask(ctx, &pb.ReserveTaskReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("reserve: %v, want Unauthenticated", err)
	}
	if _, err := h.GetReservation(ctx, &pb.GetReservationReq{Reservation: handleFor("id-a", "r1")}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("poll: %v, want Unauthenticated", err)
	}
	if _, err := h.CancelReservation(ctx, &pb.CancelReservationReq{Reservation: handleFor("id-a", "r1")}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("cancel: %v, want Unauthenticated", err)
	}
}

// forge rewrites a handle's tag for another holder, which anyone holding the
// handle can do: every other input of the tag is in the handle.
func forge(handle, holder string) string {
	parts := strings.Split(handle, handleSep)
	return parts[0] + handleSep + parts[1] + handleSep + holderTag(holder, parts[0], parts[1])
}

// The tag is not the binding: a leaked handle re-tagged for whoever holds it
// passes the control plane's check, and the RELAY still refuses it. Polled it
// reads as expired, cancelled it leaves the place to its owner.
func TestReservationHandle_AReTaggedHandleIsRefusedByTheRelay(t *testing.T) {
	h, a, _ := twoRelays(t, 1, 0)
	alice := signedIn("alice")
	st, err := h.ReserveTask(alice, &pb.ReserveTaskReq{})
	if err != nil || st.GetGranted() == nil {
		t.Fatalf("reserve: %v, %v", st, err)
	}
	for name, c := range map[string]struct {
		ctx    context.Context
		holder string
	}{
		"another user": {signedIn("bob"), userHolder + "bob"},
		"no principal": {context.Background(), internalHolder},
	} {
		forged := forge(st.GetReservation(), c.holder)
		got, err := h.GetReservation(c.ctx, &pb.GetReservationReq{Reservation: forged})
		if err != nil || got.GetExpired().GetReason() != refusal.ReservationUnknown {
			t.Errorf("%s's poll with a re-tagged handle = %v, %v; want expired as unknown", name, got, err)
		}
		if got.GetGranted() != nil {
			t.Fatalf("%s collected the owner's grant with a re-tagged handle", name)
		}
		if _, err := h.CancelReservation(c.ctx, &pb.CancelReservationReq{Reservation: forged}); err != nil {
			t.Fatalf("%s's cancel: %v", name, err)
		}
	}
	if held := a.Stats().Held(); held != 1 {
		t.Fatalf("held = %d: a re-tagged handle cancelled the owner's place", held)
	}
	got, err := h.GetReservation(alice, &pb.GetReservationReq{Reservation: st.GetReservation()})
	if err != nil || got.GetGranted().GetTicket() != st.GetGranted().GetTicket() {
		t.Fatalf("the owner's poll = %v, %v; want its grant", got, err)
	}
	if _, err := h.CancelReservation(alice, &pb.CancelReservationReq{Reservation: st.GetReservation()}); err != nil {
		t.Fatal(err)
	}
	if held := a.Stats().Held(); held != 0 {
		t.Errorf("held = %d after the owner cancelled", held)
	}
}

// A handle reserved by project code (no principal) is project code's: a
// signed-in caller cannot use it, with its own tag or re-tagged — and project
// code can.
func TestReservationHandle_AnInternalHandleIsNotASignedInCallers(t *testing.T) {
	h, a, _ := twoRelays(t, 1, 0)
	st, err := h.ReserveTask(context.Background(), &pb.ReserveTaskReq{})
	if err != nil || st.GetGranted() == nil {
		t.Fatalf("reserve: %v, %v", st, err)
	}
	bob := signedIn("bob")
	for _, handle := range []string{st.GetReservation(), forge(st.GetReservation(), userHolder+"bob")} {
		got, err := h.GetReservation(bob, &pb.GetReservationReq{Reservation: handle})
		if err != nil || got.GetExpired().GetReason() != refusal.ReservationUnknown {
			t.Errorf("a signed-in poll of an internal handle = %v, %v; want expired as unknown", got, err)
		}
		if _, err := h.CancelReservation(bob, &pb.CancelReservationReq{Reservation: handle}); err != nil {
			t.Fatal(err)
		}
	}
	if held := a.Stats().Held(); held != 1 {
		t.Fatalf("held = %d: a signed-in caller cancelled an internal reservation", held)
	}
	if got, err := h.GetReservation(context.Background(), &pb.GetReservationReq{Reservation: st.GetReservation()}); err != nil || got.GetGranted() == nil {
		t.Errorf("project code's own poll = %v, %v; want its grant", got, err)
	}
}

// A user whose id happens to be "internal" is still a user: the holder kinds
// do not collide.
func TestReservationHandle_HolderKindsDoNotCollide(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	st, err := h.ReserveTask(context.Background(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	got, err := h.GetReservation(signedIn(internalHolder), &pb.GetReservationReq{Reservation: st.GetReservation()})
	if err != nil || got.GetExpired() == nil {
		t.Errorf("a user named %q polled an internal handle: %v, %v", internalHolder, got, err)
	}
}

// An envelope that reads but names no user is refused: every such caller
// would otherwise share one identity, and one leaked handle would serve all.
func TestReservationHandle_AnEnvelopeWithNoUserIsRefused(t *testing.T) {
	h, _, _ := twoRelays(t, 1, 0)
	if _, err := h.ReserveTask(signedIn(""), &pb.ReserveTaskReq{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("reserve: %v, want Unauthenticated", err)
	}
	if _, err := h.GetReservation(signedIn(""), &pb.GetReservationReq{Reservation: handleFor("id-a", "r1")}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("poll: %v, want Unauthenticated", err)
	}
}

// A relay older than owners would let anyone holding the handle collect the
// place. Its reservation is given back and the next relay takes it; with no
// other relay the answer is NO_RELAY, saying why.
func TestReserveTask_ARelayThatDoesNotBindIsSkipped(t *testing.T) {
	old := &scripted{unbound: true}
	h, _ := pool(t, map[string]*scripted{"a": old, "b": {stats: loaded}}, "a", "b")
	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || !strings.HasPrefix(st.GetReservation(), "id-b.") {
		t.Fatalf("ReserveTask = %v, %v; want it placed on b", st, err)
	}
	if old.reserves.Load() != 1 || old.cancels.Load() != 1 {
		t.Errorf("the old relay: %d reserves, %d cancels; want its place given back", old.reserves.Load(), old.cancels.Load())
	}

	h, _ = pool(t, map[string]*scripted{"a": {unbound: true}}, "a")
	_, err = h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if refusal.ReasonOf(err) != refusal.NoRelay || !strings.Contains(err.Error(), "does not bind") {
		t.Errorf("only an old relay: %v, want %s naming the binding", err, refusal.NoRelay)
	}
}
