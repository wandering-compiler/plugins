package relayserver

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
)

// A reservation is recorded under the owner the control plane sends, and the
// relay confirms it. A poll under another owner, or under none, answers like
// an id never issued; a cancel under either leaves the place to its owner.
func TestServer_AReservationAnswersOnlyItsOwner(t *testing.T) {
	pool := poolWith(t, 1)
	c := serveManagement(t, configured(t, pool))
	alice := resowner.With(t.Context(), "owner-alice")

	var hdr metadata.MD
	r, err := c.ReserveTask(alice, &pb.ReserveTaskReq{}, grpc.Header(&hdr))
	if err != nil || r.GetGranted() == nil {
		t.Fatalf("reserve: %v, %v", r, err)
	}
	if !resowner.Confirmed(hdr) {
		t.Fatalf("the relay did not confirm the owner: header %v", hdr)
	}
	id := r.GetReservation()

	for name, ctx := range map[string]context.Context{
		"another owner": resowner.With(t.Context(), "owner-bob"),
		"no owner":      t.Context(),
	} {
		st, err := c.GetReservation(ctx, &pb.GetReservationReq{Reservation: id})
		if err != nil || st.GetExpired().GetReason() != refusal.ReservationUnknown || st.GetReservation() != id {
			t.Errorf("%s's poll = %v, %v; want expired %s, as for an id never issued", name, st, err, refusal.ReservationUnknown)
		}
		if _, err := c.CancelReservation(ctx, &pb.CancelReservationReq{Reservation: id}); err != nil {
			t.Errorf("%s's cancel: %v, want the same success as for an id never issued", name, err)
		}
	}
	if held := pool.Stats().Held(); held != 1 {
		t.Fatalf("held = %d: a stranger's cancel gave the owner's slot away", held)
	}
	st, err := c.GetReservation(alice, &pb.GetReservationReq{Reservation: id})
	if err != nil || st.GetGranted().GetTicket() != r.GetGranted().GetTicket() {
		t.Fatalf("the owner's poll = %v, %v; want its grant", st, err)
	}
	if _, err := c.CancelReservation(alice, &pb.CancelReservationReq{Reservation: id}); err != nil {
		t.Fatal(err)
	}
	if held := pool.Stats().Held(); held != 0 {
		t.Errorf("held = %d after the owner cancelled", held)
	}
}

// A control plane from before owners sends none: the relay still reserves,
// but confirms no binding, so a control plane that needs one can tell.
func TestServer_NoOwnerIsNoConfirmation(t *testing.T) {
	c := serveManagement(t, configured(t, poolWith(t, 1)))
	var hdr metadata.MD
	if _, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{}, grpc.Header(&hdr)); err != nil {
		t.Fatal(err)
	}
	if resowner.Confirmed(hdr) {
		t.Errorf("a reservation with no owner was confirmed as bound: header %v", hdr)
	}
}
