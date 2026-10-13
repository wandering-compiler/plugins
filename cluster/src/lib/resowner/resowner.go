// Package resowner carries the owner of a polled reservation between the
// control plane and the relay that holds it.
//
// A reservation handle names the relay and the relay's reservation id, both
// of which the holder of a leaked handle can read. Nothing computed from them
// alone can tell the holder apart from the caller that reserved: anyone can
// compute it again for themselves. So the relay records the owner when the
// place is taken and checks it on every poll and cancel. That needs no secret
// and no state shared between relays or control-plane replicas: the relay
// already holds the reservation, in memory, for exactly as long as it exists.
//
// The control plane sends an opaque owner value on ReserveTask,
// GetReservation and CancelReservation (Header). A relay that recorded it says
// so in the ReserveTask response header (BoundHeader). A relay too old to know
// either ignores both, and the control plane refuses to hand out a handle such
// a relay would not bind.
package resowner

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Header carries the owner on every control-plane → relay reservation call.
// The value is opaque to the relay: it is compared, never parsed. A control
// plane always sends a non-empty one; an absent header is a control plane
// from before owners existed, and reads as the empty owner.
const Header = "w17-cluster-reservation-owner"

// BoundHeader is the relay's answer to ReserveTask: the reservation was
// recorded under the owner Header carried.
const BoundHeader = "w17-cluster-reservation-owner-bound"

// With returns ctx carrying owner, and only owner, to a relay. It REPLACES any
// owner already on ctx: the relay reads the first value, so an appended one
// could lose to whatever was there before.
func With(ctx context.Context, owner string) context.Context {
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	md.Set(Header, owner)
	return metadata.NewOutgoingContext(ctx, md)
}

// From reads the owner a control plane sent; "" when it sent none.
func From(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get(Header); len(v) > 0 {
		return v[0]
	}
	return ""
}

// Confirm tells the control plane the reservation is bound to its owner.
func Confirm(ctx context.Context) error {
	return grpc.SetHeader(ctx, metadata.Pairs(BoundHeader, "1"))
}

// Confirmed is whether a relay's response header confirms the binding.
func Confirmed(md metadata.MD) bool {
	v := md.Get(BoundHeader)
	return len(v) > 0 && v[0] == "1"
}
