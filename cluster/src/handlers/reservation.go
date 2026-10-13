package handlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/sdk/go/lib/principal"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
)

// handleSep joins a relay's registry id, its own reservation id and the
// holder tag into the handle the project hands out. A dot, because no part can
// contain one: registry ids are UUIDs, and the other two are hex.
const handleSep = "."

// ReserveTask places a reservation on the least-loaded relay, exactly as
// ScheduleTask chooses — and falls through the same failures — but answers at
// once with a handle to poll instead of holding a stream.
//
// The handle is `<relay_id>.<relay_reservation_id>.<holder_tag>`. Naming the
// relay in it is what keeps the control plane stateless: any replica can route
// the poll, and none has to remember where anything was placed.
//
// The handle is bound to the caller reserving now in two places. The RELAY
// records the place under the caller's owner value (ownerOf) and answers a
// poll or cancel under any other as if the id were unknown: that is the
// binding, and it needs no secret, because the relay holds the reservation
// anyway. The tag (holderTag) only turns a handle presented by the wrong
// caller away before a relay is dialled; anyone can compute it, so it is not
// what keeps a leaked handle from working.
//
// A relay that does not confirm the binding (resowner.BoundHeader) is older
// than this control plane and would let any holder of the handle collect the
// place. Its reservation is cancelled and the next relay is tried.
func (h *ClusterServiceHandler) ReserveTask(ctx context.Context, req *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	holder, err := holderOf(ctx)
	if err != nil {
		return nil, err
	}
	cands, err := h.placeable(ctx)
	if err != nil {
		return nil, err
	}
	defer cands.close()
	ctx = resowner.With(ctx, ownerOf(holder))

	var lastErr error
	var unbound []string
	for _, c := range cands.list {
		var hdr metadata.MD
		rc := newRelayClient(c.conn)
		st, err := rc.ReserveTask(ctx, req, grpc.Header(&hdr))
		if err == nil && !resowner.Confirmed(hdr) {
			_, _ = rc.CancelReservation(ctx, &pb.CancelReservationReq{Reservation: st.GetReservation()})
			unbound = append(unbound, c.Name)
			lastErr = fmt.Errorf("relay %q does not bind a reservation to its caller", c.Name)
			continue
		}
		if err == nil {
			return stampReservation(st, c.Relay, holder), nil
		}
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		if refusal.ReasonOf(err) == "" {
			// No reason: the connection that just answered its stats failed
			// under us. Not this relay's opinion of the request.
			h.note(ctx, c.Relay, err)
			err = errors.Join(errUnreachable, err)
		}
		if !fallsThrough(err) {
			return nil, err
		}
		lastErr = err
	}
	// An old relay is named whatever failed after it: it is the one cause
	// an operator can fix, and the last error would hide it behind, say, a
	// full queue on the next relay.
	upgrade := ""
	if len(unbound) > 0 {
		upgrade = fmt.Sprintf("; relay(s) %s do not bind a reservation to its caller — upgrade them to this plugin's version",
			strings.Join(unbound, ", "))
	}
	return nil, refusal.New(codes.Unavailable, refusal.NoRelay, fmt.Sprintf(
		"cluster: no registered relay could take a reservation (%d enabled, %d placeable)%s; last error: %v",
		cands.enabled, len(cands.list), upgrade, lastErr))
}

// GetReservation polls the relay the handle names.
//
// A relay that no longer has a registry row answers `expired` like a
// reservation the relay forgot: the place cannot be collected either way. A
// relay that cannot be REACHED is an error, not `expired` — a blip must not
// cost a client its place, and the relay abandons a reservation that really is
// unreachable for long enough on its own.
func (h *ClusterServiceHandler) GetReservation(ctx context.Context, req *pb.GetReservationReq) (*pb.ReservationState, error) {
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	holder, err := holderOf(ctx)
	if err != nil {
		return nil, err
	}
	relay, local, gone, err := h.resolveHandle(ctx, req.GetReservation(), holder)
	if err != nil {
		return nil, err
	}
	if gone {
		return &pb.ReservationState{
			Reservation: req.GetReservation(),
			State: &pb.ReservationState_Expired{Expired: &pb.ReservationExpired{
				Reason: refusal.ReservationUnknown,
			}},
		}, nil
	}
	conn, err := h.dialReady(ctx, relay)
	if err != nil {
		h.note(ctx, relay, err)
		return nil, status.Errorf(codes.Unavailable, "cluster: relay %q is not reachable: %v", relay.Name, err)
	}
	defer func() { _ = conn.Close() }()
	ctx = resowner.With(ctx, ownerOf(holder))
	st, err := newRelayClient(conn).GetReservation(ctx, &pb.GetReservationReq{Reservation: local})
	if err != nil {
		return nil, err
	}
	return stampReservation(st, relay, holder), nil
}

// CancelReservation forwards a cancellation. Idempotent like the relay's: a
// handle whose relay is gone has nothing left to cancel.
func (h *ClusterServiceHandler) CancelReservation(ctx context.Context, req *pb.CancelReservationReq) (*pb.CancelReservationResp, error) {
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	holder, err := holderOf(ctx)
	if err != nil {
		return nil, err
	}
	relay, local, gone, err := h.resolveHandle(ctx, req.GetReservation(), holder)
	if err != nil {
		return nil, err
	}
	if gone {
		return &pb.CancelReservationResp{}, nil
	}
	conn, err := h.dialReady(ctx, relay)
	if err != nil {
		h.note(ctx, relay, err)
		return nil, status.Errorf(codes.Unavailable, "cluster: relay %q is not reachable: %v", relay.Name, err)
	}
	defer func() { _ = conn.Close() }()
	ctx = resowner.With(ctx, ownerOf(holder))
	return newRelayClient(conn).CancelReservation(ctx, &pb.CancelReservationReq{Reservation: local})
}

// resolveHandle splits a handle and finds its relay. `gone` is a well-formed
// handle whose relay the registry no longer holds, or one minted for a caller
// other than `holder`.
func (h *ClusterServiceHandler) resolveHandle(ctx context.Context, handle, holder string) (Relay, string, bool, error) {
	parts := strings.Split(handle, handleSep)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Relay{}, "", false, status.Error(codes.InvalidArgument,
			"cluster: that is not a reservation handle — pass back exactly what ReserveTask returned")
	}
	relayID, local, tag := parts[0], parts[1], parts[2]
	// Another caller's handle answers like a reservation the relay forgot:
	// expired, nothing to cancel. No answer tells it the handle was real.
	if subtle.ConstantTimeCompare([]byte(tag), []byte(holderTag(holder, relayID, local))) != 1 {
		return Relay{}, "", true, nil
	}
	relay, err := h.Relays.Get(ctx, relayID)
	if errors.Is(err, ErrRelayNotFound) {
		return Relay{}, "", true, nil
	}
	if err != nil {
		return Relay{}, "", false, status.Errorf(codes.Unavailable, "cluster: cannot read the relay registry: %v", err)
	}
	return relay, local, false, nil
}

// envelopeKey is the metadata key the gateway threads the verified principal
// under (principal's own constant is unexported).
const envelopeKey = "x-w17-user"

// Holders: a signed-in caller is userHolder plus its user id, a call with no
// principal is internalHolder. The prefix keeps the two kinds apart: no user
// id makes a signed-in caller the internal one, or the reverse.
const (
	internalHolder = "internal"
	userHolder     = "user:"
)

// holderOf is the caller a reservation is bound to: the signed-in user
// (pb.Caller, envelope field 2), or internalHolder for a call that carries no
// principal — the project's own code, or an unauthenticated surface. So a
// handle reserved by project code works only for project code, and one
// reserved by a user only for that user.
//
// An envelope that is present but cannot be read, or that names no user, is
// refused rather than read as "no principal" or as one shared empty user:
// either would hand every such caller one identity they all share, and a
// leaked handle would work for all of them.
func holderOf(ctx context.Context) (string, error) {
	var who pb.Caller
	err := principal.Envelope(ctx, &who)
	if err == nil {
		if who.GetUserId() == "" {
			return "", status.Error(codes.Unauthenticated,
				"cluster: the caller's principal names no user, so a reservation cannot be bound to it")
		}
		return userHolder + who.GetUserId(), nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get(envelopeKey); len(v) == 0 || v[0] == "" {
		return internalHolder, nil
	}
	return "", status.Error(codes.Unauthenticated,
		"cluster: the caller's principal cannot be read, so a reservation cannot be bound to it")
}

// ownerOf is the value the relay records a reservation under for holder
// (resowner.Header). A hash, so a relay does not see user ids in the clear —
// but an unkeyed one: it is a stable pseudonym, the same for one user on every
// reservation and every relay, and `internal` hashes alike in every project.
// A relay can link a user's reservations, and anyone who can guess a user id
// can confirm it. That is acceptable because relays are run by the operator
// that runs the control plane; the hash keeps ids out of relay memory and
// logs, it does not hide them from a relay. Never empty: the empty owner is a
// control plane from before owners existed.
func ownerOf(holder string) string {
	sum := sha256.Sum256([]byte("cluster-reservation-owner\x00" + holder))
	return hex.EncodeToString(sum[:])
}

// holderTag is a hash of the holder (holderOf), the relay's registry id and
// its reservation id. It lets the control plane turn away a handle presented
// by another caller without dialling the relay. It is NOT the binding: every
// input but the holder is in the handle, so whoever holds a leaked handle can
// compute the tag for themselves. The relay's owner check is what refuses
// them (see ReserveTask).
func holderTag(holder, relayID, local string) string {
	sum := sha256.Sum256([]byte("cluster-reservation\x00" + holder + "\x00" + relayID + "\x00" + local))
	return hex.EncodeToString(sum[:16])
}

// stampReservation turns a relay's answer into the project's: the handle gains
// the relay's registry id, and the relay's name goes where a relay cannot put
// it itself.
func stampReservation(st *pb.ReservationState, r Relay, holder string) *pb.ReservationState {
	local := st.GetReservation()
	st.Reservation = r.ID + handleSep + local + handleSep + holderTag(holder, r.ID, local)
	switch s := st.GetState().(type) {
	case *pb.ReservationState_Queued:
		s.Queued.Relay = r.Name
	case *pb.ReservationState_Granted:
		s.Granted.Relay = r.Name
	}
	return st
}
