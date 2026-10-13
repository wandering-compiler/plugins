package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
)

// ScheduleTask picks a relay and proxies its scheduling stream to the caller.
//
// The caller's connection is what holds the queue place, so this handler's job
// is to keep one open toward a relay for exactly as long as the caller keeps
// one open toward it. Everything else — the queue, the capacity, the ticket —
// belongs to the relay and is never modelled here.
func (h *ClusterServiceHandler) ScheduleTask(
	req *pb.ScheduleTaskReq,
	srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent],
) error {
	ctx := srv.Context()

	// The caller's own deadline wins when it is shorter. max_wait_seconds is a
	// second opinion the caller volunteered, and a zero there means "I already
	// have a deadline and would rather you used it".
	if s := req.GetMaxWaitSeconds(); s > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s)*time.Second)
		defer cancel()
	}
	ctx, err := h.withBans(ctx)
	if err != nil {
		return err
	}
	holder, err := holderOf(ctx)
	if err != nil {
		return err
	}

	cands, err := h.placeable(ctx)
	if err != nil {
		return err
	}
	defer h.closeCandidates(cands)
	// The caller's queue places count against its share of each relay's
	// queue (CALLER_QUEUE_FULL), under the same owner as its reservations.
	ctx = resowner.With(ctx, ownerOf(holder))

	var lastErr error
	callerFull := false
	for _, c := range cands.list {
		err := h.proxyOne(ctx, c, req, srv)
		if err == nil {
			return nil
		}
		// The caller went away, or their deadline passed. Trying the next
		// relay would place work for somebody who is no longer listening.
		if ctx.Err() != nil {
			return status.FromContextError(ctx.Err()).Err()
		}
		// Anything else the RELAY said is final for this request — it accepted
		// the conversation and then refused or failed, and a second relay would
		// be answering a question the first one already answered.
		if !fallsThrough(err) {
			return err
		}
		callerFull = callerFull || refusal.ReasonOf(err) == refusal.CallerQueueFull
		lastErr = err
	}
	if callerFull {
		return callerQueueFull(cands)
	}
	return refusal.New(codes.Unavailable, refusal.NoRelay, fmt.Sprintf(
		"cluster: no registered relay could take the task (%d enabled, %d placeable); last error: %v",
		cands.enabled, len(cands.list), lastErr))
}

// callerQueueFull answers a caller that some relay refused because the caller
// already holds its share of that relay's queue, and no other relay took it.
// Not NO_RELAY: the pool is up, and what frees a place is the caller's own
// places being granted or cancelled.
func callerQueueFull(c candidates) error {
	return refusal.New(codes.ResourceExhausted, refusal.CallerQueueFull, fmt.Sprintf(
		"cluster: this caller already holds its share of the queue on every relay that could take it "+
			"(%d enabled, %d placeable) — wait for the places it holds, or cancel some", c.enabled, len(c.list)))
}

// errUnreachable marks the failures that justify trying another relay: the
// connection never got far enough for the relay to have an opinion.
var errUnreachable = errors.New("relay unreachable")

// fallsThrough is whether a failure on one relay sends the request to the
// next. Unreachable, plus the two refusals that are about the RELAY rather
// than the request: it is draining, or it is misconfigured. Both say "not
// here", and neither is an answer to the caller.
func fallsThrough(err error) bool {
	if errors.Is(err, errUnreachable) {
		return true
	}
	switch refusal.ReasonOf(err) {
	case refusal.RelayDraining, refusal.RelayMisconfigured, refusal.QueueFull,
		refusal.CallerQueueFull, refusal.BanSetNeeded:
		return true
	}
	return false
}

// candidate is a relay that answered its stats and may be placed on, with its
// shared management connection held for the placement.
type candidate struct {
	Relay
	conn  *relayConn
	stats *pb.RelayStatsResp
}

type candidates struct {
	list    []candidate
	enabled int
}

func (h *ClusterServiceHandler) closeCandidates(c candidates) {
	for _, x := range c.list {
		h.release(x.conn)
	}
}

// placeable asks every enabled relay for its load, in parallel, and returns
// the ones that can be placed on, least loaded first.
//
// Unreachable relays are noted and left out; draining relays are left out.
// Asked fresh every time: the load a relay reported a second ago already
// belongs to a world in which other callers have since been placed.
func (h *ClusterServiceHandler) placeable(ctx context.Context) (candidates, error) {
	relays, err := h.Relays.ListEnabled(ctx)
	if err != nil {
		return candidates{}, status.Errorf(codes.Unavailable, "cluster: cannot read the relay registry: %v", err)
	}
	if len(relays) == 0 {
		// Unavailable and not NotFound: the pool is EMPTY, which an operator
		// fixes by registering or enabling a relay. NotFound would read as
		// "you asked for something that does not exist", and the caller asked
		// for nothing but capacity.
		return candidates{}, refusal.New(codes.Unavailable, refusal.NoRelay,
			"cluster: no enabled relay is registered — register one, or re-enable one that was turned off")
	}

	// Rotated BEFORE the stable sort, so relays with equal load keep rotated
	// order and consecutive tasks land on different machines.
	//
	// Loads tie constantly — every relay reads zero whenever the pool is idle
	// — so the tiebreak is not a detail, it IS the scheduler under light load.
	// A name tiebreak was the original, and it sent every task to the
	// alphabetically first relay for as long as the pool was not saturated.
	// Random would also spread, but this is deterministic, which a test can
	// state as "three tasks, three relays" instead of a distribution.
	if n := len(relays); n > 1 {
		k := int((h.rotate.Add(1) - 1) % uint64(n))
		rotated := make([]Relay, 0, n)
		rotated = append(rotated, relays[k:]...)
		rotated = append(rotated, relays[:k]...)
		relays = rotated
	}

	polled := make([]candidate, len(relays))
	errs := make([]error, len(relays))
	var wg sync.WaitGroup
	for i, r := range relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, st, err := h.poll(ctx, r)
			polled[i] = candidate{Relay: r, conn: conn, stats: st}
			errs[i] = err
			// Queued, never waited for: a slow registry must not delay the
			// placement at all (see observe).
			h.observe(ctx, r, err)
		}()
	}
	wg.Wait()

	out := candidates{enabled: len(relays)}
	for i, c := range polled {
		if errs[i] != nil {
			continue
		}
		if c.stats.GetDraining() {
			h.release(c.conn)
			continue
		}
		out.list = append(out.list, c)
	}
	sort.SliceStable(out.list, func(i, j int) bool {
		return load(out.list[i].stats) < load(out.list[j].stats)
	})
	return out, nil
}

// load is the share of a relay's capacity already spoken for: running work,
// promised slots and its queue, over what its workers can take. A relay with
// no capacity sorts last — it can grant nothing until a worker attaches — but
// it is still a candidate, because one might.
func load(st *pb.RelayStatsResp) float64 {
	if st.GetCapacity() <= 0 {
		return math.Inf(1)
	}
	return float64(st.GetInUse()+st.GetReserved()+st.GetQueued()) / float64(st.GetCapacity())
}

// poll takes a relay's shared management connection and asks for its load.
func (h *ClusterServiceHandler) poll(ctx context.Context, r Relay) (*relayConn, *pb.RelayStatsResp, error) {
	conn, err := h.acquire(ctx, r)
	if err != nil {
		return nil, nil, err
	}
	c, cancel := context.WithTimeout(ctx, h.dialTimeout())
	defer cancel()
	st, err := newRelayClient(conn).RelayStats(c, &pb.RelayStatsReq{})
	if err != nil {
		h.release(conn)
		return nil, nil, fmt.Errorf("relay %q: stats: %w", r.Name, err)
	}
	return conn, st, nil
}

func (h *ClusterServiceHandler) proxyOne(
	ctx context.Context,
	c candidate,
	req *pb.ScheduleTaskReq,
	srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent],
) error {
	up, err := newRelayClient(c.conn).ScheduleTask(ctx, req)
	if err != nil {
		h.observe(ctx, c.Relay, err)
		return errors.Join(errUnreachable, err)
	}

	answered := false
	resent := false
	for {
		ev, err := up.Recv()
		if err != nil && !answered && !resent && refusal.ReasonOf(err) == refusal.BanSetNeeded {
			// The relay holds an older ban set than the version named alone
			// (it restarted without its saved set since it last answered).
			// It refused before queueing anything: send it the set, once.
			resent = true
			c.conn.forgetHeld()
			if up, err = newRelayClient(c.conn).ScheduleTask(ctx, req); err != nil {
				h.observe(ctx, c.Relay, err)
				return errors.Join(errUnreachable, err)
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			// The relay closed without granting. That is not success: the
			// caller is owed either a grant or a reason, and an empty stream
			// is neither.
			return status.Errorf(codes.Unavailable,
				"cluster: relay %q closed the stream without granting a slot", c.Name)
		}
		if err != nil {
			if !answered && refusal.ReasonOf(err) == "" {
				// Nothing came back and the relay gave no reason: the
				// connection that just answered its stats failed under us.
				h.observe(ctx, c.Relay, err)
				return errors.Join(errUnreachable, err)
			}
			return err
		}
		answered = true

		// The relay has never been told its registry name, so it cannot fill
		// this in and the caller needs it — to read a queue position, and to
		// say which relay an incident is about.
		switch e := ev.GetEvent().(type) {
		case *pb.ScheduleTaskEvent_Queued:
			e.Queued.Relay = c.Name
		case *pb.ScheduleTaskEvent_Granted:
			e.Granted.Relay = c.Name
		}

		if err := srv.Send(ev); err != nil {
			return err
		}
		if ev.GetGranted() != nil {
			// Granted is terminal. Returning closes both streams — this one
			// because the caller has what it came for, and the upstream
			// because its context ends with the call. The SLOT is not
			// released by that: it is held by the ticket until claimed, and
			// then by the worker connection.
			return nil
		}
	}
}

// note and noteOK write the observed state at once, waiting for the write.
// Operator actions (CheckWorkers, IssueRegistrationCode, DrainRelay) use them:
// an operator who just pressed a button reads the row next and expects it to
// say so. Placements and polls use observe, which never waits. Both swallow
// their own errors (see record).
func (h *ClusterServiceHandler) note(ctx context.Context, r Relay, cause error) {
	if ctx.Err() != nil {
		return // the operator left; the relay did not fail (see observe)
	}
	h.retireRelay(r.ID)
	h.record(ctx, r, cause, true)
}

func (h *ClusterServiceHandler) noteOK(ctx context.Context, r Relay) {
	h.record(ctx, r, nil, true)
}

// RelayStats is a RELAY's method; the project has no load of its own to
// report — it asks the relays.
func (h *ClusterServiceHandler) RelayStats(context.Context, *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	return nil, status.Error(codes.Unimplemented,
		"cluster: RelayStats is answered by a relay, not by the control plane")
}

// DrainRelay asks each selected relay to drain.
//
// Every id is resolved BEFORE any relay is touched, so a selection with one
// stale id fails whole instead of draining half of what the operator meant.
// A relay that cannot be reached is reported, not fatal: the others still
// drain, and the operator sees which one to chase.
func (h *ClusterServiceHandler) DrainRelay(ctx context.Context, req *pb.DrainRelayReq) (*pb.DrainRelayResp, error) {
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	relays := make([]Relay, 0, len(req.GetIds()))
	for _, id := range req.GetIds() {
		r, err := h.Relays.Get(ctx, id)
		if errors.Is(err, ErrRelayNotFound) {
			return nil, status.Errorf(codes.NotFound, "cluster: no relay %q is registered", id)
		}
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cluster: cannot read the relay registry: %v", err)
		}
		relays = append(relays, r)
	}

	var unreachable []string
	for _, r := range relays {
		if err := h.drainOne(ctx, r); err != nil {
			h.note(ctx, r, err)
			unreachable = append(unreachable, r.Name)
			continue
		}
		h.noteOK(ctx, r)
	}
	sort.Strings(unreachable)
	return &pb.DrainRelayResp{UnreachableRelays: unreachable}, nil
}

func (h *ClusterServiceHandler) drainOne(ctx context.Context, r Relay) error {
	conn, err := h.acquire(ctx, r)
	if err != nil {
		return err
	}
	defer h.release(conn)
	c, cancel := context.WithTimeout(ctx, h.dialTimeout())
	defer cancel()
	_, err = newRelayClient(conn).DrainRelay(c, &pb.DrainRelayReq{})
	return err
}
