package handlers

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// WorkerStore is the seam onto the worker registry, wired by RegisterPlugin.
type WorkerStore interface {
	// Banned returns every banned worker id (SPKI fingerprint), across every
	// relay — the set that rides on each call to a relay.
	Banned(ctx context.Context) ([]string, error)
	// Record is idempotent by fingerprint and must NOT reset a decision: a
	// banned worker keeps being reported by its relay, and returning it to
	// enrolled on every sweep would make a ban mean nothing.
	Record(ctx context.Context, relayID string, w *pb.KnownWorker) error
	// EnrolledCount is the number of enrolled, unbanned workers across every
	// relay.
	EnrolledCount(ctx context.Context) (int, error)
	// Decide bans (ban) or unbans the workers with these registry ids,
	// recording who decided and when.
	Decide(ctx context.Context, ids []string, ban bool, by string) error
}

// withBans puts the complete ban set on ctx, for every relay call made under
// it.
//
// EVERY call, not a sync now and then: a relay holds bans in memory only, so
// one that restarted would let a banned but CA-valid worker attach until the
// next manual sync. With the set on every contact — and every placement
// begins with one — a restarted relay is corrected before any work is placed
// on it.
//
// A registry that cannot be read REFUSES the call rather than sending an
// empty set: empty is "nobody is banned", and a database blip must not lift
// every ban at once.
func (h *ClusterServiceHandler) withBans(ctx context.Context) (context.Context, error) {
	if h.Workers == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"cluster: no worker registry is wired — the ban set cannot be sent to a relay")
	}
	bans, err := h.Workers.Banned(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cluster: cannot read the ban set: %v", err)
	}
	return workeradmit.WithBans(ctx, bans), nil
}

// CheckWorkers contacts every enabled relay and records every worker it has
// met, so an operator can see the fleet and ban from it.
//
// Pulled by an operator rather than swept in the background: the console is
// HA, and a sweep would run in every replica needing coordination it does not
// have. Nothing waits on it — a worker is admitted by its certificate, and a
// ban travels on every call — so the only cost of not pressing it is a worker
// not yet listed.
func (h *ClusterServiceHandler) CheckWorkers(
	ctx context.Context, _ *pb.CheckWorkersReq,
) (*pb.CheckWorkersResp, error) {
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	relays, err := h.Relays.ListEnabled(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cluster: cannot read the relay registry: %v", err)
	}

	// Counted before and after rather than reported per row, because the
	// recording statement is an idempotent upsert and cannot say whether it
	// inserted. The difference is the honest answer to "what is new", and it
	// stays honest if two operators press the button at once — the second one
	// simply discovers nothing.
	before, err := h.Workers.EnrolledCount(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cluster: cannot count workers: %v", err)
	}

	var unreachable []string
	for i, r := range relays {
		rejected, err := h.exchangeOne(ctx, r)
		if err != nil {
			if errors.Is(err, errRecording) {
				// The RELAY answered; it is this control plane's own registry
				// that failed — the database is down or refusing writes, not
				// one worker's row being bad (that is `rejected`, below). Not
				// the relay's fault, so neither listed as unreachable nor
				// written onto its row — which would send an operator to debug
				// a healthy machine — and fatal, because every other relay's
				// workers would fail to record the same way. The upsert is
				// idempotent: pressing again is the retry.
				//
				// What the sweep already learnt is not thrown away: the rows
				// recorded so far stay recorded, unreachable relays were
				// already noted on their rows, and the message names them and
				// the relays never asked, so the operator does not have to
				// press again just to find out.
				return nil, status.Errorf(codes.Unavailable,
					"cluster: cannot record the workers relay %q reported: %v%s",
					r.Name, err, sweepSoFar(unreachable, relays[i+1:]))
			}
			// Reported, not returned. One unreachable relay must not hide the
			// workers every other relay is holding — which is exactly the
			// moment an operator is most likely to be pressing this button.
			unreachable = append(unreachable, r.Name)
			h.note(ctx, r, err)
			continue
		}
		for _, w := range rejected {
			// Logged rather than failing the sweep: the response has no field
			// for it, and the alternative — aborting — is what let one worker
			// with an over-long hostname hide the whole fleet.
			log.Printf("cluster: relay %q reported worker %s (name %q, device %q) and the registry refused it: %v",
				r.Name, w.worker.GetCertFingerprint(), w.worker.GetName(), w.worker.GetDeviceId(), w.err)
		}
		h.noteOK(ctx, r)
	}

	after, err := h.Workers.EnrolledCount(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cluster: cannot count workers: %v", err)
	}
	sort.Strings(unreachable)

	discovered := after - before
	if discovered < 0 {
		// Somebody banned a worker while the sweep ran. "Negative
		// discoveries" is not a thing to report.
		discovered = 0
	}
	return &pb.CheckWorkersResp{
		Discovered:        int32(discovered),
		EnrolledTotal:     int32(after),
		UnreachableRelays: unreachable,
	}, nil
}

// rejectedWorker is one worker the registry refused to record because of
// what the worker itself claimed.
type rejectedWorker struct {
	worker *pb.KnownWorker
	err    error
}

func (h *ClusterServiceHandler) exchangeOne(ctx context.Context, r Relay) ([]rejectedWorker, error) {
	conn, err := h.dialReady(ctx, r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	resp, err := newRelayClient(conn).ExchangeWorkers(ctx, &pb.ExchangeWorkersReq{})
	if err != nil {
		return nil, err
	}
	var rejected []rejectedWorker
	for _, w := range resp.GetWorkers() {
		if w.GetCertFingerprint() == "" {
			// No fingerprint, no identity to ban. Skipped rather than stored:
			// a row an operator cannot act on is worse than no row.
			continue
		}
		if err := h.Workers.Record(ctx, r.ID, w); err != nil {
			if refusedForItsOwnData(err) {
				// ONE worker's claims do not fit the registry (a name longer
				// than the column, a constraint on its own row). That is about
				// this worker, not about the relay nor the registry, so the
				// rest of this relay's workers — and every other relay's —
				// are still recorded. It used to abort the whole sweep: one
				// machine with a 200-character hostname made fleet discovery
				// fail on every press, for every relay.
				rejected = append(rejected, rejectedWorker{worker: w, err: err})
				continue
			}
			return rejected, fmt.Errorf("%w: %w", errRecording, err)
		}
	}
	return rejected, nil
}

// refusedForItsOwnData tells a registry that refused ONE row — validation of
// the request, or a constraint the row broke — from a registry that cannot
// write at all (Unavailable, Internal, a deadline, a transport error).
//
// The generated storage answers both a failed field validation and a mapped
// constraint violation with InvalidArgument, and a mapped violation also
// carries a w17 ErrorDetail; either is enough. Everything else is treated as
// registry-wide, because skipping on a registry that is actually down would
// report a "successful" sweep that recorded nothing.
func refusedForItsOwnData(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.OutOfRange:
		return true
	}
	for _, d := range st.Details() {
		if _, ok := d.(*w17pb.ErrorDetail); ok {
			return true
		}
	}
	return false
}

// errRecording marks a failure to WRITE what a relay reported, as opposed to a
// failure to reach the relay.
var errRecording = errors.New("recording a worker")

// sweepSoFar renders what an aborted sweep had already found, for its error.
func sweepSoFar(unreachable []string, notAsked []Relay) string {
	var b strings.Builder
	if len(unreachable) > 0 {
		sorted := slices.Clone(unreachable)
		sort.Strings(sorted)
		fmt.Fprintf(&b, "; unreachable so far: %s", strings.Join(sorted, ", "))
	}
	if len(notAsked) > 0 {
		names := make([]string, 0, len(notAsked))
		for _, r := range notAsked {
			names = append(names, r.Name)
		}
		fmt.Fprintf(&b, "; not asked: %s", strings.Join(names, ", "))
	}
	return b.String()
}

// ExchangeWorkers is a RELAY's method. The project holds the decisions; it has
// no relay to be one for.
func (h *ClusterServiceHandler) ExchangeWorkers(
	context.Context, *pb.ExchangeWorkersReq,
) (*pb.ExchangeWorkersResp, error) {
	return nil, status.Error(codes.Unimplemented,
		"cluster: ExchangeWorkers is answered by a relay, not by the control plane")
}

// IssueRegistrationCode asks the selected relay for a one-time code a new
// worker enrols with. Exactly one relay: a code is that relay's, and a worker
// joins one relay.
//
// The code passes through here on its way to the operator and is not kept: the
// relay holds it (as a hash), and a lost code is replaced by asking again.
func (h *ClusterServiceHandler) IssueRegistrationCode(
	ctx context.Context, req *pb.IssueRegistrationCodeReq,
) (*pb.IssueRegistrationCodeResp, error) {
	if len(req.GetIds()) != 1 {
		return nil, status.Errorf(codes.InvalidArgument,
			"cluster: a registration code is for exactly one relay, %d were selected", len(req.GetIds()))
	}
	ctx, err := h.withBans(ctx)
	if err != nil {
		return nil, err
	}
	r, err := h.Relays.Get(ctx, req.GetIds()[0])
	if errors.Is(err, ErrRelayNotFound) {
		return nil, status.Errorf(codes.NotFound, "cluster: no relay %q is registered", req.GetIds()[0])
	}
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "cluster: cannot read the relay registry: %v", err)
	}
	conn, err := h.dialReady(ctx, r)
	if err != nil {
		h.note(ctx, r, err)
		return nil, status.Errorf(codes.Unavailable, "cluster: relay %q is not reachable: %v", r.Name, err)
	}
	defer func() { _ = conn.Close() }()
	resp, err := newRelayClient(conn).IssueRegistrationCode(ctx, &pb.IssueRegistrationCodeReq{})
	if err != nil {
		return nil, err
	}
	h.noteOK(ctx, r)
	resp.Relay = r.Name
	// The fingerprint THIS connection was pinned to, i.e. the registry's —
	// the relay presents one certificate on every listener, so it is also the
	// one the worker will meet. Taken from what was verified rather than from
	// what the relay said about itself.
	resp.RelayFingerprint = r.Fingerprint
	return resp, nil
}
