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
	skipped := 0
	for i, r := range relays {
		rejected, err := h.exchangeOne(ctx, r)
		// Logged BEFORE the error is looked at: a relay whose exchange failed
		// part-way may already have had workers refused, and an abort that
		// returned first used to drop exactly the lines that said which.
		logRejected(r, rejected)
		skipped += len(rejected)
		if err != nil {
			if errors.Is(err, errRecording) {
				// The RELAY answered; it is this control plane's own registry
				// that failed — the database is down or refusing writes, not
				// one worker's row being bad (that is `rejected`, above). Not
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
					r.Name, err, sweepSoFar(unreachable, relays[i+1:], skipped))
			}
			// Reported, not returned. One unreachable relay must not hide the
			// workers every other relay is holding — which is exactly the
			// moment an operator is most likely to be pressing this button.
			// A relay the registry refused to file workers under (errRelayRow)
			// lands here too: it is that relay's fault, not the fleet's.
			unreachable = append(unreachable, r.Name)
			h.note(ctx, r, err)
			continue
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
		SkippedWorkers:    int32(skipped),
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
		err := h.Workers.Record(ctx, r.ID, w)
		switch classifyRecordError(err) {
		case recorded:
			continue
		case refusedWorker:
			// ONE worker's claims do not fit the registry (a name longer
			// than the column, a constraint on its own row). That is about
			// this worker, not about the relay nor the registry, so the
			// rest of this relay's workers — and every other relay's —
			// are still recorded. It used to abort the whole sweep: one
			// machine with a 200-character hostname made fleet discovery
			// fail on every press, for every relay.
			rejected = append(rejected, rejectedWorker{worker: w, err: err})
		case refusedRelay:
			// The registry refused the RELAY this worker would be filed
			// under — its row is gone (deleted since the relay list was
			// read) or its id is not one the registry takes. Every other
			// worker of this relay would be refused the same way, so it is
			// this relay that failed, not each of its workers; skipping them
			// one by one used to log every worker as "refused" and then mark
			// the relay reached.
			return rejected, fmt.Errorf("%w: %w", errRelayRow, err)
		default:
			return rejected, fmt.Errorf("%w: %w", errRecording, err)
		}
	}
	return rejected, nil
}

// logRejected says which workers the registry refused to record, and why.
//
// Logged per worker, and counted in CheckWorkersResp.skipped_workers: the
// count is what an operator pressing the button sees, the log is where the
// names and reasons are.
func logRejected(r Relay, rejected []rejectedWorker) {
	for _, w := range rejected {
		log.Printf("cluster: relay %q reported worker %s (name %q, device %q) and the registry refused it: %v",
			r.Name, w.worker.GetCertFingerprint(), w.worker.GetName(), w.worker.GetDeviceId(), w.err)
	}
}

// recordOutcome is what one refused (or accepted) RecordWorker means for the
// sweep.
type recordOutcome int

const (
	// recorded — the row was written.
	recorded recordOutcome = iota
	// refusedWorker — the worker's OWN claims do not fit; skip it.
	refusedWorker
	// refusedRelay — the relay it would be filed under is the problem; that
	// relay failed.
	refusedRelay
	// registryDown — the registry cannot write at all; abort the sweep.
	registryDown
)

// relayIDField is RecordWorkerReq's relay_id, as the generated storage names
// it in an ErrorDetail's field.
const relayIDField = "relay_id"

// classifyRecordError tells a registry that refused ONE row from one that
// cannot write at all — by the gRPC CODE, never by whether a detail is
// attached.
//
// The generated storage's error wrapper (sdk core/grpcerr) attaches a w17
// ErrorDetail to EVERY error it returns: Internal for a database it cannot
// reach (code INTERNAL), Aborted for a serialization failure, Canceled,
// DeadlineExceeded, FailedPrecondition for an unmapped constraint. So "a
// detail is present" says nothing about whose fault it was; an earlier
// version read it as "the worker's own data", and a Postgres outage then
// skipped every worker of every relay and reported the sweep a success.
//
// Only InvalidArgument and OutOfRange are about the request — a failed field
// validation, a mapped constraint, a value the column cannot hold. Of those,
// one whose detail names relay_id is about the RELAY's id, not the worker's
// claims (a relay_id foreign key or a malformed id): today's schema has no
// foreign key on Worker.relay_id, so that is defensive, but an operator would
// otherwise read every worker of a vanished relay as individually refused.
// Everything else aborts.
func classifyRecordError(err error) recordOutcome {
	if err == nil {
		return recorded
	}
	st, ok := status.FromError(err)
	if !ok {
		return registryDown
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.OutOfRange:
	default:
		return registryDown
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*w17pb.ErrorDetail); ok && ed.GetField() == relayIDField {
			return refusedRelay
		}
	}
	return refusedWorker
}

// errRecording marks a failure to WRITE what a relay reported, as opposed to a
// failure to reach the relay.
var errRecording = errors.New("recording a worker")

// errRelayRow marks a relay the registry would not file workers under.
var errRelayRow = errors.New("the registry refused this relay's id")

// sweepSoFar renders what an aborted sweep had already found, for its error.
func sweepSoFar(unreachable []string, notAsked []Relay, skipped int) string {
	var b strings.Builder
	if skipped > 0 {
		fmt.Fprintf(&b, "; %d worker(s) skipped for their own claims (logged)", skipped)
	}
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
