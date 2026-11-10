package handlers

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// NewRelayStore adapts the bundle's generated clients to the seam the
// scheduler uses. The handler is written against the interface so that the
// scheduling rules can be tested against a store that fails on command; this
// is the one implementation that talks to a database.
func NewRelayStore(q pb.RelayQueryClient, m pb.RelayMutationClient) RelayStore {
	return relayStore{q: q, m: m}
}

type relayStore struct {
	q pb.RelayQueryClient
	m pb.RelayMutationClient
}

func (s relayStore) ListEnabled(ctx context.Context) ([]Relay, error) {
	return s.list(ctx, true)
}

func (s relayStore) ListAll(ctx context.Context) ([]Relay, error) {
	return s.list(ctx, false)
}

func (s relayStore) list(ctx context.Context, enabledOnly bool) ([]Relay, error) {
	resp, err := s.q.ListRelays(ctx, &pb.ListRelaysReq{EnabledOnly: enabledOnly})
	if err != nil {
		return nil, err
	}
	out := make([]Relay, 0, len(resp.GetRelays()))
	for _, r := range resp.GetRelays() {
		out = append(out, Relay{
			ID:          r.GetId(),
			Name:        r.GetName(),
			URL:         r.GetUrl(),
			Fingerprint: r.GetCertFingerprint(),
		})
	}
	return out, nil
}

func (s relayStore) Get(ctx context.Context, id string) (Relay, error) {
	r, err := s.q.GetRelay(ctx, &pb.GetRelayReq{Id: id})
	if status.Code(err) == codes.NotFound {
		return Relay{}, ErrRelayNotFound
	}
	if err != nil {
		return Relay{}, err
	}
	if r.GetId() == "" {
		// A single-row read that matched nothing. Whether the generated read
		// answers NotFound or an empty row is the bundle's choice; both mean
		// the same thing here.
		return Relay{}, ErrRelayNotFound
	}
	return Relay{ID: r.GetId(), Name: r.GetName(), URL: r.GetUrl(), Fingerprint: r.GetCertFingerprint()}, nil
}

func (s relayStore) RecordReached(ctx context.Context, id string) error {
	_, err := s.m.RecordRelayReached(ctx, &pb.RecordRelayReachedReq{Id: id, At: timestamppb.Now()})
	return err
}

func (s relayStore) RecordFailed(ctx context.Context, id, msg string) error {
	_, err := s.m.RecordRelayFailed(ctx, &pb.RecordRelayFailedReq{Id: id, Error: msg})
	return err
}

// NewWorkerStore adapts the generated clients to the admission seam.
func NewWorkerStore(q pb.WorkerQueryClient, m pb.WorkerMutationClient) WorkerStore {
	return workerRegistry{q: q, m: m}
}

type workerRegistry struct {
	q pb.WorkerQueryClient
	m pb.WorkerMutationClient
}

func (s workerRegistry) Banned(ctx context.Context) ([]string, int64, error) {
	// The version is read before AND after the set, and the pair is used only
	// when the two agree. Read once before, a decision landing between the
	// reads labelled the NEWER set with the OLD version; a relay accepts an
	// equal version, so another replica's old set at that version could then
	// replace it and lift a ban.
	for attempt := 0; attempt < banReadAttempts; attempt++ {
		before, err := s.banVersion(ctx)
		if err != nil {
			return nil, 0, err
		}
		resp, err := s.q.FingerprintsByState(ctx, &pb.FingerprintsByStateReq{State: pb.WorkerState_WORKER_STATE_BANNED})
		if err != nil {
			return nil, 0, err
		}
		after, err := s.banVersion(ctx)
		if err != nil {
			return nil, 0, err
		}
		if before == after {
			return resp.GetFingerprints(), after, nil
		}
	}
	return nil, 0, errBanSetUnsettled
}

// banReadAttempts bounds how many times Banned retries while decisions keep
// landing between its reads.
const banReadAttempts = 3

var errBanSetUnsettled = errors.New("the ban set changed during every read; try again")

func (s workerRegistry) BanVersion(ctx context.Context) (int64, error) {
	return s.banVersion(ctx)
}

func (s workerRegistry) banVersion(ctx context.Context) (int64, error) {
	v, err := s.q.BanSetVersion(ctx, &pb.BanSetVersionReq{})
	if err != nil {
		return 0, err
	}
	if t := v.GetVersion(); t != nil {
		return t.AsTime().UnixNano(), nil
	}
	return 0, nil
}

func (s workerRegistry) Record(ctx context.Context, relayID string, w *pb.KnownWorker) error {
	_, err := s.m.RecordWorker(ctx, &pb.RecordWorkerReq{
		CertFingerprint: w.GetCertFingerprint(),
		Name:            w.GetName(),
		DeviceId:        w.GetDeviceId(),
		RelayId:         relayID,
	})
	return err
}

func (s workerRegistry) Decide(ctx context.Context, ids []string, ban bool, by string) error {
	// The decision time is the ban set's version (see Banned), so it must
	// never fall below the newest decision already recorded: a replica whose
	// clock runs behind would otherwise LOWER the version, and every relay
	// that had applied the newer one would ignore this decision until the
	// clocks caught up. Moved just past the newest decision when needed.
	at := time.Now()
	v, err := s.q.BanSetVersion(ctx, &pb.BanSetVersionReq{})
	if err != nil {
		return err
	}
	if t := v.GetVersion(); t != nil && !at.After(t.AsTime()) {
		at = pastNewestDecision(t.AsTime())
	}
	req := &pb.DecideWorkersReq{Ids: ids, DecidedBy: by, At: timestamppb.New(at)}
	if ban {
		_, err = s.m.BanWorkers(ctx, req)
	} else {
		_, err = s.m.UnbanWorkers(ctx, req)
	}
	return err
}

// pastNewestDecision is a decision time just past the newest one: 1 ms plus a
// random whole number of microseconds below a millisecond (the column keeps
// microseconds). Two replicas that both lag the newest decision read the same
// newest time; moved by exactly 1 ms they recorded the SAME version, and a
// relay applies a set at an equal version — so the set one of them read
// between the two commits (missing the other's ban) could replace the newer
// one until the next delivery. The random part makes that collision a 1 in
// 1000 event instead of a certainty; a collision that still happens heals at
// the next set any replica sends (cluster SPEC, bans gap).
func pastNewestDecision(newest time.Time) time.Time {
	return newest.Truncate(time.Microsecond).
		Add(time.Millisecond + time.Duration(rand.IntN(1000))*time.Microsecond)
}

func (s workerRegistry) Exists(ctx context.Context, id string) (bool, error) {
	w, err := s.q.GetWorker(ctx, &pb.GetWorkerReq{Id: id})
	switch status.Code(err) {
	case codes.OK:
		// An empty row is a single-row read that matched nothing (see
		// relayStore.Get).
		return w.GetId() != "", nil
	case codes.NotFound, codes.InvalidArgument:
		// InvalidArgument: not a well-formed id, so no row has it.
		return false, nil
	}
	return false, err
}

func (s workerRegistry) EnrolledCount(ctx context.Context) (int, error) {
	resp, err := s.q.CountWorkersByState(ctx, &pb.CountWorkersByStateReq{
		State: pb.WorkerState_WORKER_STATE_ENROLLED,
	})
	if err != nil {
		return 0, err
	}
	return int(resp.GetTotal()), nil
}
