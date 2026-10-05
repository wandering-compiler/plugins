package handlers

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
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
	resp, err := s.q.ListRelays(ctx, &pb.ListRelaysReq{EnabledOnly: true})
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

func (s workerRegistry) Banned(ctx context.Context) ([]string, error) {
	resp, err := s.q.FingerprintsByState(ctx, &pb.FingerprintsByStateReq{State: pb.WorkerState_WORKER_STATE_BANNED})
	if err != nil {
		return nil, err
	}
	return resp.GetFingerprints(), nil
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
	req := &pb.DecideWorkersReq{Ids: ids, DecidedBy: by, At: timestamppb.Now()}
	var err error
	if ban {
		_, err = s.m.BanWorkers(ctx, req)
	} else {
		_, err = s.m.UnbanWorkers(ctx, req)
	}
	return err
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
