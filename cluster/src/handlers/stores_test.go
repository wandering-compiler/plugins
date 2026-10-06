package handlers

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
)

// tablesServer is the bundle's side of the four generated services, answered
// from memory: the store adapters are tested through the REAL generated
// clients over a real gRPC connection, so a status code that only exists on
// the wire (NotFound from a single-row read) is the one they meet.
type tablesServer struct {
	pb.UnimplementedRelayQueryServer
	pb.UnimplementedRelayMutationServer
	pb.UnimplementedWorkerQueryServer
	pb.UnimplementedWorkerMutationServer

	mu        sync.Mutex
	relays    []*pb.Relay
	emptyRow  bool  // GetRelay answers an empty row instead of NotFound
	fail      error // every call fails with this, when set
	listReqs  []*pb.ListRelaysReq
	reached   []*pb.RecordRelayReachedReq
	failed    []*pb.RecordRelayFailedReq
	stateReqs []pb.WorkerState
	recorded  []*pb.RecordWorkerReq
	bans      []*pb.DecideWorkersReq
	unbans    []*pb.DecideWorkersReq
	banned    []string
	enrolled  int64
}

func (s *tablesServer) ListRelays(_ context.Context, in *pb.ListRelaysReq) (*pb.ListRelaysResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listReqs = append(s.listReqs, in)
	if s.fail != nil {
		return nil, s.fail
	}
	return &pb.ListRelaysResp{Relays: s.relays}, nil
}

func (s *tablesServer) GetRelay(_ context.Context, in *pb.GetRelayReq) (*pb.Relay, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	for _, r := range s.relays {
		if r.GetId() == in.GetId() {
			return r, nil
		}
	}
	if s.emptyRow {
		return &pb.Relay{}, nil
	}
	return nil, status.Error(codes.NotFound, "no such relay")
}

func (s *tablesServer) RecordRelayReached(_ context.Context, in *pb.RecordRelayReachedReq) (*pb.RecordRelayReachedResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reached = append(s.reached, in)
	return &pb.RecordRelayReachedResp{}, s.fail
}

func (s *tablesServer) RecordRelayFailed(_ context.Context, in *pb.RecordRelayFailedReq) (*pb.RecordRelayFailedResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, in)
	return &pb.RecordRelayFailedResp{}, s.fail
}

func (s *tablesServer) FingerprintsByState(_ context.Context, in *pb.FingerprintsByStateReq) (*pb.FingerprintsByStateResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateReqs = append(s.stateReqs, in.GetState())
	if s.fail != nil {
		return nil, s.fail
	}
	return &pb.FingerprintsByStateResp{Fingerprints: s.banned}, nil
}

func (s *tablesServer) CountWorkersByState(_ context.Context, in *pb.CountWorkersByStateReq) (*pb.CountWorkersByStateResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateReqs = append(s.stateReqs, in.GetState())
	if s.fail != nil {
		return nil, s.fail
	}
	return &pb.CountWorkersByStateResp{Total: s.enrolled}, nil
}

func (s *tablesServer) RecordWorker(_ context.Context, in *pb.RecordWorkerReq) (*pb.RecordWorkerResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorded = append(s.recorded, in)
	return &pb.RecordWorkerResp{}, s.fail
}

func (s *tablesServer) BanWorkers(_ context.Context, in *pb.DecideWorkersReq) (*pb.DecideWorkersResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bans = append(s.bans, in)
	return &pb.DecideWorkersResp{}, s.fail
}

func (s *tablesServer) UnbanWorkers(_ context.Context, in *pb.DecideWorkersReq) (*pb.DecideWorkersResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unbans = append(s.unbans, in)
	return &pb.DecideWorkersResp{}, s.fail
}

// serveTables stands the four services up and returns the stores RegisterPlugin
// would build over their generated clients.
func serveTables(t *testing.T, s *tablesServer) (RelayStore, WorkerStore) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterRelayQueryServer(srv, s)
	pb.RegisterRelayMutationServer(srv, s)
	pb.RegisterWorkerQueryServer(srv, s)
	pb.RegisterWorkerMutationServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///tables",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return NewRelayStore(pb.NewRelayQueryClient(cc), pb.NewRelayMutationClient(cc)),
		NewWorkerStore(pb.NewWorkerQueryClient(cc), pb.NewWorkerMutationClient(cc))
}

// Scheduling asks for ENABLED relays only — a disabled relay must leave the
// pool the moment its switch is flipped — and gets back every field it dials
// and pins with.
func TestRelayStore_ListEnabledAsksForEnabledOnlyAndMapsTheRow(t *testing.T) {
	tb := &tablesServer{relays: []*pb.Relay{
		{Id: "r-1", Name: "acme-eu", Url: "eu.example.com:13444", CertFingerprint: "ab12", Enabled: true},
		{Id: "r-2", Name: "acme-us", Url: "us.example.com:13444", CertFingerprint: "cd34", Enabled: true},
	}}
	relays, _ := serveTables(t, tb)
	got, err := relays.ListEnabled(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []Relay{
		{ID: "r-1", Name: "acme-eu", URL: "eu.example.com:13444", Fingerprint: "ab12"},
		{ID: "r-2", Name: "acme-us", URL: "us.example.com:13444", Fingerprint: "cd34"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d relays, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("relay %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(tb.listReqs) != 1 || !tb.listReqs[0].GetEnabledOnly() {
		t.Errorf("ListRelays was asked %v — scheduling must ask for enabled relays only", tb.listReqs)
	}
}

// An unknown id is ErrRelayNotFound whichever way the bundle says it — a
// NotFound status or an empty row — because the handlers turn exactly that
// error into "expired" and "no such relay"; anything else would read as the
// registry being down.
func TestRelayStore_GetNotFoundBothWays(t *testing.T) {
	for _, empty := range []bool{false, true} {
		tb := &tablesServer{emptyRow: empty, relays: []*pb.Relay{{Id: "r-1", Name: "acme-eu", Url: "u", CertFingerprint: "f"}}}
		relays, _ := serveTables(t, tb)
		if _, err := relays.Get(t.Context(), "r-404"); !errors.Is(err, ErrRelayNotFound) {
			t.Errorf("emptyRow=%v: unknown id gave %v, want ErrRelayNotFound", empty, err)
		}
		r, err := relays.Get(t.Context(), "r-1")
		if err != nil || r != (Relay{ID: "r-1", Name: "acme-eu", URL: "u", Fingerprint: "f"}) {
			t.Errorf("emptyRow=%v: Get(r-1) = %+v, %v", empty, r, err)
		}
	}
}

// A registry that FAILS is not a registry that has no such relay: the error
// passes through, so a database blip is never mistaken for a deleted relay
// (which a reservation poll would answer `expired`, costing a client its place).
func TestRelayStore_AFailureIsNotNotFound(t *testing.T) {
	tb := &tablesServer{fail: status.Error(codes.Unavailable, "database restarting")}
	relays, _ := serveTables(t, tb)
	_, err := relays.Get(t.Context(), "r-1")
	if err == nil || errors.Is(err, ErrRelayNotFound) {
		t.Fatalf("a failing registry gave %v, want the failure itself", err)
	}
	if _, err := relays.ListEnabled(t.Context()); status.Code(err) != codes.Unavailable {
		t.Errorf("ListEnabled on a failing registry: %v", err)
	}
}

// The observed-state cache: reached carries a timestamp, failed carries the
// message an operator reads.
func TestRelayStore_RecordsReachedAndFailed(t *testing.T) {
	tb := &tablesServer{}
	relays, _ := serveTables(t, tb)
	before := time.Now().Add(-time.Second)
	if err := relays.RecordReached(t.Context(), "r-1"); err != nil {
		t.Fatal(err)
	}
	if err := relays.RecordFailed(t.Context(), "r-2", "not reachable within 5s"); err != nil {
		t.Fatal(err)
	}
	if len(tb.reached) != 1 || tb.reached[0].GetId() != "r-1" || tb.reached[0].GetAt().AsTime().Before(before) {
		t.Errorf("reached = %v, want r-1 at about now", tb.reached)
	}
	if len(tb.failed) != 1 || tb.failed[0].GetId() != "r-2" || tb.failed[0].GetError() != "not reachable within 5s" {
		t.Errorf("failed = %v", tb.failed)
	}
}

// The ban set is the BANNED state, nothing else; enrolled counts the ENROLLED
// state. Asking for the wrong state would ship the wrong set to every relay.
func TestWorkerStore_BannedAndEnrolledAskForTheirState(t *testing.T) {
	tb := &tablesServer{banned: []string{"aa", "bb"}, enrolled: 7}
	_, workers := serveTables(t, tb)
	bans, err := workers.Banned(t.Context())
	if err != nil || len(bans) != 2 || bans[0] != "aa" || bans[1] != "bb" {
		t.Fatalf("Banned = %v, %v", bans, err)
	}
	n, err := workers.EnrolledCount(t.Context())
	if err != nil || n != 7 {
		t.Fatalf("EnrolledCount = %d, %v", n, err)
	}
	if len(tb.stateReqs) != 2 || tb.stateReqs[0] != pb.WorkerState_WORKER_STATE_BANNED || tb.stateReqs[1] != pb.WorkerState_WORKER_STATE_ENROLLED {
		t.Errorf("states asked = %v, want [BANNED ENROLLED]", tb.stateReqs)
	}
}

// A ban set that cannot be read is an ERROR, never an empty set — withBans
// turns this into a refused call, and an empty set would lift every ban.
func TestWorkerStore_AnUnreadableBanSetIsAnError(t *testing.T) {
	tb := &tablesServer{fail: status.Error(codes.Unavailable, "database restarting")}
	_, workers := serveTables(t, tb)
	if bans, err := workers.Banned(t.Context()); err == nil {
		t.Fatalf("a failing registry answered the ban set %v", bans)
	}
	if _, err := workers.EnrolledCount(t.Context()); err == nil {
		t.Fatal("a failing registry answered a count")
	}
}

// A worker is recorded under the relay that reported it, with every claim it
// made, keyed by its fingerprint.
func TestWorkerStore_RecordCarriesTheRelayAndTheClaims(t *testing.T) {
	tb := &tablesServer{}
	_, workers := serveTables(t, tb)
	err := workers.Record(t.Context(), "r-1", &pb.KnownWorker{CertFingerprint: "aa", Name: "acme-1", DeviceId: "dev-1"})
	if err != nil {
		t.Fatal(err)
	}
	want := &pb.RecordWorkerReq{CertFingerprint: "aa", Name: "acme-1", DeviceId: "dev-1", RelayId: "r-1"}
	if len(tb.recorded) != 1 || tb.recorded[0].String() != want.String() {
		t.Errorf("recorded %v, want %v", tb.recorded, want)
	}
}

// Ban and unban go to their OWN mutations, carrying who decided and when —
// swapped, an operator's ban would lift one.
func TestWorkerStore_DecideRoutesBanAndUnban(t *testing.T) {
	tb := &tablesServer{}
	_, workers := serveTables(t, tb)
	if err := workers.Decide(t.Context(), []string{"w-1", "w-2"}, true, "op-7"); err != nil {
		t.Fatal(err)
	}
	if err := workers.Decide(t.Context(), []string{"w-3"}, false, "op-8"); err != nil {
		t.Fatal(err)
	}
	if len(tb.bans) != 1 || len(tb.unbans) != 1 {
		t.Fatalf("bans %v, unbans %v — want one each", tb.bans, tb.unbans)
	}
	b, u := tb.bans[0], tb.unbans[0]
	if len(b.GetIds()) != 2 || b.GetDecidedBy() != "op-7" || b.GetAt() == nil {
		t.Errorf("ban = %v, want both ids, op-7, a timestamp", b)
	}
	if len(u.GetIds()) != 1 || u.GetIds()[0] != "w-3" || u.GetDecidedBy() != "op-8" || u.GetAt() == nil {
		t.Errorf("unban = %v, want w-3, op-8, a timestamp", u)
	}
	tb.fail = status.Error(codes.Internal, "constraint")
	if err := workers.Decide(t.Context(), []string{"w-1"}, true, "op-7"); err == nil {
		t.Error("a failed ban was reported as done")
	}
}
