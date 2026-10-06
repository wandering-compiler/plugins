package handlers

// An in-memory usage store served over REAL gRPC (bufconn), so the
// usage_persistence code is exercised through the generated clients it uses in
// a bundle — request marshalling, status codes and all — instead of a fake of
// the client interface. It applies the columns' own limits (max_len, the
// `<> ''` checks) and returns NotFound for a missing row, which is what the
// generated storage does (sql.ErrNoRows → codes.NotFound).

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
)

type usageStore struct {
	mu sync.Mutex

	nextID int64
	scopes map[string]int64
	models map[string]int64
	labels map[[2]string]int64
	rows   map[int64]*pb.RecordUsageReq
	order  []int64
	attach map[int64][]int64 // usage id → label ids

	limits map[int64]*pb.GetScopeLimitResp
	spend  map[int64][]*pb.ScopeSpendLine

	calls map[string]int
	// fail makes the named method fail with this error, `failN[m]` times (0 =
	// every time).
	fail  map[string]error
	failN map[string]int

	limitReqs []*pb.GetScopeLimitReq
	spendReqs []*pb.GetScopeSpendReq
}

func newUsageStore() *usageStore {
	return &usageStore{
		scopes: map[string]int64{}, models: map[string]int64{}, labels: map[[2]string]int64{},
		rows: map[int64]*pb.RecordUsageReq{}, attach: map[int64][]int64{},
		limits: map[int64]*pb.GetScopeLimitResp{}, spend: map[int64][]*pb.ScopeSpendLine{},
		calls: map[string]int{}, fail: map[string]error{}, failN: map[string]int{},
	}
}

// enter counts a call and returns the injected failure, if any.
func (s *usageStore) enter(method string) error {
	s.calls[method]++
	err, ok := s.fail[method]
	if !ok {
		return nil
	}
	if n := s.failN[method]; n > 0 {
		if n == 1 {
			delete(s.fail, method)
			delete(s.failN, method)
		} else {
			s.failN[method] = n - 1
		}
	}
	return err
}

func (s *usageStore) failWith(method string, err error, times int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail[method] = err
	s.failN[method] = times
}

func (s *usageStore) count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *usageStore) intern(m map[string]int64, key string) int64 {
	if id, ok := m[key]; ok {
		return id
	}
	s.nextID++
	m[key] = s.nextID
	return s.nextID
}

// scopeIDOf is the id a scope was interned under, or 0.
func (s *usageStore) scopeIDOf(name string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopes[name]
}

// setLimit installs a monthly cap for a scope, interning it first.
func (s *usageStore) setLimit(scope string, minor int64, currency string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.intern(s.scopes, scope)
	s.limits[id] = &pb.GetScopeLimitResp{LimitMinor: minor, Currency: currency}
}

func (s *usageStore) setSpend(scope string, lines ...*pb.ScopeSpendLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.intern(s.scopes, scope)
	s.spend[id] = lines
}

type storedRow struct {
	id     int64
	row    *pb.RecordUsageReq
	labels map[string]string
}

// usageRows returns every recorded row in insertion order, labels resolved.
func (s *usageStore) usageRows() []storedRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := map[int64][2]string{}
	for kv, id := range s.labels {
		byID[id] = kv
	}
	var out []storedRow
	for _, id := range s.order {
		r := storedRow{id: id, row: s.rows[id], labels: map[string]string{}}
		for _, l := range s.attach[id] {
			kv := byID[l]
			r.labels[kv[0]] = kv[1]
		}
		out = append(out, r)
	}
	return out
}

type mutationServer struct {
	pb.UnimplementedUsageMutationServer
	s *usageStore
}

func (m mutationServer) InternScope(_ context.Context, r *pb.InternScopeReq) (*pb.InternScopeResp, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if err := m.s.enter("InternScope"); err != nil {
		return nil, err
	}
	if r.GetExternalId() == "" || len(r.GetExternalId()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "external_id: length out of range")
	}
	return &pb.InternScopeResp{Id: m.s.intern(m.s.scopes, r.GetExternalId())}, nil
}

func (m mutationServer) InternModel(_ context.Context, r *pb.InternModelReq) (*pb.InternModelResp, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if err := m.s.enter("InternModel"); err != nil {
		return nil, err
	}
	if len(r.GetName()) > 128 {
		return nil, status.Error(codes.InvalidArgument, "name: too long")
	}
	return &pb.InternModelResp{Id: m.s.intern(m.s.models, r.GetName())}, nil
}

func (m mutationServer) InternLabel(_ context.Context, r *pb.InternLabelReq) (*pb.InternLabelResp, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if err := m.s.enter("InternLabel"); err != nil {
		return nil, err
	}
	if r.GetKey() == "" || len(r.GetKey()) > 64 || len(r.GetValue()) > 256 {
		return nil, status.Error(codes.InvalidArgument, "label: length out of range")
	}
	kv := [2]string{r.GetKey(), r.GetValue()}
	if id, ok := m.s.labels[kv]; ok {
		return &pb.InternLabelResp{Id: id}, nil
	}
	m.s.nextID++
	m.s.labels[kv] = m.s.nextID
	return &pb.InternLabelResp{Id: m.s.nextID}, nil
}

func (m mutationServer) RecordUsage(_ context.Context, r *pb.RecordUsageReq) (*pb.RecordUsageResp, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if err := m.s.enter("RecordUsage"); err != nil {
		return nil, err
	}
	m.s.nextID++
	m.s.rows[m.s.nextID] = r
	m.s.order = append(m.s.order, m.s.nextID)
	return &pb.RecordUsageResp{Id: m.s.nextID}, nil
}

func (m mutationServer) AttachUsageLabel(_ context.Context, r *pb.AttachUsageLabelReq) (*pb.AttachUsageLabelResp, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if err := m.s.enter("AttachUsageLabel"); err != nil {
		return nil, err
	}
	if _, ok := m.s.rows[r.GetUsageId()]; !ok {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("no usage row %d", r.GetUsageId()))
	}
	m.s.attach[r.GetUsageId()] = append(m.s.attach[r.GetUsageId()], r.GetLabelId())
	m.s.nextID++
	return &pb.AttachUsageLabelResp{Id: m.s.nextID}, nil
}

type queryServer struct {
	pb.UnimplementedUsageQueryServer
	s *usageStore
}

func (q queryServer) GetScopeLimit(_ context.Context, r *pb.GetScopeLimitReq) (*pb.GetScopeLimitResp, error) {
	q.s.mu.Lock()
	defer q.s.mu.Unlock()
	q.s.limitReqs = append(q.s.limitReqs, r)
	if err := q.s.enter("GetScopeLimit"); err != nil {
		return nil, err
	}
	l, ok := q.s.limits[r.GetScopeId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "GetScopeLimit: not found")
	}
	return l, nil
}

func (q queryServer) GetScopeSpend(_ context.Context, r *pb.GetScopeSpendReq) (*pb.GetScopeSpendResp, error) {
	q.s.mu.Lock()
	defer q.s.mu.Unlock()
	q.s.spendReqs = append(q.s.spendReqs, r)
	if err := q.s.enter("GetScopeSpend"); err != nil {
		return nil, err
	}
	return &pb.GetScopeSpendResp{Lines: q.s.spend[r.GetScopeId()]}, nil
}

// usageClients is the shape of the bundle's ClientSet in an activation with
// the feature on: it has both accessors.
type usageClients struct{ conn *grpc.ClientConn }

func (c usageClients) UsageMutation() pb.UsageMutationClient {
	return pb.NewUsageMutationClient(c.conn)
}
func (c usageClients) UsageQuery() pb.UsageQueryClient { return pb.NewUsageQueryClient(c.conn) }

// mutationOnly has the writer's half and not the limiter's.
type mutationOnly struct{ conn *grpc.ClientConn }

func (c mutationOnly) UsageMutation() pb.UsageMutationClient {
	return pb.NewUsageMutationClient(c.conn)
}

// serveUsageStore starts the store on an in-process listener.
func serveUsageStore(t *testing.T) (*usageStore, usageClients) {
	t.Helper()
	store := newUsageStore()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterUsageMutationServer(srv, mutationServer{s: store})
	pb.RegisterUsageQueryServer(srv, queryServer{s: store})
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
	})
	return store, usageClients{conn: conn}
}
