package handlers

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
)

// fakeRelay is a relay: it speaks the same ClusterService the project does,
// which is the property the proxy design rests on.
type fakeRelay struct {
	pb.UnimplementedClusterServiceServer
	queued  int   // emit this many TaskQueued before granting
	grant   bool  // grant at the end, or close without one
	failErr error // fail the stream instead, after `sent` events
	sent    int
	seen    []string // labels this relay was asked for

	// stats is what RelayStats answers. Nil answers an idle relay with one
	// slot, which is what most tests want: the choice then falls to the
	// rotation.
	stats *pb.RelayStatsResp
}

func (f *fakeRelay) RelayStats(context.Context, *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	if f.stats != nil {
		return f.stats, nil
	}
	return &pb.RelayStatsResp{Capacity: 1}, nil
}

func (f *fakeRelay) ScheduleTask(req *pb.ScheduleTaskReq, srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
	f.seen = append(f.seen, req.GetLabel())
	for i := 0; i < f.queued; i++ {
		// Position is the relay's to report; `relay` is left EMPTY on purpose
		// — a relay has never been told its registry name.
		if err := srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Queued{
			Queued: &pb.TaskQueued{Position: int32(i + 1)},
		}}); err != nil {
			return err
		}
		f.sent++
	}
	if f.failErr != nil {
		return f.failErr
	}
	if !f.grant {
		return nil
	}
	return srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Granted{
		Granted: &pb.TaskGranted{Address: "10.0.0.1:9000", Ticket: "t-1"},
	}})
}

// serve stands the fake up in-process and returns a dialer for it.
func serve(t *testing.T, f *fakeRelay) func() (*grpc.ClientConn, error) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterClusterServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return func() (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// store is guarded: relays are polled for their load concurrently, and each
// poll records its outcome.
type store struct {
	relays []Relay

	mu      sync.Mutex
	reached []string
	failed  []string
}

func (s *store) ListEnabled(context.Context) ([]Relay, error) { return s.relays, nil }
func (s *store) Get(_ context.Context, id string) (Relay, error) {
	for _, r := range s.relays {
		if r.ID == id {
			return r, nil
		}
	}
	return Relay{}, ErrRelayNotFound
}
func (s *store) RecordReached(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reached = append(s.reached, id)
	return nil
}
func (s *store) RecordFailed(_ context.Context, id, msg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failed = append(s.failed, id+":"+msg)
	return nil
}

// collect drives the handler and gathers what the CALLER would see.
//
// Guarded: the end-to-end tests read it while the handler is still running in
// another goroutine, which is exactly how a caller watches a queue.
type collect struct {
	grpc.ServerStream
	ctx context.Context

	mu     sync.Mutex
	events []*pb.ScheduleTaskEvent
}

func (c *collect) Context() context.Context { return c.ctx }

func (c *collect) Send(e *pb.ScheduleTaskEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

// seen returns a snapshot. The slice is copied because the handler keeps
// appending to the original.
func (c *collect) seen() []*pb.ScheduleTaskEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*pb.ScheduleTaskEvent(nil), c.events...)
}

func run(t *testing.T, h *ClusterServiceHandler) (*collect, error) {
	t.Helper()
	c := &collect{ctx: t.Context()}
	return c, h.ScheduleTask(&pb.ScheduleTaskReq{Label: "job"}, c)
}

// The one transformation this layer performs. A relay cannot fill its own
// registry name — it has never been told it — so if the proxy does not stamp
// it, every queue position the caller sees belongs to an anonymous relay and
// an incident cannot name one.
func TestScheduleTask_StampsTheRelayNameOnEveryEvent(t *testing.T) {
	dial := serve(t, &fakeRelay{queued: 2, grant: true})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "eu-west-1", URL: "x", Fingerprint: "f"}}},
		Dial:    func(string, string) (*grpc.ClientConn, error) { return dial() },
	}
	c, err := run(t, h)
	if err != nil {
		t.Fatalf("ScheduleTask: %v", err)
	}
	if len(c.seen()) != 3 {
		t.Fatalf("caller saw %d events, want 2 queued + 1 granted", len(c.seen()))
	}
	for i, ev := range c.seen() {
		var got string
		if q := ev.GetQueued(); q != nil {
			got = q.GetRelay()
		} else {
			got = ev.GetGranted().GetRelay()
		}
		if got != "eu-west-1" {
			t.Errorf("event %d carries relay %q — the proxy did not stamp it", i, got)
		}
	}
}

// Granted is terminal: the handler returns, which closes the upstream too. A
// relay that kept sending would otherwise have the caller's stream outlive the
// answer it was waiting for.
func TestScheduleTask_GrantedEndsTheStream(t *testing.T) {
	dial := serve(t, &fakeRelay{grant: true})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "a"}}},
		Dial:    func(string, string) (*grpc.ClientConn, error) { return dial() },
	}
	c, _ := run(t, h)
	if n := len(c.seen()); n != 1 || c.seen()[0].GetGranted() == nil {
		t.Fatalf("want exactly one granted event, got %d", n)
	}
}

// An UNREACHABLE relay is skipped; the next one serves. This is the case a
// pool exists for.
func TestScheduleTask_FallsThroughAnUnreachableRelay(t *testing.T) {
	dial := serve(t, &fakeRelay{grant: true})
	st := &store{relays: []Relay{
		{ID: "dead", Name: "a-dead"},
		{ID: "live", Name: "b-live"},
	}}
	h := &ClusterServiceHandler{Workers: &workerStore{}, Relays: st}
	h.Dial = func(target, _ string) (*grpc.ClientConn, error) {
		if target == "" { // the dead one carries no url
			return nil, errors.New("connection refused")
		}
		return dial()
	}
	st.relays[1].URL = "live:1"

	c, err := run(t, h)
	if err != nil {
		t.Fatalf("a reachable relay behind a dead one did not serve: %v", err)
	}
	if got := c.seen()[0].GetGranted().GetRelay(); got != "b-live" {
		t.Errorf("granted by %q, want b-live", got)
	}
	if len(st.failed) != 1 || !strings.Contains(st.failed[0], "dead:") {
		t.Errorf("the dead relay was not recorded as failed: %v", st.failed)
	}
}

// …but a relay that ANSWERED and then failed is final. It formed an opinion,
// and asking a second relay would place the same work twice on the strength of
// a failure that happened after the first one accepted the conversation.
func TestScheduleTask_DoesNotRetryAfterARelayHasAnswered(t *testing.T) {
	boom := status.Error(codes.ResourceExhausted, "over quota")
	dialBad := serve(t, &fakeRelay{queued: 1, failErr: boom})
	dialGood := serve(t, &fakeRelay{grant: true})

	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "a"}, {ID: "2", Name: "b"}}},
	}
	h.Dial = func(_, fp string) (*grpc.ClientConn, error) {
		if fp == "second" {
			return dialGood()
		}
		return dialBad()
	}

	c, err := run(t, h)
	if err == nil {
		t.Fatal("a relay that answered and then failed was retried elsewhere")
	}
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Errorf("code = %s, want the RELAY's own ResourceExhausted", got)
	}
	// The queued event it did send still reached the caller, stamped.
	if len(c.seen()) != 1 || c.seen()[0].GetQueued().GetRelay() != "a" {
		t.Errorf("the pre-failure event did not reach the caller stamped: %v", c.seen())
	}
}

// An empty pool is an OPERATOR problem and the message has to say so — the
// caller cannot fix it and must not be told to retry forever.
func TestScheduleTask_EmptyPoolSaysWhatToDo(t *testing.T) {
	h := &ClusterServiceHandler{Workers: &workerStore{}, Relays: &store{}}
	_, err := run(t, h)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %s, want Unavailable", status.Code(err))
	}
	if !strings.Contains(err.Error(), "register") {
		t.Errorf("the refusal does not say what to do: %v", err)
	}
}

// Selection prefers the least loaded; ties go round-robin.
//
// The tie is the NORMAL case, not the corner one: every relay reads zero
// whenever the pool is below capacity, so whatever breaks it is what schedules
// the cluster most of the time.
//
// This test replaces one that asserted a NAME tiebreak — it pinned the defect
// as the contract, which is why the behaviour survived review. On an idle pool
// the name rule sent every task to the alphabetically first relay and left the
// rest cold (a consumer, 2026-09-25), turning off the spread that is the whole
// reason for running more than one machine.
func TestScheduleTask_IdlePoolSpreadsAcrossRelays(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"z-url": {grant: true}, "a-url": {grant: true}, "m-url": {grant: true},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays: &store{relays: []Relay{
			{ID: "z", Name: "z", URL: "z-url"},
			{ID: "a", Name: "a", URL: "a-url"},
			{ID: "m", Name: "m", URL: "m-url"},
		}},
		Dial: rs.Dial,
	}
	seen := map[string]int{}

	// Three tasks onto three idle relays must touch all three. Deterministic
	// because the rotation is a counter, not a coin.
	for i := 0; i < 3; i++ {
		seen[scheduledOn(t, h)]++
	}
	if len(seen) != 3 {
		t.Errorf("three tasks over three idle relays reached %d of them (%v) — "+
			"an idle pool is not spreading, which is the state it is usually in", len(seen), seen)
	}
}

// relaysByURL serves one fake relay per url; a url it does not know refuses
// the connection, which is how a test spells an unreachable relay.
type relaysByURL struct {
	dial map[string]func() (*grpc.ClientConn, error)
}

func newRelays(t *testing.T, fakes map[string]*fakeRelay) *relaysByURL {
	r := &relaysByURL{dial: map[string]func() (*grpc.ClientConn, error){}}
	for url, f := range fakes {
		r.dial[url] = serve(t, f)
	}
	return r
}

func (r *relaysByURL) Dial(target, _ string) (*grpc.ClientConn, error) {
	d, ok := r.dial[target]
	if !ok {
		return nil, errors.New("connection refused")
	}
	return d()
}

// scheduledOn names the relay that granted, from the event the caller saw.
func scheduledOn(t *testing.T, h *ClusterServiceHandler) string {
	t.Helper()
	c, err := run(t, h)
	if err != nil {
		t.Fatalf("ScheduleTask: %v", err)
	}
	return c.seen()[len(c.seen())-1].GetGranted().GetRelay()
}

// Load outranks the rotation, and the load is the RELAY's own account of
// itself — running work, promised slots and its queue, over its capacity.
//
// It used to be a count of the callers THIS console process was holding open,
// which on a pool below capacity read zero everywhere (a grant ends the hold
// at once) and knew nothing about any other replica.
func TestScheduleTask_PlacesOnTheLeastLoadedRelay(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 1, Reserved: 1, Capacity: 2}},
		"z-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 1, Capacity: 4}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays: &store{relays: []Relay{
			{ID: "a", Name: "a", URL: "a-url"},
			{ID: "z", Name: "z", URL: "z-url"},
		}},
		Dial: rs.Dial,
	}
	// Every rotation, so the choice cannot be the rotation's.
	for i := 0; i < 3; i++ {
		if got := scheduledOn(t, h); got != "z" {
			t.Fatalf("placed on %q; a is full (2 of 2), z has 3 of 4 free", got)
		}
	}
}

// Queued callers are load too: a relay with a free slot on paper and a queue
// in front of it is not idle.
func TestScheduleTask_AQueueCountsAsLoad(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {grant: true, stats: &pb.RelayStatsResp{Queued: 3, Capacity: 1}},
		"z-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 1, Capacity: 2}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "z", Name: "z", URL: "z-url"}}},
		Dial:    rs.Dial,
	}
	for i := 0; i < 2; i++ {
		if got := scheduledOn(t, h); got != "z" {
			t.Fatalf("placed on %q, behind a queue of 3", got)
		}
	}
}

// A draining relay is not a candidate at all, however idle it looks.
func TestScheduleTask_SkipsADrainingRelay(t *testing.T) {
	drainingRelay := &fakeRelay{grant: true, stats: &pb.RelayStatsResp{Capacity: 8, Draining: true}}
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": drainingRelay,
		"z-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 3, Capacity: 4}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "z", Name: "z", URL: "z-url"}}},
		Dial:    rs.Dial,
	}
	for i := 0; i < 2; i++ {
		if got := scheduledOn(t, h); got != "z" {
			t.Fatalf("placed on %q — a draining relay was chosen", got)
		}
	}
	if len(drainingRelay.seen) != 0 {
		t.Errorf("the draining relay was asked to schedule %d time(s)", len(drainingRelay.seen))
	}
}

// A relay that STARTS draining between the stats poll and the placement
// answers RELAY_DRAINING — and that is fall-through, like an unreachable
// relay, not a final answer. The relay did not judge the request; it is going
// away.
func TestScheduleTask_RelayDrainingIsFallThrough(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {queued: 1, failErr: refusal.New(codes.Unavailable, refusal.RelayDraining, "draining")},
		"z-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 3, Capacity: 4}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "z", Name: "z", URL: "z-url"}}},
		Dial:    rs.Dial,
	}
	if got := scheduledOn(t, h); got != "z" {
		t.Fatalf("granted by %q, want z after a drained", got)
	}
}

// Every relay is unreachable or draining: the caller is told the pool has
// nothing, not handed one relay's private refusal.
func TestScheduleTask_NothingPlaceableIsUnavailable(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {grant: true, stats: &pb.RelayStatsResp{Capacity: 1, Draining: true}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "d", Name: "dead", URL: "nowhere"}}},
		Dial:    rs.Dial,
	}
	_, err := run(t, h)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %s, want Unavailable", status.Code(err))
	}
}
