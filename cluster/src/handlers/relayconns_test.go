package handlers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// countDials wraps a handler's dialer and counts the connections it opens.
func countDials(h *ClusterServiceHandler) *atomic.Int32 {
	var n atomic.Int32
	dial := h.Dial
	h.Dial = func(target, fp string) (*grpc.ClientConn, error) {
		n.Add(1)
		return dial(target, fp)
	}
	return &n
}

// Placements, reservations and polls share ONE connection per relay: the
// connections opened do not grow with the calls made. Before, every placement
// opened one per enabled relay and every poll one more — 3 relays, 5 rounds of
// ScheduleTask + ReserveTask + GetReservation was 35 connections (and as many
// TLS handshakes); it is 3.
func TestRelayConns_OneConnectionPerRelayWhateverTheCalls(t *testing.T) {
	h, _ := pool(t, map[string]*scripted{"a": {}, "b": {}, "c": {}}, "a", "b", "c")
	dials := countDials(h)
	for i := 0; i < 5; i++ {
		if _, err := run(t, h); err != nil {
			t.Fatalf("ScheduleTask: %v", err)
		}
		st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
		if err != nil {
			t.Fatalf("ReserveTask: %v", err)
		}
		if _, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: st.GetReservation()}); err != nil {
			t.Fatalf("GetReservation: %v", err)
		}
	}
	if got := dials.Load(); got != 3 {
		t.Errorf("%d connections opened for 15 calls over 3 relays, want 3 (one per relay)", got)
	}
}

// A row edited to another pin (or url) gets a new connection at once; the
// old one stays up for the call still using it and closes when that call
// ends. A failure retires the connection, so the next call dials afresh.
func TestRelayConns_ANewPinOrAFailureGetsANewConnection(t *testing.T) {
	h, _ := pool(t, map[string]*scripted{"a": {}}, "a")
	dials := countDials(h)
	r := Relay{ID: "id-a", Name: "relay-a", URL: "a", Fingerprint: "f-a"}

	old, err := h.acquire(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	rotated := r
	rotated.Fingerprint = "f-rotated"
	fresh, err := h.acquire(t.Context(), rotated)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == old || dials.Load() != 2 {
		t.Fatalf("a rotated pin reused the old connection (dials=%d)", dials.Load())
	}
	if st := old.cc.GetState(); st == connectivity.Shutdown {
		t.Fatal("the old connection was closed under the call still using it")
	}
	h.release(old)
	if st := old.cc.GetState(); st != connectivity.Shutdown {
		t.Errorf("the old connection is %v after its last call ended, want closed", st)
	}
	h.release(fresh)

	h.observe(rotated, errors.New("transport is closing"))
	settle(t, h)
	again, err := h.acquire(t.Context(), rotated)
	if err != nil {
		t.Fatal(err)
	}
	defer h.release(again)
	if again == fresh || dials.Load() != 3 {
		t.Errorf("after a failure the same connection was reused (dials=%d)", dials.Load())
	}
}

// The periodic delivery uses the shared connections too, and closes those of
// relays no longer registered.
func TestRelayConns_DeliveryReusesAndPrunes(t *testing.T) {
	h, st := pool(t, map[string]*scripted{"a": {}, "b": {}}, "a", "b")
	dials := countDials(h)
	h.pushBans(t.Context(), true)
	h.pushBans(t.Context(), true)
	if dials.Load() != 2 {
		t.Fatalf("two deliveries to two relays opened %d connections, want 2", dials.Load())
	}
	h.connsMu.Lock()
	gone := h.conns["id-b"]
	h.connsMu.Unlock()
	st.relays = st.relays[:1]
	h.pushBans(t.Context(), true)
	if s := gone.cc.GetState(); s != connectivity.Shutdown {
		t.Errorf("the connection to a deleted relay is %v, want closed", s)
	}
	if err := h.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.acquire(t.Context(), st.relays[0]); !errors.Is(err, errConnsClosed) {
		t.Errorf("acquire after Close: %v, want refused", err)
	}
}

// blockingStore holds every observed-state write until released, the way a
// registry under load does.
type blockingStore struct {
	*store
	release chan struct{}
	writes  atomic.Int32
}

func (b *blockingStore) RecordReached(ctx context.Context, id string) error {
	b.writes.Add(1)
	<-b.release
	return b.store.RecordReached(ctx, id)
}

func (b *blockingStore) RecordFailed(ctx context.Context, id, msg string) error {
	b.writes.Add(1)
	<-b.release
	return b.store.RecordFailed(ctx, id, msg)
}

// A placement never waits for the observed state to be written: with every
// write stuck, placements still complete, and the writes in flight stay one
// per relay however many placements ran.
func TestPlacement_DoesNotWaitForTheObservedState(t *testing.T) {
	h, st := pool(t, map[string]*scripted{"a": {}, "b": {}}, "a", "b", "")
	bs := &blockingStore{store: st, release: make(chan struct{})}
	h.Relays = bs
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 10; i++ {
			if _, err := h.ReserveTask(context.Background(), &pb.ReserveTaskReq{}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		close(bs.release)
		t.Fatal("placements waited for the observed-state writes")
	}
	if n := bs.writes.Load(); n > 3 {
		t.Errorf("%d writes in flight for 3 relays, want at most one each", n)
	}
	close(bs.release)
	settle(t, h)
	if len(st.failedFor("id-")) != 1 || len(st.reached) != 2 {
		t.Errorf("failed=%v reached=%v; the queued observations were not written", st.failed, st.reached)
	}
}

// banHeaders records, per call, whether the complete ban set arrived and how
// long its header was — what the control plane put on the wire.
type banHeaders struct {
	mu    sync.Mutex
	full  int
	bytes int
	calls int
}

func (b *banHeaders) interceptors() []grpc.ServerOption {
	note := func(ctx context.Context) {
		md, _ := metadata.FromIncomingContext(ctx)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.calls++
		if v := md.Get(workeradmit.BannedHeader); len(v) > 0 {
			b.full++
			b.bytes += len(v[0])
		}
	}
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			note(ctx)
			return h(ctx, req)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			note(ss.Context())
			return h(srv, ss)
		}),
	}
}

func (b *banHeaders) snapshot() (full, bytes, calls int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.full, b.bytes, b.calls
}

// swappableRegistry stands in for a relay process: replacing it is a restart
// that lost the saved set.
type swappableRegistry struct {
	cur atomic.Pointer[workeradmit.Registry]
}

func (s *swappableRegistry) options() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			u, _ := relayserver.BanInterceptors(s.cur.Load())
			return u(ctx, req, info, h)
		}),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			_, st := relayserver.BanInterceptors(s.cur.Load())
			return st(srv, ss, info, h)
		}),
	}
}

// banRelay stands a real relay up behind the ban interceptor, recording the
// ban headers each call carried.
func banRelay(t *testing.T) (*swappableRegistry, *banHeaders, *ClusterServiceHandler, *workerStore) {
	t.Helper()
	regs := &swappableRegistry{}
	regs.cur.Store(workeradmit.New())
	seen := &banHeaders{}
	p, err := relaycore.New(relaycore.Options{TicketTTL: minute})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(64)
	opts := append(seen.interceptors(), regs.options()...)
	_, dial := serveWithOptions(t, &relayserver.Server{Pool: p, Workers: workeradmit.New(), ProxyAddress: "w:1", ProxyFingerprint: "cafe"}, opts...)
	banned := make([]string, 200)
	for i := range banned {
		banned[i] = fmt.Sprintf("%064x", i)
	}
	ws := &workerStore{banned: banned, banVersion: 7}
	h := &ClusterServiceHandler{
		Relays:  &store{relays: []Relay{{ID: "r", Name: "r", URL: "r", Fingerprint: "f"}}},
		Workers: ws,
		Dial:    dial,
	}
	return regs, seen, h, ws
}

// The complete ban set travels once per version, not on every call: after a
// relay confirmed holding it, placements and polls carry the version alone.
// 200 bans is a 13 kB header; ten placements used to send it twenty times.
func TestBans_TheSetTravelsOncePerVersion(t *testing.T) {
	regs, seen, h, ws := banRelay(t)
	for i := 0; i < 10; i++ {
		st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
		if err != nil {
			t.Fatalf("ReserveTask: %v", err)
		}
		if _, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: st.GetReservation()}); err != nil {
			t.Fatalf("GetReservation: %v", err)
		}
	}
	full, bytes, calls := seen.snapshot()
	if full != 1 {
		t.Errorf("the complete set was sent on %d of %d calls (%d bytes), want once", full, calls, bytes)
	}
	reg := regs.cur.Load()
	if reg.Admitted(ws.banned[0]) || reg.Version() != 7 {
		t.Fatalf("the relay does not hold the set: version %d", reg.Version())
	}

	// A decision moves the version: the next call carries the new set, once.
	ws.mu.Lock()
	ws.banned, ws.banVersion = append([]string{"ab"}, ws.banned...), 8
	ws.mu.Unlock()
	h.forgetBans()
	for i := 0; i < 3; i++ {
		if _, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); err != nil {
			t.Fatal(err)
		}
	}
	if full, _, _ := seen.snapshot(); full != 2 {
		t.Errorf("after a decision the set was sent %d times in all, want 2", full)
	}
	if reg.Admitted("ab") {
		t.Error("the new ban did not reach the relay")
	}
}

// A relay that restarted without its saved set is named a version it does
// not hold: it refuses before the call runs, and the call is sent again with
// the set — unary and stream alike. No call is served under the empty set.
func TestBans_ARelayBehindIsSentTheSet(t *testing.T) {
	regs, seen, h, ws := banRelay(t)
	if _, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); err != nil {
		t.Fatal(err)
	}
	restarted := workeradmit.New()
	regs.cur.Store(restarted)
	if _, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); err != nil {
		t.Fatalf("ReserveTask on a relay that lost its set: %v", err)
	}
	if restarted.Admitted(ws.banned[0]) {
		t.Fatal("the restarted relay was not sent the set")
	}

	// The stream: the stats call that precedes it would already correct the
	// relay, so the restart is placed between the two.
	ctx, err := h.withBans(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	r := Relay{ID: "r", Name: "r", URL: "r", Fingerprint: "f"}
	conn, err := h.acquire(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer h.release(conn)
	again := workeradmit.New()
	regs.cur.Store(again)
	before, _, _ := seen.snapshot()
	c := &collect{ctx: ctx}
	if err := h.proxyOne(ctx, candidate{Relay: r, conn: conn}, &pb.ScheduleTaskReq{}, c); err != nil {
		t.Fatalf("ScheduleTask on a relay that lost its set: %v", err)
	}
	if after, _, _ := seen.snapshot(); after != before+1 {
		t.Errorf("the stream was resent with the set %d times, want once", after-before)
	}
	if again.Admitted(ws.banned[0]) || c.seen()[0].GetGranted() == nil {
		t.Error("the stream was served without the relay holding the set")
	}
}

// A relay too old to confirm what it holds keeps getting the complete set on
// every call, as before.
func TestBans_AnOldRelayGetsTheSetEveryTime(t *testing.T) {
	seen := &banHeaders{}
	_, dial := serveWithOptions(t, &scripted{}, seen.interceptors()...)
	h := &ClusterServiceHandler{
		Relays:  &store{relays: []Relay{{ID: "r", Name: "r", URL: "r", Fingerprint: "f"}}},
		Workers: &workerStore{banned: []string{"aa"}, banVersion: 3},
		Dial:    dial,
	}
	for i := 0; i < 3; i++ {
		if _, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); err != nil {
			t.Fatal(err)
		}
	}
	if full, _, calls := seen.snapshot(); full != calls {
		t.Errorf("an old relay got the set on %d of %d calls, want every one", full, calls)
	}
}

// Past its TTL, the cache reads the version alone; the set — which grows with
// every ban ever taken — is read again only when the version moved.
func TestCachedBans_AnUnchangedVersionDoesNotReadTheSet(t *testing.T) {
	ws := &workerStore{banned: []string{"aa"}, banVersion: 4}
	h := &ClusterServiceHandler{Workers: ws}
	expire := func() {
		h.bansMu.Lock()
		h.bansAt = time.Now().Add(-2 * banCacheTTL)
		h.bansMu.Unlock()
	}
	if _, _, err := h.cachedBans(t.Context()); err != nil {
		t.Fatal(err)
	}
	expire()
	if _, _, err := h.cachedBans(t.Context()); err != nil {
		t.Fatal(err)
	}
	if ws.bannedCalls != 1 || ws.versionCalls != 1 {
		t.Fatalf("set reads=%d version reads=%d past the TTL, want 1 and 1", ws.bannedCalls, ws.versionCalls)
	}
	ws.mu.Lock()
	ws.banned, ws.banVersion = []string{"aa", "bb"}, 5
	ws.mu.Unlock()
	expire()
	bans, v, err := h.cachedBans(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if v != 5 || len(bans) != 2 || ws.bannedCalls != 2 {
		t.Errorf("after the version moved: %v at %d (set reads %d), want the new set", bans, v, ws.bannedCalls)
	}
	ws.mu.Lock()
	ws.bannedErr = errors.New("registry down")
	ws.mu.Unlock()
	expire()
	if _, _, err := h.cachedBans(t.Context()); err == nil {
		t.Error("an unreadable version served the cached set")
	}
}

// Every relay refusing because the CALLER holds its share of the queue is
// answered as that, not as an unavailable pool; and the owner a placement
// sends is the caller's, on the stream as on a reservation.
func TestPlacement_CallerQueueFull(t *testing.T) {
	full := func(context.Context) (*pb.ReservationState, error) {
		return nil, refusal.New(codes.ResourceExhausted, refusal.CallerQueueFull, "share used")
	}
	var owners []string
	var mu sync.Mutex
	stream := func(srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
		mu.Lock()
		owners = append(owners, resowner.From(srv.Context()))
		mu.Unlock()
		return refusal.New(codes.ResourceExhausted, refusal.CallerQueueFull, "share used")
	}
	h, _ := pool(t, map[string]*scripted{
		"a": {reserve: full, schedule: stream},
		"b": {reserve: full, schedule: stream},
	}, "a", "b", "")
	_, err := h.ReserveTask(signedIn("alice"), &pb.ReserveTaskReq{})
	if refusal.ReasonOf(err) != refusal.CallerQueueFull {
		t.Errorf("ReserveTask = %v, want CALLER_QUEUE_FULL", err)
	}
	c := &collect{ctx: signedIn("alice")}
	err = h.ScheduleTask(&pb.ScheduleTaskReq{}, c)
	if refusal.ReasonOf(err) != refusal.CallerQueueFull || !strings.Contains(err.Error(), "share") {
		t.Errorf("ScheduleTask = %v, want CALLER_QUEUE_FULL", err)
	}
	if len(owners) != 2 || owners[0] != ownerOf(userHolder+"alice") || owners[1] != owners[0] {
		t.Errorf("owners the relays saw on the stream = %v, want alice's on both", owners)
	}
}
