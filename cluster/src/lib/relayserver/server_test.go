package relayserver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

const (
	testProxyAddress = "relay-a.example.com:9000"
	testProxyFP      = "cafe01"
)

func poolWith(t *testing.T, capacity int) *relaycore.Pool {
	t.Helper()
	p, err := relaycore.New(relaycore.Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	p.SetCapacity(capacity)
	return p
}

// configured is a relay server as cmd/relay builds it: a work endpoint it can
// name and pin, a worker registry, and a registration-code store.
func configured(t *testing.T, pool *relaycore.Pool) *Server {
	t.Helper()
	codes, err := regcode.New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		Pool:             pool,
		Workers:          workeradmit.New(),
		Codes:            codes,
		ProxyAddress:     testProxyAddress,
		ProxyFingerprint: testProxyFP,
	}
}

// serveManagement puts s on a real gRPC server — with the ban interceptors
// the management server is built with — and returns a client for it.
func serveManagement(t *testing.T, s *Server, opts ...grpc.ServerOption) pb.ClusterServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(opts...)
	pb.RegisterClusterServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient("passthrough:///relay",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewClusterServiceClient(cc)
}

// streamRecorder is the server side of a ScheduleTask stream, driven directly
// so a test can decide what the caller does between events.
type streamRecorder struct {
	grpc.ServerStream
	ctx    context.Context
	onSend func(*pb.ScheduleTaskEvent) error

	mu     sync.Mutex
	events []*pb.ScheduleTaskEvent
}

func (s *streamRecorder) Context() context.Context { return s.ctx }

func (s *streamRecorder) Send(e *pb.ScheduleTaskEvent) error {
	s.mu.Lock()
	s.events = append(s.events, e)
	s.mu.Unlock()
	if s.onSend != nil {
		return s.onSend(e)
	}
	return nil
}

func wantRefusal(t *testing.T, err error, code codes.Code, reason string) {
	t.Helper()
	if status.Code(err) != code || refusal.ReasonOf(err) != reason {
		t.Fatalf("err = %v (code %s, reason %q), want %s / %s", err, status.Code(err), refusal.ReasonOf(err), code, reason)
	}
}

// A relay that cannot name or pin its own work endpoint refuses BEFORE a slot
// is taken: a grant naming somewhere the caller cannot verify would consume a
// slot and fail later with less context.
func TestServer_AMisconfiguredRelayRefusesWithoutTakingASlot(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addr, fpr string
	}{
		{"no proxy address", "", testProxyFP},
		{"no proxy fingerprint", testProxyAddress, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := poolWith(t, 1)
			s := &Server{Pool: pool, ProxyAddress: tc.addr, ProxyFingerprint: tc.fpr}
			c := serveManagement(t, s)

			stream, err := c.ScheduleTask(t.Context(), &pb.ScheduleTaskReq{})
			if err == nil {
				_, err = stream.Recv()
			}
			wantRefusal(t, err, codes.FailedPrecondition, refusal.RelayMisconfigured)

			_, err = c.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
			wantRefusal(t, err, codes.FailedPrecondition, refusal.RelayMisconfigured)

			if st := pool.Stats(); st.Held() != 0 || st.Queued != 0 {
				t.Errorf("a refused request left the pool holding something: %+v", st)
			}
		})
	}
}

// The caller queues, sees its position, and is granted the moment capacity
// appears — with everything it needs to go and use the slot, and the relay's
// name left for the control plane to stamp.
func TestServer_ScheduleTaskQueuesThenGrantsAUsableTicket(t *testing.T) {
	pool := poolWith(t, 0)
	c := serveManagement(t, configured(t, pool))

	stream, err := c.ScheduleTask(t.Context(), &pb.ScheduleTaskReq{Label: "job-1"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	q := ev.GetQueued()
	if q == nil || q.GetPosition() != 1 {
		t.Fatalf("first event %v, want queued at position 1 on an empty relay", ev)
	}
	if q.GetRelay() != "" {
		t.Errorf("relay = %q — a relay must not invent its registry name", q.GetRelay())
	}

	pool.SetCapacity(1) // a worker attached
	ev, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	g := ev.GetGranted()
	if g == nil {
		t.Fatalf("second event %v, want a grant", ev)
	}
	if g.GetAddress() != testProxyAddress || g.GetCertFingerprint() != testProxyFP || g.GetRelay() != "" {
		t.Errorf("grant = %+v, want the configured address and fingerprint and no relay name", g)
	}
	if !g.GetExpiresAt().AsTime().After(time.Now()) {
		t.Errorf("expires_at %v is not in the future", g.GetExpiresAt().AsTime())
	}
	if err := pool.Claim(g.GetTicket()); err != nil {
		t.Fatalf("the granted ticket is not redeemable: %v", err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the grant: %v, want the stream to end — a grant is terminal", err)
	}
}

// A draining relay tells the queued caller so, with the reason a control
// plane falls through on.
func TestServer_ScheduleTaskOnADrainingRelayIsRelayDraining(t *testing.T) {
	pool := poolWith(t, 0)
	c := serveManagement(t, configured(t, pool))

	stream, err := c.ScheduleTask(t.Context(), &pb.ScheduleTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DrainRelay(t.Context(), &pb.DrainRelayReq{}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	wantRefusal(t, err, codes.Unavailable, refusal.RelayDraining)

	// And a newcomer is refused at once rather than queued.
	stream, err = c.ScheduleTask(t.Context(), &pb.ScheduleTaskReq{})
	if err == nil {
		_, err = stream.Recv()
	}
	wantRefusal(t, err, codes.Unavailable, refusal.RelayDraining)
}

// A caller that leaves gets its own status back — not a relay failure — and
// its queue place goes with it.
func TestServer_ScheduleTaskCallerLeavingIsTheCallersStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(context.Context) (context.Context, context.CancelFunc)
		want codes.Code
	}{
		{"cancelled", context.WithCancel, codes.Canceled},
		{"deadline", func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithDeadline(ctx, time.Now().Add(-time.Second))
		}, codes.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := poolWith(t, 0)
			s := configured(t, pool)
			ctx, cancel := tc.end(t.Context())
			defer cancel()
			rec := &streamRecorder{ctx: ctx, onSend: func(*pb.ScheduleTaskEvent) error {
				cancel() // the caller hangs up while queued
				return nil
			}}
			err := s.ScheduleTask(&pb.ScheduleTaskReq{}, rec)
			if status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %s", err, tc.want)
			}
			if refusal.ReasonOf(err) != "" {
				t.Errorf("a caller leaving was reported as a relay refusal: %v", err)
			}
			if st := pool.Stats(); st.Queued != 0 || st.Held() != 0 {
				t.Errorf("the departed caller still holds a place: %+v", st)
			}
		})
	}
}

// A queue event that cannot be delivered ends the call and gives the place
// back, rather than leaving a ghost at the head of the queue.
func TestServer_ScheduleTaskSendFailureGivesThePlaceBack(t *testing.T) {
	pool := poolWith(t, 0)
	s := configured(t, pool)
	boom := errors.New("caller's transport broke")
	err := s.ScheduleTask(&pb.ScheduleTaskReq{}, &streamRecorder{
		ctx:    t.Context(),
		onSend: func(*pb.ScheduleTaskEvent) error { return boom },
	})
	if err == nil {
		t.Fatal("a failed send was reported as success")
	}
	if st := pool.Stats(); st.Queued != 0 {
		t.Errorf("the place survived a caller that could not be told about it: %+v", st)
	}
}

// The polled flow: a reservation is granted or queued at once, the poll says
// how it stands, a cancel frees the place for the next in line, and the
// interval the client is told is the relay's.
func TestServer_ReservationsQueueGrantAndCancel(t *testing.T) {
	pool := poolWith(t, 1)
	s := configured(t, pool)
	s.PollInterval = 250 * time.Millisecond
	c := serveManagement(t, s)

	first, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	g := first.GetGranted()
	if g == nil || g.GetAddress() != testProxyAddress || g.GetCertFingerprint() != testProxyFP || g.GetTicket() == "" {
		t.Fatalf("first reservation %v, want an immediate, complete grant", first)
	}
	if first.GetPollAfterMs() != 250 {
		t.Errorf("poll_after_ms = %d, want the configured 250", first.GetPollAfterMs())
	}

	second, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	if q := second.GetQueued(); q == nil || q.GetPosition() != 1 {
		t.Fatalf("second reservation %v, want queued at 1", second)
	}
	polled, err := c.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: second.GetReservation()})
	if err != nil || polled.GetQueued().GetPosition() != 1 {
		t.Fatalf("poll = %v, %v; want still queued at 1", polled, err)
	}

	// Giving the first one up hands its slot to the second.
	if _, err := c.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: first.GetReservation()}); err != nil {
		t.Fatal(err)
	}
	polled, err = c.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: second.GetReservation()})
	if err != nil || polled.GetGranted() == nil {
		t.Fatalf("poll after cancel = %v, %v; want the freed slot granted", polled, err)
	}
	if polled.GetReservation() != second.GetReservation() {
		t.Errorf("the poll answered for %q, asked about %q", polled.GetReservation(), second.GetReservation())
	}

	// Cancelling is idempotent, including for something never issued.
	for _, id := range []string{first.GetReservation(), "never-issued"} {
		if _, err := c.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: id}); err != nil {
			t.Errorf("cancelling %q: %v, want the outcome the caller wanted", id, err)
		}
	}
}

// A poll for a reservation the relay does not hold is `expired` with the
// reason, not an error: the answer is to place again.
func TestServer_GetReservationUnknownIsExpired(t *testing.T) {
	s := configured(t, poolWith(t, 1))
	c := serveManagement(t, s)
	st, err := c.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetExpired().GetReason() != refusal.ReservationUnknown || st.GetReservation() != "nope" {
		t.Errorf("state = %v, want expired %s for the id asked", st, refusal.ReservationUnknown)
	}
	if st.GetPollAfterMs() != int32(relaycore.DefaultPollInterval.Milliseconds()) {
		t.Errorf("poll_after_ms = %d, want the default %s", st.GetPollAfterMs(), relaycore.DefaultPollInterval)
	}
}

// A drain expires a polled place with RELAY_DRAINING, and a new reservation is
// refused with the same reason, so the control plane falls through.
func TestServer_DrainExpiresPolledPlacesAndRefusesNewOnes(t *testing.T) {
	pool := poolWith(t, 0)
	c := serveManagement(t, configured(t, pool))
	r, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || r.GetQueued() == nil {
		t.Fatalf("reserve = %v, %v; want queued", r, err)
	}
	if _, err := c.DrainRelay(t.Context(), &pb.DrainRelayReq{}); err != nil {
		t.Fatal(err)
	}
	st, err := c.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: r.GetReservation()})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetExpired().GetReason() != refusal.RelayDraining {
		t.Errorf("state = %v, want expired %s", st, refusal.RelayDraining)
	}
	_, err = c.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	wantRefusal(t, err, codes.Unavailable, refusal.RelayDraining)
}

// RelayStats is what a control plane ranks relays by; every number must be
// the pool's, and the worker count the attached fleet's.
func TestServer_RelayStatsReportsThePoolAndTheFleet(t *testing.T) {
	pool := poolWith(t, 2)
	s := configured(t, pool)
	c := serveManagement(t, s)

	if _, err := c.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); err != nil {
		t.Fatal(err)
	}
	st, err := c.RelayStats(t.Context(), &pb.RelayStatsReq{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetCapacity() != 2 || st.GetReserved() != 1 || st.GetInUse() != 0 || st.GetDraining() || st.GetWorkers() != 0 {
		t.Errorf("stats = %+v, want capacity 2, one reserved, no workers without Backends", st)
	}

	s.Backends = NewBackends()
	s.Backends.Add("w-1", conn(t))
	if _, err := c.DrainRelay(t.Context(), &pb.DrainRelayReq{}); err != nil {
		t.Fatal(err)
	}
	st, err = c.RelayStats(t.Context(), &pb.RelayStatsReq{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetWorkers() != 1 || !st.GetDraining() {
		t.Errorf("stats = %+v, want one attached worker and draining", st)
	}
}

// A registration code is minted into the relay's own store — redeemable there
// once — and carries the relay's fingerprint so the worker can pin it.
func TestServer_IssueRegistrationCode(t *testing.T) {
	s := configured(t, poolWith(t, 1))
	c := serveManagement(t, s)
	resp, err := c.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetRelayFingerprint() != testProxyFP {
		t.Errorf("relay_fingerprint = %q, want %q", resp.GetRelayFingerprint(), testProxyFP)
	}
	if !resp.GetExpiresAt().AsTime().After(time.Now()) {
		t.Errorf("expires_at %v is not in the future", resp.GetExpiresAt().AsTime())
	}
	if err := s.Codes.Redeem(resp.GetCode()); err != nil {
		t.Fatalf("the issued code is not redeemable at this relay: %v", err)
	}
	if err := s.Codes.Redeem(resp.GetCode()); err == nil {
		t.Error("the issued code was redeemable twice")
	}

	s.Codes = nil
	_, err = c.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{})
	wantRefusal(t, err, codes.FailedPrecondition, refusal.RelayMisconfigured)
}

// ExchangeWorkers reports every worker met, by key fingerprint; a relay with
// no registry says it is misconfigured rather than "nobody".
func TestServer_ExchangeWorkers(t *testing.T) {
	s := configured(t, poolWith(t, 1))
	s.Workers.Met(workeradmit.Worker{ID: "bb", Name: "vps-2", DeviceID: "dev-2"})
	s.Workers.Met(workeradmit.Worker{ID: "aa", Name: "vps-1", DeviceID: "dev-1"})
	c := serveManagement(t, s)
	resp, err := c.ExchangeWorkers(t.Context(), &pb.ExchangeWorkersReq{})
	if err != nil {
		t.Fatal(err)
	}
	ws := resp.GetWorkers()
	if len(ws) != 2 || ws[0].GetCertFingerprint() != "aa" || ws[0].GetName() != "vps-1" ||
		ws[0].GetDeviceId() != "dev-1" || ws[1].GetCertFingerprint() != "bb" {
		t.Errorf("workers = %v, want both, by fingerprint, with their claims", ws)
	}

	s.Workers = nil
	_, err = c.ExchangeWorkers(t.Context(), &pb.ExchangeWorkersReq{})
	wantRefusal(t, err, codes.FailedPrecondition, refusal.RelayMisconfigured)
}

// CheckWorkers belongs to the control plane; a relay says so rather than
// answering for a side it is not.
func TestServer_CheckWorkersIsNotARelaysMethod(t *testing.T) {
	c := serveManagement(t, configured(t, poolWith(t, 1)))
	_, err := c.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("err = %v, want Unimplemented", err)
	}
}

// The ban set rides on EVERY management call, unary and streaming alike, and
// the server installed with BanServerOptions applies it before the call runs.
func TestBanServerOptions_ApplyTheBanSetOnUnaryAndStreamingCalls(t *testing.T) {
	s := configured(t, poolWith(t, 1))
	c := serveManagement(t, s, BanServerOptions(s.Workers)...)

	if _, err := c.RelayStats(workeradmit.WithBans(t.Context(), []string{"aa"}), &pb.RelayStatsReq{}); err != nil {
		t.Fatal(err)
	}
	if s.Workers.Admitted("aa") {
		t.Fatal("a unary call's ban set was not applied")
	}

	stream, err := c.ScheduleTask(workeradmit.WithBans(t.Context(), []string{"bb"}), &pb.ScheduleTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if s.Workers.Admitted("bb") || !s.Workers.Admitted("aa") {
		t.Error("a streaming call's ban set was not applied wholesale (bb banned, aa lifted)")
	}

	// A call WITHOUT the header leaves the set alone.
	if _, err := c.RelayStats(t.Context(), &pb.RelayStatsReq{}); err != nil {
		t.Fatal(err)
	}
	if s.Workers.Admitted("bb") {
		t.Error("a call without the header lifted the bans")
	}
}
