package handlers

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// scripted is a relay whose every answer a test writes. Nil hooks answer like
// an idle, healthy relay. Called concurrently (stats are polled in parallel),
// so it counts with atomics.
type scripted struct {
	pb.UnimplementedClusterServiceServer
	stats    *pb.RelayStatsResp
	reserve  func(ctx context.Context) (*pb.ReservationState, error)
	get      func(id string) (*pb.ReservationState, error)
	schedule func(srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error
	issue    func() (*pb.IssueRegistrationCodeResp, error)
	exchange func() (*pb.ExchangeWorkersResp, error)

	reserves, drains, cancels atomic.Int32
}

func (s *scripted) RelayStats(context.Context, *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	if s.stats != nil {
		return s.stats, nil
	}
	return &pb.RelayStatsResp{Capacity: 1}, nil
}

func (s *scripted) ReserveTask(ctx context.Context, _ *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	s.reserves.Add(1)
	if s.reserve != nil {
		return s.reserve(ctx)
	}
	return &pb.ReservationState{Reservation: "r1", State: &pb.ReservationState_Granted{Granted: &pb.TaskGranted{Ticket: "t"}}}, nil
}

func (s *scripted) GetReservation(_ context.Context, req *pb.GetReservationReq) (*pb.ReservationState, error) {
	if s.get != nil {
		return s.get(req.GetReservation())
	}
	return &pb.ReservationState{Reservation: req.GetReservation(), State: &pb.ReservationState_Queued{Queued: &pb.TaskQueued{Position: 3}}}, nil
}

func (s *scripted) CancelReservation(context.Context, *pb.CancelReservationReq) (*pb.CancelReservationResp, error) {
	s.cancels.Add(1)
	return &pb.CancelReservationResp{}, nil
}

func (s *scripted) ScheduleTask(_ *pb.ScheduleTaskReq, srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
	if s.schedule != nil {
		return s.schedule(srv)
	}
	return srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Granted{Granted: &pb.TaskGranted{Ticket: "t"}}})
}

func (s *scripted) DrainRelay(context.Context, *pb.DrainRelayReq) (*pb.DrainRelayResp, error) {
	s.drains.Add(1)
	return &pb.DrainRelayResp{}, nil
}

func (s *scripted) IssueRegistrationCode(context.Context, *pb.IssueRegistrationCodeReq) (*pb.IssueRegistrationCodeResp, error) {
	if s.issue != nil {
		return s.issue()
	}
	return &pb.IssueRegistrationCodeResp{Code: "c-1"}, nil
}

func (s *scripted) ExchangeWorkers(context.Context, *pb.ExchangeWorkersReq) (*pb.ExchangeWorkersResp, error) {
	if s.exchange != nil {
		return s.exchange()
	}
	return &pb.ExchangeWorkersResp{}, nil
}

// pool stands the scripted relays up under their urls ("" = unreachable) and
// returns a handler over them. Relay ids are "id-<url>".
func pool(t *testing.T, relays map[string]*scripted, order ...string) (*ClusterServiceHandler, *store) {
	t.Helper()
	dials := map[string]Dialer{}
	st := &store{}
	for _, url := range order {
		st.relays = append(st.relays, Relay{ID: "id-" + url, Name: "relay-" + url, URL: url, Fingerprint: "f-" + url})
		if r := relays[url]; r != nil {
			_, dials[url] = serveOn(t, r)
		}
	}
	h := &ClusterServiceHandler{
		Relays:      st,
		Workers:     &workerStore{},
		DialTimeout: 2 * time.Second,
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			d, ok := dials[target]
			if !ok {
				return nil, errors.New("connection refused")
			}
			return d(target, fp)
		},
	}
	return h, st
}

func (s *store) failedFor(id string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, f := range s.failed {
		if strings.HasPrefix(f, id+":") {
			out = append(out, f)
		}
	}
	return out
}

// loaded is a relay already half full, so an idle one sorts ahead of it and
// the order a test relies on does not depend on the rotation.
var loaded = &pb.RelayStatsResp{Capacity: 2, InUse: 1}

// A relay that said it had room and then turns out to be draining or
// misconfigured is "not here", not an answer: the reservation falls through
// to the next relay rather than reaching the caller as a refusal.
func TestReserveTask_ANotHereRefusalFallsThrough(t *testing.T) {
	for _, reason := range []string{refusal.RelayDraining, refusal.RelayMisconfigured} {
		t.Run(reason, func(t *testing.T) {
			first := &scripted{reserve: func(context.Context) (*pb.ReservationState, error) {
				return nil, refusal.New(codes.Unavailable, reason, "not here")
			}}
			second := &scripted{stats: loaded}
			h, _ := pool(t, map[string]*scripted{"a": first, "b": second}, "a", "b")
			st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
			if err != nil {
				t.Fatalf("ReserveTask: %v", err)
			}
			if !strings.HasPrefix(st.GetReservation(), "id-b.") || st.GetGranted().GetRelay() != "relay-b" {
				t.Errorf("reservation %q / %v, want it placed on b", st.GetReservation(), st.GetGranted())
			}
			if first.reserves.Load() != 1 {
				t.Errorf("a was asked %d times, want once", first.reserves.Load())
			}
		})
	}
}

// A refusal about the REQUEST is final: the next relay would only answer a
// question the first already answered, and the caller gets the reason as sent.
func TestReserveTask_ARefusalAboutTheRequestIsFinal(t *testing.T) {
	first := &scripted{reserve: func(context.Context) (*pb.ReservationState, error) {
		return nil, refusal.New(codes.ResourceExhausted, refusal.InputTooLarge, "too big")
	}}
	second := &scripted{stats: loaded}
	h, _ := pool(t, map[string]*scripted{"a": first, "b": second}, "a", "b")
	_, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if refusal.ReasonOf(err) != refusal.InputTooLarge || status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("err = %v, want the relay's own refusal", err)
	}
	if n := second.reserves.Load(); n != 0 {
		t.Errorf("the request was re-placed on b %d time(s) after a final refusal", n)
	}
}

// A relay whose connection fails under the call (no reason given) is noted on
// its row and skipped — the healthy relay behind it still takes the work.
func TestReserveTask_AFailureWithoutAReasonIsUnreachable(t *testing.T) {
	first := &scripted{reserve: func(context.Context) (*pb.ReservationState, error) {
		return nil, status.Error(codes.Unavailable, "transport is closing")
	}}
	h, st := pool(t, map[string]*scripted{"a": first, "b": {stats: loaded}}, "a", "b")
	got, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || !strings.HasPrefix(got.GetReservation(), "id-b.") {
		t.Fatalf("ReserveTask = %v, %v — want placed on b", got, err)
	}
	if f := st.failedFor("id-a"); len(f) == 0 || !strings.Contains(f[0], "transport is closing") {
		t.Errorf("a's failure was not recorded on its row: %v", f)
	}
}

// With every relay failing the caller is told NO_RELAY, with the counts and
// the last failure — something an operator can act on.
func TestReserveTask_EveryRelayFailingIsNoRelay(t *testing.T) {
	fail := func(context.Context) (*pb.ReservationState, error) {
		return nil, refusal.New(codes.Unavailable, refusal.RelayDraining, "draining now")
	}
	h, _ := pool(t, map[string]*scripted{"a": {reserve: fail}, "b": {reserve: fail}}, "a", "b", "")
	_, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if refusal.ReasonOf(err) != refusal.NoRelay {
		t.Fatalf("err = %v, want %s", err, refusal.NoRelay)
	}
	for _, want := range []string{"3 enabled", "2 placeable", "draining now"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// A caller that leaves mid-placement stops the search: its status is its own,
// and no further relay is asked to reserve for somebody no longer listening.
func TestReserveTask_TheCallerLeavingStopsTheSearch(t *testing.T) {
	entered := make(chan struct{})
	first := &scripted{reserve: func(ctx context.Context) (*pb.ReservationState, error) {
		close(entered)
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}}
	second := &scripted{stats: loaded}
	h, _ := pool(t, map[string]*scripted{"a": first, "b": second}, "a", "b")
	ctx, cancel := context.WithCancel(t.Context())
	go func() { <-entered; cancel() }()
	_, err := h.ReserveTask(ctx, &pb.ReserveTaskReq{})
	if status.Code(err) != codes.Canceled {
		t.Fatalf("err = %v, want Canceled", err)
	}
	if n := second.reserves.Load(); n != 0 {
		t.Errorf("b was asked to reserve %d time(s) for a caller that had left", n)
	}
}

// failingStore is a registry that cannot be read.
type failingStore struct{ err error }

func (f failingStore) ListEnabled(context.Context) ([]Relay, error)       { return nil, f.err }
func (f failingStore) Get(context.Context, string) (Relay, error)         { return Relay{}, f.err }
func (f failingStore) RecordReached(context.Context, string) error        { return nil }
func (f failingStore) RecordFailed(context.Context, string, string) error { return nil }

// A registry that cannot be read is Unavailable on every entry point — never
// an empty pool (which would read as "register a relay") and never "expired"
// (which would cost a client its place over a database blip).
func TestHandlers_AnUnreadableRegistryIsUnavailable(t *testing.T) {
	h := &ClusterServiceHandler{Relays: failingStore{errors.New("db down")}, Workers: &workerStore{}}
	ctx := t.Context()
	for name, call := range map[string]func() error{
		"ScheduleTask": func() error { _, err := run(t, h); return err },
		"ReserveTask":  func() error { _, err := h.ReserveTask(ctx, &pb.ReserveTaskReq{}); return err },
		"GetReservation": func() error {
			_, err := h.GetReservation(ctx, &pb.GetReservationReq{Reservation: "id-a.r1"})
			return err
		},
		"CancelReservation": func() error {
			_, err := h.CancelReservation(ctx, &pb.CancelReservationReq{Reservation: "id-a.r1"})
			return err
		},
		"DrainRelay": func() error { _, err := h.DrainRelay(ctx, &pb.DrainRelayReq{Ids: []string{"id-a"}}); return err },
		"IssueRegistrationCode": func() error {
			_, err := h.IssueRegistrationCode(ctx, &pb.IssueRegistrationCodeReq{Ids: []string{"id-a"}})
			return err
		},
		"CheckWorkers": func() error { _, err := h.CheckWorkers(ctx, &pb.CheckWorkersReq{}); return err },
	} {
		if err := call(); status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "registry") {
			t.Errorf("%s with the registry down: %v, want Unavailable naming the registry", name, err)
		}
	}
}

// A ban set that cannot be read refuses EVERY relay-bound call before any
// relay is touched — sending none would lift every ban on a restarted relay.
func TestHandlers_AnUnreadableBanSetRefusesEveryCall(t *testing.T) {
	r := &scripted{}
	h, _ := pool(t, map[string]*scripted{"a": r}, "a")
	h.Workers = &workerStore{bannedErr: errors.New("db down")}
	ctx := t.Context()
	for name, call := range map[string]func() error{
		"ReserveTask": func() error { _, err := h.ReserveTask(ctx, &pb.ReserveTaskReq{}); return err },
		"GetReservation": func() error {
			_, err := h.GetReservation(ctx, &pb.GetReservationReq{Reservation: "id-a.r1"})
			return err
		},
		"CancelReservation": func() error {
			_, err := h.CancelReservation(ctx, &pb.CancelReservationReq{Reservation: "id-a.r1"})
			return err
		},
		"DrainRelay": func() error { _, err := h.DrainRelay(ctx, &pb.DrainRelayReq{Ids: []string{"id-a"}}); return err },
		"IssueRegistrationCode": func() error {
			_, err := h.IssueRegistrationCode(ctx, &pb.IssueRegistrationCodeReq{Ids: []string{"id-a"}})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.Unavailable {
			t.Errorf("%s with an unreadable ban set: %v, want Unavailable", name, err)
		}
	}
	if r.reserves.Load()+r.drains.Load()+r.cancels.Load() != 0 {
		t.Error("a relay was called without the ban set")
	}
}

// A poll whose relay cannot be reached is an ERROR, not `expired`: a blip
// must not cost a client its place. The failure is recorded on the relay's row.
func TestGetReservation_AnUnreachableRelayIsNotExpired(t *testing.T) {
	h, st := pool(t, map[string]*scripted{}, "")
	_, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: "id-.r1"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable (the place may still be there)", err)
	}
	if len(st.failedFor("id-")) == 0 {
		t.Error("the unreachable relay was not noted on its row")
	}
	if _, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: "id-.r1"}); status.Code(err) != codes.Unavailable {
		t.Errorf("cancel on an unreachable relay: %v, want Unavailable", err)
	}
}

// The relay's answer is relayed with the handle and the relay's name restored
// — the poll's handle is what the caller polls with next — and a relay's own
// error passes through untouched.
func TestGetReservation_StampsTheRelaysAnswer(t *testing.T) {
	r := &scripted{}
	h, _ := pool(t, map[string]*scripted{"a": r}, "a")
	st, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: "id-a.r7"})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetReservation() != "id-a.r7" || st.GetQueued().GetRelay() != "relay-a" || st.GetQueued().GetPosition() != 3 {
		t.Errorf("poll = %v, want handle id-a.r7, relay-a, position 3", st)
	}
	r.get = func(string) (*pb.ReservationState, error) {
		return nil, status.Error(codes.Internal, "relay: polling: boom")
	}
	if _, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: "id-a.r7"}); status.Code(err) != codes.Internal {
		t.Errorf("a relay's own error became %v", err)
	}
}

// A handle whose relay was removed from the registry has nothing left to
// cancel: success, without dialling anything. A malformed one is the caller's
// mistake.
func TestCancelReservation_GoneAndMalformed(t *testing.T) {
	h, _ := pool(t, map[string]*scripted{}, "a")
	if _, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: "id-removed.r1"}); err != nil {
		t.Errorf("cancelling on a removed relay: %v, want success", err)
	}
	for _, bad := range []string{"", "no-separator", ".r1", "id-a."} {
		if _, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: bad}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("handle %q: %v, want InvalidArgument", bad, err)
		}
	}
}

// max_wait_seconds is honoured: a caller that asked to wait at most a second
// on a relay that never grants gets DeadlineExceeded, not an endless queue.
func TestScheduleTask_MaxWaitBoundsTheQueue(t *testing.T) {
	r := &scripted{schedule: func(srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
		if err := srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Queued{Queued: &pb.TaskQueued{Position: 1}}}); err != nil {
			return err
		}
		<-srv.Context().Done()
		return status.FromContextError(srv.Context().Err()).Err()
	}}
	h, _ := pool(t, map[string]*scripted{"a": r}, "a")
	c := &collect{ctx: t.Context()}
	start := time.Now()
	err := h.ScheduleTask(&pb.ScheduleTaskReq{MaxWaitSeconds: 1}, c)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
	if waited := time.Since(start); waited > 10*time.Second {
		t.Errorf("waited %s for a 1 s max_wait", waited)
	}
	if len(c.seen()) != 1 || c.seen()[0].GetQueued() == nil {
		t.Errorf("the caller saw %v, want its queue position before the deadline", c.seen())
	}
}

// A relay that ends the stream without granting has NOT placed the task, and
// the caller is told so rather than getting a silent success.
func TestScheduleTask_AStreamThatEndsWithoutAGrantIsAnError(t *testing.T) {
	r := &scripted{schedule: func(grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error { return nil }}
	h, _ := pool(t, map[string]*scripted{"a": r}, "a")
	_, err := run(t, h)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "without granting") {
		t.Fatalf("err = %v, want Unavailable saying no slot was granted", err)
	}
}

// The caller hanging up while events are being relayed ends the placement;
// it is not retried on another relay.
func TestScheduleTask_ACallerThatCannotBeReachedIsNotReplaced(t *testing.T) {
	first, second := &scripted{}, &scripted{stats: loaded}
	h, _ := pool(t, map[string]*scripted{"a": first, "b": second}, "a", "b")
	gone := &deadCaller{collect: collect{ctx: t.Context()}}
	err := h.ScheduleTask(&pb.ScheduleTaskReq{}, gone)
	if err == nil || !strings.Contains(err.Error(), "caller hung up") {
		t.Fatalf("err = %v, want the send failure", err)
	}
	if gone.sends.Load() != 1 {
		t.Errorf("%d sends attempted, want exactly one — a second relay placed the task again", gone.sends.Load())
	}
}

type deadCaller struct {
	collect
	sends atomic.Int32
}

func (d *deadCaller) Send(*pb.ScheduleTaskEvent) error {
	d.sends.Add(1)
	return errors.New("caller hung up")
}

// An unfinished registry row — no fingerprint pinned — is never dialled with
// "trust anything". The real dialer refuses it, the refusal lands on the row
// for the operator, and placement uses the relays that ARE pinned.
func TestScheduleTask_AnUnpinnedRowIsSkippedAndSaysWhy(t *testing.T) {
	_, dialB := serveOn(t, &scripted{})
	st := &store{relays: []Relay{
		{ID: "id-a", Name: "unfinished", URL: "a.example.com:13444", Fingerprint: ""},
		{ID: "id-b", Name: "pinned", URL: "b", Fingerprint: "f-b"},
	}}
	h := &ClusterServiceHandler{
		Relays: st, Workers: &workerStore{}, DialTimeout: 2 * time.Second,
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			if target == "b" {
				return dialB(target, fp)
			}
			return relaydial.Dial(relaydial.Config{}, target, fp)
		},
	}
	c, err := run(t, h)
	if err != nil {
		t.Fatalf("ScheduleTask: %v", err)
	}
	if g := c.seen()[0].GetGranted(); g.GetRelay() != "pinned" {
		t.Errorf("granted on %q, want the pinned relay", g.GetRelay())
	}
	if f := st.failedFor("id-a"); len(f) == 0 || !strings.Contains(f[0], "cert_fingerprint") {
		t.Errorf("the unpinned row's refusal was not recorded on it: %v", f)
	}
}

// A relay that accepts TCP and then says nothing — a black hole — costs the
// caller DialTimeout, not its own deadline: the placement falls through to the
// healthy relay well within it. This is the promise dial_timeout_seconds makes.
func TestScheduleTask_ABlackHoledRelayIsSkippedWithinTheDialTimeout(t *testing.T) {
	hole, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hole.Close() })
	var held sync.WaitGroup
	t.Cleanup(held.Wait)
	go func() {
		for {
			c, err := hole.Accept()
			if err != nil {
				return
			}
			held.Add(1)
			go func() { // read and discard, never answer
				defer held.Done()
				_, _ = c.Read(make([]byte, 64<<10))
				buf := make([]byte, 64<<10)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}()
		}
	}()
	_, dialB := serveOn(t, &scripted{})
	st := &store{relays: []Relay{
		{ID: "id-hole", Name: "hole", URL: hole.Addr().String(), Fingerprint: "f"},
		{ID: "id-b", Name: "healthy", URL: "b", Fingerprint: "f"},
	}}
	h := &ClusterServiceHandler{
		Relays: st, Workers: &workerStore{}, DialTimeout: 300 * time.Millisecond,
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			if target == "b" {
				return dialB(target, fp)
			}
			return grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		},
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	c := &collect{ctx: ctx}
	start := time.Now()
	if err := h.ScheduleTask(&pb.ScheduleTaskReq{}, c); err != nil {
		t.Fatalf("ScheduleTask with one black-holed relay: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("placement took %s with a 300ms dial timeout", took)
	}
	if g := c.seen()[0].GetGranted(); g.GetRelay() != "healthy" {
		t.Errorf("granted on %q", g.GetRelay())
	}
	if f := st.failedFor("id-hole"); len(f) == 0 || !strings.Contains(f[0], "not reachable within") {
		t.Errorf("the black hole was not noted as unreachable: %v", f)
	}
	// Release the held sockets so the accept loop's goroutines can finish.
	_ = hole.Close()
}

// A dialer that hands back a connection that is already shut down is an
// unreachable relay, reported at once rather than waited on.
func TestDialReady_AShutDownConnectionIsUnreachable(t *testing.T) {
	h := &ClusterServiceHandler{Dial: func(target, _ string) (*grpc.ClientConn, error) {
		cc, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err == nil {
			_ = cc.Close()
		}
		return cc, err
	}}
	if _, err := h.dialReady(t.Context(), Relay{Name: "acme", URL: "127.0.0.1:1"}); err == nil || !strings.Contains(err.Error(), "shut down") {
		t.Fatalf("err = %v, want a shut-down connection reported", err)
	}
	if got := (&ClusterServiceHandler{}).dialTimeout(); got != 5*time.Second {
		t.Errorf("default dial timeout %s, want the documented 5s", got)
	}
}

// IssueRegistrationCode on a relay that cannot be reached says which, and
// records it; a relay's own refusal (no code store wired) reaches the operator
// as the relay said it.
func TestIssueRegistrationCode_UnreachableAndRefused(t *testing.T) {
	h, st := pool(t, map[string]*scripted{
		"a": {issue: func() (*pb.IssueRegistrationCodeResp, error) {
			return nil, refusal.New(codes.FailedPrecondition, refusal.RelayMisconfigured, "no code store")
		}},
	}, "a", "")
	_, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"id-"}})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "relay-") {
		t.Errorf("unreachable relay: %v, want Unavailable naming it", err)
	}
	if len(st.failedFor("id-")) == 0 {
		t.Error("the unreachable relay was not noted on its row")
	}
	_, err = h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"id-a"}})
	if refusal.ReasonOf(err) != refusal.RelayMisconfigured {
		t.Errorf("a relay's refusal became %v", err)
	}
	if _, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"id-nope"}}); status.Code(err) != codes.NotFound {
		t.Errorf("an unknown relay: %v, want NotFound", err)
	}
}

// A drain selection is resolved WHOLE before any relay is touched: one stale
// id fails the request and drains nothing, rather than half of what the
// operator meant.
func TestDrainRelay_OneStaleIDDrainsNothing(t *testing.T) {
	a, b := &scripted{}, &scripted{}
	h, _ := pool(t, map[string]*scripted{"a": a, "b": b}, "a", "b")
	_, err := h.DrainRelay(t.Context(), &pb.DrainRelayReq{Ids: []string{"id-a", "id-stale", "id-b"}})
	if status.Code(err) != codes.NotFound || !strings.Contains(err.Error(), "id-stale") {
		t.Fatalf("err = %v, want NotFound naming the stale id", err)
	}
	if a.drains.Load()+b.drains.Load() != 0 {
		t.Error("relays were drained by a request that was refused")
	}
}

// An unreachable relay is REPORTED, not fatal: the rest drain, and the
// operator gets a sorted list of what to chase.
func TestDrainRelay_UnreachableRelaysAreReportedSorted(t *testing.T) {
	a := &scripted{}
	h, st := pool(t, map[string]*scripted{"a": a}, "a", "", "z")
	st.relays[1].Name, st.relays[2].Name = "zeta", "alpha" // both unreachable
	st.relays[2].URL = "unknown-host"
	resp, err := h.DrainRelay(t.Context(), &pb.DrainRelayReq{Ids: []string{"id-", "id-z", "id-a"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := resp.GetUnreachableRelays(); len(got) != 2 || got[0] != "alpha" || got[1] != "zeta" {
		t.Errorf("unreachable = %v, want [alpha zeta]", got)
	}
	if a.drains.Load() != 1 {
		t.Error("the reachable relay was not drained")
	}
}

// recordFails is a worker registry whose WRITES fail.
type recordFails struct {
	*workerStore
	counts []int // successive EnrolledCount answers
	n      int
}

func (r *recordFails) Record(context.Context, string, *pb.KnownWorker) error {
	return errors.New("db: read-only transaction")
}

func (r *recordFails) EnrolledCount(context.Context) (int, error) {
	if r.n >= len(r.counts) {
		return 0, errors.New("db down")
	}
	r.n++
	return r.counts[r.n-1], nil
}

// A sweep whose RECORDING fails is the control plane's own problem: it is
// reported as such, and the relay — which answered fine — is neither listed
// as unreachable nor has the database error written onto its row.
//
// It used to be both: the operator was sent to debug a healthy relay, and the
// relay's last_error read "db: read-only transaction".
func TestCheckWorkers_ARegistryWriteFailureIsNotTheRelays(t *testing.T) {
	_, dial := serveRelayWithWorkers(t, workeradmit.Worker{ID: "aa", Name: "acme-1"})
	st := &store{relays: []Relay{{ID: "r-1", Name: "acme-eu", URL: "live"}}}
	h := &ClusterServiceHandler{Relays: st, Workers: &recordFails{workerStore: &workerStore{}, counts: []int{0, 0}}, Dial: dial}
	resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cannot record") {
		t.Fatalf("CheckWorkers = %v, %v — want Unavailable saying the recording failed", resp, err)
	}
	if f := st.failedFor("r-1"); len(f) != 0 {
		t.Errorf("the healthy relay's row was marked failed: %v", f)
	}
}

// The counts around a sweep are read from the registry, and a registry that
// cannot count fails the sweep rather than reporting made-up numbers. A count
// that DROPS during the sweep (somebody banned a worker meanwhile) is zero
// discoveries, never negative.
func TestCheckWorkers_Counts(t *testing.T) {
	_, dial := serveRelayWithWorkers(t)
	st := &store{relays: []Relay{{ID: "r-1", Name: "acme-eu", URL: "live"}}}
	for _, tc := range []struct {
		name   string
		counts []int
		ok     bool
	}{
		{"cannot count before", nil, false},
		{"cannot count after", []int{3}, false},
		{"a ban during the sweep", []int{5, 4}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &ClusterServiceHandler{Relays: st, Workers: &recordFails{workerStore: &workerStore{}, counts: tc.counts}, Dial: dial}
			resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
			if !tc.ok {
				if status.Code(err) != codes.Unavailable {
					t.Fatalf("err = %v, want Unavailable", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetDiscovered() != 0 || resp.GetEnrolledTotal() != 4 {
				t.Errorf("discovered %d / total %d, want 0 / 4", resp.GetDiscovered(), resp.GetEnrolledTotal())
			}
		})
	}
}

// A worker the relay reports with no fingerprint has no identity to ban, and
// is not stored as a row an operator could not act on.
func TestCheckWorkers_SkipsAWorkerWithoutAFingerprint(t *testing.T) {
	r := &scripted{exchange: func() (*pb.ExchangeWorkersResp, error) {
		return &pb.ExchangeWorkersResp{Workers: []*pb.KnownWorker{{Name: "anonymous"}, {CertFingerprint: "aa", Name: "acme-1"}}}, nil
	}}
	h, _ := pool(t, map[string]*scripted{"a": r}, "a")
	ws := h.Workers.(*workerStore)
	if _, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{}); err != nil {
		t.Fatal(err)
	}
	if len(ws.recorded) != 1 || ws.recorded[0] != "id-a:aa" {
		t.Errorf("recorded = %v, want only the worker with a fingerprint", ws.recorded)
	}
}

// decideFails is a registry that refuses a decision.
type decideFails struct{ *workerStore }

func (decideFails) Decide(context.Context, []string, bool, string) error {
	return status.Error(codes.FailedPrecondition, "no such worker")
}

// A ban needs a selection, and a ban the registry refused is not reported as
// done.
func TestDecideWorkers_EmptySelectionAndRefusedDecision(t *testing.T) {
	h := &ClusterServiceHandler{Workers: &workerStore{}}
	if _, err := h.UnbanWorkers(signedIn("op-1"), &pb.DecideWorkersActionReq{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("an empty selection: %v, want InvalidArgument", err)
	}
	h.Workers = decideFails{&workerStore{}}
	if _, err := h.BanWorkers(signedIn("op-1"), &pb.DecideWorkersActionReq{Ids: []string{"w-1"}}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a refused ban: %v, want the registry's refusal", err)
	}
}

// The control plane does not pretend to be a relay: the two relay-only methods
// say where they are answered instead of answering for a side they are not.
func TestHandlers_RelayOnlyMethodsAreUnimplemented(t *testing.T) {
	h := &ClusterServiceHandler{}
	if _, err := h.RelayStats(t.Context(), &pb.RelayStatsReq{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("RelayStats: %v", err)
	}
	if _, err := h.ExchangeWorkers(t.Context(), &pb.ExchangeWorkersReq{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ExchangeWorkers: %v", err)
	}
}

// A stream to a relay whose connection is already closed fails at once with
// an error the placement loop treats as unreachable — not a hang.
func TestRelayClient_ScheduleTaskOnAClosedConnection(t *testing.T) {
	cc, err := grpc.NewClient("passthrough:///closed", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	_ = cc.Close()
	if _, err := newRelayClient(cc).ScheduleTask(t.Context(), &pb.ScheduleTaskReq{}); err == nil {
		t.Fatal("a stream opened on a closed connection")
	}
}
