package handlers

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// workerStore is a registry in memory. Guarded: relays are polled in parallel.
type workerStore struct {
	mu        sync.Mutex
	banned    []string
	recorded  []string // "<relayID>:<fingerprint>"
	enrolled  int
	bannedErr error
	decisions []decision
}

type decision struct {
	ids []string
	ban bool
	by  string
}

func (w *workerStore) Banned(context.Context) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.banned, w.bannedErr
}
func (w *workerStore) Record(_ context.Context, relayID string, k *pb.KnownWorker) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.recorded = append(w.recorded, relayID+":"+k.GetCertFingerprint())
	w.enrolled++
	return nil
}
func (w *workerStore) Decide(_ context.Context, ids []string, ban bool, by string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.decisions = append(w.decisions, decision{ids: ids, ban: ban, by: by})
	return nil
}
func (w *workerStore) EnrolledCount(context.Context) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enrolled, nil
}

// serveRelayWithWorkers stands a real relay up — with the ban interceptor a
// real relay's management server has — whose registry has met `met`.
func serveRelayWithWorkers(t *testing.T, met ...workeradmit.Worker) (*workeradmit.Registry, Dialer) {
	t.Helper()
	reg := workeradmit.New()
	for _, w := range met {
		reg.Met(w)
	}
	pool, err := relaycore.New(relaycore.Options{TicketTTL: minute})
	if err != nil {
		t.Fatal(err)
	}
	pool.SetCapacity(16) // room for every call a test makes, so none of them queues
	_, dial := serveWithOptions(t, &relayserver.Server{Pool: pool, Workers: reg, ProxyAddress: "w:1", ProxyFingerprint: "cafe"},
		relayserver.BanServerOptions(reg)...)
	return reg, dial
}

// One unreachable relay must not hide the workers every other relay is
// holding — which is exactly the moment an operator is most likely to be
// pressing this button.
func TestCheckWorkers_AnUnreachableRelayIsReportedNotFatal(t *testing.T) {
	_, dialLive := serveRelayWithWorkers(t, workeradmit.Worker{ID: "aa", Name: "vps-1"})

	ws := &workerStore{}
	h := &ClusterServiceHandler{
		Relays: &store{relays: []Relay{
			{ID: "dead", Name: "a-dead"},
			{ID: "live", Name: "b-live", URL: "live"},
		}},
		Workers: ws,
	}
	h.Dial = func(target, _ string) (*grpc.ClientConn, error) {
		if target == "" {
			return nil, errors.New("connection refused")
		}
		return dialLive(target, "")
	}

	resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if err != nil {
		t.Fatalf("CheckWorkers failed because one relay was down: %v", err)
	}
	if got := resp.GetUnreachableRelays(); len(got) != 1 || got[0] != "a-dead" {
		t.Errorf("unreachable = %v, want [a-dead]", got)
	}
	if len(ws.recorded) != 1 || ws.recorded[0] != "live:aa" {
		t.Errorf("recorded = %v, want the live relay's worker", ws.recorded)
	}
	if resp.GetDiscovered() != 1 || resp.GetEnrolledTotal() != 1 {
		t.Errorf("discovered=%d enrolled=%d, want 1 and 1", resp.GetDiscovered(), resp.GetEnrolledTotal())
	}
}

// The ban set reaches the relay on the sweep — as on every call — and what
// the relay does with it is the revocation: a banned worker stops being
// admitted.
func TestCheckWorkers_BansReachTheRelay(t *testing.T) {
	reg, dial := serveRelayWithWorkers(t, workeradmit.Worker{ID: "aa"}, workeradmit.Worker{ID: "bb"})
	ws := &workerStore{banned: []string{"bb"}}
	h := &ClusterServiceHandler{
		Relays:  &store{relays: []Relay{{ID: "1", Name: "r", URL: "live"}}},
		Workers: ws,
		Dial:    dial,
	}
	if _, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{}); err != nil {
		t.Fatalf("CheckWorkers: %v", err)
	}
	if !reg.Admitted("aa") {
		t.Error("an unbanned worker is refused at the relay")
	}
	if reg.Admitted("bb") {
		t.Error("the banned worker is still admitted at the relay")
	}
}

// Wiring that is missing must SAY so rather than sweeping nothing and
// reporting success.
func TestCheckWorkers_RefusesWithNoRegistry(t *testing.T) {
	h := &ClusterServiceHandler{Relays: &store{}}
	if _, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{}); err == nil {
		t.Fatal("a handler with no worker registry reported a successful sweep")
	}
}

// A ban set that cannot be read REFUSES the call. Sending an empty one
// instead would tell every relay that nobody is banned — a database blip
// lifting every ban at once.
func TestWithBans_AnUnreadableBanSetRefusesTheCall(t *testing.T) {
	_, dial := serveRelayWithWorkers(t)
	h := &ClusterServiceHandler{
		Relays:  &store{relays: []Relay{{ID: "1", Name: "r", URL: "live"}}},
		Workers: &workerStore{bannedErr: errors.New("db down")},
		Dial:    dial,
	}
	_, err := run(t, h)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("placing with an unreadable ban set: %v, want Unavailable", err)
	}
}

// EVERY call the control plane makes to a relay carries the ban set — not
// only the sweep. A relay keeps bans in memory, so after a restart a banned
// but CA-valid worker would otherwise attach and take work until somebody
// happened to press "check".
func TestEveryRelayCallCarriesTheBanSet(t *testing.T) {
	reg, dial := serveRelayWithWorkers(t)
	ws := &workerStore{banned: []string{"bb"}}
	h := &ClusterServiceHandler{
		Relays:  &store{relays: []Relay{{ID: "11111111-1111-1111-1111-111111111111", Name: "r", URL: "live"}}},
		Workers: ws,
		Dial:    dial,
	}
	reserved, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]func() error{
		"ScheduleTask": func() error { _, err := run(t, h); return err },
		"ReserveTask":  func() error { _, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{}); return err },
		"GetReservation": func() error {
			_, err := h.GetReservation(t.Context(), &pb.GetReservationReq{Reservation: reserved.GetReservation()})
			return err
		},
		"CancelReservation": func() error {
			_, err := h.CancelReservation(t.Context(), &pb.CancelReservationReq{Reservation: reserved.GetReservation()})
			return err
		},
		"CheckWorkers": func() error { _, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{}); return err },
		"IssueRegistrationCode": func() error {
			// No code store on this relay: it refuses — AFTER the interceptor
			// has applied the bans, which is what is under test.
			_, _ = h.IssueRegistrationCode(t.Context(),
				&pb.IssueRegistrationCodeReq{Ids: []string{"11111111-1111-1111-1111-111111111111"}})
			return nil
		},
		// Last: it drains the relay.
		"DrainRelay": func() error {
			_, err := h.DrainRelay(t.Context(), &pb.DrainRelayReq{Ids: []string{"11111111-1111-1111-1111-111111111111"}})
			return err
		},
	}
	for _, name := range []string{"ScheduleTask", "ReserveTask", "GetReservation", "CancelReservation",
		"CheckWorkers", "IssueRegistrationCode", "DrainRelay"} {
		reg.SetBanned(nil) // as after a relay restart
		_ = calls[name]()
		if reg.Admitted("bb") {
			t.Errorf("%s reached the relay without the ban set — a restarted relay would admit a banned worker", name)
		}
	}
}
