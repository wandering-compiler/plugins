package handlers

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
)

// A relay whose queue is full is skipped like a draining one: another relay
// may have room, and the caller should not see this relay's limit.
func TestFallsThrough_AFullQueue(t *testing.T) {
	if !fallsThrough(refusal.New(codes.ResourceExhausted, refusal.QueueFull, "relay: the queue is full")) {
		t.Error("QUEUE_FULL does not fall through to the next relay")
	}
}

// Through the stream: the full relay is skipped and the next one grants.
func TestScheduleTask_AFullQueueFallsThrough(t *testing.T) {
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {failErr: refusal.New(codes.ResourceExhausted, refusal.QueueFull, "full")},
		"z-url": {grant: true, stats: &pb.RelayStatsResp{InUse: 3, Capacity: 4}},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "z", Name: "z", URL: "z-url"}}},
		Dial:    rs.Dial,
	}
	if got := scheduledOn(t, h); got != "z" {
		t.Fatalf("granted by %q, want z after a's full queue", got)
	}
}

// Every relay's queue is full: the caller is told NO_RELAY, retryable, and not
// one relay's QUEUE_FULL. Deployed clients (w17ctl) classify by reason and
// place again on NO_RELAY; a reason they do not know is final for them.
func TestScheduleTask_EveryQueueFullIsNoRelay(t *testing.T) {
	full := refusal.New(codes.ResourceExhausted, refusal.QueueFull, "full")
	rs := newRelays(t, map[string]*fakeRelay{
		"a-url": {failErr: full},
		"z-url": {failErr: full},
	})
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "a", Name: "a", URL: "a-url"}, {ID: "z", Name: "z", URL: "z-url"}}},
		Dial:    rs.Dial,
	}
	_, err := run(t, h)
	if status.Code(err) != codes.Unavailable || refusal.ReasonOf(err) != refusal.NoRelay {
		t.Fatalf("err = %v (reason %q), want Unavailable %s", err, refusal.ReasonOf(err), refusal.NoRelay)
	}
}

// Real relays, polled entrance: a reservation skips a relay whose queue is
// full and queues on the one with room; once both are full it is NO_RELAY.
func TestReserveTask_AFullQueueFallsThroughThenNoRelay(t *testing.T) {
	relayWithQueue := func(addr string) (*relaycore.Pool, Dialer) {
		pool, err := relaycore.New(relaycore.Options{TicketTTL: minute, MaxQueue: 1})
		if err != nil {
			t.Fatal(err)
		}
		_, dial := serveOn(t, &relayserver.Server{Pool: pool, ProxyAddress: addr, ProxyFingerprint: "cafe"})
		return pool, dial // capacity 0: every reservation queues
	}
	a, dialA := relayWithQueue("a-net:9000")
	b, dialB := relayWithQueue("b-net:9000")
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays: &store{relays: []Relay{
			{ID: "11111111-1111-1111-1111-111111111111", Name: "a", URL: "a-url", Fingerprint: "fa"},
			{ID: "22222222-2222-2222-2222-222222222222", Name: "b", URL: "b-url", Fingerprint: "fb"},
		}},
		Dial: func(target, fp string) (*grpc.ClientConn, error) {
			if target == "a-url" {
				return dialA(target, fp)
			}
			return dialB(target, fp)
		},
	}
	if _, err := a.Reserve(""); err != nil { // a's one place is taken
		t.Fatal(err)
	}
	// Whichever relay the rotation tries first, the place lands on b.
	st, err := h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if err != nil || st.GetQueued().GetRelay() != "b" {
		t.Fatalf("reserve = %v, %v; want queued on b past a's full queue", st, err)
	}
	_, err = h.ReserveTask(t.Context(), &pb.ReserveTaskReq{})
	if status.Code(err) != codes.Unavailable || refusal.ReasonOf(err) != refusal.NoRelay {
		t.Fatalf("with both queues full: %v (reason %q), want Unavailable %s", err, refusal.ReasonOf(err), refusal.NoRelay)
	}
	if a.Stats().Queued != 1 || b.Stats().Queued != 1 {
		t.Errorf("queued a=%d b=%d, want 1 and 1", a.Stats().Queued, b.Stats().Queued)
	}
}
