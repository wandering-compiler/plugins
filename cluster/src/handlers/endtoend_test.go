package handlers

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
)

// serveRelay stands a REAL relay up — relayserver over relaycore — and returns
// its pool and a dialer. The fake in schedule_task_test.go pins the proxy's own
// behaviour; this pins that the two halves agree.
func serveRelay(t *testing.T, capacity int, ttl time.Duration, addr string) (*relaycore.Pool, Dialer) {
	t.Helper()
	pool, err := relaycore.New(relaycore.Options{TicketTTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	// A relay is EMPTY until workers attach, so `capacity` here stands in for
	// the fleet the relay wiring would have summed up. Without it these tests
	// would queue forever, which is the correct behaviour they are not about.
	pool.SetCapacity(capacity)
	_, dial := serveOn(t, &relayserver.Server{Pool: pool, ProxyAddress: addr, ProxyFingerprint: "cafe"})
	return pool, dial
}

const minute = time.Minute

// serveOn puts any ClusterService on an in-process listener and returns a
// dialer for it.
func serveOn(t *testing.T, impl pb.ClusterServiceServer) (*grpc.Server, Dialer) {
	t.Helper()
	return serveWithOptions(t, impl)
}

func serveWithOptions(t *testing.T, impl pb.ClusterServiceServer, opts ...grpc.ServerOption) (*grpc.Server, Dialer) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(opts...)
	pb.RegisterClusterServiceServer(srv, impl)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return srv, func(string, string) (*grpc.ClientConn, error) {
		return grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
}

// The whole hop: a caller asks the project, the project picks a relay, the
// relay mints a ticket, and what comes back is usable.
//
// The last assertion is the one that matters — the ticket the CALLER holds is
// redeemable in the relay's own pool. Anything that mangled it in transit
// (truncation, a wrong field, a re-minted value) would leave the caller with a
// credential that looks fine and opens nothing.
func TestEndToEnd_TheGrantThatArrivesIsTheOneTheRelayMinted(t *testing.T) {
	pool, dial := serveRelay(t, 1, time.Minute, "worker-net:9000")
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "eu-west-1", URL: "mgmt:13444", Fingerprint: "f"}}},
		Dial:    dial,
	}

	c, err := run(t, h)
	if err != nil {
		t.Fatalf("ScheduleTask: %v", err)
	}
	if len(c.seen()) != 1 {
		t.Fatalf("caller saw %d events, want exactly one grant", len(c.seen()))
	}
	g := c.seen()[0].GetGranted()
	if g == nil {
		t.Fatalf("the single event is not a grant: %v", c.seen()[0])
	}

	// Each half contributes the part only it knows.
	if g.GetRelay() != "eu-west-1" {
		t.Errorf("relay = %q — the control plane did not stamp the registry name", g.GetRelay())
	}
	if g.GetAddress() != "worker-net:9000" {
		t.Errorf("address = %q — the relay's own proxy address did not survive the hop", g.GetAddress())
	}
	// Without this the caller has an address and no way to tell what answers
	// there, while holding a bearer ticket for it.
	if g.GetCertFingerprint() != "cafe" {
		t.Errorf("cert_fingerprint = %q — the caller cannot pin the work endpoint", g.GetCertFingerprint())
	}
	if !g.GetExpiresAt().AsTime().After(time.Now()) {
		t.Errorf("expires_at is not in the future: %v", g.GetExpiresAt().AsTime())
	}

	if err := pool.Claim(g.GetTicket()); err != nil {
		t.Fatalf("the ticket the caller received is not redeemable at the relay: %v", err)
	}
}

// Queueing survives the proxy: the position comes from the relay, the name
// from the control plane, and the caller sees both on one event.
func TestEndToEnd_QueuePositionFlowsThroughTheProxy(t *testing.T) {
	pool, dial := serveRelay(t, 1, time.Minute, "worker-net:9000")
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "eu-west-1"}}},
		Dial:    dial,
	}

	// Occupy the only slot, through the same path.
	first, err := run(t, h)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Claim(first.seen()[0].GetGranted().GetTicket()); err != nil {
		t.Fatal(err)
	}

	second := &collect{ctx: t.Context()}
	done := make(chan error, 1)
	go func() { done <- h.ScheduleTask(&pb.ScheduleTaskReq{Label: "queued"}, second) }()

	// The queued event must arrive before anything frees up.
	deadline := time.After(2 * time.Second)
	for len(second.seen()) == 0 {
		select {
		case err := <-done:
			t.Fatalf("the second caller finished without queueing: %v", err)
		case <-deadline:
			t.Fatal("no queued event arrived")
		case <-time.After(5 * time.Millisecond):
		}
	}
	q := second.seen()[0].GetQueued()
	if q == nil {
		t.Fatalf("first event is not a queue position: %v", second.seen()[0])
	}
	if q.GetPosition() != 1 {
		t.Errorf("position = %d, want 1 (the relay reports it)", q.GetPosition())
	}
	if q.GetRelay() != "eu-west-1" {
		t.Errorf("relay = %q (the control plane stamps it)", q.GetRelay())
	}

	pool.Done()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the queued caller failed once the slot freed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the freed slot never reached the queued caller")
	}
}
