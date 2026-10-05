package handlers

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
)

// DrainRelay reaches the REAL relay, and the relay then takes no new work —
// which the stats the control plane polls report, so the next placement skips
// it without anyone having to disable its row.
func TestEndToEnd_DrainRelayDrainsTheRelay(t *testing.T) {
	pool, dial := serveRelay(t, 1, time.Minute, "worker-net:9000")
	h := &ClusterServiceHandler{
		Workers: &workerStore{},
		Relays:  &store{relays: []Relay{{ID: "1", Name: "eu-west-1", URL: "mgmt:13444", Fingerprint: "f"}}},
		Dial:    dial,
	}
	resp, err := h.DrainRelay(t.Context(), &pb.DrainRelayReq{Ids: []string{"1"}})
	if err != nil {
		t.Fatalf("DrainRelay: %v", err)
	}
	if len(resp.GetUnreachableRelays()) != 0 {
		t.Fatalf("unreachable = %v", resp.GetUnreachableRelays())
	}
	if !pool.Stats().Draining {
		t.Fatal("the relay is not draining after DrainRelay")
	}
	if _, err := run(t, h); status.Code(err) != codes.Unavailable {
		t.Errorf("placing on a pool whose only relay drains: %v, want Unavailable", err)
	}
}

// An id the registry does not hold is the operator's mistake and is said so;
// it is not silently "drained".
func TestDrainRelay_UnknownIDIsNotFound(t *testing.T) {
	h := &ClusterServiceHandler{Workers: &workerStore{}, Relays: &store{}}
	_, err := h.DrainRelay(t.Context(), &pb.DrainRelayReq{Ids: []string{"nope"}})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %s, want NotFound", status.Code(err))
	}
}

// The relay's stats are what the control plane ranks by, so the real relay's
// answer is checked against its real pool rather than trusted.
func TestEndToEnd_RelayStatsReportsThePool(t *testing.T) {
	pool, dial := serveRelay(t, 2, time.Minute, "worker-net:9000")
	g, err := pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Claim(g.Ticket); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Wait(t.Context(), nil); err != nil { // reserved
		t.Fatal(err)
	}
	conn, err := dial("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	st, err := pb.NewClusterServiceClient(conn).RelayStats(t.Context(), &pb.RelayStatsReq{})
	if err != nil {
		t.Fatalf("RelayStats: %v", err)
	}
	if st.GetInUse() != 1 || st.GetReserved() != 1 || st.GetCapacity() != 2 || st.GetDraining() {
		t.Errorf("stats = %v, want 1 in use, 1 reserved, capacity 2, not draining", st)
	}
}
