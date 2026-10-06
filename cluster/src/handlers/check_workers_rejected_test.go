package handlers

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	w17pb "github.com/wandering-compiler/sdk/go/pb/w17"
)

// validatingStore refuses a row the way the generated storage does: a name
// longer than RecordWorkerReq's max_len is InvalidArgument, and a device id
// the table's constraint rejects is InvalidArgument carrying a w17 detail.
// `down`, once set, makes every write fail the way a lost database does.
type validatingStore struct {
	*workerStore
	refuseDevice string
	down         error
}

func (v *validatingStore) Record(ctx context.Context, relayID string, k *pb.KnownWorker) error {
	if v.down != nil {
		return v.down
	}
	if utf8.RuneCountInString(k.GetName()) > 128 {
		return status.Error(codes.InvalidArgument, "RecordWorker: name: longer than 128 characters")
	}
	if v.refuseDevice != "" && k.GetDeviceId() == v.refuseDevice {
		st, err := status.New(codes.InvalidArgument, "RecordWorker: invalid value").
			WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{}))
		if err != nil {
			panic(err)
		}
		return st.Err()
	}
	return v.workerStore.Record(ctx, relayID, k)
}

// sweepTwoRelays stands up two real relays with the given workers and a handler
// dialling them by URL "a" and "b".
func sweepTwoRelays(t *testing.T, ws WorkerStore, a, b []workeradmit.Worker, extra ...Relay) (*ClusterServiceHandler, *store) {
	t.Helper()
	_, dialA := serveRelayWithWorkers(t, a...)
	_, dialB := serveRelayWithWorkers(t, b...)
	st := &store{relays: append([]Relay{
		{ID: "r-a", Name: "acme-a", URL: "a"},
		{ID: "r-b", Name: "acme-b", URL: "b"},
	}, extra...)}
	h := &ClusterServiceHandler{Relays: st, Workers: ws, Dial: func(target, fp string) (*grpc.ClientConn, error) {
		switch target {
		case "a":
			return dialA(target, fp)
		case "b":
			return dialB(target, fp)
		}
		return nil, status.Error(codes.Unavailable, "connection refused")
	}}
	return h, st
}

// One worker whose OWN claims the registry refuses — a 200-character
// hostname, a device id a constraint rejects — is skipped and reported, and
// is never the relay's failure nor the sweep's.
//
// It used to abort the sweep with Unavailable: the relay's other workers, and
// every later relay, went unrecorded on every press, deterministically, for
// as long as that one machine stayed attached.
func TestCheckWorkers_AWorkerTheRegistryRefusesDoesNotHideTheFleet(t *testing.T) {
	ws := &validatingStore{workerStore: &workerStore{}, refuseDevice: "bad-device"}
	h, st := sweepTwoRelays(t, ws,
		[]workeradmit.Worker{
			{ID: "aa", Name: strings.Repeat("h", 200)},
			{ID: "ab", Name: "acme-2", DeviceID: "bad-device"},
			{ID: "ac", Name: "acme-3"},
		},
		[]workeradmit.Worker{{ID: "bb", Name: "acme-4"}},
	)
	resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if err != nil {
		t.Fatalf("one worker's bad claims failed the whole sweep: %v", err)
	}
	if got := strings.Join(ws.recorded, ","); !strings.Contains(got, "r-a:ac") || !strings.Contains(got, "r-b:bb") || len(ws.recorded) != 2 {
		t.Errorf("recorded = %v, want r-a:ac and r-b:bb — every worker the registry accepts", ws.recorded)
	}
	if resp.GetDiscovered() != 2 || len(resp.GetUnreachableRelays()) != 0 {
		t.Errorf("discovered=%d unreachable=%v, want 2 and none", resp.GetDiscovered(), resp.GetUnreachableRelays())
	}
	for _, id := range []string{"r-a", "r-b"} {
		if f := st.failedFor(id); len(f) != 0 {
			t.Errorf("relay %s, which answered, was marked failed: %v", id, f)
		}
	}
	st.mu.Lock()
	reached := strings.Join(st.reached, ",")
	st.mu.Unlock()
	if reached != "r-a,r-b" {
		t.Errorf("relays noted reached = %q, want r-a,r-b", reached)
	}
}

// A registry that cannot write at all still aborts — skipping would report a
// sweep that recorded nothing as a success — but what the sweep had already
// found is carried in the error rather than thrown away: the relays found
// unreachable, and the relays it never got to ask.
func TestCheckWorkers_ARegistryOutageKeepsWhatTheSweepFound(t *testing.T) {
	ws := &validatingStore{workerStore: &workerStore{}, down: status.Error(codes.Unavailable, "db: connection refused")}
	h, st := sweepTwoRelays(t, ws,
		[]workeradmit.Worker{{ID: "aa", Name: "acme-1"}},
		nil,
		Relay{ID: "r-c", Name: "acme-c", URL: "nowhere"},
	)
	// Dead first, then the relay whose workers cannot be written, then one
	// never asked.
	st.relays = []Relay{st.relays[2], st.relays[0], st.relays[1]}
	_, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable — the registry is down", err)
	}
	for _, want := range []string{"cannot record", "unreachable so far: acme-c", "not asked: acme-b"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if f := st.failedFor("r-a"); len(f) != 0 {
		t.Errorf("the healthy relay's row was marked failed: %v", f)
	}
	if f := st.failedFor("r-c"); len(f) != 1 {
		t.Errorf("the unreachable relay was not noted on its row: %v", f)
	}
}

func TestRefusedForItsOwnData(t *testing.T) {
	withDetail, err := status.New(codes.FailedPrecondition, "x").WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		err  error
		own  bool
	}{
		{"validation", status.Error(codes.InvalidArgument, "too long"), true},
		{"out of range", status.Error(codes.OutOfRange, "x"), true},
		{"w17 constraint detail", withDetail.Err(), true},
		{"database down", status.Error(codes.Unavailable, "x"), false},
		{"internal", status.Error(codes.Internal, "x"), false},
		{"deadline", status.Error(codes.DeadlineExceeded, "x"), false},
		{"not a status", context.Canceled, false},
	} {
		if got := refusedForItsOwnData(tc.err); got != tc.own {
			t.Errorf("%s: refusedForItsOwnData = %v, want %v", tc.name, got, tc.own)
		}
	}
}
