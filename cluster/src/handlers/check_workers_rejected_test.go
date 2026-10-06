package handlers

import (
	"context"
	"log"
	"strings"
	"sync"
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

// wrapped builds an error the way the generated storage's wrapper (sdk
// core/grpcerr) does: EVERY error it returns carries a w17 ErrorDetail —
// Internal for a database it cannot reach (code INTERNAL), Aborted for a
// serialization failure, FailedPrecondition for an unmapped constraint,
// InvalidArgument for a mapped one or a failed validation. A fake that
// returned a bare status would hide exactly the defect where a detail's mere
// presence was read as "the worker's own data".
func wrapped(c codes.Code, detailCode, field string) error {
	st, err := status.New(c, "WorkerMutation.RecordWorker: x").
		WithDetails(protoadapt.MessageV1Of(&w17pb.ErrorDetail{Code: detailCode, Field: field, Message: "x"}))
	if err != nil {
		panic(err)
	}
	return st.Err()
}

// validatingStore refuses a row the way the generated storage does: a name
// longer than RecordWorkerReq's max_len is InvalidArgument (MAX_LEN_VIOLATION
// on name), and a device id the table's constraint rejects is InvalidArgument
// carrying a constraint detail. `down`, once set, makes every write fail the
// way a lost database does; `failFor` fails one fingerprint's write, and
// `failRelay` every write filed under one relay id.
type validatingStore struct {
	*workerStore
	refuseDevice string
	down         error
	failFor      map[string]error
	failRelay    map[string]error
}

func (v *validatingStore) Record(ctx context.Context, relayID string, k *pb.KnownWorker) error {
	if v.down != nil {
		return v.down
	}
	if err := v.failRelay[relayID]; err != nil {
		return err
	}
	if err := v.failFor[k.GetCertFingerprint()]; err != nil {
		return err
	}
	if utf8.RuneCountInString(k.GetName()) > 128 {
		return wrapped(codes.InvalidArgument, "MAX_LEN_VIOLATION", "name")
	}
	if v.refuseDevice != "" && k.GetDeviceId() == v.refuseDevice {
		return wrapped(codes.InvalidArgument, "INVALID_VALUE", "device_id")
	}
	return v.workerStore.Record(ctx, relayID, k)
}

// captureLog sends the standard logger to a buffer for the test's duration.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(prev) })
	return b
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
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
	if resp.GetSkippedWorkers() != 2 {
		t.Errorf("skipped_workers = %d, want 2 — an operator must see that the sweep left workers out", resp.GetSkippedWorkers())
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
//
// The failures are shaped as the generated storage really returns them, each
// WITH a w17 ErrorDetail. Reading the detail's presence as "the worker's own
// data" made a Postgres outage skip every worker and answer OK.
func TestCheckWorkers_ARegistryOutageKeepsWhatTheSweepFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"database unreachable", wrapped(codes.Internal, "INTERNAL", "")},
		{"serialization failure", wrapped(codes.Aborted, "CONFLICT_RETRY", "")},
		{"unmapped constraint", wrapped(codes.FailedPrecondition, "INTERNAL", "")},
		{"deadline", wrapped(codes.DeadlineExceeded, "TIMEOUT", "")},
		{"canceled", wrapped(codes.Canceled, "REQUEST_CANCELED", "")},
		{"unavailable", status.Error(codes.Unavailable, "db: connection refused")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws := &validatingStore{workerStore: &workerStore{}, down: tc.err}
			h, st := sweepTwoRelays(t, ws,
				[]workeradmit.Worker{{ID: "aa", Name: "acme-1"}},
				nil,
				Relay{ID: "r-c", Name: "acme-c", URL: "nowhere"},
			)
			// Dead first, then the relay whose workers cannot be written, then
			// one never asked.
			st.relays = []Relay{st.relays[2], st.relays[0], st.relays[1]}
			resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("err = %v (resp %v), want Unavailable — the registry is down", err, resp)
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
			st.mu.Lock()
			reached := strings.Join(st.reached, ",")
			st.mu.Unlock()
			if strings.Contains(reached, "r-a") {
				t.Errorf("the relay whose workers could not be recorded was noted reached: %q", reached)
			}
		})
	}
}

// Workers the registry refused for their own claims BEFORE the sweep aborted
// are still logged. The abort returned before the logging, so the one
// diagnosis the operator had — which worker, which claim — was dropped
// exactly when the sweep failed.
func TestCheckWorkers_AnAbortStillLogsTheWorkersAlreadyRefused(t *testing.T) {
	logs := captureLog(t)
	ws := &validatingStore{workerStore: &workerStore{}, failFor: map[string]error{
		"ab": wrapped(codes.Internal, "INTERNAL", ""),
	}}
	h, _ := sweepTwoRelays(t, ws,
		[]workeradmit.Worker{
			{ID: "aa", Name: strings.Repeat("h", 200)},
			{ID: "ab", Name: "acme-2"},
		},
		nil,
	)
	_, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable — the registry failed on ab", err)
	}
	if !strings.Contains(logs.String(), "worker aa (name") || !strings.Contains(logs.String(), "refused it") {
		t.Errorf("the worker refused before the abort was not logged; log:\n%s", logs.String())
	}
	if !strings.Contains(err.Error(), "1 worker(s) skipped") {
		t.Errorf("the abort does not say a worker was skipped: %v", err)
	}
}

// A relay the registry will not file workers under — deleted between the
// relay list and the write (a relay_id foreign key), or an id it does not
// take — is THAT relay failing. It used to read as every one of its workers
// being refused for its own data, and the relay was then noted reached.
func TestCheckWorkers_ARelayTheRegistryRefusesIsTheRelaysFailure(t *testing.T) {
	logs := captureLog(t)
	ws := &validatingStore{workerStore: &workerStore{}, failRelay: map[string]error{
		"r-a": wrapped(codes.InvalidArgument, "INVALID_VALUE", "relay_id"),
	}}
	h, st := sweepTwoRelays(t, ws,
		[]workeradmit.Worker{{ID: "aa", Name: "acme-1"}, {ID: "ab", Name: "acme-2"}},
		[]workeradmit.Worker{{ID: "bb", Name: "acme-4"}},
	)
	resp, err := h.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if err != nil {
		t.Fatalf("one relay's row failed the whole sweep: %v", err)
	}
	if got := resp.GetUnreachableRelays(); len(got) != 1 || got[0] != "acme-a" {
		t.Errorf("unreachable = %v, want [acme-a] — the relay the registry refused", got)
	}
	if resp.GetSkippedWorkers() != 0 {
		t.Errorf("skipped_workers = %d, want 0 — no WORKER was at fault", resp.GetSkippedWorkers())
	}
	if f := st.failedFor("r-a"); len(f) != 1 {
		t.Errorf("the refused relay was not noted failed: %v", f)
	}
	st.mu.Lock()
	reached := strings.Join(st.reached, ",")
	st.mu.Unlock()
	if reached != "r-b" {
		t.Errorf("relays noted reached = %q, want only r-b", reached)
	}
	if got := strings.Join(ws.recorded, ","); got != "r-b:bb" {
		t.Errorf("recorded = %q, want r-b:bb", got)
	}
	if strings.Contains(logs.String(), "refused it") {
		t.Errorf("workers of the refused relay were logged as refused for their own data:\n%s", logs.String())
	}
}

// Classified by the gRPC CODE. The generated storage attaches a w17
// ErrorDetail to every error it returns, so a detail's presence means nothing;
// only InvalidArgument / OutOfRange are about the request, and of those one
// naming relay_id is about the relay.
func TestClassifyRecordError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want recordOutcome
	}{
		{"recorded", nil, recorded},
		{"validation", wrapped(codes.InvalidArgument, "MAX_LEN_VIOLATION", "name"), refusedWorker},
		{"validation without a detail", status.Error(codes.InvalidArgument, "too long"), refusedWorker},
		{"mapped constraint on the worker", wrapped(codes.InvalidArgument, "UNIQUE_VIOLATION", "device_id"), refusedWorker},
		{"value out of range", wrapped(codes.InvalidArgument, "VALUE_OUT_OF_RANGE", ""), refusedWorker},
		{"out of range", status.Error(codes.OutOfRange, "x"), refusedWorker},
		{"relay_id foreign key", wrapped(codes.InvalidArgument, "INVALID_VALUE", "relay_id"), refusedRelay},
		{"relay_id malformed", wrapped(codes.InvalidArgument, "UUID_VIOLATION", "relay_id"), refusedRelay},
		{"unmapped constraint, with detail", wrapped(codes.FailedPrecondition, "INTERNAL", ""), registryDown},
		{"database down, with detail", wrapped(codes.Internal, "INTERNAL", ""), registryDown},
		{"serialization, with detail", wrapped(codes.Aborted, "CONFLICT_RETRY", ""), registryDown},
		{"canceled, with detail", wrapped(codes.Canceled, "REQUEST_CANCELED", ""), registryDown},
		{"deadline, with detail", wrapped(codes.DeadlineExceeded, "TIMEOUT", ""), registryDown},
		{"database down", status.Error(codes.Unavailable, "x"), registryDown},
		{"not a status", context.Canceled, registryDown},
	} {
		if got := classifyRecordError(tc.err); got != tc.want {
			t.Errorf("%s: classifyRecordError = %v, want %v", tc.name, got, tc.want)
		}
	}
}
