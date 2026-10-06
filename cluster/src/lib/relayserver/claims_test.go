package relayserver

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

// A worker's name and device id must fit the control plane's registry
// (RecordWorkerReq, max_len 128). One that does not is refused at enrolment
// with a message the worker can act on — and is never met, so it never
// reaches the control plane's sweep, where it used to fail fleet discovery for
// every relay. The limit is in characters, not bytes.
func TestEnroll_AClaimLongerThanTheRegistryHoldsIsRefused(t *testing.T) {
	long := strings.Repeat("h", maxClaimLen+1)
	for _, tc := range []struct {
		name, claim, device string
		ok                  bool
	}{
		{"name at the limit", strings.Repeat("h", maxClaimLen), "", true},
		{"multibyte name at the limit", strings.Repeat("ř", maxClaimLen), "", true},
		{"name over the limit", long, "", false},
		{"device id over the limit", "acme-1", long, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newEnrolRig(t)
			code := r.code(t)
			_, csr, err := identity.NewKeyAndCSR("a")
			if err != nil {
				t.Fatal(err)
			}
			_, err = r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr, Name: tc.claim, DeviceId: tc.device})
			if tc.ok {
				if err != nil {
					t.Fatalf("a claim the registry holds was refused: %v", err)
				}
				return
			}
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "the most a relay accepts is 128") {
				t.Fatalf("err = %v, want InvalidArgument naming the limit", err)
			}
			if known := r.reg.Known(); len(known) != 0 {
				t.Errorf("the refused worker was met anyway: %+v", known)
			}
			// Refused before the code was spent, like any malformed request.
			_, csr2, _ := identity.NewKeyAndCSR("a")
			if _, err := r.e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: code, Csr: csr2, Name: "acme-1"}); err != nil {
				t.Errorf("the code was spent by the refused request: %v", err)
			}
		})
	}
}

// The same limit on attach, where a claim is re-made on every connection: an
// over-long one is refused and the worker is not met, so the control plane is
// never told about a row it cannot hold.
func TestAttach_AClaimLongerThanTheRegistryHoldsIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  *workerpb.AttachReq
	}{
		{"name", &workerpb.AttachReq{Name: strings.Repeat("h", 200), DeviceId: "dev-1", Slots: 1}},
		{"device id", &workerpb.AttachReq{Name: "vps-1", DeviceId: strings.Repeat("d", 200), Slots: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := serveWorkers(t)
			w := r.issue(t, time.Hour)
			stream, err := r.dial(t, &w).Attach(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if err := stream.Send(&workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Announce{Announce: tc.req}}); err != nil {
				t.Fatal(err)
			}
			_, err = stream.Recv()
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "200 characters long") {
				t.Fatalf("err = %v, want InvalidArgument naming the length", err)
			}
			if known := r.reg.Known(); len(known) != 0 {
				t.Errorf("the refused worker was met: %+v", known)
			}
			if r.backends.Capacity() != 0 {
				t.Error("a refused worker added capacity")
			}
		})
	}
}
