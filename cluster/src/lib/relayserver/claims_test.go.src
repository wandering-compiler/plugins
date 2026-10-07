package relayserver

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// A worker's name and device id must be something the control plane's
// registry can record (RecordWorkerReq, max_len 128; no control character —
// Postgres refuses a NUL outright). One that is not is refused at enrolment
// with a REASON, so the worker ends with the message instead of retrying
// forever behind "disconnected" — and is never met, so it never reaches the
// control plane's sweep. The limit is in characters, not bytes.
func TestEnroll_AClaimTheRegistryCannotRecordIsRefused(t *testing.T) {
	long := strings.Repeat("h", workeradmit.MaxClaimLen+1)
	for _, tc := range []struct {
		name, claim, device string
		ok                  bool
		says                string
	}{
		{"name at the limit", strings.Repeat("h", workeradmit.MaxClaimLen), "", true, ""},
		{"multibyte name at the limit", strings.Repeat("ř", workeradmit.MaxClaimLen), "", true, ""},
		{"name over the limit", long, "", false, "the most a relay accepts is 128"},
		{"device id over the limit", "acme-1", long, false, "the most a relay accepts is 128"},
		{"NUL in the name", "acme\x001", "", false, "control character U+0000"},
		{"newline in the device id", "acme-1", "dev\n1", false, "control character U+000A"},
		{"right-to-left override in the name", "acme-\u202e1", "", false, "format character U+202E"},
		{"zero-width space in the device id", "acme-1", "dev\u200b1", false, "format character U+200B"},
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
			if status.Code(err) != codes.InvalidArgument || refusal.ReasonOf(err) != refusal.WorkerClaimInvalid ||
				!strings.Contains(err.Error(), tc.says) {
				t.Fatalf("err = %v (reason %q), want InvalidArgument/%s saying %q",
					err, refusal.ReasonOf(err), refusal.WorkerClaimInvalid, tc.says)
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

// On ATTACH the worker already holds a certificate — it enrolled, perhaps
// before any relay checked claims — so an over-long or control-character
// claim is SANITIZED, not refused: refusing it would take a machine that
// served fine out of the fleet on a relay upgrade. It is admitted (attachAs
// waits for that), and what
// it is met as (and so what the control plane is told) is what the registry
// can record.
func TestAttach_AClaimTheRegistryCannotRecordIsSanitizedNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name              string
		req               *workerpb.AttachReq
		wantName, wantDev string
	}{
		{name: "long name", req: &workerpb.AttachReq{Name: strings.Repeat("h", 200), DeviceId: "dev-1", Slots: 1},
			wantName: strings.Repeat("h", 128), wantDev: "dev-1"},
		{name: "long multibyte device id", req: &workerpb.AttachReq{Name: "vps-1", DeviceId: strings.Repeat("ř", 200), Slots: 1},
			wantName: "vps-1", wantDev: strings.Repeat("ř", 128)},
		{name: "NUL in the name", req: &workerpb.AttachReq{Name: "vps\x001", DeviceId: "dev\t1", Slots: 1},
			wantName: "vps\uFFFD1", wantDev: "dev\uFFFD1"},
		{name: "format characters", req: &workerpb.AttachReq{Name: "vps-\u202e1", DeviceId: "dev\u200d1", Slots: 1},
			wantName: "vps-\uFFFD1", wantDev: "dev\uFFFD1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := serveWorkers(t)
			w := r.issue(t, time.Hour)
			r.attachAs(t, t.Context(), w, &workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Announce{Announce: tc.req}})
			known := r.reg.Known()
			if len(known) != 1 || known[0].Name != tc.wantName || known[0].DeviceID != tc.wantDev {
				t.Fatalf("known = %+v, want the worker met as %q / %q", known, tc.wantName, tc.wantDev)
			}
			if err := workeradmit.CheckClaims(known[0].Name, known[0].DeviceID); err != nil {
				t.Errorf("met with claims the registry still cannot record: %v", err)
			}
		})
	}
}

// A BANNED worker with claims the registry cannot hold is still met — under
// sanitized claims — so an operator sees it knocking. Checking the claims
// before Met used to return first, and such a worker vanished from the
// registry while it kept knocking.
func TestAttach_ABannedWorkerWithAnOverLongClaimIsStillSeen(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	r.reg.SetBanned([]string{w.id})
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Announce{Announce: &workerpb.AttachReq{
		Name: strings.Repeat("h", 300), DeviceId: "dev\x00x", Slots: 1,
	}}}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if refusal.ReasonOf(err) != refusal.WorkerBanned {
		t.Fatalf("err = %v, want the ban refusal", err)
	}
	known := r.reg.Known()
	if len(known) != 1 || known[0].ID != w.id || utf8.RuneCountInString(known[0].Name) != workeradmit.MaxClaimLen ||
		known[0].DeviceID != "dev\uFFFDx" {
		t.Errorf("known = %+v, want the banned worker recorded under its key with sanitized claims", known)
	}
}
