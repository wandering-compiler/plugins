package workerconn

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
)

// A worker configured with a name or device id the registry cannot record
// ENDS, before it dials, with an error that says what to fix — and does not
// spend its code. A relay would refuse the enrolment; a worker that only
// learnt that from the relay used to retry every few seconds forever, showing
// "disconnected", with the reason thrown away.
func TestRun_AnUnrecordableClaimEndsBeforeEnrolling(t *testing.T) {
	for _, tc := range []struct {
		name         string
		claim, dev   string
		wantInReason string
	}{
		{"name too long", strings.Repeat("h", 200), "dev-1", "200 characters long"},
		{"NUL in the device id", "vps-1", "dev\x001", "control character U+0000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := serveAttach(t, time.Hour)
			cfg := r.config(t.TempDir(), r.code(t))
			cfg.Name, cfg.DeviceID = tc.claim, tc.dev
			_, done, cancel := runWorker(t, cfg)
			defer cancel()
			select {
			case err := <-done:
				if !errors.Is(err, ErrInvalidClaim) || !strings.Contains(err.Error(), tc.wantInReason) {
					t.Fatalf("Run = %v, want ErrInvalidClaim saying %q", err, tc.wantInReason)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run kept retrying a configuration no relay will accept")
			}
			if r.codes.Outstanding() != 1 {
				t.Error("the registration code was spent")
			}
			if known := r.reg.Known(); len(known) != 0 {
				t.Errorf("the relay met the worker: %+v", known)
			}
		})
	}
}

// A worker that is ALREADY enrolled keeps working under an over-long name:
// the check guards enrolment only, and the relay records the claim
// shortened. Refusing it would take a machine that served fine out of the
// fleet on an upgrade.
func TestRun_AnEnrolledWorkerWithAnOverLongNameKeepsAttaching(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	cfg := r.config(dir, "")
	cfg.Name = strings.Repeat("h", 200)
	states, _, cancel := runWorker(t, cfg)
	defer cancel()
	awaitState(t, states, Admitted)
	known := r.reg.Known()
	if len(known) != 1 || known[0].ID != id || utf8.RuneCountInString(known[0].Name) != workeradmit.MaxClaimLen {
		t.Errorf("known = %+v, want the worker met under its key with its name cut to %d", known, workeradmit.MaxClaimLen)
	}
}
