package relayserver

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

// An Enrollment wired with no lifetime and no clock issues certificates for
// the documented default, judged by the real time — a relay built from the
// zero value must not issue certificates that are already expired, or that
// last forever.
func TestEnrollment_ZeroValueUsesTheDefaults(t *testing.T) {
	rig := newEnrolRig(t)
	e := &Enrollment{CA: rig.ca, Codes: rig.codes, Workers: rig.reg}
	if got := e.lifetime(); got != DefaultWorkerCertLifetime {
		t.Errorf("lifetime = %s, want %s", got, DefaultWorkerCertLifetime)
	}
	if d := time.Since(e.now()); d < 0 || d > time.Minute {
		t.Errorf("now() is %s away from the real clock", d)
	}

	_, csr, err := identity.NewKeyAndCSR("vps-1")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.Enroll(withPeer(nil), &workerpb.EnrollReq{RegistrationCode: rig.code(t), Csr: csr, Name: "vps-1"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := identity.ParseCertificatePEM(resp.GetCertificatePem())
	if err != nil {
		t.Fatal(err)
	}
	if left := time.Until(cert.NotAfter); left < DefaultWorkerCertLifetime-time.Hour || left > DefaultWorkerCertLifetime {
		t.Errorf("the certificate lasts %s, want about %s", left, DefaultWorkerCertLifetime)
	}
	if string(resp.GetCaPem()) != string(rig.ca.CertPEM) {
		t.Error("the response does not carry the CA the worker chains to")
	}
	// The default clock accepts it for renewal: Verify with the real time.
	if _, err := e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: []byte("x")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("renewing a fresh certificate under the default clock: %v, want only the malformed request refused", err)
	}
}

// A renewal whose request is not a certificate request is InvalidArgument —
// the worker's bug — not "needs a new code", which would send an operator off
// to re-enrol a perfectly good machine.
func TestRenew_AMalformedRequestIsInvalidArgument(t *testing.T) {
	r := newEnrolRig(t)
	_, cert := enrol(t, r)
	_, err := r.e.Renew(withPeer(cert), &workerpb.RenewReq{Csr: []byte("not a csr")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
}
