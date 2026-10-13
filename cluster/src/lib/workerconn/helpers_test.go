package workerconn

import (
	"testing"
	"time"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// enrolledDir is a worker identity directory as enrolment leaves it: a key,
// and a certificate for it from `ca`. Issued directly rather than through the
// Enroll RPC, for the tests that are about something else (the tunnel); the
// enrolment itself is driven end to end in attach_e2e_test.
func enrolledDir(t *testing.T, ca *identity.CA, lifetime time.Duration) (dir, workerID string) {
	t.Helper()
	dir = t.TempDir()
	keyPEM, err := identity.LoadOrCreateWorkerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := identity.CSRFor(keyPEM, "w")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.IssueClientCert(csr.PublicKey, "w", lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveWorkerCertificate(dir, certPEM); err != nil {
		t.Fatal(err)
	}
	_, leaf, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, identity.WorkerID(leaf)
}

// reissue renews the certificate in dir for the same key, as Renew would.
func reissue(t *testing.T, ca *identity.CA, dir string, lifetime time.Duration) {
	t.Helper()
	keyPEM, err := identity.LoadOrCreateWorkerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := identity.CSRFor(keyPEM, "w")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := ca.IssueClientCert(csr.PublicKey, "w", lifetime)
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.SaveWorkerCertificate(dir, certPEM); err != nil {
		t.Fatal(err)
	}
}

func newCA(t *testing.T) *identity.CA {
	t.Helper()
	ca, err := identity.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// deliveredRegistry is a relay's admission state after a control plane has
// delivered the (empty) ban set — what every relay holds in steady state. A
// fresh workeradmit.New() admits nobody until then.
func deliveredRegistry() *workeradmit.Registry {
	r := workeradmit.New()
	r.SetBanned(nil)
	return r
}
