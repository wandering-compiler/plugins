package identity

import (
	"crypto/x509"
	"testing"
	"time"
)

// A pre-issued worker identity is one the relay accepts: the certificate is
// for the worker's own key, chains to the CA, and is a client certificate.
func TestIssueWorkerIdentity_ChainsToTheCAForTheWorkersKey(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	id, notAfter, err := ca.IssueWorkerIdentity(dir, "w1", time.Hour)
	if err != nil {
		t.Fatalf("IssueWorkerIdentity: %v", err)
	}
	_, leaf, err := LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatalf("the worker cannot load what was issued: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("the issued certificate does not chain to the CA as a client certificate: %v", err)
	}
	got, err := PublicKeyID(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("returned ID %s, the certificate's key is %s — a ban by the printed ID would miss", id, got)
	}
	if !leaf.NotAfter.Equal(notAfter) {
		t.Fatalf("returned expiry %v, certificate says %v", notAfter, leaf.NotAfter)
	}
}

// Re-issuing keeps the key: the worker's identity — and any ban on it — stays.
func TestIssueWorkerIdentity_ReissueKeepsTheIdentity(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	first, _, err := ca.IssueWorkerIdentity(dir, "w1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := ca.IssueWorkerIdentity(dir, "w1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("re-issuing changed the worker's identity %s → %s", first, second)
	}
}
