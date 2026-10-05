package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The CA survives the process. A relay that minted a new CA on every start
// would invalidate every worker certificate it ever issued — and a container
// scheduler restarts relays freely.
func TestLoadOrCreateCA_SurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Cert.Equal(second.Cert) {
		t.Fatal("a second start produced a different CA")
	}
	if fi, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("the CA key is readable beyond its owner: %v %v", fi.Mode(), err)
	}
}

func TestLoadOrCreateCA_RefusesAHalfWrittenCA(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCA(dir); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("a half-written CA was replaced silently: %v", err)
	}
}

// A worker's identity is its KEY. Renewal reissues for the same key, and the
// identity — the registry row, any ban — must come through unchanged; a
// hash of the certificate would not.
func TestWorkerID_IsStableAcrossRenewal(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrDER, err := NewKeyAndCSR("w1")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	want, err := PublicKeyID(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var ids, ders []string
	for i := 0; i < 2; i++ {
		renewal, err := CSRFor(keyPEM, "w1")
		if err != nil {
			t.Fatal(err)
		}
		r, err := ParseCSR(renewal)
		if err != nil {
			t.Fatal(err)
		}
		certPEM, err := ca.IssueClientCert(r.PublicKey, "w1", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := ParseCertificatePEM(certPEM)
		if err != nil {
			t.Fatal(err)
		}
		if err := ca.Verify(cert, time.Now()); err != nil {
			t.Fatalf("an issued certificate does not verify against its own CA: %v", err)
		}
		ids = append(ids, WorkerID(cert))
		ders = append(ders, string(cert.Raw))
	}
	if ids[0] != want || ids[1] != want {
		t.Errorf("WorkerID changed across issues (%v), want the key's %s", ids, want)
	}
	if ders[0] == ders[1] {
		t.Error("two issues produced the same certificate — this test proved nothing about renewal")
	}
}

// Verify is the CA's rule, not merely "some certificate": another relay's
// worker and an expired one are both refused.
func TestCA_VerifyRefusesAnotherCAAndExpiry(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, csrDER, _ := NewKeyAndCSR("w")
	csr, _ := ParseCSR(csrDER)
	certPEM, err := other.IssueClientCert(csr.PublicKey, "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCertificatePEM(certPEM)
	if err := ca.Verify(cert, time.Now()); err == nil {
		t.Error("a certificate from another relay's CA verified")
	}
	mine, _ := ca.IssueClientCert(csr.PublicKey, "w", time.Hour)
	mc, _ := ParseCertificatePEM(mine)
	if err := ca.Verify(mc, time.Now().Add(2*time.Hour)); err == nil {
		t.Error("an expired certificate verified")
	}
}

// The worker's key is created once and kept; a certificate for some OTHER key
// is refused rather than stored beside it.
func TestWorkerCredentials_KeyIsKeptAndForeignCertsRefused(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateWorkerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateWorkerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(k1) != string(k2) {
		t.Fatal("the worker key changed between loads — the worker would become a stranger")
	}
	if _, _, err := LoadWorkerCertificate(dir); err != ErrNoCertificate {
		t.Fatalf("before enrolment: %v, want ErrNoCertificate", err)
	}

	ca, _ := LoadOrCreateCA(t.TempDir())
	_, foreignCSR, _ := NewKeyAndCSR("x")
	fc, _ := ParseCSR(foreignCSR)
	foreign, _ := ca.IssueClientCert(fc.PublicKey, "x", time.Hour)
	if err := SaveWorkerCertificate(dir, foreign); err == nil {
		t.Error("a certificate for another key was stored as this worker's")
	}

	own, _ := CSRFor(k1, "w")
	oc, _ := ParseCSR(own)
	certPEM, _ := ca.IssueClientCert(oc.PublicKey, "w", time.Hour)
	if err := SaveWorkerCertificate(dir, certPEM); err != nil {
		t.Fatalf("storing the worker's own certificate: %v", err)
	}
	if _, leaf, err := LoadWorkerCertificate(dir); err != nil || leaf == nil {
		t.Fatalf("loading it back: %v", err)
	}
}
