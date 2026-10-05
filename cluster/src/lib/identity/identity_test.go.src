package identity

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE property the relay pin rests on. An operator pastes a relay's
// fingerprint into its row; if a restart produced a different one, the relay
// would come back as a stranger and every pin to it would break.
func TestLoadOrCreateIdentity_SurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateIdentity(dir, "worker")
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if first.Fingerprint == "" {
		t.Fatal("no fingerprint was produced")
	}
	second, err := LoadOrCreateIdentity(dir, "worker")
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if second.Fingerprint != first.Fingerprint {
		t.Errorf("the fingerprint changed across a restart:\n  %s\n  %s",
			first.Fingerprint, second.Fingerprint)
	}
}

// The printed fingerprint has to be the one a TLS peer will see, or the
// operator is comparing against the wrong thing and the comparison is theatre.
func TestLoadOrCreateIdentity_FingerprintIsWhatAPeerSees(t *testing.T) {
	id, err := LoadOrCreateIdentity(t.TempDir(), "worker")
	if err != nil {
		t.Fatal(err)
	}
	// Exactly how a server computes it: SHA-256 of the leaf's DER bytes.
	crt, err := tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	if err != nil {
		t.Fatalf("the pair does not load as a TLS certificate: %v", err)
	}
	sum := sha256.Sum256(crt.Certificate[0])
	if got := hex.EncodeToString(sum[:]); got != id.Fingerprint {
		t.Errorf("reported %s, a peer would see %s", id.Fingerprint, got)
	}
}

// Usable as a CLIENT certificate — the relay verifies client certs, and a
// certificate without that usage is rejected by some stacks at handshake time,
// which would be a failure with no obvious cause.
func TestLoadOrCreateIdentity_IsAClientCertificate(t *testing.T) {
	id, err := LoadOrCreateIdentity(t.TempDir(), "worker")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(id.CertPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, u := range cert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			found = true
		}
	}
	if !found {
		t.Error("the certificate does not declare client authentication")
	}
}

// Half an identity is REFUSED, not silently replaced. Minting a new key there
// would have a pinned relay reappear as a stranger with no explanation —
// and the disk-full case that produces this state is exactly when nobody is
// watching.
func TestLoadOrCreateIdentity_RefusesAHalfWrittenIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir, "worker"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "worker.key")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOrCreateIdentity(dir, "worker")
	if err == nil {
		t.Fatal("a half-written identity was silently replaced")
	}
	// The message has to say what to do, because the fix costs an edit to the
	// relay's row.
	for _, want := range []string{"both", "remove both", "pasted into the relay's row again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// The private key must not be world-readable on a shared machine.
func TestLoadOrCreateIdentity_KeyIsNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir, "worker"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "worker.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("worker.key is %04o — readable beyond its owner", mode)
	}
}
