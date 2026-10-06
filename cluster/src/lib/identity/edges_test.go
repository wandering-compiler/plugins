package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// skipIfRoot skips a test that relies on file permissions: root reads and
// writes through them, so the test would pass without exercising anything.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not stop root")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A truncated KEY beside an intact certificate is a half-written identity too
// — it is what a disk filling up mid-write leaves — and it is refused, not
// accepted with a fingerprint printed for an identity nothing can present.
//
// It used to be accepted: only the certificate was read back, so `relay mint`
// printed a fingerprint for the operator to paste, and the failure surfaced
// later at a handshake, far from its cause. Nothing is regenerated either: the
// files are left exactly as found.
func TestLoadOrCreateIdentity_RefusesATruncatedOrForeignKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		damage func(t *testing.T, dir string)
	}{
		{"truncated key", func(t *testing.T, dir string) {
			key := mustRead(t, filepath.Join(dir, "relay.key"))
			mustWrite(t, filepath.Join(dir, "relay.key"), key[:len(key)/2])
		}},
		{"empty key", func(t *testing.T, dir string) {
			mustWrite(t, filepath.Join(dir, "relay.key"), nil)
		}},
		{"another identity's key", func(t *testing.T, dir string) {
			other, err := LoadOrCreateIdentity(t.TempDir(), "relay")
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(dir, "relay.key"), other.KeyPEM)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := LoadOrCreateIdentity(dir, "relay"); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, dir)
			certBefore := mustRead(t, filepath.Join(dir, "relay.crt"))
			keyBefore := mustRead(t, filepath.Join(dir, "relay.key"))

			_, err := LoadOrCreateIdentity(dir, "relay")
			if err == nil {
				t.Fatal("an identity whose key cannot present its certificate was accepted")
			}
			for _, want := range []string{"relay.key", "remove both", "pasted into the relay's row again"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %q: %v", want, err)
				}
			}
			if !bytes.Equal(certBefore, mustRead(t, filepath.Join(dir, "relay.crt"))) ||
				!bytes.Equal(keyBefore, mustRead(t, filepath.Join(dir, "relay.key"))) {
				t.Error("the damaged identity was rewritten — a pinned relay would come back as a stranger")
			}
		})
	}
}

// A certificate file that is not a PEM certificate is refused and left alone.
func TestLoadOrCreateIdentity_RefusesACorruptCertificate(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateIdentity(dir, "relay"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "relay.crt"), []byte("not a certificate"))
	if _, err := LoadOrCreateIdentity(dir, "relay"); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("a corrupt certificate: %v, want it refused as unreadable", err)
	}
	if got := mustRead(t, filepath.Join(dir, "relay.crt")); string(got) != "not a certificate" {
		t.Error("the corrupt certificate was replaced instead of reported")
	}
}

// A directory that cannot be created is an error, not a panic or an identity
// held only in memory — which would mint a NEW fingerprint on every start.
func TestLoadOrCreateIdentity_UnwritableDirectoryIsAnError(t *testing.T) {
	skipIfRoot(t)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if _, err := LoadOrCreateIdentity(filepath.Join(parent, "id"), "relay"); err == nil {
		t.Fatal("an identity was returned that could not have been stored")
	}
	if _, err := LoadOrCreateCA(filepath.Join(parent, "ca")); err == nil {
		t.Fatal("a CA was returned that could not have been stored — the next start would orphan every worker")
	}
	if _, err := LoadOrCreateWorkerKey(filepath.Join(parent, "worker")); err == nil {
		t.Fatal("a worker key was returned that could not have been stored — the worker would be a new identity on every start")
	}
	// The directory itself exists, read-only: the files cannot be written.
	if _, err := LoadOrCreateIdentity(parent, "relay"); err == nil {
		t.Fatal("an identity was returned that could not have been written")
	}
	if _, err := LoadOrCreateCA(parent); err == nil {
		t.Fatal("a CA was returned that could not have been written")
	}
	if _, err := LoadOrCreateWorkerKey(parent); err == nil {
		t.Fatal("a worker key was returned that could not have been written")
	}
}

// A mounted CA that is incomplete or wrong is refused at load, each with a
// reason an operator can act on — never replaced by a fresh one.
func TestLoadCA_Refusals(t *testing.T) {
	caDir := t.TempDir()
	if _, err := LoadOrCreateCA(caDir); err != nil {
		t.Fatal(err)
	}
	otherDir := t.TempDir()
	if _, err := LoadOrCreateCA(otherDir); err != nil {
		t.Fatal(err)
	}
	leafDir := t.TempDir()
	if _, err := LoadOrCreateIdentity(leafDir, "relay"); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(t.TempDir(), "garbage.key")
	mustWrite(t, garbage, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	notPEM := filepath.Join(t.TempDir(), "plain.key")
	mustWrite(t, notPEM, []byte("hunter2"))

	caCrt, caKey := filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key")
	for _, tc := range []struct {
		name, cert, key, want string
	}{
		{"missing certificate", filepath.Join(caDir, "nope.crt"), caKey, "CA certificate"},
		{"missing key", caCrt, filepath.Join(caDir, "nope.key"), "CA key"},
		{"a leaf, not a CA", filepath.Join(leafDir, "relay.crt"), filepath.Join(leafDir, "relay.key"), "not a CA"},
		{"another CA's key", caCrt, filepath.Join(otherDir, "ca.key"), "does not belong"},
		{"a key that does not parse", caCrt, garbage, "CA key"},
		{"a key that is not PEM", caCrt, notPEM, "not a PEM key"},
		{"a certificate that is not PEM", notPEM, caKey, "not a PEM certificate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCA(tc.cert, tc.key)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// An operator may mount the CA key as a SEC1 "EC PRIVATE KEY" — what
// `openssl ecparam -genkey` writes — rather than PKCS#8. It loads, and signs.
func TestLoadCA_AcceptsASEC1Key(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, ok := ca.key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("the minted CA key is a %T", ca.key)
	}
	der, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	sec1 := filepath.Join(t.TempDir(), "ca.key")
	mustWrite(t, sec1, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	loaded, err := LoadCA(filepath.Join(dir, "ca.crt"), sec1)
	if err != nil {
		t.Fatalf("a SEC1 CA key was refused: %v", err)
	}
	_, csr, _ := NewKeyAndCSR("w")
	parsed, _ := ParseCSR(csr)
	certPEM, err := loaded.IssueClientCert(parsed.PublicKey, "w", time.Hour)
	if err != nil {
		t.Fatalf("issuing from a SEC1-loaded CA: %v", err)
	}
	cert, _ := ParseCertificatePEM(certPEM)
	if err := ca.Verify(cert, time.Now()); err != nil {
		t.Errorf("a certificate from the SEC1-loaded CA does not chain to the same CA: %v", err)
	}
}

// A key that cannot sign is refused by name, not with a nil-interface panic
// on the first issue. X25519 is the realistic case: valid PKCS#8, wrong job.
func TestParsePrivateKeyPEM_RefusesAKeyThatCannotSign(t *testing.T) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	_, err = parsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err == nil || !strings.Contains(err.Error(), "cannot sign") {
		t.Fatalf("an X25519 key: %v, want it refused as unable to sign", err)
	}
}

// A certificate never outlives the CA that issued it, however long the
// requested lifetime: past the CA's end it would chain to nothing.
func TestIssueClientCert_LifetimeIsPositiveAndBoundedByTheCA(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, csr, _ := NewKeyAndCSR("w")
	parsed, _ := ParseCSR(csr)

	for _, d := range []time.Duration{0, -time.Hour} {
		if _, err := ca.IssueClientCert(parsed.PublicKey, "w", d); err == nil {
			t.Errorf("lifetime %s was accepted — a certificate already expired at issue", d)
		}
	}

	certPEM, err := ca.IssueClientCert(parsed.PublicKey, "w", 100*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := ParseCertificatePEM(certPEM)
	if cert.NotAfter.After(ca.Cert.NotAfter) {
		t.Errorf("the certificate ends %v, after its CA (%v)", cert.NotAfter, ca.Cert.NotAfter)
	}
	if !cert.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Errorf("a lifetime past the CA's end gave %v, want it clamped to %v", cert.NotAfter, ca.Cert.NotAfter)
	}
	if err := ca.Verify(cert, ca.Cert.NotAfter.Add(-time.Minute)); err != nil {
		t.Errorf("the clamped certificate does not verify just before the CA ends: %v", err)
	}
}

// A request has to be signed by the key it names — that signature is the
// proof the sender holds the key the certificate will be for.
func TestParseCSR_RefusesGarbageAndAForgedSignature(t *testing.T) {
	if _, err := ParseCSR([]byte("nope")); err == nil || !strings.Contains(err.Error(), "not a certificate request") {
		t.Errorf("garbage: %v", err)
	}
	if _, err := ParseCSR(nil); err == nil {
		t.Error("an empty request was accepted")
	}

	_, csr, err := NewKeyAndCSR("w")
	if err != nil {
		t.Fatal(err)
	}
	forged := append([]byte(nil), csr...)
	forged[len(forged)-1] ^= 0xff // the last byte of the signature
	if _, err := ParseCSR(forged); err == nil {
		t.Fatal("a request whose signature does not match its key was accepted")
	} else if !strings.Contains(err.Error(), "not signed by its own key") {
		t.Errorf("the refusal does not say the signature is wrong: %v", err)
	}
}

// CSRFor refuses a key it cannot read rather than signing with nothing.
func TestCSRFor_RefusesAnUnreadableKey(t *testing.T) {
	if _, err := CSRFor([]byte("not a key"), "w"); err == nil {
		t.Fatal("a request was made for a key that does not parse")
	}
}

// A worker's corrupt key is REPORTED, never replaced. The key is the worker's
// identity: regenerating it would turn an enrolled machine into a stranger
// whose registry row — and whose ban — no longer applies.
func TestLoadOrCreateWorkerKey_ACorruptKeyIsReportedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateWorkerKey(dir); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "worker.key")
	mustWrite(t, keyPath, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	before := mustRead(t, keyPath)

	if _, err := LoadOrCreateWorkerKey(dir); err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("a corrupt worker key: %v, want it refused as unreadable", err)
	}
	if !bytes.Equal(before, mustRead(t, keyPath)) {
		t.Error("the corrupt key was replaced — the worker would come back as a new identity")
	}
}

// A key the worker cannot READ (permissions) is an error too — not "absent",
// which would mint a second key over the first.
func TestLoadOrCreateWorkerKey_AnUnreadableKeyIsNotAbsent(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	if _, err := LoadOrCreateWorkerKey(dir); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "worker.key")
	if err := os.Chmod(keyPath, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyPath, 0o600) })
	if _, err := LoadOrCreateWorkerKey(dir); err == nil {
		t.Fatal("an unreadable key was treated as no key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateWorkerKey(dir); err != nil {
		t.Fatalf("the original key is gone: %v", err)
	}
}

// What a worker directory can hold that is NOT a usable credential, and what
// each one is reported as.
func TestLoadWorkerCertificate_Refusals(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no key at all", func(t *testing.T) {
		if _, _, err := LoadWorkerCertificate(t.TempDir()); err == nil || err == ErrNoCertificate {
			t.Fatalf("an empty directory: %v — it has no KEY, which enrolling cannot fix by itself", err)
		}
	})
	t.Run("a certificate for another key", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := LoadOrCreateWorkerKey(dir); err != nil {
			t.Fatal(err)
		}
		_, csr, _ := NewKeyAndCSR("x")
		parsed, _ := ParseCSR(csr)
		foreign, _ := ca.IssueClientCert(parsed.PublicKey, "x", time.Hour)
		mustWrite(t, filepath.Join(dir, "worker.crt"), foreign)
		if _, _, err := LoadWorkerCertificate(dir); err == nil || !strings.Contains(err.Error(), "does not match its key") {
			t.Fatalf("a mismatched certificate: %v", err)
		}
	})
	t.Run("a corrupt certificate", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := LoadOrCreateWorkerKey(dir); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(dir, "worker.crt"), []byte("garbage"))
		if _, _, err := LoadWorkerCertificate(dir); err == nil || err == ErrNoCertificate {
			t.Fatalf("a corrupt certificate: %v — it is not the same as never having enrolled", err)
		}
	})
}

// A certificate is stored only beside the key it is for, atomically: a refused
// one leaves the current certificate untouched, and a stored one leaves no
// temporary file behind for the next renewal to trip over.
func TestSaveWorkerCertificate_RefusesAndReplacesAtomically(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveWorkerCertificate(t.TempDir(), []byte("x")); err == nil {
		t.Error("a certificate was stored in a directory with no worker key")
	}

	dir := t.TempDir()
	id, _, err := ca.IssueWorkerIdentity(dir, "w", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	good := mustRead(t, filepath.Join(dir, "worker.crt"))

	for _, bad := range [][]byte{nil, []byte("garbage"), func() []byte {
		_, csr, _ := NewKeyAndCSR("x")
		parsed, _ := ParseCSR(csr)
		c, _ := ca.IssueClientCert(parsed.PublicKey, "x", time.Hour)
		return c
	}()} {
		if err := SaveWorkerCertificate(dir, bad); err == nil {
			t.Errorf("stored %q as this worker's certificate", bad)
		}
	}
	if !bytes.Equal(good, mustRead(t, filepath.Join(dir, "worker.crt"))) {
		t.Fatal("a refused certificate damaged the one the worker holds")
	}

	// A renewal replaces it, and the identity stays.
	id2, _, err := ca.IssueWorkerIdentity(dir, "w", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != id {
		t.Error("reissuing changed the worker's identity")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 {
		t.Errorf("the identity directory holds %v, want worker.key and worker.crt and nothing else", names)
	}
	if info, err := os.Stat(filepath.Join(dir, "worker.crt")); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("worker.crt mode = %v (%v), want 0644", info.Mode().Perm(), err)
	}
}

// When the directory cannot be written, the store fails and the certificate
// already there survives — a renewal that cannot land must not cost the worker
// the certificate it is still attached with.
func TestSaveWorkerCertificate_AnUnwritableDirectoryKeepsTheOldCertificate(t *testing.T) {
	skipIfRoot(t)
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, _, err := ca.IssueWorkerIdentity(dir, "w", time.Hour); err != nil {
		t.Fatal(err)
	}
	old := mustRead(t, filepath.Join(dir, "worker.crt"))
	keyPEM := mustRead(t, filepath.Join(dir, "worker.key"))
	csr, _ := CSRFor(keyPEM, "w")
	parsed, _ := ParseCSR(csr)
	renewed, _ := ca.IssueClientCert(parsed.PublicKey, "w", 2*time.Hour)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := SaveWorkerCertificate(dir, renewed); err == nil {
		t.Fatal("a certificate was reported stored in a directory that cannot be written")
	}
	if !bytes.Equal(old, mustRead(t, filepath.Join(dir, "worker.crt"))) {
		t.Error("the failed store damaged the certificate the worker holds")
	}
}

// Enrolling without a code still refuses what an enrolment would: a corrupt
// key is not overwritten, and a lifetime of nothing issues nothing.
func TestIssueWorkerIdentity_Refusals(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "worker.key"), []byte("garbage"))
	if _, _, err := ca.IssueWorkerIdentity(dir, "w", time.Hour); err == nil {
		t.Error("a worker with a corrupt key was issued an identity")
	}
	if got := mustRead(t, filepath.Join(dir, "worker.key")); string(got) != "garbage" {
		t.Error("the corrupt key was overwritten")
	}
	if _, _, err := ca.IssueWorkerIdentity(t.TempDir(), "w", 0); err == nil {
		t.Error("a zero lifetime issued a certificate")
	}
}

// PublicKeyID refuses a key type it cannot marshal instead of hashing nothing
// into an identity every such key would share.
func TestPublicKeyID_RefusesAnUnknownKeyType(t *testing.T) {
	if _, err := PublicKeyID(struct{}{}); err == nil {
		t.Fatal("an unmarshallable key produced an identity")
	}
}
