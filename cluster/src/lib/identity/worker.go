package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A worker's credentials live in one directory: worker.key, which it
// generates once and never sends anywhere, and worker.crt, which its relay
// issues against that key at enrolment and reissues at every renewal.
const (
	workerKeyFile  = "worker.key"
	workerCertFile = "worker.crt"
)

// ErrNoCertificate is a worker directory with a key and no certificate yet —
// the state before enrolment.
var ErrNoCertificate = errors.New("identity: no worker certificate yet — the worker has not enrolled")

// NewKeyAndCSR generates a key pair and a certificate request for it. The
// relay signs the request; the key stays with the caller.
func NewKeyAndCSR(name string) (keyPEM, csrDER []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generating a key: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: marshalling the key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrDER, err = CSRFor(keyPEM, name)
	return keyPEM, csrDER, err
}

// CSRFor is a certificate request for an EXISTING key — what a renewal sends,
// so the reissued certificate carries the same key and the same WorkerID.
func CSRFor(keyPEM []byte, name string) ([]byte, error) {
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: the worker key: %w", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "w17-worker-" + name},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("identity: creating a certificate request: %w", err)
	}
	return der, nil
}

// ParseCSR parses a request and checks it is signed by the key it names —
// the proof that whoever sent it holds that key.
func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("identity: not a certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("identity: the certificate request is not signed by its own key: %w", err)
	}
	return csr, nil
}

// LoadOrCreateWorkerKey returns the worker's key from dir, generating it the
// first time. The key is the worker's identity (WorkerID), so it is created
// once and kept: a worker that regenerated it would be a new worker, needing a
// new registration code, with its old registry row orphaned.
func LoadOrCreateWorkerKey(dir string) ([]byte, error) {
	keyPath := filepath.Join(dir, workerKeyFile)
	keyPEM, err := os.ReadFile(keyPath)
	if err == nil {
		if _, perr := parsePrivateKeyPEM(keyPEM); perr != nil {
			return nil, fmt.Errorf("identity: %s is unreadable: %w", keyPath, perr)
		}
		return keyPEM, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("identity: reading %s: %w", keyPath, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: creating %s: %w", dir, err)
	}
	keyPEM, _, err = NewKeyAndCSR("unused")
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return keyPEM, nil
}

// LoadWorkerCertificate returns the worker's current certificate as a TLS
// certificate (with its key) and as parsed, or ErrNoCertificate.
func LoadWorkerCertificate(dir string) (tls.Certificate, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, workerKeyFile))
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("identity: the worker key: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, workerCertFile))
	if os.IsNotExist(err) {
		return tls.Certificate{}, nil, ErrNoCertificate
	}
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("identity: the worker certificate: %w", err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("identity: the worker certificate does not match its key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pair.Leaf = leaf
	return pair, leaf, nil
}

// SaveWorkerCertificate stores a certificate the relay issued, refusing one
// that is not for this worker's key. Written atomically, because the renewal
// loop replaces it while tunnels are being dialled with it.
func SaveWorkerCertificate(dir string, certPEM []byte) error {
	keyPEM, err := os.ReadFile(filepath.Join(dir, workerKeyFile))
	if err != nil {
		return fmt.Errorf("identity: the worker key: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("identity: the issued certificate is not for this worker's key: %w", err)
	}
	return writeAtomic(filepath.Join(dir, workerCertFile), certPEM, 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("identity: writing %s: %w", path, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity: writing %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("identity: writing %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("identity: writing %s: %w", path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("identity: writing %s: %w", path, err)
	}
	return nil
}

// IssueWorkerIdentity enrols a worker WITHOUT a registration code: it makes
// (or keeps) the worker's key in dir and stores a certificate this CA issued
// for it, so a worker started on dir attaches at once and renews from then on
// like any other. For an operator who holds the CA — the first worker of a
// deployment, a dev stack, a test — where no admin exists yet to issue a code.
//
// It returns the worker's ID, the same SPKI fingerprint a ban names.
func (ca *CA) IssueWorkerIdentity(dir, name string, lifetime time.Duration) (string, time.Time, error) {
	keyPEM, err := LoadOrCreateWorkerKey(dir)
	if err != nil {
		return "", time.Time{}, err
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return "", time.Time{}, err
	}
	id, err := PublicKeyID(key.Public())
	if err != nil {
		return "", time.Time{}, err
	}
	certPEM, err := ca.IssueClientCert(key.Public(), name, lifetime)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := SaveWorkerCertificate(dir, certPEM); err != nil {
		return "", time.Time{}, err
	}
	_, leaf, err := LoadWorkerCertificate(dir)
	if err != nil {
		return "", time.Time{}, err
	}
	return id, leaf.NotAfter, nil
}
