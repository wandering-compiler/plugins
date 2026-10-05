package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA is one relay's certificate authority for ITS OWN workers.
//
// Every relay is its own CA, and a worker certificate is valid at that relay
// only. A compromised relay exposes the workers it issued to, nothing else;
// and a worker joins by presenting a one-time registration code the relay
// minted, receiving a certificate for a key it generated itself — the key
// never leaves the worker.
//
// The CA key MUST outlive the process. A relay that minted a fresh CA on every
// start would invalidate every certificate it ever issued, and container
// schedulers recreate processes freely. So it is loaded from secrets in
// production (LoadCA) or kept in the relay's identity directory in dev
// (LoadOrCreateCA) — never minted silently anywhere else.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer
}

// caLifetime is long because the CA is the anchor every worker certificate
// chains to; rotating it re-enrols the fleet. What keeps exposure short is
// the WORKER certificates' lifetime, not this.
const caLifetime = 10 * 365 * 24 * time.Hour

// LoadOrCreateCA returns the CA kept in dir as ca.crt / ca.key, minting one
// the first time. Like LoadOrCreateIdentity it refuses a half-written pair
// rather than silently replacing it: a new CA orphans every worker.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return LoadCA(certPath, keyPath)
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
	default:
		return nil, fmt.Errorf(
			"identity: %s and %s must both exist or both be absent — found one of the two; "+
				"a NEW CA would invalidate every worker certificate this relay issued, so it is "+
				"not minted over a half-written one", certPath, keyPath)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("identity: creating %s: %w", dir, err)
	}
	certPEM, keyPEM, err := mintCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("identity: writing %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("identity: writing %s: %w", certPath, err)
	}
	return parseCA(certPEM, keyPEM)
}

// LoadCA reads a CA from explicit files — the production shape, where both
// are mounted secrets.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("identity: reading the CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("identity: reading the CA key: %w", err)
	}
	return parseCA(certPEM, keyPEM)
}

func mintCA() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: generating the CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "w17-cluster-relay-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Path length 0: this CA signs worker leaves and nothing else, so a
		// leaked worker key can never be used to mint further certificates.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: creating the CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: marshalling the CA key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: the CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("identity: the CA certificate is not a CA (basic constraints)")
	}
	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: the CA key: %w", err)
	}
	if !publicKeysEqual(cert.PublicKey, key.Public()) {
		return nil, errors.New("identity: the CA key does not belong to the CA certificate")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

// Pool is the CA as a verification pool, for a listener's ClientCAs.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// IssueClientCert signs a client certificate for pub, valid for lifetime.
//
// The worker's identity is the SPKI fingerprint of pub (WorkerID), which is
// why the certificate carries no identity of its own worth checking: renewing
// reissues for the SAME key, the fingerprint stays, and so do the registry
// row and any ban recorded against it. `name` is a label for logs only.
func (ca *CA) IssueClientCert(pub crypto.PublicKey, name string, lifetime time.Duration) ([]byte, error) {
	if lifetime <= 0 {
		return nil, fmt.Errorf("identity: certificate lifetime must be positive, got %s", lifetime)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(lifetime)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "w17-worker-" + name},
		// A small backdate absorbs clock skew between relay and worker; the
		// end is what bounds exposure.
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
	if err != nil {
		return nil, fmt.Errorf("identity: issuing a worker certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// Verify reports whether cert is a client certificate this CA issued and that
// is valid at `at`. The TLS handshake already checks this on the worker
// listeners; it is repeated where a decision does not come straight from a
// handshake (renewal), so that rule has one implementation.
func (ca *CA) Verify(cert *x509.Certificate, at time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       ca.Pool(),
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

// WorkerID is a worker's identity: the lowercase hex SHA-256 of its
// certificate's SubjectPublicKeyInfo.
//
// The KEY, not the certificate. Certificates are short-lived and renewed; a
// hash of the certificate's DER would change on every renewal and orphan the
// worker's registry row and every ban against it. The key is what the worker
// holds and never shows anyone, so it is what the identity is.
func WorkerID(cert *x509.Certificate) string {
	return SPKIFingerprint(cert.RawSubjectPublicKeyInfo)
}

// SPKIFingerprint hashes a DER SubjectPublicKeyInfo.
func SPKIFingerprint(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// PublicKeyID is WorkerID for a bare public key — a CSR's, before any
// certificate exists for it.
func PublicKeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("identity: marshalling a public key: %w", err)
	}
	return SPKIFingerprint(der), nil
}

// ParseCertificatePEM reads the first CERTIFICATE block.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("not a PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		if ek, ecErr := x509.ParseECPrivateKey(block.Bytes); ecErr == nil {
			return ek, nil
		}
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("a %T cannot sign", k)
	}
	return s, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	ea, ok := a.(equaler)
	return ok && ea.Equal(b)
}

func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("identity: generating a serial: %w", err)
	}
	return serial, nil
}
