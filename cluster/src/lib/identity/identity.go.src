// Package identity is every key and certificate in the cluster.
//
// Two kinds of identity, deliberately different:
//
//   - A RELAY has one long-lived, self-signed certificate (LoadOrCreateIdentity
//     or a mounted pair) that the control plane and every caller PIN by the
//     SHA-256 of its DER — the fingerprint on the relay's registry row.
//   - A WORKER has a key it generates itself and a SHORT-LIVED certificate its
//     relay's CA issues against it (ca.go, worker.go). Its identity is the
//     SPKI fingerprint of that key (WorkerID), which survives renewal.
//
// One package, so no two places disagree about what a fingerprint IS.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Identity is a self-signed key pair and the fingerprint a peer pins it by:
// the lowercase hex SHA-256 of the certificate's DER.
type Identity struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
}

// certLifetime is long because this certificate is PINNED, not validated:
// the control plane holds its exact fingerprint on the relay's row, and a
// caller receives it with every grant. Replacing it is an edit to that row —
// the audit trail — and an expiry would only force that edit on a calendar
// instead of when the key is actually in doubt.
//
// Workers are the opposite case and get the opposite answer: their
// certificates are issued by the relay's CA and short-lived (ca.go), because
// a fleet that comes and goes cannot be pinned row by row, and a forgotten
// ban should still run out.
const certLifetime = 10 * 365 * 24 * time.Hour

// LoadOrCreateIdentity returns the machine's self-signed identity, generating
// one the first time — a relay's, in a dev sandbox or wherever its pair is not
// mounted from secrets.
//
// IDEMPOTENT, and that is the whole point: the fingerprint pasted into the
// relay's row must survive every restart, or every restart would break the
// pin.
func LoadOrCreateIdentity(dir, name string) (Identity, error) {
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		fp, err := fingerprintOfPEM(certPEM)
		if err != nil {
			return Identity{}, fmt.Errorf("identity: %s is unreadable: %w", certPath, err)
		}
		return Identity{CertPEM: certPEM, KeyPEM: keyPEM, Fingerprint: fp}, nil
	case os.IsNotExist(certErr) && os.IsNotExist(keyErr):
		// Neither half exists — first run.
	default:
		// Exactly one half exists. REFUSED rather than regenerated: a
		// half-written identity is the state a disk filling up leaves behind,
		// and silently minting a new key there would make an approved machine
		// come back as a stranger with no explanation.
		return Identity{}, fmt.Errorf(
			"identity: %s and %s must both exist or both be absent — found one of the two, "+
				"which is a half-written identity; remove both to mint a new one "+
				"(the new fingerprint then has to be pasted into the relay's row again)", certPath, keyPath)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Identity{}, fmt.Errorf("identity: creating %s: %w", dir, err)
	}
	id, err := mint(name)
	if err != nil {
		return Identity{}, err
	}
	// The key is written 0600 and the directory 0700. Nothing here protects
	// against a reader who is already root; it protects against the ordinary
	// case of another account on a shared box.
	if err := os.WriteFile(keyPath, id.KeyPEM, 0o600); err != nil {
		return Identity{}, fmt.Errorf("identity: writing %s: %w", keyPath, err)
	}
	if err := os.WriteFile(certPath, id.CertPEM, 0o644); err != nil {
		return Identity{}, fmt.Errorf("identity: writing %s: %w", certPath, err)
	}
	return id, nil
}

func mint(name string) (Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: generating a key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Identity{}, fmt.Errorf("identity: generating a serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// SELF-SIGNED: this certificate is pinned by its fingerprint, so a
		// signature from an authority would add a second trust root that
		// decides nothing. (The relay's CA signs WORKER certificates only.)
		Subject:   pkix.Name{CommonName: "w17-cluster-" + name},
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(certLifetime),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Both usages: a relay presents it as a SERVER to everyone and as a
		// client nowhere today, but a peer stack that checks usage must not be
		// the first to discover which.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: creating a certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Identity{}, fmt.Errorf("identity: marshalling the key: %w", err)
	}
	sum := sha256.Sum256(der)
	return Identity{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}

func fingerprintOfPEM(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
