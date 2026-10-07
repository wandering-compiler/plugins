package workerconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// ErrNeedsRegistration is a worker with no usable certificate and no
// registration code to get one with. Fatal on purpose: retrying cannot fix it,
// an operator has to issue a code (or lift a ban) and restart the worker with
// it.
var ErrNeedsRegistration = errors.New(
	"workerconn: this worker has no valid certificate and no registration code — " +
		"ask an operator to issue one for this relay and start the worker with it")

// ErrInvalidClaim is a worker whose configured Name or DeviceID the control
// plane's registry could not record — too long, or with a control character
// (workeradmit.CheckClaims). Checked before an enrolment is attempted, and
// fatal: a relay would refuse it with refusal.WorkerClaimInvalid, and
// retrying the same configuration cannot succeed.
//
// Only when ENROLLING. A worker that already holds a certificate keeps
// attaching under whatever it is configured with — its relay records the
// claims shortened and sanitized — so upgrading this package never takes an
// enrolled machine out of its fleet over a label.
var ErrInvalidClaim = errors.New("workerconn: invalid worker name or device id")

// EnsureEnrolled makes sure IdentityDir holds a key and a valid certificate
// for this relay, enrolling with RegistrationCode when it does not.
//
// The key is generated here the first time and never leaves the directory; the
// relay sees a certificate request for it. A worker that already holds a valid
// certificate does not spend its code — so the same code in a deployment's
// environment is harmless on every restart after the first.
func EnsureEnrolled(ctx context.Context, cfg Config) error {
	if err := cfg.validateIdentity(); err != nil {
		return err
	}
	keyPEM, err := identity.LoadOrCreateWorkerKey(cfg.IdentityDir)
	if err != nil {
		return err
	}
	_, leaf, err := identity.LoadWorkerCertificate(cfg.IdentityDir)
	switch {
	case err == nil && time.Now().Before(leaf.NotAfter):
		return nil
	case err != nil && !errors.Is(err, identity.ErrNoCertificate):
		return err
	}
	code := strings.TrimSpace(cfg.RegistrationCode)
	if code == "" {
		return ErrNeedsRegistration
	}
	// Before anything is dialled or any code is offered: a relay would refuse
	// it, and the operator reading this machine's log is the one who can fix
	// it.
	if err := workeradmit.CheckClaims(cfg.Name, cfg.DeviceID); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidClaim, err)
	}
	csr, err := identity.CSRFor(keyPEM, cfg.Name)
	if err != nil {
		return err
	}
	conn, err := dialAttach(cfg, false)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := workerpb.NewWorkerEnrollmentClient(conn).Enroll(c, &workerpb.EnrollReq{
		RegistrationCode: code,
		Csr:              csr,
		Name:             cfg.Name,
		DeviceId:         cfg.DeviceID,
	})
	if err != nil {
		return fmt.Errorf("workerconn: enrolling: %w", err)
	}
	return identity.SaveWorkerCertificate(cfg.IdentityDir, resp.GetCertificatePem())
}

// renew asks the relay to reissue this worker's certificate for its own key,
// authenticated by the certificate it still holds.
func renew(ctx context.Context, cfg Config) error {
	keyPEM, err := identity.LoadOrCreateWorkerKey(cfg.IdentityDir)
	if err != nil {
		return err
	}
	csr, err := identity.CSRFor(keyPEM, cfg.Name)
	if err != nil {
		return err
	}
	conn, err := dialAttach(cfg, true)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := workerpb.NewWorkerEnrollmentClient(conn).Renew(c, &workerpb.RenewReq{Csr: csr})
	if err != nil {
		return fmt.Errorf("workerconn: renewing: %w", err)
	}
	return identity.SaveWorkerCertificate(cfg.IdentityDir, resp.GetCertificatePem())
}

// keepRenewed renews the certificate whenever less than RenewBefore of it
// remains, until ctx ends or renewal becomes impossible.
//
// A failed renewal is retried every RetryInterval for as long as the old
// certificate is still valid — a relay that is briefly down must not cost a
// worker its identity. A refusal that no retry fixes (banned, not renewable)
// ends the loop and is reported; the attach loop then finds the certificate
// expired in due course and the worker stops with ErrNeedsRegistration.
func keepRenewed(ctx context.Context, cfg Config, onRenewed func(time.Time), onFailed func(error)) {
	for {
		_, leaf, err := identity.LoadWorkerCertificate(cfg.IdentityDir)
		if err != nil {
			onFailed(err)
			return
		}
		wait := time.Until(leaf.NotAfter.Add(-cfg.renewBefore(leaf)))
		if wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		if err := renew(ctx, cfg); err != nil {
			if ctx.Err() != nil {
				return
			}
			onFailed(err)
			switch refusal.ReasonOf(err) {
			case refusal.WorkerBanned, refusal.CertificateNotRenewable:
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.retry()):
			}
			continue
		}
		if _, leaf, err := identity.LoadWorkerCertificate(cfg.IdentityDir); err == nil {
			onRenewed(leaf.NotAfter)
		}
	}
}

func (cfg Config) renewBefore(leaf *x509.Certificate) time.Duration {
	if cfg.RenewBefore > 0 {
		return cfg.RenewBefore
	}
	return leaf.NotAfter.Sub(leaf.NotBefore) / 3
}

// clientTLS is the worker's side of every connection to its relay.
//
// The relay is PINNED by the fingerprint the operator handed over with the
// registration code — through relaydial's verifiers, the one implementation of
// a pin in this plugin, on both the full and the resumed handshake. The
// worker's own certificate is read from IdentityDir at each handshake, so a
// renewal takes effect on the next connection without a restart.
//
// withCert false presents no certificate: an enrolment, which happens before
// there is one.
func clientTLS(cfg Config, withCert bool) *tls.Config {
	want := strings.ToLower(strings.TrimSpace(cfg.RelayFingerprint))
	c := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// #nosec G402 -- chain verification off, identity verification on:
		// the relay presents a self-signed certificate that is pinned, which
		// is narrower than any CA would be.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: relaydial.PinnedVerifier(cfg.RelayAddress, want),
		VerifyConnection:      relaydial.PinnedConnectionVerifier(cfg.RelayAddress, want),
	}
	if withCert {
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			pair, _, err := identity.LoadWorkerCertificate(cfg.IdentityDir)
			if err != nil {
				return nil, err
			}
			return &pair, nil
		}
	}
	return c
}

func dialAttach(cfg Config, withCert bool) (*grpc.ClientConn, error) {
	return grpc.NewClient(cfg.RelayAddress,
		// Keepalive because the attach stream IS this worker's availability: a
		// relay that vanished without a RST would otherwise leave the worker
		// believing itself attached, and its loop would never reconnect.
		tunnel.ClientKeepalive(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS(cfg, withCert))))
}

// certificateUsable reports whether the stored certificate can still open a
// connection. Checked before each attach, so a worker whose certificate ran
// out (and could not be renewed) stops with a reason instead of failing
// handshakes forever.
func certificateUsable(cfg Config) (*x509.Certificate, error) {
	_, leaf, err := identity.LoadWorkerCertificate(cfg.IdentityDir)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(leaf.NotAfter) {
		return leaf, ErrNeedsRegistration
	}
	return leaf, nil
}
