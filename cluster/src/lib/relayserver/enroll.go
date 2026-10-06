package relayserver

import (
	"context"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

// DefaultWorkerCertLifetime is how long a worker certificate lasts: weeks, so
// a ban that was never taken still runs out, and a worker renews long before.
const DefaultWorkerCertLifetime = 30 * 24 * time.Hour

// Enrollment issues and renews worker certificates from this relay's CA.
//
// Served on the WORKER-ATTACH listener, which verifies a client certificate
// if one is presented and lets a handshake through without one — because
// Enroll is the call a worker makes before it has one.
type Enrollment struct {
	workerpb.UnimplementedWorkerEnrollmentServer

	CA      *identity.CA
	Codes   *regcode.Store
	Workers *workeradmit.Registry
	// Lifetime of an issued certificate. Zero uses
	// DefaultWorkerCertLifetime.
	Lifetime time.Duration
	// Now is a test seam; nil uses the real clock.
	Now func() time.Time
}

func (e *Enrollment) lifetime() time.Duration {
	if e.Lifetime <= 0 {
		return DefaultWorkerCertLifetime
	}
	return e.Lifetime
}

func (e *Enrollment) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// Enroll trades a registration code for a certificate on the worker's own key.
//
// The request is validated BEFORE the code is spent, so a worker that sent a
// malformed request can retry with the same code; a refused code is never
// told apart from an expired or invented one.
func (e *Enrollment) Enroll(_ context.Context, req *workerpb.EnrollReq) (*workerpb.Certificate, error) {
	csr, err := identity.ParseCSR(req.GetCsr())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "relay: "+err.Error())
	}
	id, err := identity.PublicKeyID(csr.PublicKey)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "relay: "+err.Error())
	}
	if err := checkClaims(req.GetName(), req.GetDeviceId()); err != nil {
		return nil, err
	}
	if !e.Workers.Admitted(id) {
		return nil, refusal.New(codes.PermissionDenied, refusal.WorkerBanned,
			"relay: the key in this request ("+id+") is banned — enrol with a new key")
	}
	if err := e.Codes.Redeem(req.GetRegistrationCode()); err != nil {
		if errors.Is(err, regcode.ErrInvalid) {
			return nil, refusal.New(codes.PermissionDenied, refusal.RegistrationCodeInvalid,
				"relay: that registration code is not valid — it may have expired or already been used; ask for a new one")
		}
		return nil, status.Errorf(codes.Internal, "relay: redeeming the code: %v", err)
	}
	certPEM, err := e.CA.IssueClientCert(csr.PublicKey, req.GetName(), e.lifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay: issuing the certificate: %v", err)
	}
	e.Workers.Met(workeradmit.Worker{ID: id, Name: req.GetName(), DeviceID: req.GetDeviceId()})
	return &workerpb.Certificate{CertificatePem: certPEM, CaPem: e.CA.CertPEM}, nil
}

// Renew reissues the presented certificate for the same key.
//
// The certificate in the handshake is the whole credential, so every
// condition on it is checked here, not assumed from the listener: it must be
// this CA's, unexpired, not banned, and the request must be for its key — a
// renewal that changed the key would be a new identity slipping in under an
// old one's standing.
func (e *Enrollment) Renew(ctx context.Context, req *workerpb.RenewReq) (*workerpb.Certificate, error) {
	notRenewable := func(why string) error {
		return refusal.New(codes.Unauthenticated, refusal.CertificateNotRenewable,
			"relay: cannot renew — "+why+"; this worker needs a new registration code")
	}
	cert, err := peerCertificate(ctx)
	if err != nil {
		return nil, notRenewable("no certificate was presented")
	}
	if err := e.CA.Verify(cert, e.now()); err != nil {
		return nil, notRenewable("the certificate is not a valid one from this relay's CA (" + err.Error() + ")")
	}
	id := identity.WorkerID(cert)
	if !e.Workers.Admitted(id) {
		return nil, refusal.New(codes.PermissionDenied, refusal.WorkerBanned,
			"relay: worker "+id+" is banned and cannot renew")
	}
	csr, err := identity.ParseCSR(req.GetCsr())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "relay: "+err.Error())
	}
	reqID, err := identity.PublicKeyID(csr.PublicKey)
	if err != nil || reqID != id {
		return nil, notRenewable("the request is for a different key than the certificate presented")
	}
	name := strings.TrimPrefix(cert.Subject.CommonName, "w17-worker-")
	certPEM, err := e.CA.IssueClientCert(csr.PublicKey, name, e.lifetime())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "relay: issuing the certificate: %v", err)
	}
	return &workerpb.Certificate{CertificatePem: certPEM, CaPem: e.CA.CertPEM}, nil
}

// checkClaims refuses, at ENROLMENT, a worker's name or device id that the
// control plane's registry could not record (workeradmit.CheckClaims: too
// long, or a control character such as NUL).
//
// Refused at the edge, where the worker can be told, rather than met and
// passed on: a claim the registry cannot hold used to reach the control
// plane's sweep, where the only thing that could happen to it was a failure
// nobody on the worker's machine would ever see. A refusal with a REASON,
// not a bare InvalidArgument: a worker ends on a reasoned refusal and shows
// the message, where a bare status was retried every few seconds forever
// behind "disconnected".
//
// Attach does NOT use it — a worker that already holds a certificate has its
// claims sanitized instead (see WorkerServer.Attach).
func checkClaims(name, deviceID string) error {
	if err := workeradmit.CheckClaims(name, deviceID); err != nil {
		return refusal.New(codes.InvalidArgument, refusal.WorkerClaimInvalid, "relay: "+err.Error())
	}
	return nil
}
