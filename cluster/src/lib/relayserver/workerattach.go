package relayserver

import (
	"context"
	"crypto/x509"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

// WorkerServer is the relay's WORKER-facing half: a different audience, a
// different credential, and therefore a different listener from the one the
// control plane manages this relay on.
//
// The control plane is one known peer whose certificate is pinned. Workers are
// a fleet that comes and goes, each holding a certificate this relay's CA
// issued at enrolment — so the handshake on this listener verifies the chain,
// and this side only has to ask whether the worker has been banned since.
type WorkerServer struct {
	workerpb.UnimplementedWorkerAttachServer

	Workers *workeradmit.Registry

	// Backends is where a worker's declared capacity and readiness land, so
	// scheduling can see them. Optional: nil means nothing records profiles,
	// which is the shape the admission-only tests use.
	Backends *Backends

	// PollInterval is how often an attached worker's ban and certificate
	// expiry are re-checked. A field so a test does not have to wait at
	// production speed.
	PollInterval time.Duration
}

// Attach admits or refuses a connecting worker, and holds the stream open for
// as long as the worker is available.
//
// The stream is bidirectional: the worker opens with an announcement and may
// keep talking, which is how it drains or reports itself unhealthy without
// dropping the tunnel its running work is travelling over.
func (s *WorkerServer) Attach(
	srv grpc.BidiStreamingServer[workerpb.WorkerMessage, workerpb.AttachEvent],
) error {
	ctx := srv.Context()
	cert, err := peerCertificate(ctx)
	if err != nil {
		return err
	}
	id := identity.WorkerID(cert)

	first, err := srv.Recv()
	if err != nil {
		return err
	}
	req := first.GetAnnounce()
	if req == nil {
		// Refused rather than defaulted. A status before an announcement is
		// about a worker that has not said what it is.
		return status.Error(codes.InvalidArgument,
			"relay: the first message on an attach stream must be the announcement")
	}
	// Recorded before the ban check, so a banned worker that keeps knocking
	// is still visible to an operator reading the registry.
	s.Workers.Met(workeradmit.Worker{ID: id, Name: req.GetName(), DeviceID: req.GetDeviceId()})
	if !s.Workers.Admitted(id) {
		// The message names the identity on purpose: a banned machine's
		// operator is usually its owner, and "you were banned" without saying
		// WHICH key is unactionable on a box that has been reinstalled.
		return refusal.New(codes.PermissionDenied, refusal.WorkerBanned,
			"relay: worker "+id+" is banned")
	}

	// One attachment, one generation. Every profile write below carries it, so
	// a reconnect that overtakes this stream's unwind is not erased by it.
	att := s.newAttachment(id, req.GetSlots())
	defer att.close()
	// The worker's OWN answer, as of the announcement. Taken from the
	// announcement rather than waiting for a first status, so a machine that
	// came up already draining is never briefly counted as ready.
	att.setWorkerReady(req.GetReadiness() == workerpb.WorkerStatus_READY)

	// Everything the worker says after the announcement, for as long as it is
	// connected.
	go att.readStatuses(srv)

	att.setAdmitted(true)
	if err := srv.Send(&workerpb.AttachEvent{
		Event: &workerpb.AttachEvent_Admitted{Admitted: &workerpb.Admitted{Slots: req.GetSlots()}},
	}); err != nil {
		return err
	}
	// And then HOLD. The stream is the worker's availability — the relay
	// knows it is there because this is open — so returning here would close
	// it, the worker would see EOF, report a disconnect and reconnect, forever,
	// in a loop that looks like a flapping network.
	return s.holdAdmitted(ctx, id, cert.NotAfter)
}

// peerCertificate reads the worker's certificate out of the TLS handshake —
// already verified against this relay's CA by the listener.
//
// A missing certificate is refused rather than treated as an anonymous worker.
// This listener lets a handshake through WITHOUT one, because enrolment
// happens before a worker has a certificate; every call that needs one has to
// say so, and this is where Attach does.
func peerCertificate(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, status.Error(codes.Unauthenticated,
			"relay: the worker listener accepted a connection with no TLS information")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated,
			"relay: no worker certificate was presented — enrol with a registration code first")
	}
	return tlsInfo.State.PeerCertificates[0], nil
}

// attachment is one worker's stream, and the single place its two independent
// answers are combined.
//
// A worker contributes capacity only when BOTH are true: it is admitted, and
// it says it wants work. They arrive from different places and change
// independently, so neither can be folded into the other.
//
// Admission being part of it is not a detail. capacityLocked sums over
// profiles and knows nothing about admission, so a profile published before
// admission would let a worker raise the relay's capacity before it was
// known not to be banned: callers would be granted tickets and then refused
// at the proxy, because take() does check admission (caught in review on PR
// #9, when the gate was an operator's approval).
type attachment struct {
	b     *Backends
	fp    string
	gen   uint64
	slots uint32

	mu       sync.Mutex
	admitted bool
	ready    bool
}

func (s *WorkerServer) newAttachment(fp string, slots uint32) *attachment {
	a := &attachment{fp: fp, slots: slots}
	if s.Backends != nil {
		a.b = s.Backends
		a.gen = s.Backends.NewAttachment()
	}
	return a
}

func (a *attachment) setAdmitted(v bool) {
	a.mu.Lock()
	a.admitted = v
	a.mu.Unlock()
	a.publish()
}

func (a *attachment) setWorkerReady(v bool) {
	a.mu.Lock()
	a.ready = v
	a.mu.Unlock()
	a.publish()
}

func (a *attachment) publish() {
	if a.b == nil {
		return
	}
	a.mu.Lock()
	ready := a.admitted && a.ready
	a.mu.Unlock()
	a.b.SetProfile(a.fp, a.gen, a.slots, ready)
}

func (a *attachment) close() {
	if a.b != nil {
		a.b.ClearProfile(a.fp, a.gen)
	}
}

// readStatuses applies every status update until the stream ends.
//
// Errors end it silently: a failed Recv means the worker is gone, and the
// admission half owns reporting that. The deferred close on the way out of
// Attach is what stops the fleet counting a machine that stopped talking.
func (a *attachment) readStatuses(
	srv grpc.BidiStreamingServer[workerpb.WorkerMessage, workerpb.AttachEvent],
) {
	for {
		msg, err := srv.Recv()
		if err != nil {
			return
		}
		st := msg.GetStatus()
		if st == nil {
			// A second announcement, or an empty message. Ignored rather than
			// fatal: the identity is the certificate and cannot be re-declared,
			// so there is nothing here to act on and nothing worth killing a
			// live worker's stream over.
			continue
		}
		a.setWorkerReady(st.GetReadiness() == workerpb.WorkerStatus_READY)
	}
}

// holdAdmitted keeps an admitted worker's stream open for as long as it stays
// admitted and its certificate stays valid.
//
// Two jobs, and both are easy to miss: the open stream IS the availability,
// and the facts that admitted it can change while it is open. A worker banned
// mid-attachment has to be told, or it keeps its tunnel and keeps taking work
// until it next reconnects — which, for a healthy worker, is never. And a
// certificate checked only at the handshake would let a connection outlive
// it; ending the stream at expiry sends the worker back through a handshake
// with its renewed one.
func (s *WorkerServer) holdAdmitted(ctx context.Context, id string, notAfter time.Time) error {
	interval := s.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case now := <-tick.C:
			if !s.Workers.Admitted(id) {
				return refusal.New(codes.PermissionDenied, refusal.WorkerBanned,
					"relay: worker "+id+" was banned")
			}
			if !now.Before(notAfter) {
				return refusal.New(codes.Unauthenticated, refusal.CertificateExpired,
					"relay: this worker's certificate has expired — reconnect with the renewed one")
			}
		}
	}
}
