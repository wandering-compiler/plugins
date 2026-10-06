package relayserver

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// workerRig is the relay's WORKER-ATTACH listener on real TCP with real TLS,
// wired as cmd/relay wires it: a client certificate is verified against the
// relay's CA if one is presented. The worker's identity reaches Attach the
// only way it does in production — through the handshake.
type workerRig struct {
	addr     string
	relay    identity.Identity
	ca       *identity.CA
	reg      *workeradmit.Registry
	backends *Backends
	// capacity receives every total the fleet publishes.
	capacity chan int
	// ended receives once per Attach call, after the handler has fully
	// unwound (its deferred profile clear included).
	ended chan error
}

func serveWorkers(t *testing.T) *workerRig {
	t.Helper()
	relay, err := identity.LoadOrCreateIdentity(t.TempDir(), "relay")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := tls.X509KeyPair(relay.CertPEM, relay.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &workerRig{
		relay: relay, ca: ca, reg: workeradmit.New(), backends: NewBackends(),
		capacity: make(chan int, 64), ended: make(chan error, 8),
	}
	r.backends.OnCapacityChange(func(n int) { r.capacity <- n })
	<-r.capacity // the initial report

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{crt},
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    ca.Pool(),
		})),
		grpc.ChainStreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			err := h(srv, ss)
			r.ended <- err
			return err
		}),
	)
	workerpb.RegisterWorkerAttachServer(srv, &WorkerServer{
		Workers:      r.reg,
		Backends:     r.backends,
		PollInterval: 10 * time.Millisecond,
	})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	r.addr = lis.Addr().String()
	return r
}

// worker is one machine's credential: a key it made and a certificate the CA
// issued for it.
type worker struct {
	cert tls.Certificate
	id   string
}

func (r *workerRig) issue(t *testing.T, lifetime time.Duration) worker {
	t.Helper()
	keyPEM, csrDER, err := identity.NewKeyAndCSR("vps-1")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := identity.ParseCSR(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := r.ca.IssueClientCert(csr.PublicKey, "vps-1", lifetime)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.PublicKeyID(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return worker{cert: pair, id: id}
}

// dial connects as w; a nil w presents no certificate (an enrolling worker).
func (r *workerRig) dial(t *testing.T, w *worker) workerpb.WorkerAttachClient {
	t.Helper()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// #nosec G402 -- the relay is pinned, as a worker pins it.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: relaydial.PinnedVerifier(r.addr, r.relay.Fingerprint),
		VerifyConnection:      relaydial.PinnedConnectionVerifier(r.addr, r.relay.Fingerprint),
	}
	if w != nil {
		cfg.Certificates = []tls.Certificate{w.cert}
	}
	cc, err := grpc.NewClient(r.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return workerpb.NewWorkerAttachClient(cc)
}

func announce(slots uint32, readiness workerpb.WorkerStatus_Readiness) *workerpb.WorkerMessage {
	return &workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Announce{Announce: &workerpb.AttachReq{
		Name: "vps-1", DeviceId: "dev-1", Slots: slots, Readiness: readiness,
	}}}
}

func statusMsg(readiness workerpb.WorkerStatus_Readiness) *workerpb.WorkerMessage {
	return &workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Status{Status: &workerpb.WorkerStatus{Readiness: readiness}}}
}

// attachAs opens an attach stream as w, announces, and returns once admitted.
func (r *workerRig) attachAs(t *testing.T, ctx context.Context, w worker, msg *workerpb.WorkerMessage) workerpb.WorkerAttach_AttachClient {
	t.Helper()
	stream, err := r.dial(t, &w).Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(msg); err != nil {
		t.Fatal(err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if ev.GetAdmitted() == nil {
		t.Fatalf("first event %v, want admitted", ev)
	}
	return stream
}

// awaitCapacity waits for the fleet to publish `want`.
func (r *workerRig) awaitCapacity(t *testing.T, want int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n := <-r.capacity:
			if n == want {
				return
			}
		case <-deadline:
			t.Fatalf("capacity never became %d (now %d)", want, r.backends.Capacity())
		}
	}
}

func (r *workerRig) awaitEnded(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.ended:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the attach handler never returned")
		return nil
	}
}

func recvErr(t *testing.T, stream workerpb.WorkerAttach_AttachClient) error {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				errc <- err
				return
			}
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the attach stream never ended")
		return nil
	}
}

// Attach without a certificate is refused: the listener lets a certless
// handshake in for ENROLMENT, and Attach must not mistake that for an
// anonymous worker.
func TestAttach_WithoutACertificateIsUnauthenticated(t *testing.T) {
	r := serveWorkers(t)
	stream, err := r.dial(t, nil).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Send(announce(1, workerpb.WorkerStatus_READY))
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
	if len(r.reg.Known()) != 0 {
		t.Error("an anonymous connection was recorded as a worker")
	}
}

// The first message must say what the worker is; a status before that is
// refused rather than defaulted.
func TestAttach_AStatusBeforeTheAnnouncementIsInvalid(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(statusMsg(workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v, want InvalidArgument", err)
	}
	if r.backends.Capacity() != 0 {
		t.Error("a worker that never announced was credited with capacity")
	}
}

// A banned worker is refused with the reason, naming its key — and it is
// still RECORDED, so an operator sees it knocking.
func TestAttach_ABannedWorkerIsRefusedButStillSeen(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	r.reg.SetBanned([]string{w.id})
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(announce(2, workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.PermissionDenied || refusal.ReasonOf(err) != refusal.WorkerBanned {
		t.Fatalf("err = %v, want PermissionDenied/%s", err, refusal.WorkerBanned)
	}
	if !strings.Contains(status.Convert(err).Message(), w.id) {
		t.Errorf("the refusal does not name the banned key: %v", err)
	}
	known := r.reg.Known()
	if len(known) != 1 || known[0].ID != w.id || known[0].Name != "vps-1" || known[0].DeviceID != "dev-1" {
		t.Errorf("known = %+v, want the banned worker recorded under its key", known)
	}
	if r.backends.Capacity() != 0 {
		t.Error("a banned worker added capacity")
	}
}

// The admitted worker's slots and readiness are the fleet's capacity, and
// they follow what it says for as long as it is attached; when it leaves, its
// share goes with it.
func TestAttach_ReadinessDrivesCapacityForTheLifeOfTheStream(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	r.backends.Add(w.id, conn(t)) // its tunnel; capacity needs both halves

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := r.attachAs(t, ctx, w, announce(3, workerpb.WorkerStatus_READY))
	r.awaitCapacity(t, 3)

	if err := stream.Send(statusMsg(workerpb.WorkerStatus_DRAINING)); err != nil {
		t.Fatal(err)
	}
	r.awaitCapacity(t, 0)

	// A second announcement is not a status: ignored, not fatal.
	if err := stream.Send(announce(99, workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(statusMsg(workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	r.awaitCapacity(t, 3) // 3, not 99: the identity's claims cannot be re-declared

	cancel()
	r.awaitEnded(t)
	if got := r.backends.Capacity(); got != 0 {
		t.Errorf("capacity = %d after the worker hung up, want 0", got)
	}
}

// The Admitted event carries the slots the relay credited.
func TestAttach_AdmittedEchoesTheSlots(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(announce(4, workerpb.WorkerStatus_READY)); err != nil {
		t.Fatal(err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if ev.GetAdmitted().GetSlots() != 4 {
		t.Errorf("admitted = %v, want slots 4", ev)
	}
}

// A ban taken while a worker is attached ends its stream with the reason —
// otherwise it keeps its tunnel until it next reconnects, which is never.
func TestAttach_ABanWhileAttachedEndsTheStream(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	stream := r.attachAs(t, t.Context(), w, announce(1, workerpb.WorkerStatus_READY))
	r.reg.SetBanned([]string{w.id})
	err := recvErr(t, stream)
	if status.Code(err) != codes.PermissionDenied || refusal.ReasonOf(err) != refusal.WorkerBanned {
		t.Fatalf("err = %v, want PermissionDenied/%s", err, refusal.WorkerBanned)
	}
}

// A certificate checked only at the handshake would let a connection outlive
// it. The stream ends at expiry, sending the worker back through a handshake
// with its renewed certificate.
func TestAttach_CertificateExpiryEndsTheStream(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, 2*time.Second)
	stream := r.attachAs(t, t.Context(), w, announce(1, workerpb.WorkerStatus_READY))
	err := recvErr(t, stream)
	if status.Code(err) != codes.Unauthenticated || refusal.ReasonOf(err) != refusal.CertificateExpired {
		t.Fatalf("err = %v, want Unauthenticated/%s", err, refusal.CertificateExpired)
	}
}

// A worker that comes up already draining is never counted ready, not even
// for a moment between the announcement and its first status.
func TestAttach_AnnouncedDrainingIsNeverReady(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	r.backends.Add(w.id, conn(t))
	r.attachAs(t, t.Context(), w, announce(2, workerpb.WorkerStatus_DRAINING))
	for {
		select {
		case n := <-r.capacity:
			if n != 0 {
				t.Fatalf("a worker that announced DRAINING was counted with capacity %d", n)
			}
		default:
			if got := r.backends.Capacity(); got != 0 {
				t.Fatalf("capacity = %d, want 0", got)
			}
			return
		}
	}
}

// The same machine reconnecting: the OLD stream unwinding afterwards must not
// erase the NEW stream's profile, or a healthy worker drops out of the fleet.
func TestAttach_AReconnectSurvivesTheOldStreamsUnwind(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	r.backends.Add(w.id, conn(t))

	oldCtx, cancelOld := context.WithCancel(t.Context())
	defer cancelOld()
	r.attachAs(t, oldCtx, w, announce(2, workerpb.WorkerStatus_READY))
	r.awaitCapacity(t, 2)

	r.attachAs(t, t.Context(), w, announce(2, workerpb.WorkerStatus_READY))
	cancelOld()
	r.awaitEnded(t)
	if got := r.backends.Capacity(); got != 2 {
		t.Fatalf("capacity = %d after the old stream unwound, want the new stream's 2", got)
	}
}

// A context that carries no peer at all — a listener without TLS credentials —
// is refused, never treated as an anonymous worker.
func TestPeerCertificate_NoPeerIsUnauthenticated(t *testing.T) {
	if _, err := peerCertificate(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}

// A worker that hangs up before announcing leaves nothing behind.
func TestAttach_HangingUpBeforeAnnouncingLeavesNoTrace(t *testing.T) {
	r := serveWorkers(t)
	w := r.issue(t, time.Hour)
	stream, err := r.dial(t, &w).Attach(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if err := r.awaitEnded(t); err == nil {
		t.Error("an attach with no announcement ended as a success")
	}
	if len(r.reg.Known()) != 0 || r.backends.Capacity() != 0 {
		t.Error("a worker that never announced was recorded or credited")
	}
}
