package workerconn

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// fakeWork is what the WORKER serves. ClusterService is borrowed as a stand-in
// for "whatever this pool's workers speak" — and it is a pointed choice: a
// relay's own ClusterService answers CheckWorkers with Unimplemented, so an
// answer of 42 can only have come from the far end of the tunnel.
type fakeWork struct {
	pb.UnimplementedClusterServiceServer
	seenTicket []string
	// hold, if set, keeps CheckWorkers running until it is closed: work
	// that is still in flight when something happens to its tunnel.
	hold chan struct{}
}

// ReserveTask echoes the label back as the reservation, which makes it a
// payload of any size in BOTH directions: what the caller sends, the worker
// returns.
func (f *fakeWork) ReserveTask(_ context.Context, req *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	return &pb.ReservationState{Reservation: req.GetLabel()}, nil
}

func (f *fakeWork) CheckWorkers(ctx context.Context, _ *pb.CheckWorkersReq) (*pb.CheckWorkersResp, error) {
	if f.hold != nil {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	md, _ := metadata.FromIncomingContext(ctx)
	f.seenTicket = md.Get(relayserver.TicketHeader)
	return &pb.CheckWorkersResp{Discovered: 42}, nil
}

type rig struct {
	pool       *relaycore.Pool
	workers    *workeradmit.Registry
	backends   *relayserver.Backends
	proxyAddr  string
	work       *fakeWork
	workerFP   string
	stopWorker context.CancelFunc
	// For a second, hand-made worker: the tunnel listener, the relay pin.
	tunnelAddr string
	relayFP    string
	ca         *identity.CA
	workerDir  string
	workerCtx  context.Context
}

// rigOptions bend standUp for the tests that need a different wire.
type rigOptions struct {
	// via, if set, is put between the worker and the relay's tunnel listener:
	// it is handed the listener's address and returns the one the worker dials.
	via func(addr string) string
	// relayDial is appended to the relay's options for the tunnel's client
	// side; workerServe to the worker's for its server side.
	relayDial   []grpc.DialOption
	workerServe []grpc.ServerOption
	// tunnelDone receives what ServeTunnel returned.
	tunnelDone chan error
	// lifetime of the worker's certificate (default an hour); retry is the
	// worker's RetryInterval, which paces its check for a renewed one;
	// grace is the relay's expiry grace; work replaces the worker's service.
	lifetime time.Duration
	retry    time.Duration
	grace    time.Duration
	work     *fakeWork
}

// standUp builds a whole relay: a TLS tunnel listener, a schema-blind proxy in
// front of it, and one worker attached through both.
func standUp(t *testing.T) *rig {
	t.Helper()
	return standUpWith(t, rigOptions{})
}

func standUpWith(t *testing.T, o rigOptions) *rig {
	t.Helper()
	relayID, err := identity.LoadOrCreateIdentity(t.TempDir(), "w")
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t)
	lifetime := o.lifetime
	if lifetime == 0 {
		lifetime = time.Hour
	}
	workerDir, workerFP := enrolledDir(t, ca, lifetime)
	crt, err := tls.X509KeyPair(relayID.CertPEM, relayID.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	pool, err := relaycore.New(relaycore.Options{Capacity: 2, TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	workers := deliveredRegistry() // nobody banned
	backends := relayserver.NewBackends()
	backends.SetExpiryGrace(o.grace)
	// The wiring a real relay has: capacity comes from the attached fleet.
	backends.OnCapacityChange(pool.SetCapacity)
	// This rig runs the TUNNEL only, not the attach stream, so nothing here
	// would ever announce a profile — and a worker that has not said what it
	// can take is credited with nothing, which is deliberate. Declaring it
	// directly stands in for the announcement, and keeps this test about the
	// tunnel.
	backends.SetProfile(workerFP, backends.NewAttachment(), 2, true)

	// The work listener: TLS, and it must ask for a client certificate —
	// that handshake is where the worker's identity comes from.
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tunLis := tls.NewListener(raw, &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		// As a real relay: REQUIRE a certificate and verify it against the
		// relay's CA — the tunnel carries work, and nothing enrols on it.
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.Pool(),
	})
	go func() { _ = relayserver.ServeTunnels(tunLis, workers, backends, nil, o.relayDial...) }()
	t.Cleanup(func() { _ = tunLis.Close() })

	// The proxy: NO services of its own, only the unknown-service handler.
	proxyLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := grpc.NewServer(tunnel.ProxyServerOptions(
		relayserver.TicketPicker(pool, backends, workers))...)
	go func() { _ = proxy.Serve(proxyLis) }()
	t.Cleanup(proxy.Stop)

	// The worker: dials the tunnel and serves on it.
	work := o.work
	if work == nil {
		work = &fakeWork{}
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tunnelAddr := tunLis.Addr().String()
	if o.via != nil {
		tunnelAddr = o.via(tunnelAddr)
	}
	go func() {
		err := ServeTunnel(ctx, Config{
			TunnelAddress:    tunnelAddr,
			RelayFingerprint: relayID.Fingerprint,
			IdentityDir:      workerDir,
			RetryInterval:    o.retry,
		}, func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, work) }, o.workerServe...)
		if o.tunnelDone != nil {
			o.tunnelDone <- err
		}
	}()

	for deadline := time.After(10 * time.Second); backends.Capacity() == 0; {
		select {
		case <-deadline:
			t.Fatal("the worker never attached its tunnel")
		case <-time.After(10 * time.Millisecond):
		}
	}
	return &rig{pool: pool, workers: workers, backends: backends,
		proxyAddr: proxyLis.Addr().String(), work: work,
		workerFP: workerFP, stopWorker: cancel,
		tunnelAddr: tunLis.Addr().String(), relayFP: relayID.Fingerprint, ca: ca, workerDir: workerDir, workerCtx: ctx}
}

func callThroughProxy(t *testing.T, r *rig, ticket string) (*pb.CheckWorkersResp, error) {
	t.Helper()
	ctx, c := proxyClient(t, r, ticket)
	return c.CheckWorkers(ctx, &pb.CheckWorkersReq{})
}

func proxyClient(t *testing.T, r *rig, ticket string) (context.Context, pb.ClusterServiceClient) {
	t.Helper()
	cc, err := grpc.NewClient(r.proxyAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// The CALLER's own limit, raised the way w17ctl raises it. What is under
		// test is everything between it and the worker.
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(tunnel.MaxMessage),
			grpc.MaxCallSendMsgSize(tunnel.MaxMessage)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	ctx := t.Context()
	if ticket != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, relayserver.TicketHeader, ticket)
	}
	return ctx, pb.NewClusterServiceClient(cc)
}

// The whole point of the thing: a call made to the RELAY is answered by the
// WORKER, over a connection the worker opened, with the relay never decoding
// a byte of it.
func TestTunnel_ACallReachesTheWorkerAndComesBack(t *testing.T) {
	r := standUp(t)
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := callThroughProxy(t, r, grant.Ticket)
	if err != nil {
		t.Fatalf("the call did not survive the tunnel: %v", err)
	}
	// 42 is the worker's answer. A relay answering for itself would have said
	// Unimplemented — CheckWorkers is the control plane's method, not a
	// relay's — so this number cannot have come from anywhere else.
	if resp.GetDiscovered() != 42 {
		t.Errorf("discovered = %d, want the worker's 42", resp.GetDiscovered())
	}
	// The caller's metadata travels as-is; the relay is a pipe.
	if len(r.work.seenTicket) != 1 || r.work.seenTicket[0] != grant.Ticket {
		t.Errorf("the worker saw ticket %v, want the caller's", r.work.seenTicket)
	}
}

// The ticket is redeemed AT THE PROXY, which is what makes a grant a
// reservation rather than a promise. Spending it twice must fail.
func TestTunnel_ATicketIsSpentOnFirstUse(t *testing.T) {
	r := standUp(t)
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callThroughProxy(t, r, grant.Ticket); err != nil {
		t.Fatalf("first call: %v", err)
	}
	_, err = callThroughProxy(t, r, grant.Ticket)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("replaying a ticket gave %v, want PermissionDenied", status.Code(err))
	}
	// PermissionDenied is also what "not your project" looks like; the REASON is
	// what tells a client that a new placement fixes this one.
	if got := refusal.ReasonOf(err); got != refusal.TicketNotRedeemable {
		t.Errorf("reason = %q, want %q", got, refusal.TicketNotRedeemable)
	}
}

// No ticket at all is refused, and the message says where to get one — the
// caller reaching this port without one has skipped the control plane.
func TestTunnel_NoTicketIsRefused(t *testing.T) {
	r := standUp(t)
	_, err := callThroughProxy(t, r, "")
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
	}
	if !contains(err.Error(), "schedule a task") {
		t.Errorf("the refusal does not say how to get a ticket: %v", err)
	}
	if got := refusal.ReasonOf(err); got != refusal.TicketMissing {
		t.Errorf("reason = %q, want %q", got, refusal.TicketMissing)
	}
}

// A slot returns when the call ends. Without that the pool shrinks by one per
// task until a restart, and the symptom — a queue that grows for no reason —
// points nowhere near the cause.
func TestTunnel_TheSlotComesBackWhenTheCallEnds(t *testing.T) {
	r := standUp(t)
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callThroughProxy(t, r, grant.Ticket); err != nil {
		t.Fatal(err)
	}
	for deadline := time.After(5 * time.Second); ; {
		if r.pool.Stats().Held() == 0 {
			return
		}
		select {
		case <-deadline:
			st := r.pool.Stats()
			t.Fatalf("%d slot(s) of %d still held after the call ended — the slot leaked", st.Held(), st.Capacity)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// Revocation must bite a worker that is ALREADY CONNECTED. Checking admission
// only when the tunnel opened would leave a revoked machine taking work until
// it happened to reconnect — which, for a healthy worker, is never.
func TestTunnel_RevokingAWorkerStopsItReceivingWork(t *testing.T) {
	r := standUp(t)
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callThroughProxy(t, r, grant.Ticket); err != nil {
		t.Fatalf("setup call: %v", err)
	}

	// The operator denies it while its tunnel is still open.
	r.workers.SetBanned([]string{r.workerFP})

	next, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = callThroughProxy(t, r, next.Ticket)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable — a revoked worker is still being picked", status.Code(err))
	}
	if got := refusal.ReasonOf(err); got != refusal.NoWorker {
		t.Errorf("reason = %q, want %q", got, refusal.NoWorker)
	}
	// And the slot did not leak: the ticket was claimed, then given back when
	// there turned out to be nobody to run it.
	for deadline := time.After(3 * time.Second); ; {
		if r.pool.Stats().Held() == 0 {
			break
		}
		select {
		case <-deadline:
			inUse := r.pool.Stats().Held()
			t.Fatalf("inUse = %d after a refused pick — the slot leaked", inUse)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// A tunnel that dies must stop being selectable. Left in place, Count keeps
// reporting a worker and later tickets are sent into a dead connection —
// a failure that looks like a flaky relay and points nowhere near the cause.
func TestTunnel_ADeadTunnelStopsBeingABackend(t *testing.T) {
	r := standUp(t)
	if n := r.backends.Count(); n != 1 {
		t.Fatalf("setup: %d backends, want 1", n)
	}
	r.stopWorker() // the worker goes away

	for deadline := time.After(10 * time.Second); ; {
		if r.backends.Count() == 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("the dead tunnel is still registered as a backend")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// A tunnel is opened only with a certificate from THIS relay's CA. A worker of
// another relay — a perfectly valid certificate, from the wrong authority —
// never becomes a backend; neither does a banned one.
func TestTunnel_OnlyThisRelaysUnbannedWorkersBecomeBackends(t *testing.T) {
	r := standUp(t)

	foreignDir, _ := enrolledDir(t, newCA(t), time.Hour)
	bannedDir, bannedID := enrolledDir(t, r.ca, time.Hour)
	r.workers.SetBanned([]string{bannedID})

	for _, dir := range []string{foreignDir, bannedDir} {
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		_ = ServeTunnel(ctx, Config{
			TunnelAddress:    r.tunnelAddr,
			RelayFingerprint: r.relayFP,
			IdentityDir:      dir,
		}, func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, &fakeWork{}) })
		cancel()
	}
	if n := r.backends.Count(); n != 1 {
		t.Fatalf("%d backends, want only the rig's own worker — a foreign or banned "+
			"certificate opened a tunnel", n)
	}
}

// A worker that renews keeps serving across its old certificate's expiry. It
// opens a tunnel with the new certificate; the relay sends new work there and
// lets the call already running on the old tunnel finish where it is. Before,
// the old tunnel was the only one: at its certificate's expiry the worker left
// the capacity, and the relay closed the tunnel under its running work.
func TestTunnel_ARenewedWorkerKeepsServingAcrossTheOldExpiry(t *testing.T) {
	work := &fakeWork{hold: make(chan struct{})}
	r := standUpWith(t, rigOptions{lifetime: 3 * time.Second, retry: 20 * time.Millisecond, grace: time.Minute, work: work})
	_, leaf, err := identity.LoadWorkerCertificate(r.workerDir)
	if err != nil {
		t.Fatal(err)
	}

	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, client := proxyClient(t, r, grant.Ticket)
	running := make(chan error, 1)
	go func() {
		_, err := client.CheckWorkers(ctx, &pb.CheckWorkersReq{})
		running <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); r.pool.Stats().InUse == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the call never started")
		}
	}

	reissue(t, r.ca, r.workerDir, time.Hour)
	time.Sleep(time.Until(leaf.NotAfter.Add(500 * time.Millisecond)))
	if c := r.backends.Capacity(); c != 2 {
		t.Errorf("capacity %d after the old certificate expired, want the renewed tunnel's 2", c)
	}
	select {
	case err := <-running:
		t.Fatalf("the call on the old tunnel ended before it was done: %v", err)
	default:
	}

	close(work.hold)
	select {
	case err := <-running:
		if err != nil {
			t.Errorf("the call that ran across the renewal failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call that ran across the renewal never returned")
	}
	wctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	next, err := r.pool.Wait(wctx, nil)
	if err != nil {
		t.Fatalf("no slot for new work after the old expiry: %v", err)
	}
	if resp, err := callThroughProxy(t, r, next.Ticket); err != nil || resp.GetDiscovered() != 42 {
		t.Errorf("new work after the old expiry: %v, %v; want the worker's answer", resp, err)
	}
}

// When the current tunnel drops while a tunnel retired by a renewal is still
// finishing a call, ServeTunnel returns at once so the worker redials, and the
// retired tunnel goes on serving its call until the relay closes it. The
// worker is back in the capacity while the old call is still running.
func TestServeTunnel_ADroppedTunnelIsRedialledWhileARetiredOneFinishes(t *testing.T) {
	work := &fakeWork{hold: make(chan struct{})}
	var fw *forwarder
	done := make(chan error, 1)
	r := standUpWith(t, rigOptions{
		retry: 20 * time.Millisecond, grace: time.Minute, work: work, tunnelDone: done,
		via: func(addr string) string { fw = newForwarder(t, addr); return fw.addr() },
	})
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, client := proxyClient(t, r, grant.Ticket)
	running := make(chan error, 1)
	go func() {
		_, err := client.CheckWorkers(ctx, &pb.CheckWorkersReq{})
		running <- err
	}()
	waitFor(t, "the call to start", func() bool { return r.pool.Stats().InUse == 1 })

	reissue(t, r.ca, r.workerDir, time.Hour)
	// The relay has the renewal's tunnel as current and the first one retired.
	waitFor(t, "the relay to retire the first tunnel", func() bool { return r.backends.Retiring() == 1 })
	fw.cut(1) // the current tunnel drops

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeTunnel did not return when its current tunnel dropped")
	}
	waitFor(t, "the dropped tunnel to leave", func() bool { return r.backends.Count() == 0 })

	// The worker's loop dials again at once.
	again := make(chan error, 1)
	go func() {
		again <- ServeTunnel(r.workerCtx, Config{
			TunnelAddress: fw.addr(), RelayFingerprint: r.relayFP, IdentityDir: r.workerDir,
		}, func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, work) })
	}()
	waitFor(t, "a new tunnel while the old call runs", func() bool { return r.backends.Capacity() == 2 })
	select {
	case err := <-running:
		t.Fatalf("the call on the retired tunnel ended early: %v", err)
	default:
	}

	close(work.hold)
	select {
	case err := <-running:
		if err != nil {
			t.Errorf("the call on the retired tunnel failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call on the retired tunnel never returned")
	}
	waitFor(t, "the retired tunnel to close with its call", func() bool { return r.backends.Retiring() == 0 })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// forwarder relays TCP between the worker and the relay, one pair of sockets
// per tunnel, and closes both ends when either does — so the worker sees the
// relay closing a tunnel, and a test can cut one tunnel by its index.
type forwarder struct {
	lis   net.Listener
	mu    sync.Mutex
	conns []net.Conn // worker side, relay side; two per tunnel
}

func newForwarder(t *testing.T, target string) *forwarder {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &forwarder{lis: lis}
	t.Cleanup(func() {
		_ = lis.Close()
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			in, err := lis.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("tcp", target)
			if err != nil {
				_ = in.Close()
				continue
			}
			f.mu.Lock()
			f.conns = append(f.conns, in, out)
			f.mu.Unlock()
			go f.pipe(in, out)
			go f.pipe(out, in)
		}
	}()
	return f
}

func (f *forwarder) addr() string { return f.lis.Addr().String() }

// cut closes the i-th tunnel's sockets (in the order they were accepted).
func (f *forwarder) cut(i int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.conns[2*i].Close()
	_ = f.conns[2*i+1].Close()
}

func (f *forwarder) pipe(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}
