package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workerconn"
)

// quiet sends the relay's log (fingerprint banner, listener shutdowns) to the
// test's own log, where it shows on failure instead of on every run.
func quiet(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(testWriter{t})
	t.Cleanup(func() { log.SetOutput(prev) })
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// controlPlane is the identity a project's control plane would hold, minted
// the way `relay mint --name console` mints it.
func controlPlane(t *testing.T) (relaydial.Config, string) {
	t.Helper()
	id, err := identity.LoadOrCreateIdentity(t.TempDir(), "console")
	if err != nil {
		t.Fatal(err)
	}
	return relaydial.Config{ClientCertPEM: id.CertPEM, ClientKeyPEM: id.KeyPEM}, id.Fingerprint
}

// runningRelay is the relay BINARY's wiring, run in-process on ports it chose.
type runningRelay struct {
	at   listening
	fp   string // its own certificate's fingerprint, what the registry pins
	stop chan os.Signal
	done chan error
}

// startRelay runs serve with every listener on 127.0.0.1:0 and the identity
// minted in a fresh directory, plus whatever args the test adds. It returns
// once every listener is up.
func startRelay(t *testing.T, controlFP string, extra ...string) *runningRelay {
	t.Helper()
	dir := t.TempDir()
	args := append([]string{
		"--listen", "127.0.0.1:0", "--attach-listen", "127.0.0.1:0",
		"--tunnel-listen", "127.0.0.1:0", "--proxy-listen", "127.0.0.1:0",
		"--proxy-address", "relay.example.com:9000",
		"--identity-dir", dir,
		"--control-plane-fingerprint", strings.ToUpper(controlFP), // normalised by the relay
		"--drain-timeout", "5s",
	}, extra...)
	cfg, err := parseConfig(args, io.Discard)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	r := &runningRelay{stop: make(chan os.Signal, 1), done: make(chan error, 1)}
	up := make(chan listening, 1)
	go func() { r.done <- serve(cfg, r.stop, func(l listening) { up <- l }) }()
	select {
	case r.at = <-up:
	case err := <-r.done:
		t.Fatalf("the relay did not start: %v", err)
	case <-time.After(20 * time.Second):
		t.Fatal("the relay never reported its listeners")
	}
	t.Cleanup(func() { r.shutdown(t) })
	id, err := identity.LoadOrCreateIdentity(dir, "relay")
	if err != nil {
		t.Fatal(err)
	}
	r.fp = id.Fingerprint
	return r
}

// shutdown sends SIGTERM the way a supervisor does and waits for serve to
// return. Idempotent, so a test can stop the relay itself and the cleanup
// still runs.
func (r *runningRelay) shutdown(t *testing.T) {
	t.Helper()
	select {
	case r.stop <- syscall.SIGTERM:
	default:
	}
	select {
	case err, ok := <-r.done:
		if ok && err != nil {
			t.Errorf("serve returned %v on SIGTERM, want a clean stop", err)
		}
		if ok {
			close(r.done)
		}
	case <-time.After(30 * time.Second):
		t.Error("the relay did not stop within 30 s of SIGTERM")
	}
}

// manage is the control plane's management client, pinned to the relay.
func (r *runningRelay) manage(t *testing.T, cp relaydial.Config) pb.ClusterServiceClient {
	t.Helper()
	cc, err := relaydial.Dial(cp, r.at.management.String(), r.fp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewClusterServiceClient(cc)
}

// work is what the test's worker serves: CheckWorkers answers 42, which a
// relay's own ClusterService never would (it answers Unimplemented), so the
// number can only have come from the far end of the tunnel.
type work struct {
	pb.UnimplementedClusterServiceServer
}

func (work) CheckWorkers(ctx context.Context, _ *pb.CheckWorkersReq) (*pb.CheckWorkersResp, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	return &pb.CheckWorkersResp{Discovered: 42, UnreachableRelays: md.Get("x-acme-trace")}, nil
}

// joinWorker enrols a real worker with a code from the relay, attaches it,
// and opens its tunnel — the three connections a production worker holds.
func joinWorker(t *testing.T, r *runningRelay, code string) (states <-chan workerconn.State, dir string) {
	t.Helper()
	dir = t.TempDir()
	cfg := workerconn.Config{
		RelayAddress:        r.at.attach.String(),
		TunnelAddress:       r.at.tunnels.String(),
		RelayFingerprint:    r.fp,
		IdentityDir:         dir,
		RegistrationCode:    code,
		Name:                "acme-worker-1",
		DeviceID:            "dev-1",
		Slots:               2,
		RetryInterval:       50 * time.Millisecond,
		BannedRetryInterval: time.Hour, // a banned worker stays out for the rest of the test
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	out := make(chan workerconn.State, 64)
	tunnelOnce := sync.Once{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = workerconn.Run(ctx, cfg, func(s workerconn.State) {
			// The tunnel needs the certificate the enrolment writes, so it is
			// opened once the worker has been admitted — as a worker process
			// sequences it. One tunnel: a real worker loops, this test does
			// not need to.
			if s == workerconn.Admitted {
				tunnelOnce.Do(func() {
					wg.Add(1)
					go func() {
						defer wg.Done()
						_ = workerconn.ServeTunnel(ctx, cfg, func(s *grpc.Server) {
							pb.RegisterClusterServiceServer(s, work{})
						})
					}()
				})
			}
			select {
			case out <- s:
			default:
			}
		})
	}()
	return out, dir
}

func awaitState(t *testing.T, states <-chan workerconn.State, want workerconn.State) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case s := <-states:
			if s == want {
				return
			}
		case <-deadline:
			t.Fatalf("the worker never reached %q", want)
		}
	}
}

// awaitStats polls the relay until its stats satisfy ok.
func awaitStats(t *testing.T, c pb.ClusterServiceClient, what string, ok func(*pb.RelayStatsResp) bool) *pb.RelayStatsResp {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		st, err := c.RelayStats(t.Context(), &pb.RelayStatsReq{})
		if err != nil {
			t.Fatalf("RelayStats: %v", err)
		}
		if ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("the relay never reported %s; last stats %v", what, st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// schedule asks the relay for a slot over the management API and returns the
// grant.
func schedule(t *testing.T, c pb.ClusterServiceClient) *pb.TaskGranted {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	stream, err := c.ScheduleTask(ctx, &pb.ScheduleTaskReq{Label: "acme-build"})
	if err != nil {
		t.Fatal(err)
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("ScheduleTask: %v", err)
		}
		if g := ev.GetGranted(); g != nil {
			return g
		}
	}
}

// caller is a client of the relay's PROXY, pinning it with the fingerprint the
// grant carried, exactly as a caller that just received one must.
func caller(t *testing.T, r *runningRelay, g *pb.TaskGranted) pb.ClusterServiceClient {
	t.Helper()
	want := g.GetCertFingerprint()
	cc, err := grpc.NewClient(r.at.proxy.String(), grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true, // #nosec G402 -- pinned below, as every hop in the cluster is
		VerifyPeerCertificate: relaydial.PinnedVerifier("proxy", want),
		VerifyConnection:      relaydial.PinnedConnectionVerifier("proxy", want),
	})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return pb.NewClusterServiceClient(cc)
}

func withTicket(ctx context.Context, ticket string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, relayserver.TicketHeader, ticket, "x-acme-trace", "trace-7")
}

// The relay binary, whole: every listener is wired to the right half with the
// right credential, and the four parties meet.
//
// The control plane manages it over a PINNED connection and mints a code; a
// worker enrols with the code, attaches, and opens its tunnel; the relay's
// capacity becomes what the worker said; a grant names the ADVERTISED address
// and the proxy's real fingerprint; a call redeemed with it at the proxy is
// answered by the worker over the tunnel, metadata and all; the ticket is
// spent; and SIGTERM stops everything.
//
// Every piece is tested on its own elsewhere. This is the only test of the
// wiring in main, which is where a listener with the wrong TLS rule or a
// service registered on the wrong server lives — the split the comments in
// main defend, and nothing else would notice if it was undone.
func TestServe_TheWholeRelayCarriesWorkEndToEnd(t *testing.T) {
	quiet(t)
	cp, cpFP := controlPlane(t)
	r := startRelay(t, cpFP)
	mgmt := r.manage(t, cp)

	st := awaitStats(t, mgmt, "an empty fleet", func(*pb.RelayStatsResp) bool { return true })
	if st.GetCapacity() != 0 || st.GetWorkers() != 0 {
		t.Fatalf("a relay with nobody attached reports capacity %d / %d workers, want 0 / 0", st.GetCapacity(), st.GetWorkers())
	}

	code, err := mgmt.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{})
	if err != nil {
		t.Fatalf("IssueRegistrationCode: %v", err)
	}
	if code.GetRelayFingerprint() != r.fp {
		t.Errorf("the code carries fingerprint %q, want the relay's own %q", code.GetRelayFingerprint(), r.fp)
	}

	states, _ := joinWorker(t, r, code.GetCode())
	awaitState(t, states, workerconn.Admitted)
	awaitStats(t, mgmt, "the worker's two slots", func(st *pb.RelayStatsResp) bool {
		return st.GetCapacity() == 2 && st.GetWorkers() == 1
	})

	g := schedule(t, mgmt)
	if g.GetAddress() != "relay.example.com:9000" {
		t.Errorf("grant address = %q, want the ADVERTISED --proxy-address", g.GetAddress())
	}
	if g.GetCertFingerprint() != r.fp {
		t.Errorf("grant pins %q, want the proxy's certificate %q", g.GetCertFingerprint(), r.fp)
	}

	proxy := caller(t, r, g)
	resp, err := proxy.CheckWorkers(withTicket(t.Context(), g.GetTicket()), &pb.CheckWorkersReq{})
	if err != nil {
		t.Fatalf("a call with a fresh ticket did not reach the worker: %v", err)
	}
	if resp.GetDiscovered() != 42 {
		t.Errorf("answer %d, want 42 from the worker", resp.GetDiscovered())
	}
	if got := resp.GetUnreachableRelays(); len(got) != 1 || got[0] != "trace-7" {
		t.Errorf("the worker saw caller metadata %v, want the caller's trace header unchanged", got)
	}

	_, err = proxy.CheckWorkers(withTicket(t.Context(), g.GetTicket()), &pb.CheckWorkersReq{})
	if status.Code(err) != codes.PermissionDenied || refusal.ReasonOf(err) != refusal.TicketNotRedeemable {
		t.Errorf("a spent ticket: %v (reason %q), want PermissionDenied/%s", err, refusal.ReasonOf(err), refusal.TicketNotRedeemable)
	}
	_, err = proxy.CheckWorkers(t.Context(), &pb.CheckWorkersReq{})
	if refusal.ReasonOf(err) != refusal.TicketMissing {
		t.Errorf("no ticket: %v (reason %q), want %s", err, refusal.ReasonOf(err), refusal.TicketMissing)
	}

	// The slot came back when the call ended.
	awaitStats(t, mgmt, "the slot released", func(st *pb.RelayStatsResp) bool { return st.GetInUse() == 0 && st.GetReserved() == 0 })

	r.shutdown(t)
	if c, err := net.DialTimeout("tcp", r.at.management.String(), time.Second); err == nil {
		_ = c.Close()
		t.Error("the management port still accepts connections after SIGTERM")
	}
	if c, err := net.DialTimeout("tcp", r.at.proxy.String(), time.Second); err == nil {
		_ = c.Close()
		t.Error("the proxy port still accepts connections after SIGTERM")
	}
}

// A ban the control plane sends on ANY management call reaches the binary's
// worker side: the relay's attach server re-checks, ends the banned worker's
// stream, and its slots leave the capacity.
func TestServe_ABanOnAManagementCallRemovesTheWorker(t *testing.T) {
	quiet(t)
	cp, cpFP := controlPlane(t)
	r := startRelay(t, cpFP)
	mgmt := r.manage(t, cp)
	code, err := mgmt.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{})
	if err != nil {
		t.Fatal(err)
	}
	states, dir := joinWorker(t, r, code.GetCode())
	awaitState(t, states, workerconn.Admitted)
	awaitStats(t, mgmt, "the worker attached", func(st *pb.RelayStatsResp) bool { return st.GetCapacity() == 2 })

	_, leaf, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	banned := workeradmit.WithBans(t.Context(), []string{identity.WorkerID(leaf)})
	if _, err := mgmt.RelayStats(banned, &pb.RelayStatsReq{}); err != nil {
		t.Fatal(err)
	}
	awaitState(t, states, workerconn.Banned)
	awaitStats(t, mgmt, "the banned worker's slots gone", func(st *pb.RelayStatsResp) bool { return st.GetCapacity() == 0 })
}

// Only the PINNED control plane may manage the relay. A client certificate
// that is perfectly valid but not the pinned one gets nothing — not stats, not
// a registration code.
func TestServe_ManagementRefusesAnyOtherControlPlane(t *testing.T) {
	quiet(t)
	cp, cpFP := controlPlane(t)
	intruder, _ := controlPlane(t)
	r := startRelay(t, cpFP)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// The control: the pinned control plane, on the same address, is served.
	// So whatever the intruder meets below is not a wrong address nor a relay
	// that is down.
	if _, err := r.manage(t, cp).RelayStats(ctx, &pb.RelayStatsReq{}); err != nil {
		t.Fatalf("the pinned control plane was not served: %v", err)
	}
	mgmt := r.manage(t, intruder)
	// The relay aborts the handshake with bad_certificate: a certificate WAS
	// presented (the listener requires one, without checking a chain) and the
	// pin rejected it. A refused connection, a timeout or the client's own pin
	// of the relay would each read differently.
	refusedByThePin := func(what string, err error) {
		t.Helper()
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "tls: bad certificate") {
			t.Fatalf("%s as a control plane the relay does not pin: %v — want Unavailable from the relay rejecting its certificate (tls: bad certificate)", what, err)
		}
	}
	_, err := mgmt.IssueRegistrationCode(ctx, &pb.IssueRegistrationCodeReq{})
	refusedByThePin("IssueRegistrationCode", err)
	_, err = mgmt.RelayStats(ctx, &pb.RelayStatsReq{})
	refusedByThePin("RelayStats", err)
}

// A drain over the management API takes effect in the binary: the relay says
// it is draining, and a placement is refused with the reason a control plane
// falls through on.
func TestServe_DrainRefusesNewPlacements(t *testing.T) {
	quiet(t)
	cp, cpFP := controlPlane(t)
	r := startRelay(t, cpFP)
	mgmt := r.manage(t, cp)
	if _, err := mgmt.DrainRelay(t.Context(), &pb.DrainRelayReq{}); err != nil {
		t.Fatal(err)
	}
	st, err := mgmt.RelayStats(t.Context(), &pb.RelayStatsReq{})
	if err != nil || !st.GetDraining() {
		t.Fatalf("stats after drain: %v, %v — want draining", st, err)
	}
	stream, err := mgmt.ScheduleTask(t.Context(), &pb.ScheduleTaskReq{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if refusal.ReasonOf(err) != refusal.RelayDraining {
		t.Fatalf("a placement on a draining relay: %v (reason %q), want %s", err, refusal.ReasonOf(err), refusal.RelayDraining)
	}
}

// The production shape: an explicitly mounted certificate and CA rather than
// a minted directory. The relay presents the mounted certificate, and workers
// it enrols chain to the mounted CA.
func TestServe_ExplicitCertificateAndCA(t *testing.T) {
	quiet(t)
	cp, cpFP := controlPlane(t)
	keys := t.TempDir()
	relayID, err := identity.LoadOrCreateIdentity(keys, "tls")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.LoadOrCreateCA(keys)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig([]string{
		"--listen", "127.0.0.1:0", "--attach-listen", "127.0.0.1:0",
		"--tunnel-listen", "127.0.0.1:0", "--proxy-listen", "127.0.0.1:0",
		"--proxy-address", "relay.example.com:9000",
		"--cert", filepath.Join(keys, "tls.crt"), "--key", filepath.Join(keys, "tls.key"),
		"--ca-cert", filepath.Join(keys, "ca.crt"), "--ca-key", filepath.Join(keys, "ca.key"),
		"--control-plane-fingerprint", cpFP,
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	r := &runningRelay{stop: make(chan os.Signal, 1), done: make(chan error, 1), fp: relayID.Fingerprint}
	up := make(chan listening, 1)
	go func() { r.done <- serve(cfg, r.stop, func(l listening) { up <- l }) }()
	select {
	case r.at = <-up:
	case err := <-r.done:
		t.Fatalf("the relay did not start: %v", err)
	}
	t.Cleanup(func() { r.shutdown(t) })

	// The pin on the mounted certificate is what the management dial checks.
	mgmt := r.manage(t, cp)
	code, err := mgmt.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{})
	if err != nil {
		t.Fatalf("managing a relay on its mounted certificate: %v", err)
	}
	states, dir := joinWorker(t, r, code.GetCode())
	awaitState(t, states, workerconn.Admitted)
	_, leaf, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Verify(leaf, time.Now()); err != nil {
		t.Errorf("the enrolled worker does not chain to the MOUNTED CA: %v", err)
	}
}

// Every way a relay can be started wrong is refused before it serves, with a
// message naming what to fix — never a relay that looks healthy and grants
// tickets naming nowhere, accepts management from anyone, or has two answers
// to "which certificate did the operator approve".
func TestServe_RefusesToStartMisconfigured(t *testing.T) {
	quiet(t)
	_, cpFP := controlPlane(t)
	keys := t.TempDir()
	if _, err := identity.LoadOrCreateIdentity(keys, "tls"); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.LoadOrCreateCA(keys); err != nil {
		t.Fatal(err)
	}
	crt, key := filepath.Join(keys, "tls.crt"), filepath.Join(keys, "tls.key")
	caCrt, caKey := filepath.Join(keys, "ca.crt"), filepath.Join(keys, "ca.key")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()

	base := func(extra ...string) []string {
		return append([]string{
			"--listen", "127.0.0.1:0", "--attach-listen", "127.0.0.1:0",
			"--tunnel-listen", "127.0.0.1:0", "--proxy-listen", "127.0.0.1:0",
		}, extra...)
	}
	ok := []string{"--proxy-address", "relay.example.com:9000", "--control-plane-fingerprint", cpFP}
	withID := func(extra ...string) []string {
		return base(append(append([]string{}, ok...), append([]string{"--identity-dir", t.TempDir()}, extra...)...)...)
	}
	explicit := func(extra ...string) []string {
		return base(append(append([]string{}, ok...), append([]string{"--cert", crt, "--key", key}, extra...)...)...)
	}

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no advertised proxy address", base("--control-plane-fingerprint", cpFP, "--identity-dir", t.TempDir()), "--proxy-address"},
		{"no control-plane pin", base("--proxy-address", "relay.example.com:9000", "--identity-dir", t.TempDir()), "--control-plane-fingerprint"},
		{"a blank control-plane pin", base("--proxy-address", "x:1", "--control-plane-fingerprint", "  ", "--identity-dir", t.TempDir()), "--control-plane-fingerprint"},
		{"no identity at all", base(ok...), "no identity"},
		{"two identities", withID("--cert", crt, "--key", key), "two identities"},
		{"a certificate without its key", base(append(append([]string{}, ok...), "--cert", crt)...), "go together"},
		{"a certificate that is not there", base(append(append([]string{}, ok...), "--cert", crt+".missing", "--key", key)...), "loading the relay's own identity"},
		{"no worker CA", explicit(), "no worker CA"},
		{"a CA certificate without its key", explicit("--ca-cert", caCrt), "go together"},
		{"two CAs", withID("--ca-cert", caCrt, "--ca-key", caKey), "two CAs"},
		{"a CA that is not there", explicit("--ca-cert", caCrt+".missing", "--ca-key", caKey), "CA certificate"},
		{"a poll timeout shorter than two polls", withID("--poll-interval", "2s", "--poll-timeout", "3s"), "--poll-timeout"},
		{"the management port is taken", withID("--listen", busy.Addr().String()), "listening on"},
		{"the proxy port is taken", withID("--proxy-listen", busy.Addr().String()), "listening for callers"},
		{"the attach port is taken", withID("--attach-listen", busy.Addr().String()), "listening for worker attach"},
		{"the tunnel port is taken", withID("--tunnel-listen", busy.Addr().String()), "listening for worker tunnels"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig(tc.args, io.Discard)
			if err != nil {
				t.Fatalf("parseConfig: %v", err)
			}
			stop := make(chan os.Signal, 1)
			stop <- syscall.SIGTERM // a relay that DID start stops at once rather than hanging the test
			started := false
			err = serve(cfg, stop, func(listening) { started = true })
			if err == nil {
				t.Fatal("a misconfigured relay started")
			}
			if started {
				t.Error("serve reported its listeners up and then failed")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// A relay whose start failed half-way releases every port it had already
// bound: run in-process (or restarted by a supervisor in the same network
// namespace), the next attempt must not find its own ports taken.
func TestServe_AFailedStartReleasesWhatItBound(t *testing.T) {
	quiet(t)
	_, cpFP := controlPlane(t)
	// The listeners bind in the order tunnel, attach, proxy, management: the
	// management bind is made to fail, so the other three were already up.
	// Each is a real listener on a port the kernel chose, held by the test
	// until serve closes it — nothing here frees a port and hopes to get it
	// back, which raced with every other process on the machine.
	var (
		mu     sync.Mutex
		opened []*trackedListener
	)
	args := []string{
		"--tunnel-listen", "tunnel", "--attach-listen", "attach", "--proxy-listen", "proxy",
		"--listen", "management",
		"--proxy-address", "relay.example.com:9000", "--control-plane-fingerprint", cpFP,
		"--identity-dir", t.TempDir(),
	}
	cfg, err := parseConfig(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg.netListen = func(network, address string) (net.Listener, error) {
		if address == "management" {
			return nil, errors.New("address already in use")
		}
		l, err := net.Listen(network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		tl := &trackedListener{Listener: l, name: address}
		mu.Lock()
		opened = append(opened, tl)
		mu.Unlock()
		return tl, nil
	}
	if err := serve(cfg, make(chan os.Signal), nil); err == nil || !strings.Contains(err.Error(), "listening on management") {
		t.Fatalf("serve with the management bind failing: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 3 {
		t.Fatalf("%d listeners were opened before the failing one, want 3", len(opened))
	}
	for _, l := range opened {
		if !l.closed.Load() {
			t.Errorf("the %s listener is still open after the failed start", l.name)
			_ = l.Listener.Close() // or Accept below would wait forever
			continue
		}
		// Closed for real, not merely flagged: the port is free again.
		if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the %s listener still accepts: %v", l.name, err)
		}
	}
}

// trackedListener records that it was closed.
type trackedListener struct {
	net.Listener
	name   string
	closed atomic.Bool
}

func (l *trackedListener) Close() error {
	l.closed.Store(true)
	return l.Listener.Close()
}

// The flags' defaults come from RELAY_* variables, which is how the sandbox and
// most deployments configure a relay.
func TestParseConfig_ReadsTheEnvironment(t *testing.T) {
	quiet(t)
	t.Setenv("RELAY_LISTEN", "127.0.0.1:1444")
	t.Setenv("RELAY_PROXY_ADDRESS", "relay.example.com:9000")
	t.Setenv("RELAY_CONTROL_PLANE_FINGERPRINT", "abc")
	t.Setenv("RELAY_CAPACITY", "3")
	t.Setenv("RELAY_TICKET_TTL", "45s")
	t.Setenv("RELAY_DRAIN_TIMEOUT", " 2m ")
	cfg, err := parseConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != "127.0.0.1:1444" || cfg.proxyAddress != "relay.example.com:9000" || cfg.controlPin != "abc" {
		t.Errorf("string settings not read from the environment: %+v", cfg)
	}
	if cfg.capacity != 3 || cfg.ticketTTL != 45*time.Second || cfg.drainTimeout != 2*time.Minute {
		t.Errorf("capacity %d, ttl %s, drain %s — want 3, 45s, 2m from the environment", cfg.capacity, cfg.ticketTTL, cfg.drainTimeout)
	}
	// A flag beats its variable.
	cfg, err = parseConfig([]string{"--capacity", "5"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.capacity != 5 {
		t.Errorf("--capacity 5 with RELAY_CAPACITY=3 gave %d", cfg.capacity)
	}
}

// Unset means the default; zero capacity is a real value ("no ceiling").
func TestParseConfig_Defaults(t *testing.T) {
	quiet(t)
	t.Setenv("RELAY_CAPACITY", "0")
	t.Setenv("RELAY_TICKET_TTL", "")
	cfg, err := parseConfig(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.capacity != 0 || cfg.ticketTTL != 30*time.Second || cfg.listen != ":13444" || cfg.drainTimeout != 15*time.Minute {
		t.Errorf("defaults: %+v", cfg)
	}
}

// malformedVariables are RELAY_* values that do not parse, each with the flag
// that overrides the variable and a valid value for it.
var malformedVariables = []struct{ key, val, flag, good string }{
	{"RELAY_CAPACITY", "8x", "--capacity", "5"},
	{"RELAY_CAPACITY", "-2", "--capacity", "5"},
	{"RELAY_TICKET_TTL", "60", "--ticket-ttl", "1m"},
	{"RELAY_TICKET_TTL", "0s", "--ticket-ttl", "1m"},
	{"RELAY_DRAIN_TIMEOUT", "-1m", "--drain-timeout", "1m"},
	{"RELAY_POLL_INTERVAL", "soon", "--poll-interval", "1s"},
	{"RELAY_POLL_TIMEOUT", "1h30", "--poll-timeout", "1m"},
	{"RELAY_WORKER_CERT_LIFETIME", "30d", "--worker-cert-lifetime", "720h"},
	{"RELAY_REGISTRATION_CODE_TTL", "15", "--registration-code-ttl", "15m"},
}

// A variable that is SET but does not parse is refused, naming the variable.
//
// It used to be read as something else without a word: RELAY_CAPACITY=8x as
// a capacity of 8 (the old scan stopped at the first non-digit and called
// that success), RELAY_CAPACITY=-2 as no ceiling at all (anything not
// positive fell back to the default, 0), and RELAY_TICKET_TTL=60 — no unit —
// as the default 30 s. Each is a relay running on a value its operator did
// not write.
func TestParseConfig_RefusesAMalformedVariable(t *testing.T) {
	quiet(t)
	for _, tc := range malformedVariables {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			_, err := parseConfig(nil, io.Discard)
			if err == nil {
				t.Fatalf("%s=%q was accepted", tc.key, tc.val)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Errorf("the refusal does not name %s: %v", tc.key, err)
			}
		})
	}
}

// A flag given on the command line replaces its variable, so a malformed
// variable under an explicit flag is not a reason to refuse: the operator
// said what they want. It used to be checked BEFORE the flags were parsed,
// and `RELAY_CAPACITY=8x relay --capacity 5` was refused.
//
// Every other malformed variable is still refused — the flag excuses only its
// own variable.
func TestParseConfig_AnExplicitFlagExcusesItsOwnVariable(t *testing.T) {
	quiet(t)
	for _, tc := range malformedVariables {
		t.Run(tc.flag+" over "+tc.key+"="+tc.val, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			if _, err := parseConfig([]string{tc.flag, tc.good}, io.Discard); err != nil {
				t.Fatalf("%s %s with %s=%q: %v, want the flag to win", tc.flag, tc.good, tc.key, tc.val, err)
			}
			other := "RELAY_POLL_INTERVAL"
			if tc.key == other {
				other = "RELAY_DRAIN_TIMEOUT"
			}
			t.Setenv(other, "soon")
			_, err := parseConfig([]string{tc.flag, tc.good}, io.Discard)
			if err == nil || !strings.Contains(err.Error(), other) || strings.Contains(err.Error(), tc.key) {
				t.Errorf("with %s=soon too: %v, want only %s refused", other, err, other)
			}
		})
	}
}

// `-h` is usage, whatever the environment holds. It used to print the
// environment's error instead, and no usage at all.
func TestParseConfig_HelpIsUsageWhateverTheEnvironment(t *testing.T) {
	quiet(t)
	t.Setenv("RELAY_CAPACITY", "8x")
	for _, arg := range []string{"-h", "--help"} {
		var out strings.Builder
		_, err := parseConfig([]string{arg}, &out)
		if !errors.Is(err, flag.ErrHelp) {
			t.Errorf("%s with RELAY_CAPACITY=8x: %v, want flag.ErrHelp", arg, err)
		}
		if !strings.Contains(out.String(), "-capacity") {
			t.Errorf("%s printed no usage: %q", arg, out.String())
		}
	}
}

// A word that is not a flag is refused rather than ignored. `relay mitn …`
// with the environment of a deployment used to START A RELAY — everything
// after the misspelt subcommand silently dropped.
func TestParseConfig_RefusesAStrayArgument(t *testing.T) {
	quiet(t)
	_, err := parseConfig([]string{"mitn", "--dir", "/tmp/x"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "mitn") {
		t.Fatalf("a stray argument: %v, want a refusal naming it", err)
	}
	if _, err := parseConfig([]string{"--no-such-flag"}, io.Discard); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}
