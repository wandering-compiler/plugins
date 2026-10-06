package workerconn

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// attachRig is the relay's worker-facing half on a REAL TCP listener with REAL
// TLS, wired as cmd/relay wires it: verify a client certificate against the
// relay's CA if one is presented, attach and enrolment on the same server.
//
// Not bufconn, and not an injected identity: the identity this whole model
// rests on is carried by the handshake, so a test that supplied it some other
// way would prove the bookkeeping and never the thing being trusted.
type attachRig struct {
	addr     string
	relayFP  string
	ca       *identity.CA
	codes    *regcode.Store
	reg      *workeradmit.Registry
	backends *relayserver.Backends
}

func serveAttach(t *testing.T, lifetime time.Duration) *attachRig {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveAttachOn(t, lifetime, lis)
}

// serveAttachOn is serveAttach on a listener the test controls — one that can
// refuse connections for a while, say.
func serveAttachOn(t *testing.T, lifetime time.Duration, lis net.Listener) *attachRig {
	t.Helper()
	relayID, err := identity.LoadOrCreateIdentity(t.TempDir(), "relay")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := tls.X509KeyPair(relayID.CertPEM, relayID.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	r := &attachRig{relayFP: relayID.Fingerprint, ca: newCA(t), reg: workeradmit.New(), backends: relayserver.NewBackends()}
	r.codes, err = regcode.New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    r.ca.Pool(),
	})))
	workerpb.RegisterWorkerAttachServer(srv, &relayserver.WorkerServer{
		Workers:      r.reg,
		Backends:     r.backends,
		PollInterval: 20 * time.Millisecond,
	})
	workerpb.RegisterWorkerEnrollmentServer(srv, &relayserver.Enrollment{
		CA: r.ca, Codes: r.codes, Workers: r.reg, Lifetime: lifetime,
	})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	r.addr = lis.Addr().String()
	return r
}

func (r *attachRig) code(t *testing.T) string {
	t.Helper()
	c, _, err := r.codes.Issue()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *attachRig) config(dir, code string) Config {
	return Config{
		RelayAddress:     r.addr,
		RelayFingerprint: r.relayFP,
		IdentityDir:      dir,
		RegistrationCode: code,
		Name:             "vps-1",
		DeviceID:         "dev-1",
		Slots:            1,
		RetryInterval:    20 * time.Millisecond,
		// A ban is retried slowly in production; here the reconnect is the
		// thing a test watches.
		BannedRetryInterval: 20 * time.Millisecond,
	}
}

// runWorker runs the worker; its states arrive on the channel, and what Run
// returned on the other.
func runWorker(t *testing.T, cfg Config) (<-chan State, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	states := make(chan State, 64)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, func(s State) {
			select {
			case states <- s:
			default:
			}
		})
	}()
	return states, done, cancel
}

func awaitState(t *testing.T, states <-chan State, want State) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-states:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("never reached %q", want)
		}
	}
}

// The whole join, end to end: a worker with nothing but a registration code
// generates its key, enrols, and attaches — admitted at once, because the code
// WAS the admission — and the relay knows it by its key's fingerprint, taken
// from the handshake.
func TestRun_EnrolsWithACodeThenAttaches(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir := t.TempDir()
	states, _, cancel := runWorker(t, r.config(dir, r.code(t)))
	defer cancel()

	awaitState(t, states, Admitted)

	_, leaf, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatalf("no certificate was stored after enrolling: %v", err)
	}
	if err := r.ca.Verify(leaf, time.Now()); err != nil {
		t.Errorf("the stored certificate is not the relay CA's: %v", err)
	}
	known := r.reg.Known()
	if len(known) != 1 || known[0].ID != identity.WorkerID(leaf) || known[0].Name != "vps-1" || known[0].DeviceID != "dev-1" {
		t.Errorf("the relay knows %+v, want this worker under its key's fingerprint with its claims", known)
	}
}

// A restart reuses the certificate it already holds: no code needed, and a
// code still in the environment is NOT spent again.
func TestRun_ARestartReusesTheCertificate(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir := t.TempDir()
	states, _, cancel := runWorker(t, r.config(dir, r.code(t)))
	awaitState(t, states, Admitted)
	cancel()

	spare := r.code(t)
	states, _, cancel = runWorker(t, r.config(dir, spare))
	defer cancel()
	awaitState(t, states, Admitted)
	if err := r.codes.Redeem(spare); err != nil {
		t.Errorf("a restart spent the code although it held a valid certificate: %v", err)
	}
}

// No certificate and no code is an operator's problem, and Run says so and
// STOPS — a loop retrying the impossible would look like a flaky network.
func TestRun_NoCertificateAndNoCodeStops(t *testing.T) {
	r := serveAttach(t, time.Hour)
	_, done, cancel := runWorker(t, r.config(t.TempDir(), ""))
	defer cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNeedsRegistration) {
			t.Fatalf("Run = %v, want ErrNeedsRegistration", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept going with no way to get a certificate")
	}
}

// A code the relay refuses stops Run too, with the reason.
func TestRun_ARefusedCodeStops(t *testing.T) {
	r := serveAttach(t, time.Hour)
	_, done, cancel := runWorker(t, r.config(t.TempDir(), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"))
	defer cancel()
	select {
	case err := <-done:
		if refusal.ReasonOf(err) != refusal.RegistrationCodeInvalid {
			t.Fatalf("Run = %v, want the %s refusal", err, refusal.RegistrationCodeInvalid)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept retrying a code the relay refused")
	}
}

// A banned worker is refused, and the refusal survives reconnection — which
// is what makes a ban a revocation rather than a note.
func TestAttach_BannedIsRefusedAndStaysRefused(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	r.reg.SetBanned([]string{id})

	states, _, cancel := runWorker(t, r.config(dir, ""))
	defer cancel()
	// Refused at the door — never admitted first and thrown out a tick later,
	// which would credit its slots to the relay in between.
	deadline := time.After(10 * time.Second)
	for refused := 0; refused < 2; {
		select {
		case s := <-states:
			switch s {
			case Admitted:
				t.Fatal("a banned worker was admitted")
			case Banned:
				refused++
			}
		case <-deadline:
			t.Fatal("the banned worker was not refused twice (connect and reconnect)")
		}
	}
	if n := r.backends.Capacity(); n != 0 {
		t.Errorf("a banned worker contributes capacity %d", n)
	}
}

// A ban must bite a worker that is ALREADY attached: it is told, and its
// stream ends, without waiting for it to reconnect.
func TestAttach_ABanWhileAttachedEndsTheStream(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	states, _, cancel := runWorker(t, r.config(dir, ""))
	defer cancel()
	awaitState(t, states, Admitted)

	r.reg.SetBanned([]string{id})
	awaitState(t, states, Banned)
}

// A worker pins the relay. An impostor answering on the address — with a
// perfectly valid certificate of its own — must not receive this machine's
// registration code, its certificate request, or later its work.
func TestRun_RefusesARelayThatIsNotThePinnedOne(t *testing.T) {
	r := serveAttach(t, time.Hour)
	other, err := identity.LoadOrCreateIdentity(t.TempDir(), "relay")
	if err != nil {
		t.Fatal(err)
	}
	cfg := r.config(t.TempDir(), r.code(t))
	cfg.RelayFingerprint = other.Fingerprint
	states, _, cancel := runWorker(t, cfg)
	defer cancel()

	awaitState(t, states, Disconnected)
	if n := len(r.reg.Known()); n != 0 {
		t.Errorf("the worker talked to a relay it should have refused (%d known there)", n)
	}
	if r.codes.Outstanding() != 1 {
		t.Error("the code was spent at a relay the worker does not trust")
	}
}

// A certificate from another relay's CA does not get a worker in, whatever it
// claims: the handshake itself refuses it.
func TestAttach_AnotherRelaysCertificateIsRefused(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, _ := enrolledDir(t, newCA(t), time.Hour)
	states, _, cancel := runWorker(t, r.config(dir, ""))
	defer cancel()
	awaitState(t, states, Disconnected)
	if n := len(r.reg.Known()); n != 0 {
		t.Errorf("a foreign certificate got as far as being known (%d)", n)
	}
}

// Without a pin the worker would hand its work to whoever answered.
func TestRun_RefusesWithNoRelayPin(t *testing.T) {
	err := Run(t.Context(), Config{RelayAddress: "x:1", IdentityDir: t.TempDir(), Slots: 1}, nil)
	if err == nil {
		t.Fatal("a worker with no relay fingerprint started anyway")
	}
}

// The certificate is renewed before it runs out — for the SAME key, so the
// worker's identity survives, and the new certificate is what it holds next.
func TestRun_RenewsBeforeExpiryKeepingTheIdentity(t *testing.T) {
	r := serveAttach(t, 4*time.Second)
	dir := t.TempDir()
	cfg := r.config(dir, r.code(t))
	cfg.RenewBefore = 3 * time.Second // renew about a second after enrolling
	states, _, cancel := runWorker(t, cfg)
	defer cancel()
	awaitState(t, states, Admitted)
	_, first, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}

	awaitState(t, states, Renewed)
	_, second, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !second.NotAfter.After(first.NotAfter) {
		t.Errorf("the renewed certificate ends %v, not after the first's %v", second.NotAfter, first.NotAfter)
	}
	if identity.WorkerID(second) != identity.WorkerID(first) {
		t.Error("renewal changed the worker's identity — its registry row and any ban would be orphaned")
	}
}

// A banned worker cannot renew: the loop stops, and the certificate is left to
// run out.
func TestRun_ABannedWorkerCannotRenew(t *testing.T) {
	r := serveAttach(t, 4*time.Second)
	dir, id := enrolledDir(t, r.ca, 4*time.Second)
	r.reg.SetBanned([]string{id})
	cfg := r.config(dir, "")
	err := renew(t.Context(), cfg)
	if refusal.ReasonOf(err) != refusal.WorkerBanned {
		t.Fatalf("renewing while banned: %v, want %s", err, refusal.WorkerBanned)
	}
}

// A worker that comes up ALREADY draining is never briefly counted as ready.
//
// The relay credits a worker from the moment it announces. Readiness that
// arrived only with the first status left a window one tick wide — a second by
// default — in which a machine that was already wedged got work. Carrying the
// answer in the announcement closes it, and a window is exactly the kind of
// thing a test has to hold open rather than race against: the readiness
// reporter here is set to a minute, so nothing but the announcement can have
// told the relay anything.
func TestAttach_AWorkerThatStartsDrainingIsNeverCountedReady(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	cfg := r.config(dir, "")
	cfg.Slots = 4
	cfg.Readiness = func() Readiness { return Draining }
	cfg.ReadinessInterval = time.Minute
	states, _, cancel := runWorker(t, cfg)
	defer cancel()

	// Proof the attachment actually happened — otherwise a capacity that never
	// moves proves nothing.
	awaitState(t, states, Admitted)

	// A tunnel for this fingerprint, because capacity is summed over workers
	// that HAVE one — without it this test could not observe a capacity at all
	// and would pass whatever the announcement said.
	tun, err := grpc.NewClient("passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	r.backends.Add(id, tun)

	// And now the claim: attached, and still contributing nothing.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := r.backends.Capacity(); got != 0 {
			t.Fatalf("capacity reached %d for a worker that announced while draining", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
