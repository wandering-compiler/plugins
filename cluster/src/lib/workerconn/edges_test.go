package workerconn

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

// What a worker logs is what an operator reads; every state has its word, and
// one the package does not know is not mistaken for "admitted".
func TestState_String(t *testing.T) {
	for s, want := range map[State]string{
		Admitted:     "admitted",
		Banned:       "banned",
		Disconnected: "disconnected",
		Renewed:      "certificate renewed",
		State(99):    "disconnected",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d) = %q, want %q", s, got, want)
		}
	}
}

// The worker's answer reaches the relay as the matching wire value; anything
// unknown is READY only because Ready is the zero value of the Go type.
func TestReadiness_Wire(t *testing.T) {
	for r, want := range map[Readiness]workerpb.WorkerStatus_Readiness{
		Ready:     workerpb.WorkerStatus_READY,
		Draining:  workerpb.WorkerStatus_DRAINING,
		Unhealthy: workerpb.WorkerStatus_UNHEALTHY,
	} {
		if got := r.proto(); got != want {
			t.Errorf("%d → %v, want %v", r, got, want)
		}
	}
}

// Every required field is refused BEFORE anything is dialled or written, with
// the field named — the alternative is a worker that starts, dials nowhere or
// trusts anything, and looks healthy in its own log.
func TestRun_RefusesAnIncompleteConfig(t *testing.T) {
	full := func() Config {
		return Config{RelayAddress: "relay.example.com:13446", RelayFingerprint: "ab", IdentityDir: t.TempDir(), Slots: 1}
	}
	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"no relay address", func(c *Config) { c.RelayAddress = "  " }, "RelayAddress"},
		{"no relay pin", func(c *Config) { c.RelayFingerprint = "" }, "RelayFingerprint"},
		{"no identity dir", func(c *Config) { c.IdentityDir = "" }, "IdentityDir"},
		{"no slots", func(c *Config) { c.Slots = 0 }, "Slots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full()
			tc.edit(&cfg)
			err := Run(t.Context(), cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run = %v, want a refusal naming %s", err, tc.want)
			}
			if cfg.IdentityDir != "" {
				if entries, _ := os.ReadDir(cfg.IdentityDir); len(entries) != 0 {
					t.Errorf("a refused config still wrote %d file(s) into the identity directory", len(entries))
				}
			}
		})
	}
	if err := EnsureEnrolled(t.Context(), Config{}); err == nil {
		t.Error("EnsureEnrolled accepted an empty config")
	}
}

// ServeTunnel refuses what would only fail at the relay, each with the reason:
// nothing to serve, nowhere to dial, nothing to pin, no certificate to present
// or one that has run out.
func TestServeTunnel_Refusals(t *testing.T) {
	ca := newCA(t)
	valid, _ := enrolledDir(t, ca, time.Hour)
	expired, _ := enrolledDir(t, ca, time.Nanosecond)
	keyOnly := t.TempDir()
	if _, err := identity.LoadOrCreateWorkerKey(keyOnly); err != nil {
		t.Fatal(err)
	}
	register := func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, &fakeWork{}) }
	cfg := func(dir string) Config {
		return Config{TunnelAddress: "relay.example.com:13445", RelayFingerprint: "ab", IdentityDir: dir}
	}

	for _, tc := range []struct {
		name     string
		cfg      Config
		register func(*grpc.Server)
		check    func(error) bool
	}{
		{"nothing to serve", cfg(valid), nil, func(err error) bool { return strings.Contains(err.Error(), "something to serve") }},
		{"no tunnel address", func() Config { c := cfg(valid); c.TunnelAddress = ""; return c }(), register,
			func(err error) bool { return strings.Contains(err.Error(), "TunnelAddress") }},
		{"no relay pin", func() Config { c := cfg(valid); c.RelayFingerprint = " "; return c }(), register,
			func(err error) bool { return strings.Contains(err.Error(), "RelayFingerprint") }},
		{"not enrolled yet", cfg(keyOnly), register, func(err error) bool { return errors.Is(err, identity.ErrNoCertificate) }},
		{"certificate expired", cfg(expired), register, func(err error) bool { return errors.Is(err, ErrNeedsRegistration) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A short context: a refusal must come before any dial, and a dial
			// to the invented address would otherwise just hang until it.
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := ServeTunnel(ctx, tc.cfg, tc.register)
			if err == nil || !tc.check(err) {
				t.Fatalf("ServeTunnel = %v", err)
			}
		})
	}
}

// Nothing listening on the tunnel address is a dial error the worker's loop
// can back off on, not a hang.
func TestServeTunnel_NothingListeningIsADialError(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	dir, _ := enrolledDir(t, newCA(t), time.Hour)
	err = ServeTunnel(t.Context(), Config{TunnelAddress: addr, RelayFingerprint: "ab", IdentityDir: dir},
		func(s *grpc.Server) {})
	if err == nil || !strings.Contains(err.Error(), "dialling the tunnel") {
		t.Fatalf("ServeTunnel = %v, want a dial error", err)
	}
}

// Ending the worker's context ends ServeTunnel with that context's error, and
// the relay stops counting the tunnel — the shutdown path a worker takes on
// SIGTERM, as opposed to the connection dropping.
func TestServeTunnel_CancellationEndsItWithTheContextsError(t *testing.T) {
	done := make(chan error, 1)
	r := standUpWith(t, rigOptions{tunnelDone: done})
	carryACall(t, r)
	r.stopWorker()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeTunnel = %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeTunnel did not return after its context ended")
	}
	for deadline := time.After(10 * time.Second); r.backends.Count() != 0; {
		select {
		case <-deadline:
			t.Fatal("the relay still counts a tunnel whose worker shut down")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// The worker's own readiness reaches the relay as it changes: draining or
// unhealthy takes its slots out of the relay's capacity without dropping the
// stream, and recovering puts them back.
func TestAttach_ReadinessChangesReachTheRelay(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	var now atomic.Int32 // a Readiness
	cfg := r.config(dir, "")
	cfg.Slots = 3
	cfg.Readiness = func() Readiness { return Readiness(now.Load()) }
	cfg.ReadinessInterval = 10 * time.Millisecond
	states, _, cancel := runWorker(t, cfg)
	defer cancel()
	awaitState(t, states, Admitted)

	// Capacity is summed over workers that also have a tunnel.
	tun, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tun.Close() })
	r.backends.Add(id, tun)

	awaitCapacity := func(want int) {
		t.Helper()
		for deadline := time.After(5 * time.Second); r.backends.Capacity() != want; {
			select {
			case <-deadline:
				t.Fatalf("relay capacity = %d, want %d", r.backends.Capacity(), want)
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	awaitCapacity(3)
	now.Store(int32(Draining))
	awaitCapacity(0)
	now.Store(int32(Unhealthy))
	now.Store(int32(Ready))
	awaitCapacity(3)
	now.Store(int32(Unhealthy))
	awaitCapacity(0)
	// Still attached throughout: readiness is not a reconnect.
	select {
	case s := <-states:
		if s != Admitted {
			t.Errorf("readiness changes cost the worker its attachment (%s)", s)
		}
	default:
	}
}

// A relay that is briefly down must not cost the worker its identity: renewal
// is retried, and the certificate it holds is left as it was.
func TestKeepRenewed_ARelayThatIsDownIsRetriedAndTheCertificateKept(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()

	dir, _ := enrolledDir(t, newCA(t), time.Hour)
	before, err := os.ReadFile(filepath.Join(dir, "worker.crt"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{RelayAddress: addr, RelayFingerprint: "ab", IdentityDir: dir, Name: "w",
		RenewBefore: 2 * time.Hour, RetryInterval: 10 * time.Millisecond}

	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	failures := 0
	enough := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepRenewed(ctx, cfg, func(time.Time) { t.Error("renewed against a relay that is not there") },
			func(error) {
				mu.Lock()
				defer mu.Unlock()
				if failures++; failures == 3 {
					close(enough)
				}
			})
	}()
	select {
	case <-enough:
	case <-done:
		t.Fatal("renewal gave up on a relay that is merely unreachable")
	case <-time.After(30 * time.Second):
		t.Fatal("renewal was not retried")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("keepRenewed did not stop when its context ended")
	}
	after, err := os.ReadFile(filepath.Join(dir, "worker.crt"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the certificate the worker holds changed after failed renewals (%v)", err)
	}
}

// A ban ends the renewal loop by itself — no retry can fix it — and says why.
func TestKeepRenewed_ABanStopsTheLoop(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Hour)
	r.reg.SetBanned([]string{id})
	cfg := r.config(dir, "")
	cfg.RenewBefore = 2 * time.Hour // due now

	var got error
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepRenewed(t.Context(), cfg, func(time.Time) { t.Error("a banned worker renewed") },
			func(err error) { got = err })
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the renewal loop kept retrying a ban")
	}
	if refusal.ReasonOf(got) != refusal.WorkerBanned {
		t.Errorf("reported %v, want the %s refusal", got, refusal.WorkerBanned)
	}
}

// With no certificate there is nothing to renew: reported, and the loop ends
// rather than spinning.
func TestKeepRenewed_NoCertificateEndsTheLoop(t *testing.T) {
	dir := t.TempDir()
	if _, err := identity.LoadOrCreateWorkerKey(dir); err != nil {
		t.Fatal(err)
	}
	var got error
	keepRenewed(t.Context(), Config{IdentityDir: dir}, func(time.Time) {}, func(err error) { got = err })
	if !errors.Is(got, identity.ErrNoCertificate) {
		t.Fatalf("reported %v, want ErrNoCertificate", got)
	}
}

// A worker whose certificate ran out while it was stopped re-enrols with a new
// code — for the SAME key, so it comes back as itself, not as a stranger.
func TestEnsureEnrolled_AnExpiredCertificateReEnrolsKeepingTheKey(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, time.Nanosecond)

	if err := EnsureEnrolled(t.Context(), r.config(dir, "")); !errors.Is(err, ErrNeedsRegistration) {
		t.Fatalf("expired and no code: %v, want ErrNeedsRegistration", err)
	}
	if err := EnsureEnrolled(t.Context(), r.config(dir, r.code(t))); err != nil {
		t.Fatalf("re-enrolling: %v", err)
	}
	_, leaf, err := identity.LoadWorkerCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !time.Now().Before(leaf.NotAfter) {
		t.Error("the stored certificate is still the expired one")
	}
	if identity.WorkerID(leaf) != id {
		t.Error("re-enrolling changed the worker's key — its registry row and any ban no longer apply")
	}
}

// A certificate file that is there but unreadable is REPORTED. Treating it as
// "not enrolled" would spend the code in the environment on every start and
// paper over a damaged disk.
func TestEnsureEnrolled_ACorruptCertificateIsReportedNotReEnrolled(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, _ := enrolledDir(t, r.ca, time.Hour)
	if err := os.WriteFile(filepath.Join(dir, "worker.crt"), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	code := r.code(t)
	if err := EnsureEnrolled(t.Context(), r.config(dir, code)); err == nil {
		t.Fatal("a corrupt certificate was not reported")
	}
	if r.codes.Outstanding() != 1 {
		t.Error("the code was spent over a corrupt certificate")
	}
}

// A worker that cannot renew — it is banned — runs until its certificate
// expires and then STOPS with ErrNeedsRegistration: an operator has to act,
// and a loop failing handshakes forever would hide that.
func TestRun_StopsOnceTheCertificateRunsOutUnrenewed(t *testing.T) {
	r := serveAttach(t, time.Hour)
	dir, id := enrolledDir(t, r.ca, 2*time.Second)
	r.reg.SetBanned([]string{id})
	states, done, cancel := runWorker(t, r.config(dir, ""))
	defer cancel()
	awaitState(t, states, Banned)
	select {
	case err := <-done:
		if !errors.Is(err, ErrNeedsRegistration) {
			t.Fatalf("Run = %v, want ErrNeedsRegistration", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run kept going on a certificate that ran out and could not be renewed")
	}
}

// gatedListener refuses connections until opened — a relay that is down, then
// comes up on the same address.
type gatedListener struct {
	net.Listener
	open atomic.Bool
}

func (l *gatedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil || l.open.Load() {
			return c, err
		}
		_ = c.Close()
	}
}

// A relay that is unreachable at first start is waited for: the worker reports
// itself disconnected, keeps its code, and enrols and attaches once the relay
// is up — a deployment that starts workers before the relay must not need a
// second round of codes.
func TestRun_WaitsForAnUnreachableRelayToEnrol(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate := &gatedListener{Listener: raw}
	r := serveAttachOn(t, time.Hour, gate)
	states, done, cancel := runWorker(t, r.config(t.TempDir(), r.code(t)))
	defer cancel()

	awaitState(t, states, Disconnected)
	select {
	case err := <-done:
		t.Fatalf("Run gave up on an unreachable relay: %v", err)
	default:
	}
	if r.codes.Outstanding() != 1 {
		t.Fatal("the code was spent while the relay was unreachable")
	}
	gate.open.Store(true)
	awaitState(t, states, Admitted)
	if n := len(r.reg.Known()); n != 1 {
		t.Errorf("the relay knows %d workers after the delayed enrolment, want 1", n)
	}
}
