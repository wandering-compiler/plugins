package relayserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
)

// tunnelRig is the relay's TUNNEL listener on real TCP. clientAuth is what the
// listener's TLS asks of a worker — production REQUIRES and verifies; the
// other settings exist to prove acceptTunnel fails closed on its own.
type tunnelRig struct {
	*workerRig // the relay identity, CA, registry and fleet
	lis        net.Listener
	errs       chan error
	served     chan error
}

func serveTunnels(t *testing.T, clientAuth tls.ClientAuthType, plain bool) *tunnelRig {
	t.Helper()
	wr := serveWorkers(t)
	crt, err := tls.X509KeyPair(wr.relay.CertPEM, wr.relay.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lis := raw
	if !plain {
		lis = tls.NewListener(raw, &tls.Config{
			Certificates: []tls.Certificate{crt},
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   clientAuth,
			ClientCAs:    wr.ca.Pool(),
		})
	}
	r := &tunnelRig{workerRig: wr, lis: lis, errs: make(chan error, 8), served: make(chan error, 1)}
	go func() {
		r.served <- ServeTunnels(lis, wr.reg, wr.backends, func(err error) { r.errs <- err })
	}()
	t.Cleanup(func() { _ = lis.Close() })
	return r
}

// dialTunnel opens a worker's tunnel as w (nil: no certificate).
func (r *tunnelRig) dialTunnel(t *testing.T, w *worker) *tls.Conn {
	t.Helper()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// #nosec G402 -- this test is about the RELAY's side of the tunnel.
		InsecureSkipVerify: true,
	}
	if w != nil {
		cfg.Certificates = []tls.Certificate{w.cert}
	}
	c, err := tls.Dial("tcp", r.lis.Addr().String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (r *tunnelRig) awaitRefusal(t *testing.T, want string) {
	t.Helper()
	select {
	case err := <-r.errs:
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refused with %v, want it to say %q", err, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the tunnel was never refused (want %q)", want)
	}
}

// awaitClosed reads until the relay hangs up on c.
func awaitClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("the relay kept a refused tunnel open")
		}
		return
	}
}

// A listener that was never wrapped in TLS turns every tunnel away: a tunnel
// with no identity would take work from anyone who found the port.
func TestServeTunnels_APlainConnectionIsRefusedAndClosed(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, true)
	c, err := net.Dial("tcp", r.lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	r.awaitRefusal(t, "without TLS")
	awaitClosed(t, c)
	if r.backends.Count() != 0 {
		t.Error("a plaintext connection became a backend")
	}
}

// A tunnel listener built WITHOUT the verify-client-certificate rule must
// still fail closed: no certificate, or one nothing verified, is no identity.
func TestServeTunnels_FailsClosedOnAListenerThatDoesNotVerify(t *testing.T) {
	for _, tc := range []struct {
		name    string
		auth    tls.ClientAuthType
		present bool
	}{
		{"no certificate asked for", tls.NoClientCert, true},
		{"certificate requested but not verified", tls.RequestClientCert, true},
		{"no certificate presented", tls.VerifyClientCertIfGiven, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := serveTunnels(t, tc.auth, false)
			var w *worker
			if tc.present {
				iw := r.issue(t, time.Hour)
				w = &iw
			}
			c := r.dialTunnel(t, w)
			r.awaitRefusal(t, "no verified certificate")
			awaitClosed(t, c)
			if r.backends.Count() != 0 {
				t.Error("an unverified tunnel became a backend")
			}
		})
	}
}

// A ban taken after attach bites at the tunnel too.
func TestServeTunnels_ABannedWorkersTunnelIsRefused(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, false)
	w := r.issue(t, time.Hour)
	r.reg.SetBanned([]string{w.id})
	c := r.dialTunnel(t, &w)
	r.awaitRefusal(t, "banned worker "+w.id)
	awaitClosed(t, c)
	if r.backends.Count() != 0 {
		t.Error("a banned worker's tunnel became a backend")
	}
}

// An admitted worker's tunnel becomes a backend under its KEY's fingerprint —
// carrying the capacity it announced — and leaves when the worker hangs up.
func TestServeTunnels_AnAdmittedTunnelIsABackendUntilItCloses(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, false)
	w := r.issue(t, time.Hour)
	// The worker announced first (its attach stream); the tunnel completes it.
	r.backends.SetProfile(w.id, r.backends.NewAttachment(), 2, true)

	c := r.dialTunnel(t, &w)
	// The worker SERVES on the socket it dialled.
	srv := grpc.NewServer(tunnel.WorkServerOptions()...)
	go func() { _ = srv.Serve(tunnel.NewSingleConnListener(c)) }()
	defer srv.Stop()

	r.awaitCapacity(t, 2)
	if n := r.backends.Count(); n != 1 {
		t.Fatalf("%d backends, want the one worker", n)
	}
	// The worker goes away: its server stops AND its socket closes. Stop
	// alone is not a hang-up when it wins the race with Serve — Serve then
	// returns without ever taking the connection, nothing closes it, and the
	// relay's side sits in Connecting waiting for a preface (about 1 run in
	// 30 under -race, until gRPC's 20 s connect timeout).
	srv.Stop()
	_ = c.Close()
	r.awaitCapacity(t, 0)
	if n := r.backends.Count(); n != 0 {
		t.Errorf("%d backends after the worker hung up, want 0", n)
	}
}

// ServeTunnels ends when its listener is closed, so a relay shutting down is
// not left with an accept loop running.
func TestServeTunnels_ReturnsWhenTheListenerCloses(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, false)
	_ = r.lis.Close()
	select {
	case err := <-r.served:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("ServeTunnels returned %v, want the listener's close", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeTunnels kept running on a closed listener")
	}
}

// No error sink is a valid configuration: a refusal is then silent, but the
// refused connection is still closed and nothing panics.
func TestServeTunnels_NilOnErrorStillClosesARefusedTunnel(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	go func() { _ = ServeTunnels(raw, workeradmit.New(), NewBackends(), nil) }()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	awaitClosed(t, c)
}

// --- TicketPicker: the proxy's admission ---

func pickWith(pick tunnel.Picker, ticket string) (tunnel.Backend, error) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(TicketHeader, ticket))
	if ticket == "" {
		ctx = metadata.NewIncomingContext(context.Background(), metadata.MD{})
	}
	return pick(ctx, "/acme.Work/Run")
}

func grantTicket(t *testing.T, pool *relaycore.Pool) string {
	t.Helper()
	g, err := pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return g.Ticket
}

// No ticket is Unauthenticated with the reason that tells the caller to ask
// the control plane for one.
func TestTicketPicker_NoTicketIsRefused(t *testing.T) {
	pick := TicketPicker(poolWith(t, 1), NewBackends(), workeradmit.New())
	_, err := pickWith(pick, "")
	wantRefusal(t, err, codes.Unauthenticated, refusal.TicketMissing)
}

// A ticket that was never minted, or already spent, is refused without saying
// which — and spending is single use.
func TestTicketPicker_AnInventedOrSpentTicketIsRefused(t *testing.T) {
	pool := poolWith(t, 2)
	b := NewBackends()
	attach(t, b, "w", 2, true)
	pick := TicketPicker(pool, b, workeradmit.New())

	_, err := pickWith(pick, "invented")
	wantRefusal(t, err, codes.PermissionDenied, refusal.TicketNotRedeemable)

	ticket := grantTicket(t, pool)
	be, err := pickWith(pick, ticket)
	if err != nil {
		t.Fatalf("a fresh ticket was refused: %v", err)
	}
	defer be.Release()
	_, err = pickWith(pick, ticket)
	wantRefusal(t, err, codes.PermissionDenied, refusal.TicketNotRedeemable)
}

// A valid ticket with nobody to run it is NO_WORKER, and the claimed slot goes
// back AT ONCE — otherwise every such call shrinks the relay until a restart.
func TestTicketPicker_NoWorkerReturnsTheSlot(t *testing.T) {
	pool := poolWith(t, 1)
	pick := TicketPicker(pool, NewBackends(), workeradmit.New())
	ticket := grantTicket(t, pool)
	_, err := pickWith(pick, ticket)
	wantRefusal(t, err, codes.Unavailable, refusal.NoWorker)
	if st := pool.Stats(); st.Held() != 0 {
		t.Errorf("pool = %+v after NO_WORKER, want the slot back", st)
	}
}

// A banned worker is skipped at the proxy even with its tunnel up.
func TestTicketPicker_SkipsABannedWorker(t *testing.T) {
	pool := poolWith(t, 1)
	b := NewBackends()
	attach(t, b, "w", 1, true)
	reg := workeradmit.New()
	reg.SetBanned([]string{"w"})
	pick := TicketPicker(pool, b, reg)
	_, err := pickWith(pick, grantTicket(t, pool))
	wantRefusal(t, err, codes.Unavailable, refusal.NoWorker)
}

// Release gives back BOTH books — the pool's slot and the worker's — and only
// once, however many times the proxy's unwinding calls it.
func TestTicketPicker_ReleaseIsExactlyOnce(t *testing.T) {
	pool := poolWith(t, 2)
	b := NewBackends()
	attach(t, b, "w", 2, true)
	pick := TicketPicker(pool, b, nil) // nil registry: everyone admitted

	one, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	two, err := pickWith(pick, grantTicket(t, pool))
	if err != nil {
		t.Fatal(err)
	}
	if one.Conn == nil || two.Conn == nil {
		t.Fatal("a backend came back without a connection")
	}
	one.Release()
	one.Release()
	if st := pool.Stats(); st.InUse != 1 {
		t.Errorf("pool in use = %d after one call released twice, want 1 — a double release freed the other call's slot", st.InUse)
	}
	// The worker likewise has exactly one slot free, not two.
	if _, _, _, err := b.take(nil); err != nil {
		t.Fatalf("the released slot on the worker was not freed: %v", err)
	}
	if _, _, _, err := b.take(nil); err == nil {
		t.Error("the worker had two free slots after one release called twice")
	}
	two.Release()
}

// A connection that never completes the TLS handshake is refused and closed —
// a port scanner must not hold a goroutine or a backend slot.
func TestServeTunnels_AFailedHandshakeIsRefused(t *testing.T) {
	r := serveTunnels(t, tls.RequireAndVerifyClientCert, false)
	c, err := net.Dial("tcp", r.lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	r.awaitRefusal(t, "tunnel handshake")
	awaitClosed(t, c)
}
