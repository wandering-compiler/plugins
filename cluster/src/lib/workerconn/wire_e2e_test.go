package workerconn

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/tunnel"
)

// A message over gRPC's 4 MiB default crosses every hop, both ways.
//
// gRPC caps EACH MESSAGE, and streaming does not lift that: a stream is a
// sequence of messages and every one is checked. A codegen run's first message
// (the lock, the .po files, the e2e inputs) and every output file travel whole,
// so three servers and clients sitting at the default — the proxy, the relay's
// client over the tunnel, the worker's server on it — failed any of them at
// the relay while the caller itself allowed 256 MiB.
func TestTunnel_AMessageOverTheDefaultCapCrossesBothWays(t *testing.T) {
	r := standUp(t)
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// 6 MiB in one field: over the default, far under the cap.
	big := strings.Repeat("x", 6<<20)
	ctx, c := proxyClient(t, r, grant.Ticket)
	resp, err := c.ReserveTask(ctx, &pb.ReserveTaskReq{Label: big})
	if err != nil {
		t.Fatalf("a 6 MiB request/response did not cross the relay: %v", err)
	}
	if n := len(resp.GetReservation()); n != len(big) {
		t.Errorf("the worker echoed %d bytes, want %d", n, len(big))
	}
}

// blackhole sits between the worker and the relay's tunnel listener and, once
// frozen, forwards NOTHING while keeping both sockets open.
//
// That is the failure keepalive exists for, and it is not the one a test gets
// by closing a socket: a spot VM that vanishes sends no RST, so the peer's
// kernel keeps the connection ESTABLISHED and nothing ever reads EOF. Closing
// the socket would let the closed-socket path pass this test with keepalive
// switched off.
type blackhole struct {
	lis    net.Listener
	frozen chan struct{}
	done   chan struct{}
	once   sync.Once

	mu    sync.Mutex
	conns []net.Conn
}

func newBlackhole(t *testing.T, target string) *blackhole {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &blackhole{lis: lis, frozen: make(chan struct{}), done: make(chan struct{})}
	t.Cleanup(func() {
		close(b.done)
		_ = lis.Close()
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, c := range b.conns {
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
			b.mu.Lock()
			b.conns = append(b.conns, in, out)
			b.mu.Unlock()
			go b.pipe(in, out)
			go b.pipe(out, in)
		}
	}()
	return b
}

func (b *blackhole) addr() string { return b.lis.Addr().String() }

func (b *blackhole) freeze() { b.once.Do(func() { close(b.frozen) }) }

func (b *blackhole) pipe(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		select {
		case <-b.frozen:
			// Swallow it and park. Neither socket is closed and nothing more is
			// read, so neither end can learn anything from this side.
			<-b.done
			return
		default:
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

// carryACall sends one call through the proxy and the tunnel and back.
//
// The keepalive tests freeze the wire only AFTER this, because the rig returns
// as soon as the relay has registered the tunnel — right after TLS, before the
// HTTP/2 handshake has crossed. Freezing there tested the handshake instead of
// keepalive (keepalive only starts once the handshake is done), and under -race
// it reliably did: the relay's preface never reached the worker, whose server
// then waited out the handshake timeout. That case has a test of its own
// (TestTunnel_ARelayThatNeverSpeaksHTTP2EndsTheWorkersTunnel).
func carryACall(t *testing.T, r *rig) {
	t.Helper()
	grant, err := r.pool.Wait(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callThroughProxy(t, r, grant.Ticket); err != nil {
		t.Fatalf("setup: a call did not cross the tunnel before the freeze: %v", err)
	}
}

// The RELAY stops counting a worker whose tunnel went silent.
//
// Without keepalive on the relay's client side of the tunnel, a backend whose
// machine vanished stays selectable for as long as the kernel keeps the
// connection — tickets are granted against it and every call sent into it
// hangs until the CALLER's deadline.
//
// Run with the DEFAULTS, not test-sized timings: what is under test is that the
// relay switches keepalive on by itself, and a test that supplied its own would
// pass against a relay that never does. It costs one KeepaliveTime +
// KeepaliveTimeout of wall time, in parallel with the other wire tests.
func TestTunnel_ABlackHoledTunnelStopsBeingABackend(t *testing.T) {
	t.Parallel()
	var bh *blackhole
	r := standUpWith(t, rigOptions{
		via: func(addr string) string { bh = newBlackhole(t, addr); return bh.addr() },
	})
	if n := r.backends.Count(); n != 1 {
		t.Fatalf("setup: %d backends, want 1", n)
	}
	carryACall(t, r)
	bh.freeze()

	limit := tunnel.KeepaliveTime + tunnel.KeepaliveTimeout + 15*time.Second
	for deadline := time.After(limit); r.backends.Count() != 0; {
		select {
		case <-deadline:
			t.Fatalf("a black-holed tunnel is still a backend %s later — nothing on the relay's "+
				"side of the tunnel notices a peer that stopped answering", limit)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// And the WORKER gives up on a relay that went silent, so its loop dials a new
// tunnel instead of serving a dead one forever. Defaults again, for the same
// reason.
func TestTunnel_ABlackHoledRelayEndsTheWorkersTunnel(t *testing.T) {
	t.Parallel()
	var bh *blackhole
	done := make(chan error, 1)
	r := standUpWith(t, rigOptions{
		via:        func(addr string) string { bh = newBlackhole(t, addr); return bh.addr() },
		tunnelDone: done,
	})
	carryACall(t, r)
	bh.freeze()

	limit := tunnel.KeepaliveTime + tunnel.KeepaliveTimeout + 15*time.Second
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("ServeTunnel is still serving a black-holed tunnel %s later", limit)
	}
}

// An IDLE, healthy tunnel survives the relay's keepalive pings.
//
// The other half of switching keepalive on, and the one that bites quietly: a
// gRPC server's default enforcement allows one ping per five minutes and none
// without an active stream. A relay pinging every 30 s would collect three
// strikes and be sent GOAWAY "too_many_pings" — every idle worker's tunnel cut
// and redialled on a loop that reads like a flaky network. The worker side has
// to PERMIT what the relay side sends. The fourth ping is the one that trips it
// (the first sets the clock, three strikes are allowed past two), so at the
// 10 s floor this cannot be shown in less than ~40 s.
func TestTunnel_AnIdleTunnelSurvivesTheRelaysPings(t *testing.T) {
	t.Parallel()
	done := make(chan error, 1)
	r := standUpWith(t, rigOptions{
		relayDial: []grpc.DialOption{grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 10 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true,
		})},
		tunnelDone: done,
	})
	select {
	case err := <-done:
		t.Fatalf("an idle tunnel was torn down by its own keepalive: %v", err)
	case <-time.After(45 * time.Second):
	}
	if n := r.backends.Count(); n != 1 {
		t.Fatalf("%d backends after 45 s idle, want the worker still attached", n)
	}
}

// The keepalive the clients send has to be one the servers accept. Every hop
// takes both halves from one place, so this pins the relation instead of the
// numbers.
func TestKeepalive_ClientsPingNoFasterThanServersAllow(t *testing.T) {
	if tunnel.KeepaliveTime < tunnel.KeepaliveMinTime {
		t.Fatalf("clients ping every %s, servers allow one per %s — every idle connection "+
			"collects strikes and is cut with too_many_pings", tunnel.KeepaliveTime, tunnel.KeepaliveMinTime)
	}
}

// A relay that completes TLS and then never speaks HTTP/2 releases the
// worker's tunnel within tunnel.HandshakeTimeout.
//
// Keepalive cannot cover this: it starts only after the HTTP/2 handshake, so a
// peer lost between the TLS handshake and its connection preface was bounded
// by nothing but gRPC's 120 s default — the worker's ServeTunnel sat on a
// socket that would never speak for two minutes before dialling a replacement.
// Found by the black-hole test above, which froze the wire mid-handshake under
// -race and waited out exactly that.
func TestTunnel_ARelayThatNeverSpeaksHTTP2EndsTheWorkersTunnel(t *testing.T) {
	t.Parallel()
	relayID, err := identity.LoadOrCreateIdentity(t.TempDir(), "relay")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := tls.X509KeyPair(relayID.CertPEM, relayID.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t)
	dir, _ := enrolledDir(t, ca, time.Hour)

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lis := tls.NewListener(raw, &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
	})
	t.Cleanup(func() { _ = lis.Close() })
	handshook := make(chan net.Conn, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		// TLS completes — so this is not a dial failure — and then nothing:
		// no preface, no SETTINGS, no RST. The socket is held open.
		if err := c.(*tls.Conn).Handshake(); err != nil {
			_ = c.Close()
			return
		}
		handshook <- c
	}()

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		done <- ServeTunnel(t.Context(), Config{
			TunnelAddress:    lis.Addr().String(),
			RelayFingerprint: relayID.Fingerprint,
			IdentityDir:      dir,
		}, func(s *grpc.Server) { pb.RegisterClusterServiceServer(s, &fakeWork{}) })
	}()
	select {
	case c := <-handshook:
		t.Cleanup(func() { _ = c.Close() })
	case err := <-done:
		t.Fatalf("ServeTunnel ended before TLS completed, so this is not the case under test: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("setup: the TLS handshake never completed")
	}

	limit := tunnel.HandshakeTimeout + 10*time.Second
	select {
	case <-done:
		if took := time.Since(start); took < tunnel.HandshakeTimeout/2 {
			t.Errorf("ServeTunnel gave up after %s — sooner than the handshake bound allows a slow peer", took)
		}
	case <-time.After(limit):
		t.Fatalf("ServeTunnel is still waiting on a relay that never spoke HTTP/2 %s later", limit)
	}
}
