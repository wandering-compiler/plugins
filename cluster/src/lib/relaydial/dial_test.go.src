package relaydial

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// pair is one self-signed identity, in every shape a test needs.
type pair struct {
	certPEM, keyPEM []byte
	tls             tls.Certificate
	leaf            *x509.Certificate
	fp              string
}

func newPair(t *testing.T, cn string) pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := pair{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
	if p.tls, err = tls.X509KeyPair(p.certPEM, p.keyPEM); err != nil {
		t.Fatal(err)
	}
	if p.leaf, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	p.fp = Fingerprint(p.leaf)
	return p
}

// relay answers RelayStats and remembers which client certificate it saw.
type relay struct {
	pb.UnimplementedClusterServiceServer
	mu   sync.Mutex
	seen []string
}

func (r *relay) RelayStats(ctx context.Context, _ *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			r.mu.Lock()
			r.seen = append(r.seen, Fingerprint(ti.State.PeerCertificates[0]))
			r.mu.Unlock()
		}
	}
	return &pb.RelayStatsResp{Capacity: 3}, nil
}

// serveRelay is a relay's management server on real TCP with real TLS: it
// presents `id` and requires a client certificate, as cmd/relay does.
func serveRelay(t *testing.T, id pair) (string, *relay) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{id.tls},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
	})))
	pb.RegisterClusterServiceServer(srv, r)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), r
}

func stats(t *testing.T, cc *grpc.ClientConn) (*pb.RelayStatsResp, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	return pb.NewClusterServiceClient(cc).RelayStats(ctx, &pb.RelayStatsReq{})
}

// The relay the registry pins is reached, and it sees the control plane's
// certificate — which is what the relay's own pin of the control plane checks.
func TestDial_ReachesThePinnedRelayPresentingTheClientIdentity(t *testing.T) {
	relayID, console := newPair(t, "relay-a"), newPair(t, "console")
	addr, r := serveRelay(t, relayID)
	cc, err := Dial(Config{ClientCertPEM: console.certPEM, ClientKeyPEM: console.keyPEM}, addr, relayID.fp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	resp, err := stats(t, cc)
	if err != nil {
		t.Fatalf("the pinned relay was not reachable: %v", err)
	}
	if resp.GetCapacity() != 3 {
		t.Errorf("answer = %v", resp)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) != 1 || r.seen[0] != console.fp {
		t.Errorf("the relay saw client certificates %v, want the control plane's %s", r.seen, console.fp)
	}
}

// A pin pasted with stray whitespace or in upper case still matches: the
// registry row is typed by a person, and the fingerprint is the same string.
func TestDial_APinIsNormalised(t *testing.T) {
	relayID, console := newPair(t, "relay-a"), newPair(t, "console")
	addr, _ := serveRelay(t, relayID)
	cc, err := Dial(Config{ClientCertPEM: console.certPEM, ClientKeyPEM: console.keyPEM}, addr,
		"  "+strings.ToUpper(relayID.fp)+"\n")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	if _, err := stats(t, cc); err != nil {
		t.Fatalf("an upper-case, padded pin of the right certificate was refused: %v", err)
	}
}

// A relay presenting ANY other certificate is refused on the wire — an
// impostor on the registered address receives no call.
func TestDial_RefusesARelayThatIsNotThePinnedOne(t *testing.T) {
	impostor, pinned, console := newPair(t, "relay-a"), newPair(t, "relay-a"), newPair(t, "console")
	addr, r := serveRelay(t, impostor)
	cc, err := Dial(Config{ClientCertPEM: console.certPEM, ClientKeyPEM: console.keyPEM}, addr, pinned.fp)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()
	_, err = stats(t, cc)
	if err == nil {
		t.Fatal("a call reached a relay presenting a certificate the registry does not pin")
	}
	if !strings.Contains(err.Error(), "registry pins") {
		t.Errorf("the failure does not say it was the pin: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) != 0 {
		t.Errorf("the impostor served %d calls", len(r.seen))
	}
}

// A control plane whose own key pair is unusable fails at Dial, saying so,
// rather than handshaking with no certificate and being refused by every
// relay for a reason it cannot see.
func TestDial_RefusesAnUnusableClientIdentity(t *testing.T) {
	a, b := newPair(t, "console"), newPair(t, "other")
	for name, cfg := range map[string]Config{
		"empty":            {},
		"garbage":          {ClientCertPEM: []byte("nope"), ClientKeyPEM: []byte("nope")},
		"key of another":   {ClientCertPEM: a.certPEM, ClientKeyPEM: b.keyPEM},
		"cert without key": {ClientCertPEM: a.certPEM},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Dial(cfg, "relay-a:13444", a.fp)
			if err == nil || !strings.Contains(err.Error(), "client identity") {
				t.Fatalf("Dial: %v, want a client-identity error", err)
			}
		})
	}
}

// Bytes that are not a certificate are refused with a reason, not a panic.
func TestPinnedVerifier_RefusesAnUnparseableCertificate(t *testing.T) {
	err := PinnedVerifier("relay-a:13444", "abc")([][]byte{[]byte("not der")}, nil)
	if err == nil || !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("err = %v, want unparseable", err)
	}
}

// The connection-state hook refuses a connection with no peer certificate,
// and checks the LEAF of what it does see.
func TestPinnedConnectionVerifier_ChecksTheLeaf(t *testing.T) {
	a, b := newPair(t, "relay-a"), newPair(t, "relay-b")
	v := PinnedConnectionVerifier("relay-a:13444", a.fp)
	if err := v(tls.ConnectionState{}); err == nil {
		t.Error("a connection with no certificate was accepted")
	}
	if err := v(tls.ConnectionState{PeerCertificates: []*x509.Certificate{a.leaf, b.leaf}}); err != nil {
		t.Errorf("the pinned leaf was refused: %v", err)
	}
	if err := v(tls.ConnectionState{PeerCertificates: []*x509.Certificate{b.leaf, a.leaf}}); err == nil {
		t.Error("a chain whose LEAF is not pinned was accepted because the pin appeared further up")
	}
}

// echoServer is a raw TLS 1.3 server that issues session tickets and answers
// one byte per connection — enough traffic for the client to receive the
// ticket, which TLS 1.3 sends after the handshake.
func echoServer(t *testing.T, id pair) string {
	t.Helper()
	lis, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{id.tls},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err == nil {
					_, _ = c.Write(b)
				}
			}()
		}
	}()
	return lis.Addr().String()
}

// connect handshakes, exchanges one byte (so a ticket arrives), and reports
// whether the session was resumed.
func connect(t *testing.T, addr string, cfg *tls.Config) (resumed bool, err error) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return false, err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{1}); err != nil {
		return false, err
	}
	if _, err := io.ReadFull(c, make([]byte, 1)); err != nil {
		return false, err
	}
	return c.ConnectionState().DidResume, nil
}

// The pin holds on a RESUMED session.
//
// crypto/tls skips VerifyPeerCertificate when a session resumes, so a pin
// enforced only there is enforced on the first connection and skipped on every
// one after. The control case below shows that skip is real in this setup —
// otherwise the assertion that VerifyConnection catches it would prove nothing.
func TestPinnedConnectionVerifier_HoldsOnAResumedSession(t *testing.T) {
	relayID, other := newPair(t, "relay-a"), newPair(t, "relay-b")
	addr := echoServer(t, relayID)
	cache := tls.NewLRUClientSessionCache(8)
	base := func() *tls.Config {
		return &tls.Config{
			MinVersion:         tls.VersionTLS13,
			ServerName:         "relay-a",
			InsecureSkipVerify: true, // #nosec G402 -- the pin under test replaces the chain check
			ClientSessionCache: cache,
		}
	}

	first := base()
	first.VerifyPeerCertificate = PinnedVerifier(addr, relayID.fp)
	first.VerifyConnection = PinnedConnectionVerifier(addr, relayID.fp)
	if resumed, err := connect(t, addr, first); err != nil || resumed {
		t.Fatalf("first connection: resumed=%v err=%v, want a full handshake", resumed, err)
	}

	// Control: with the WRONG pin on VerifyPeerCertificate alone, a resumed
	// session sails through. This is the gap the second hook closes.
	control := base()
	control.VerifyPeerCertificate = PinnedVerifier(addr, other.fp)
	resumed, err := connect(t, addr, control)
	if err != nil || !resumed {
		t.Fatalf("control: resumed=%v err=%v — the test is not exercising resumption", resumed, err)
	}

	right := base()
	right.VerifyPeerCertificate = PinnedVerifier(addr, relayID.fp)
	right.VerifyConnection = PinnedConnectionVerifier(addr, relayID.fp)
	if resumed, err := connect(t, addr, right); err != nil || !resumed {
		t.Fatalf("a resumed session with the right pin: resumed=%v err=%v", resumed, err)
	}

	// The wrong pin, on a session that IS resumed — recorded from inside the
	// hook, so the refusal is known to come from the resumption path and not
	// from a full handshake VerifyPeerCertificate would have caught anyway.
	wrong := base()
	wrong.VerifyPeerCertificate = PinnedVerifier(addr, other.fp)
	pinned := PinnedConnectionVerifier(addr, other.fp)
	var sawResume bool
	wrong.VerifyConnection = func(cs tls.ConnectionState) error {
		sawResume = cs.DidResume
		return pinned(cs)
	}
	if _, err := connect(t, addr, wrong); err == nil || !strings.Contains(err.Error(), "registry pins") {
		t.Fatalf("a resumed session to a certificate the pin does not name: %v, want refused by the pin", err)
	}
	if !sawResume {
		t.Fatal("the refused connection was not a resumption — the test proves nothing about the resumed path")
	}
}
