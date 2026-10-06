package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/wandering-compiler/platform/plugins/cluster/gen"
	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/handlers"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
)

// registry is the bundle's half of gen.HandlerRegistry: it keeps what the
// plugin registered so a test can call it.
type registry struct {
	impl      pb.ClusterServiceServer
	shutdowns int
}

func (r *registry) RegisterClusterServiceServer(impl pb.ClusterServiceServer) { r.impl = impl }
func (r *registry) RegisterShutdown(func(context.Context) error)              { r.shutdowns++ }

// relayRow is the one row the fake registry tables hold.
type tables struct {
	relay  *pb.Relay
	banned []string

	mu      sync.Mutex
	reached []string
	failed  []string
}

// The generated clients, answered from memory. Embedding the interface keeps
// every method the plugin does not call a nil-pointer panic, which is the
// loud failure wanted if the wiring starts calling something new.
type relayQuery struct {
	pb.RelayQueryClient
	t *tables
}

func (q relayQuery) GetRelay(_ context.Context, in *pb.GetRelayReq, _ ...grpc.CallOption) (*pb.Relay, error) {
	if in.GetId() != q.t.relay.GetId() {
		return &pb.Relay{}, nil
	}
	return q.t.relay, nil
}

type relayMutation struct {
	pb.RelayMutationClient
	t *tables
}

func (m relayMutation) RecordRelayReached(_ context.Context, in *pb.RecordRelayReachedReq, _ ...grpc.CallOption) (*pb.RecordRelayReachedResp, error) {
	m.t.mu.Lock()
	defer m.t.mu.Unlock()
	m.t.reached = append(m.t.reached, in.GetId())
	return &pb.RecordRelayReachedResp{}, nil
}

func (m relayMutation) RecordRelayFailed(_ context.Context, in *pb.RecordRelayFailedReq, _ ...grpc.CallOption) (*pb.RecordRelayFailedResp, error) {
	m.t.mu.Lock()
	defer m.t.mu.Unlock()
	m.t.failed = append(m.t.failed, in.GetId()+": "+in.GetError())
	return &pb.RecordRelayFailedResp{}, nil
}

type workerQuery struct {
	pb.WorkerQueryClient
	t *tables
}

func (q workerQuery) FingerprintsByState(_ context.Context, in *pb.FingerprintsByStateReq, _ ...grpc.CallOption) (*pb.FingerprintsByStateResp, error) {
	if in.GetState() != pb.WorkerState_WORKER_STATE_BANNED {
		return &pb.FingerprintsByStateResp{}, nil
	}
	return &pb.FingerprintsByStateResp{Fingerprints: q.t.banned}, nil
}

type clientSet struct{ t *tables }

func (c clientSet) RelayQuery() pb.RelayQueryClient       { return relayQuery{t: c.t} }
func (c clientSet) RelayMutation() pb.RelayMutationClient { return relayMutation{t: c.t} }
func (c clientSet) WorkerQuery() pb.WorkerQueryClient     { return workerQuery{t: c.t} }
func (c clientSet) WorkerMutation() pb.WorkerMutationClient {
	return nil
}

// identityFiles mints a control-plane identity on disk, the way `relay mint
// --name console` does, and returns its paths and fingerprint.
func identityFiles(t *testing.T, name string) (certPath, keyPath, fingerprint string) {
	t.Helper()
	dir := t.TempDir()
	id, err := identity.LoadOrCreateIdentity(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key"), id.Fingerprint
}

// managedRelay is a relay's MANAGEMENT server as cmd/relay builds it: TLS with
// the relay's own pinned identity, the control plane's certificate PINNED on
// the other side, and the ban set applied from every call.
type managedRelay struct {
	addr    string
	fp      string
	codes   *regcode.Store
	workers *workeradmit.Registry

	// refusals are the relay-side pin's verdicts against a client, as the
	// TLS handshake saw them.
	mu       sync.Mutex
	refusals []error
}

func (m *managedRelay) pinRefusals() []error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.refusals)
}

func serveManagedRelay(t *testing.T, controlPlaneFP string) *managedRelay {
	t.Helper()
	relayID, err := identity.LoadOrCreateIdentity(t.TempDir(), "relay")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := tls.X509KeyPair(relayID.CertPEM, relayID.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := relaycore.New(relaycore.Options{TicketTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	codes, err := regcode.New(time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	workers := workeradmit.New()
	m := &managedRelay{fp: relayID.Fingerprint, codes: codes, workers: workers}
	pin := relaydial.PinnedVerifier("control plane", controlPlaneFP)
	opts := append(relayserver.BanServerOptions(workers), grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			err := pin(raw, chains)
			if err != nil {
				m.mu.Lock()
				m.refusals = append(m.refusals, err)
				m.mu.Unlock()
			}
			return err
		},
		VerifyConnection: relaydial.PinnedConnectionVerifier("control plane", controlPlaneFP),
	})))
	srv := grpc.NewServer(opts...)
	pb.RegisterClusterServiceServer(srv, &relayserver.Server{
		Pool: pool, Workers: workers, Codes: codes,
		ProxyAddress: "relay.example.com:9000", ProxyFingerprint: relayID.Fingerprint,
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	m.addr = lis.Addr().String()
	return m
}

// The whole boot path, against a REAL relay management server: the identity
// RegisterPlugin loads from the configured paths is the one the relay's pin
// accepts, the handler it registers reaches the relay through the registry
// row, and the ban set from the worker table rides on the call.
//
// This is the only place the three halves (env contract, generated clients,
// relaydial) meet before a consumer's build — a wrong argument order or a
// store wired to the wrong client would compile everywhere else.
func TestRegisterPlugin_TheRegisteredHandlerReachesAPinnedRelay(t *testing.T) {
	certPath, keyPath, consoleFP := identityFiles(t, "console")
	relay := serveManagedRelay(t, consoleFP)
	tb := &tables{
		relay:  &pb.Relay{Id: "r-1", Name: "acme-eu", Url: relay.addr, CertFingerprint: relay.fp, Enabled: true},
		banned: []string{"bad-worker-fp"},
	}
	reg := &registry{}
	err := RegisterPlugin(&gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: keyPath, DialTimeoutSeconds: 3}, reg, clientSet{tb})
	if err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	h, ok := reg.impl.(*handlers.ClusterServiceHandler)
	if !ok {
		t.Fatalf("registered %T, want the cluster handler", reg.impl)
	}
	if h.DialTimeout != 3*time.Second {
		t.Errorf("DialTimeout = %s, want the configured 3s", h.DialTimeout)
	}

	resp, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"r-1"}})
	if err != nil {
		t.Fatalf("IssueRegistrationCode through the registered handler: %v", err)
	}
	if resp.GetRelay() != "acme-eu" || resp.GetRelayFingerprint() != relay.fp {
		t.Errorf("resp names relay %q / %q, want the registry row's name and pin", resp.GetRelay(), resp.GetRelayFingerprint())
	}
	// The code is the relay's: redeemable there, exactly once.
	if err := relay.codes.Redeem(resp.GetCode()); err != nil {
		t.Errorf("the code the control plane handed out is not the relay's: %v", err)
	}
	if relay.workers.Admitted("bad-worker-fp") {
		t.Error("the ban set from the worker table did not reach the relay on the call")
	}
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if len(tb.reached) != 1 || tb.reached[0] != "r-1" {
		t.Errorf("reached = %v, want the relay's row marked reached once", tb.reached)
	}
}

// A control plane holding a DIFFERENT identity from the one the relay pinned
// is refused by the relay — the plugin presents what it was configured with,
// not something that merely parses.
func TestRegisterPlugin_AnotherIdentityIsRefusedByTheRelay(t *testing.T) {
	pinnedCert, pinnedKey, pinnedFP := identityFiles(t, "console")
	otherCert, otherKey, otherFP := identityFiles(t, "console")
	relay := serveManagedRelay(t, pinnedFP)
	tb := &tables{relay: &pb.Relay{Id: "r-1", Name: "acme-eu", Url: relay.addr, CertFingerprint: relay.fp}}
	boot := func(cert, key string) *handlers.ClusterServiceHandler {
		t.Helper()
		reg := &registry{}
		if err := RegisterPlugin(&gen.EnvConfig{ClientCertPath: cert, ClientKeyPath: key, DialTimeoutSeconds: 2}, reg, clientSet{tb}); err != nil {
			t.Fatal(err)
		}
		return reg.impl.(*handlers.ClusterServiceHandler)
	}

	// The control: the pinned identity, against the same relay row, is served.
	// So what the other identity meets below is not a wrong address, a wrong
	// relay fingerprint, or a relay that is down.
	pinned := boot(pinnedCert, pinnedKey)
	if _, err := pinned.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"r-1"}}); err != nil {
		t.Fatalf("the pinned identity was refused: %v", err)
	}
	minted := relay.codes.Outstanding()

	h := boot(otherCert, otherKey)
	if _, err := h.IssueRegistrationCode(t.Context(), &pb.IssueRegistrationCodeReq{Ids: []string{"r-1"}}); status.Code(err) != codes.Unavailable {
		t.Fatalf("a relay pinned to another control plane: %v, want Unavailable", err)
	}
	if n := relay.codes.Outstanding(); n != minted {
		t.Errorf("the refused control plane still got %d code(s) minted", n-minted)
	}
	// Why, as the RELAY saw it (the handler reports only that the relay did
	// not become reachable, and what the client reads of a TLS 1.3 refusal
	// races with its first write): the pin refused the certificate this
	// plugin was configured with — not a missing one, not a timeout.
	refusals := relay.pinRefusals()
	if len(refusals) == 0 {
		t.Fatal("the relay's pin never refused anything — the call failed for some other reason")
	}
	for _, err := range refusals {
		if !strings.Contains(err.Error(), "presented certificate "+otherFP) {
			t.Errorf("the relay refused something other than the configured identity: %v", err)
		}
	}
}

// Zero and negative timeouts fall back to the documented default rather than
// to "no deadline", which would hold ScheduleTask on a black-holed relay until
// the caller's own deadline.
func TestRegisterPlugin_DialTimeoutDefaults(t *testing.T) {
	certPath, keyPath, _ := identityFiles(t, "console")
	for _, secs := range []int{0, -4} {
		reg := &registry{}
		if err := RegisterPlugin(&gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: keyPath, DialTimeoutSeconds: secs}, reg, clientSet{&tables{}}); err != nil {
			t.Fatal(err)
		}
		if got := reg.impl.(*handlers.ClusterServiceHandler).DialTimeout; got != 5*time.Second {
			t.Errorf("dial_timeout_seconds=%d gave %s, want the 5s default", secs, got)
		}
	}
}

// Every way the boot configuration can be unusable is refused AT BOOT, with
// the env name in the message, and nothing is registered. A control plane that
// started anyway would accept calls it is certain to fail.
func TestRegisterPlugin_RefusesAnUnusableConfiguration(t *testing.T) {
	certPath, keyPath, _ := identityFiles(t, "console")
	otherCert, otherKey, _ := identityFiles(t, "other")
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, keyPEM[:len(keyPEM)/2], 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cfg  *gen.EnvConfig
		want string
	}{
		{"no configuration at all", nil, "client_cert_path"},
		{"no key path", &gen.EnvConfig{ClientCertPath: certPath}, "client_key_path"},
		{"blank paths", &gen.EnvConfig{ClientCertPath: "  ", ClientKeyPath: "\t"}, "required"},
		{"a missing certificate", &gen.EnvConfig{ClientCertPath: filepath.Join(dir, "nope.crt"), ClientKeyPath: keyPath}, "client_cert_path"},
		{"a missing key", &gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: filepath.Join(dir, "nope.key")}, "client_key_path"},
		// The defect this pins: these three booted and then failed every
		// placement at dial time.
		{"a key from another pair", &gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: otherKey}, "key pair"},
		{"a truncated key", &gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: truncated}, "key pair"},
		{"garbage where the key goes", &gen.EnvConfig{ClientCertPath: otherCert, ClientKeyPath: garbage}, "key pair"},
		{"the certificate where the key goes", &gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: certPath}, "key pair"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &registry{}
			err := RegisterPlugin(tc.cfg, reg, clientSet{&tables{}})
			if err == nil {
				t.Fatal("an unusable configuration booted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
			if reg.impl != nil {
				t.Error("a handler was registered despite the refusal")
			}
		})
	}
}

// The bundle must hand over both collaborators; a nil one is a wiring bug in
// the bundle and is said so, not turned into a nil-pointer panic on the first
// call.
func TestRegisterPlugin_NeedsARegistryAndClients(t *testing.T) {
	certPath, keyPath, _ := identityFiles(t, "console")
	cfg := &gen.EnvConfig{ClientCertPath: certPath, ClientKeyPath: keyPath}
	if err := RegisterPlugin(cfg, nil, clientSet{&tables{}}); err == nil {
		t.Error("RegisterPlugin accepted a nil registry")
	}
	if err := RegisterPlugin(cfg, &registry{}, nil); err == nil {
		t.Error("RegisterPlugin accepted a nil client set")
	}
}
