// Command relay is one relay server: it accepts work from a control plane and
// holds a queue in front of the workers connected to it.
//
// It stores nothing but its keys. Capacity, queue, tickets, reservations,
// registration codes and the ban set all live in memory, and a restart drops
// every one of them — which is safe because the control plane sends the
// complete ban set on every call and workers reconnect forever.
//
// Its two KEYS are the exception, and both must outlive the process: its own
// certificate (pinned by the control plane and every caller) and its CA (which
// signed every worker certificate it ever issued — a new CA would orphan the
// whole fleet).
//
// # Run it
//
//	relay --listen :13444 --proxy-address relay.example.com:9000 \
//	      --cert /etc/relay/tls.crt --key /etc/relay/tls.key \
//	      --ca-cert /run/secrets/relay-ca.crt --ca-key /run/secrets/relay-ca.key \
//	      --control-plane-fingerprint <hex>
//
// At startup it prints its OWN certificate fingerprint. That string is what an
// operator pastes into the relay's row in the control plane — the trust
// decision is a comparison a human makes, so the relay has to say what to
// compare against.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/regcode"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaydial"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/relayserver"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/platform/plugins/cluster/lib/workeradmit"
	"github.com/wandering-compiler/platform/plugins/cluster/workerpb"
)

type config struct {
	listen       string
	tunnelListen string
	attachListen string
	proxyListen  string
	proxyAddress string
	certPath     string
	keyPath      string
	identityDir  string
	controlPin   string
	capacity     int
	ticketTTL    time.Duration
	drainTimeout time.Duration
	pollInterval time.Duration
	pollTimeout  time.Duration
	caCertPath   string
	caKeyPath    string
	certLifetime time.Duration
	codeTTL      time.Duration

	// netListen opens every listener; nil is net.Listen. A test seam, never
	// set from flags: it lets a test make one bind fail deterministically
	// instead of racing for a port it freed.
	netListen func(network, address string) (net.Listener, error)
}

func (c config) bind(address string) (net.Listener, error) {
	if c.netListen != nil {
		return c.netListen("tcp", address)
	}
	return net.Listen("tcp", address)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("relay: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "issue-worker" {
		return issueWorker(os.Args[2:], os.Stdout)
	}
	if len(os.Args) > 1 && os.Args[1] == "mint" {
		return mint(os.Args[2:], os.Stdout)
	}
	cfg, err := parseConfig(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	return serve(cfg, stop, nil)
}

// parseConfig reads the flags, each defaulted from its environment variable.
// Split from serve so the relay's wiring can be run in-process by a test, on
// ports it chose, without going through os.Args.
func parseConfig(args []string, out io.Writer) (config, error) {
	cfg := config{}
	env := &envReader{}
	envOr := env.str
	// The number and duration readers take the FLAG their variable defaults,
	// so a malformed variable is only an error when that flag was not given.
	envInt, envDuration := env.int, env.duration
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.StringVar(&cfg.listen, "listen", envOr("RELAY_LISTEN", ":13444"),
		"address the MANAGEMENT gRPC listens on — the half the control plane dials")
	fs.StringVar(&cfg.attachListen, "attach-listen", envOr("RELAY_ATTACH_LISTEN", ":13446"),
		"address WORKERS dial to ATTACH — a gRPC listener with its own TLS, separate from "+
			"--listen because the management port pins the control plane's certificate and a "+
			"worker does not hold it")
	fs.StringVar(&cfg.tunnelListen, "tunnel-listen", envOr("RELAY_TUNNEL_LISTEN", ":13445"),
		"address WORKERS dial to offer their work channel — a separate listener from --attach-listen, "+
			"because it REQUIRES a worker certificate, while attach must let an enrolling worker in without one")
	fs.StringVar(&cfg.proxyListen, "proxy-listen", envOr("RELAY_PROXY_LISTEN", ":9000"),
		"address CALLERS send work to, redeeming the ticket the control plane granted")
	fs.StringVar(&cfg.proxyAddress, "proxy-address", os.Getenv("RELAY_PROXY_ADDRESS"),
		"host:port callers are told to send work to, as the OUTSIDE WORLD reaches it")
	fs.StringVar(&cfg.certPath, "cert", os.Getenv("RELAY_CERT"), "PEM certificate this relay presents")
	fs.StringVar(&cfg.keyPath, "key", os.Getenv("RELAY_KEY"), "PEM private key for --cert")
	fs.StringVar(&cfg.identityDir, "identity-dir", os.Getenv("RELAY_IDENTITY_DIR"),
		"mint-or-load this relay's identity AND its worker CA in this directory instead of supplying "+
			"--cert/--key and --ca-cert/--ca-key (dev). The certificate is self-signed and pinned: replacing "+
			"it is an edit to the relay's row. Keep the directory: a new CA orphans every enrolled worker")
	fs.StringVar(&cfg.caCertPath, "ca-cert", os.Getenv("RELAY_CA_CERT"),
		"PEM certificate of the CA this relay issues WORKER certificates from (production: a secret)")
	fs.StringVar(&cfg.caKeyPath, "ca-key", os.Getenv("RELAY_CA_KEY"), "PEM private key for --ca-cert")
	fs.DurationVar(&cfg.certLifetime, "worker-cert-lifetime",
		envDuration("worker-cert-lifetime", "RELAY_WORKER_CERT_LIFETIME", relayserver.DefaultWorkerCertLifetime),
		"how long an issued worker certificate lasts; workers renew well before, and a forgotten ban runs out with it")
	fs.DurationVar(&cfg.codeTTL, "registration-code-ttl", envDuration("registration-code-ttl", "RELAY_REGISTRATION_CODE_TTL", 15*time.Minute),
		"how long a one-time registration code stays usable")
	fs.StringVar(&cfg.controlPin, "control-plane-fingerprint", os.Getenv("RELAY_CONTROL_PLANE_FINGERPRINT"),
		"lowercase hex SHA-256 of the control plane's client certificate; nothing else may manage this relay")
	fs.IntVar(&cfg.capacity, "capacity", envInt("capacity", "RELAY_CAPACITY", 0),
		"OPTIONAL ceiling on concurrent tasks; 0 means whatever the attached workers add up to")
	fs.DurationVar(&cfg.ticketTTL, "ticket-ttl", envDuration("ticket-ttl", "RELAY_TICKET_TTL", 30*time.Second),
		"how long a granted ticket stays claimable — TIME TO CLAIM, not a cap on how long work may run")
	fs.DurationVar(&cfg.drainTimeout, "drain-timeout", envDuration("drain-timeout", "RELAY_DRAIN_TIMEOUT", 15*time.Minute),
		"on SIGTERM, how long to wait for running work after draining before stopping anyway — at "+
			"least the longest task this pool runs; the supervisor's kill timeout must be longer still")
	fs.DurationVar(&cfg.pollInterval, "poll-interval", envDuration("poll-interval", "RELAY_POLL_INTERVAL", relaycore.DefaultPollInterval),
		"how often a client holding a polled reservation is told to ask again")
	fs.DurationVar(&cfg.pollTimeout, "poll-timeout", envDuration("poll-timeout", "RELAY_POLL_TIMEOUT", relaycore.DefaultPollTimeout),
		"how long a polled reservation survives without a poll before it is abandoned — a few poll intervals")
	// The command line first: `-h` is usage whatever the environment holds,
	// and a flag given explicitly replaces its variable — so the variable
	// being malformed does not matter and is not a reason to refuse.
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() > 0 {
		// A stray word is almost always a flag that lost its dashes or a
		// subcommand misspelt; starting anyway would run a relay on defaults
		// the operator believes they changed.
		return config{}, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var errs []error
	for _, e := range env.errs {
		if !set[e.flag] {
			errs = append(errs, e.err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return config{}, err
	}
	return cfg, nil
}

// listening is where a started relay's four listeners actually bound — what a
// test needs when it asked for port 0.
type listening struct {
	management, attach, tunnels, proxy net.Addr
}

// serve runs the relay until a value arrives on stop, then drains and shuts
// down (shutdownPlan). started, if set, is told the bound addresses once every
// listener is up.
//
// A start that FAILS part-way stops whatever it had already started before
// returning, so nothing keeps serving behind an error.
func serve(cfg config, stop <-chan os.Signal, started func(listening)) (err error) {
	var undo []func()
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
		}
	}()

	// Every one of these is refused rather than defaulted. A relay that starts
	// with no proxy address hands out grants naming nowhere; one with no pin
	// accepts management from anybody who can reach the port. Both are
	// failures that look like a healthy process.
	for _, req := range []struct{ flag, val string }{
		{"--proxy-address", cfg.proxyAddress},
		{"--control-plane-fingerprint", cfg.controlPin},
	} {
		if strings.TrimSpace(req.val) == "" {
			return fmt.Errorf("%s is required", req.flag)
		}
	}

	crt, err := relayIdentity(cfg)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		return fmt.Errorf("parsing the relay's own certificate: %w", err)
	}

	// Printed first, unconditionally, before anything can fail later. An
	// operator registering this relay needs this string, and the commonest
	// moment to need it is a start that then goes wrong.
	log.Printf("certificate fingerprint: %s", relaydial.Fingerprint(leaf))
	log.Printf("  ^ paste this into the relay's row in the control plane, after checking it matches")

	if cfg.pollTimeout < 2*cfg.pollInterval {
		// A client told to come back every interval must survive one late
		// poll, or obedient clients lose their place to jitter.
		return fmt.Errorf("--poll-timeout (%s) must be at least twice --poll-interval (%s)", cfg.pollTimeout, cfg.pollInterval)
	}
	pool, err := relaycore.New(relaycore.Options{Capacity: cfg.capacity, TicketTTL: cfg.ticketTTL, PollTimeout: cfg.pollTimeout})
	if err != nil {
		return err
	}
	ca, err := relayCA(cfg)
	if err != nil {
		return err
	}
	regCodes, err := regcode.New(cfg.codeTTL, nil)
	if err != nil {
		return err
	}
	workers := workeradmit.New()

	controlPin := strings.ToLower(strings.TrimSpace(cfg.controlPin))
	// A refused control plane is LOGGED, with the fingerprint it presented.
	// The handshake failure is otherwise invisible on this side, and the
	// common cause is not an intruder but a console whose identity was
	// re-minted without updating --control-plane-fingerprint — which an
	// operator can only diagnose by comparing the two fingerprints.
	logRefusal := func(err error) error {
		if err != nil {
			log.Printf("refused a management connection: %v", err)
		}
		return err
	}
	pinCert := relaydial.PinnedVerifier("control plane", controlPin)
	pinConn := relaydial.PinnedConnectionVerifier("control plane", controlPin)
	// Every server here takes tunnel.ServerKeepalive: it pings its peers on
	// the cluster schedule and accepts their pings (lib/tunnel/keepalive.go).
	// The management server also applies the ban set every control-plane call
	// carries, before the call runs (relayserver.BanInterceptors).
	mgmtOpts := append(tunnel.ServerKeepalive(), relayserver.BanServerOptions(workers)...)
	srv := grpc.NewServer(append(mgmtOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		// The control plane is ONE known peer, so its certificate is pinned
		// exactly as it pins this relay's — symmetric, and neither side needs
		// a CA. Workers are the opposite case (a fleet that comes and goes)
		// and are verified against this relay's CA on their own listeners.
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			return logRefusal(pinCert(raw, chains))
		},
		// A resumed session never reaches VerifyPeerCertificate; this hook runs
		// on both paths, so the pin holds past the first connection (G123).
		VerifyConnection: func(cs tls.ConnectionState) error { return logRefusal(pinConn(cs)) },
	})))...)
	backends := relayserver.NewBackends()
	// Capacity comes from the FLEET, and this is the wire that carries it: a
	// worker attaching, draining, going unhealthy or hanging up changes the
	// total, and the pool promotes whoever is queued as soon as it does.
	//
	// Without it the relay is back to granting against a number that has no
	// relationship to the machines present — which meant an empty relay handed
	// out its full complement of tickets and every caller found out at the
	// proxy (a consumer, 2026-09-25).
	backends.OnCapacityChange(pool.SetCapacity)
	// MANAGEMENT ONLY. This server's TLS pins the control plane, so nothing a
	// worker holds can complete its handshake — registering the worker-facing
	// service here would have published it on a port no worker can reach,
	// which is exactly the defect this split exists to prevent.
	pb.RegisterClusterServiceServer(srv, &relayserver.Server{
		Pool:             pool,
		Workers:          workers,
		Backends:         backends,
		Codes:            regCodes,
		ProxyAddress:     cfg.proxyAddress,
		ProxyFingerprint: relaydial.Fingerprint(leaf),
		PollInterval:     cfg.pollInterval,
	})

	// The WORKER listeners. Different audience, different rule: the control
	// plane is one pinned peer, workers are a fleet whose certificates this
	// relay's CA issued — so the handshake verifies the chain (and expiry),
	// and the ban set decides the rest.
	//
	// The TUNNEL requires a certificate: it carries work and nothing enrols on
	// it. ATTACH verifies one IF GIVEN, because enrolment is the call a worker
	// makes before it has one; every call there that needs one checks itself.
	tunnelTLS := &tls.Config{
		Certificates: []tls.Certificate{crt},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool(),
	}
	attachTLS := tunnelTLS.Clone()
	attachTLS.ClientAuth = tls.VerifyClientCertIfGiven
	tunnelRaw, err := cfg.bind(cfg.tunnelListen)
	if err != nil {
		return fmt.Errorf("listening for worker tunnels on %s: %w", cfg.tunnelListen, err)
	}
	tunnelLis := tls.NewListener(tunnelRaw, tunnelTLS)
	undo = append(undo, func() { _ = tunnelLis.Close() })
	go func() {
		err := relayserver.ServeTunnels(tunnelLis, workers, backends, func(e error) {
			// Logged and dropped. A refused tunnel is one machine's problem,
			// and taking the relay down over it would turn a rejected worker
			// into an outage for every accepted one.
			log.Printf("tunnel refused: %v", e)
		})
		if err != nil {
			log.Printf("tunnel listener stopped: %v", err)
		}
	}()

	// The WORKER-ATTACH server: gRPC, worker TLS, its own port.
	attachSrv := grpc.NewServer(append(tunnel.ServerKeepalive(), grpc.Creds(credentials.NewTLS(attachTLS)))...)
	// Backends is handed over so a worker's declared slots and its readiness
	// land where scheduling can see them. The attach stream and the tunnel are
	// separate connections; this is where the two halves meet.
	workerpb.RegisterWorkerAttachServer(attachSrv, &relayserver.WorkerServer{
		Workers:  workers,
		Backends: backends,
	})
	// Enrolment and renewal share the attach listener: a worker already
	// reaches it, and it is the one that lets a certificate-less handshake in.
	workerpb.RegisterWorkerEnrollmentServer(attachSrv, &relayserver.Enrollment{
		CA:       ca,
		Codes:    regCodes,
		Workers:  workers,
		Lifetime: cfg.certLifetime,
	})
	attachLis, err := cfg.bind(cfg.attachListen)
	if err != nil {
		return fmt.Errorf("listening for worker attach on %s: %w", cfg.attachListen, err)
	}
	// The listener is closed HERE as well as by Stop: Serve runs in a goroutine
	// that may not have registered it yet, and a server stopped before Serve
	// closes the listener only when Serve gets round to it — after serve has
	// already returned, with the port still held.
	undo = append(undo, func() { attachSrv.Stop(); _ = attachLis.Close() })
	go func() {
		if err := attachSrv.Serve(attachLis); err != nil {
			log.Printf("attach listener stopped: %v", err)
		}
	}()

	// The PROXY. It serves no services of its own — every call it receives is
	// forwarded to a worker without being decoded, which is what lets this one
	// binary carry compile jobs and page fetches alike.
	//
	// TLS, and not optional: the ticket is a bearer credential and the payload
	// is somebody's work. In plaintext an observer on the path reads both and
	// can race a replay ahead of the legitimate caller. The caller pins this
	// certificate using the fingerprint its grant carried.
	proxy := grpc.NewServer(append(
		tunnel.ProxyServerOptions(relayserver.TicketPicker(pool, backends, workers)),
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{crt},
			MinVersion:   tls.VersionTLS13,
		})))...)
	proxyLis, err := cfg.bind(cfg.proxyListen)
	if err != nil {
		return fmt.Errorf("listening for callers on %s: %w", cfg.proxyListen, err)
	}
	undo = append(undo, func() { proxy.Stop(); _ = proxyLis.Close() })
	go func() {
		if err := proxy.Serve(proxyLis); err != nil {
			log.Printf("proxy stopped: %v", err)
		}
	}()

	lis, err := cfg.bind(cfg.listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.listen, err)
	}
	undo = append(undo, func() { srv.Stop(); _ = lis.Close() })
	log.Printf("management %s · attach %s · tunnels %s · callers %s · capacity %d · advertised %s",
		cfg.listen, cfg.attachListen, cfg.tunnelListen, cfg.proxyListen, cfg.capacity, cfg.proxyAddress)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(lis) }()
	if started != nil {
		started(listening{management: lis.Addr(), attach: attachLis.Addr(), tunnels: tunnelLis.Addr(), proxy: proxyLis.Addr()})
	}

	select {
	case err := <-served:
		// The management listener failed on its own: nothing can manage this
		// relay any more, so it is not one.
		return err
	case <-stop:
	}
	log.Printf("draining: no new work; waiting up to %s for running work", cfg.drainTimeout)
	shutdownPlan{
		pool:         pool,
		proxy:        proxy,
		management:   srv,
		attach:       attachSrv,
		tunnels:      tunnelLis,
		drainTimeout: cfg.drainTimeout,
		stopTimeout:  10 * time.Second,
	}.run()
	log.Print("stopped")
	return nil
}

// envReader supplies the flags' defaults from RELAY_* variables.
//
// An UNSET (or blank) variable is the default. A SET one that does not parse
// is an error, collected and refused by parseConfig unless its flag was given
// on the command line — never quietly read as something else. It used to be:
// RELAY_CAPACITY=8x was read as 8 (the old scan stopped at the first
// non-digit and called that success), RELAY_CAPACITY=-2 as no ceiling at all
// (anything not positive fell back to the default, 0), and
// RELAY_TICKET_TTL=60 (no unit) as the default 30 s — each a relay running on
// a value its operator did not write.
type envReader struct{ errs []envError }

// envError is a malformed variable, and the flag that would have overridden
// it.
type envError struct {
	flag string
	err  error
}

func (e *envReader) str(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// int reads a count where 0 is meaningful (RELAY_CAPACITY: no ceiling) and a
// negative one is not.
func (e *envReader) int(flagName, k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		e.errs = append(e.errs, envError{flagName, fmt.Errorf("%s=%q is not a whole number of zero or more", k, v)})
		return def
	}
	return n
}

// duration reads a positive Go duration ("30s", "15m").
func (e *envReader) duration(flagName, k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		e.errs = append(e.errs, envError{flagName, fmt.Errorf("%s=%q is not a positive duration with a unit, like 30s or 15m", k, v)})
		return def
	}
	return d
}

// relayIdentity resolves the relay's own key pair from whichever of the two
// ways the operator chose.
//
// Explicit --cert/--key is the production shape: the material is issued and
// mounted by whatever already manages certificates there. --identity-dir mints
// one on first start and reuses it after, which is what makes a dev sandbox
// possible WITHOUT a flag that skips verification — the relay still refuses to
// start without a pinned control plane, so there is no mode here that trades
// security for convenience.
//
// Exactly one of the two, because a relay holding two identities has no answer
// to "which fingerprint did the operator approve".
func relayIdentity(cfg config) (tls.Certificate, error) {
	explicit := strings.TrimSpace(cfg.certPath) != "" || strings.TrimSpace(cfg.keyPath) != ""
	minted := strings.TrimSpace(cfg.identityDir) != ""
	switch {
	case explicit && minted:
		return tls.Certificate{}, errors.New(
			"--identity-dir cannot be combined with --cert/--key: a relay with two identities " +
				"has no answer to which fingerprint was approved")
	case explicit:
		if strings.TrimSpace(cfg.certPath) == "" || strings.TrimSpace(cfg.keyPath) == "" {
			return tls.Certificate{}, errors.New("--cert and --key go together")
		}
		crt, err := tls.LoadX509KeyPair(cfg.certPath, cfg.keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("loading the relay's own identity: %w", err)
		}
		return crt, nil
	case minted:
		id, err := identity.LoadOrCreateIdentity(cfg.identityDir, "relay")
		if err != nil {
			return tls.Certificate{}, err
		}
		return tls.X509KeyPair(id.CertPEM, id.KeyPEM)
	}
	return tls.Certificate{}, errors.New(
		"this relay has no identity: pass --cert/--key, or --identity-dir to mint one")
}

// relayCA resolves the CA this relay issues worker certificates from.
//
// --ca-cert/--ca-key is the production shape: both are secrets, mounted, so
// the CA survives every recreation of the task. --identity-dir keeps it next
// to the relay's own identity (dev). NEVER minted anywhere else: a CA that
// silently changed would invalidate every worker certificate this relay ever
// issued, and the fleet would discover it one failed handshake at a time.
func relayCA(cfg config) (*identity.CA, error) {
	explicit := strings.TrimSpace(cfg.caCertPath) != "" || strings.TrimSpace(cfg.caKeyPath) != ""
	minted := strings.TrimSpace(cfg.identityDir) != ""
	switch {
	case explicit && minted:
		return nil, errors.New(
			"--identity-dir cannot be combined with --ca-cert/--ca-key: a relay with two CAs " +
				"has no answer to which one its workers chain to")
	case explicit:
		if strings.TrimSpace(cfg.caCertPath) == "" || strings.TrimSpace(cfg.caKeyPath) == "" {
			return nil, errors.New("--ca-cert and --ca-key go together")
		}
		return identity.LoadCA(cfg.caCertPath, cfg.caKeyPath)
	case minted:
		return identity.LoadOrCreateCA(cfg.identityDir)
	}
	return nil, errors.New(
		"this relay has no worker CA: pass --ca-cert/--ca-key, or --identity-dir to keep one there — " +
			"without it no worker can enrol")
}
