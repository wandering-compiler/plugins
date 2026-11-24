package relaydial

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
)

// GrantProbeTimeout bounds how long DialGranted tries one address of a grant
// before it moves to the next: a name that does not resolve fails at once,
// a packet a firewall drops would otherwise hold the caller until its own
// deadline.
var GrantProbeTimeout = 3 * time.Second

// DialGranted opens a CALLER's connection to the relay that granted g: the
// relay's address on its own network first (g.internal_address), then the
// public one (g.address), each pinned to g.cert_fingerprint. The connection
// is to the first address a TLS handshake reaches; the caller then sends its
// call on it with the ticket, as before.
//
// The order is the point. A caller in the relay's own stack that dials the
// public address dials its host's public IP, which Docker does not translate
// back into the stack: the packet arrives on the host's INPUT chain and a
// default-deny firewall drops it — a grant that works from everywhere but
// beside the relay. The internal name resolves only on the relay's network,
// so outside it the first try fails at once and the public address is used.
//
// opts are added to the connection (interceptors, a stats handler); the
// transport credentials are the pin's.
func DialGranted(ctx context.Context, g *pb.TaskGranted, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	want := strings.ToLower(strings.TrimSpace(g.GetCertFingerprint()))
	if want == "" {
		return nil, errors.New("relaydial: the grant carries no cert_fingerprint to pin")
	}
	var addrs []string
	for _, a := range []string{g.GetInternalAddress(), g.GetAddress()} {
		if a = strings.TrimSpace(a); a != "" && !contains(addrs, a) {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("relaydial: the grant names no address")
	}
	var errs []error
	for _, addr := range addrs {
		cfg := workTLS(addr, want)
		if err := probe(ctx, addr, cfg); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", addr, err))
			continue
		}
		return grpc.NewClient(addr, append([]grpc.DialOption{tunnel.ClientKeepalive(), grpc.WithTransportCredentials(credentials.NewTLS(cfg))}, opts...)...)
	}
	return nil, fmt.Errorf("relaydial: no address of the grant answered: %w", errors.Join(errs...))
}

// workTLS is a caller's TLS to the work endpoint: no client certificate (the
// ticket is the credential), the pin on both verification hooks.
func workTLS(target, want string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// #nosec G402 -- the chain check is replaced by the leaf pin below,
		// as for the management connection (ClientTLS).
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: PinnedVerifier(target, want),
		VerifyConnection:      PinnedConnectionVerifier(target, want),
	}
}

// probe completes one pinned TLS handshake with addr and closes it.
func probe(ctx context.Context, addr string, cfg *tls.Config) error {
	ctx, cancel := context.WithTimeout(ctx, GrantProbeTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg.Clone()}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
