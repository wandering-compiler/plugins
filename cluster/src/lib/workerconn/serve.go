package workerconn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/tunnel"
)

// ServeTunnel opens the work channel and serves on it until ctx ends or the
// connection drops.
//
// The worker DIALS and then SERVES on the resulting socket. That inversion is
// the whole mechanism: a machine behind NAT cannot be called, so it calls out
// and answers on the way back.
//
// `register` installs the worker's own services on the server — this package
// has no idea what they are, which is the same ignorance the relay has. `opts`
// are extra server options (interceptors, say), applied after the cluster's.
//
// It returns when ctx ends or the ONE connection drops; a worker loops on it
// with a backoff, dialling a fresh tunnel each time.
func ServeTunnel(ctx context.Context, cfg Config, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	if register == nil {
		return errors.New("workerconn: ServeTunnel needs something to serve")
	}
	if strings.TrimSpace(cfg.TunnelAddress) == "" {
		return errors.New("workerconn: TunnelAddress is required")
	}
	if strings.TrimSpace(cfg.RelayFingerprint) == "" {
		return errors.New("workerconn: RelayFingerprint is required for the tunnel too — " +
			"it carries the work, so an impostor on this address would receive it")
	}
	if _, err := certificateUsable(cfg); err != nil {
		// No certificate yet (Run has not enrolled), or one that ran out: the
		// relay would refuse the handshake, so say why instead.
		return err
	}
	// The same TLS as every other connection to the relay: pinned through
	// relaydial (full AND resumed handshakes — the tunnel carries the work, so
	// a pin a resumed session skipped would be the worst place for one), and
	// this worker's current certificate, read at the handshake so a renewal
	// takes effect on the next tunnel.
	d := &tls.Dialer{Config: clientTLS(cfg, true)}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", cfg.TunnelAddress)
	if err != nil {
		return fmt.Errorf("workerconn: dialling the tunnel: %w", err)
	}

	// The work server is built with the cluster's keepalive and the MaxMessage
	// cap first, and the caller's options after them, so a caller can add (a
	// unary interceptor, its own limits) without having to repeat these — the
	// relay's pings are only tolerated because this side permits them.
	srv := grpc.NewServer(append(tunnel.WorkServerOptions(), opts...)...)
	register(srv)
	lis := tunnel.NewSingleConnListener(conn)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	select {
	case <-ctx.Done():
		// GracefulStop, not Stop: work already running on this tunnel is
		// somebody's job, and the relay has no way to re-place it.
		srv.GracefulStop()
		_ = lis.Close()
		return ctx.Err()
	case err := <-done:
		_ = lis.Close()
		return err
	}
}
