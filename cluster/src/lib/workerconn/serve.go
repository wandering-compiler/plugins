package workerconn

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
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
// `register` is called once per tunnel.
//
// It returns when ctx ends (stopping every tunnel it serves gracefully), or
// when the CURRENT connection drops and every retired tunnel has finished; a
// worker loops on it with a backoff, dialling a fresh tunnel each time.
//
// A tunnel carries the certificate it was opened with, and the relay retires
// it when that certificate expires. So when the certificate on disk is
// renewed (Run renews it), this opens a new tunnel with the new one and keeps
// serving the old tunnel for the work already running on it; the relay sends
// new work to the new tunnel and closes the old one when its last call ends.
// Without this a long-lived worker lost its tunnel, and the work on it, once
// per certificate lifetime, and a fleet enrolled together lost it at once.
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
	cur, err := openTunnel(ctx, cfg, register, opts)
	if err != nil {
		return err
	}
	// The retired tunnels are this call's for as long as it runs: finished
	// ones are dropped, and none outlives the return.
	var retired []*servedTunnel
	prune := func() {
		live := retired[:0]
		for _, t := range retired {
			if !t.finished() {
				live = append(live, t)
			}
		}
		retired = live
	}
	stop := func(ts []*servedTunnel) {
		// GracefulStop, not Stop: work already running on these tunnels is
		// somebody's job, and the relay has no way to re-place it.
		for _, t := range ts {
			t.srv.GracefulStop()
		}
	}
	tick := time.NewTicker(cfg.retry())
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stop(append(retired, cur))
			return ctx.Err()
		case <-cur.ended:
			// The current tunnel is gone. A retired one is still finishing
			// calls the relay will close it after; wait for them, or for
			// ctx, rather than return and leave them unowned.
			for _, t := range retired {
				select {
				case <-t.ended:
				case <-ctx.Done():
					prune()
					stop(retired)
					return ctx.Err()
				}
			}
			return cur.err
		case <-tick.C:
			prune()
			leaf, err := certificateUsable(cfg)
			if err != nil || bytes.Equal(leaf.Raw, cur.certRaw) {
				continue
			}
			next, err := openTunnel(ctx, cfg, register, opts)
			if err != nil {
				continue // keep the old tunnel; try again on the next tick
			}
			retired = append(retired, cur)
			cur = next
		}
	}
}

// servedTunnel is one tunnel and the server answering on it.
type servedTunnel struct {
	srv *grpc.Server
	// certRaw is the certificate on disk when the tunnel was dialled — the
	// one its handshake presented.
	certRaw []byte
	// ended is closed once the connection has ended; err is Serve's result,
	// readable after that.
	ended chan struct{}
	err   error
}

func (t *servedTunnel) finished() bool {
	select {
	case <-t.ended:
		return true
	default:
		return false
	}
}

func openTunnel(ctx context.Context, cfg Config, register func(*grpc.Server), opts []grpc.ServerOption) (*servedTunnel, error) {
	leaf, err := certificateUsable(cfg)
	if err != nil {
		return nil, err
	}
	// The same TLS as every other connection to the relay: pinned through
	// relaydial (full AND resumed handshakes — the tunnel carries the work, so
	// a pin a resumed session skipped would be the worst place for one), and
	// this worker's current certificate, read at the handshake.
	d := &tls.Dialer{Config: clientTLS(cfg, true)}
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "tcp", cfg.TunnelAddress)
	if err != nil {
		return nil, fmt.Errorf("workerconn: dialling the tunnel: %w", err)
	}

	// The work server is built with the cluster's keepalive and the MaxMessage
	// cap first, and the caller's options after them, so a caller can add (a
	// unary interceptor, its own limits) without having to repeat these — the
	// relay's pings are only tolerated because this side permits them.
	srv := grpc.NewServer(append(tunnel.WorkServerOptions(), opts...)...)
	register(srv)
	lis := tunnel.NewSingleConnListener(conn)
	t := &servedTunnel{srv: srv, certRaw: leaf.Raw, ended: make(chan struct{})}
	go func() {
		t.err = srv.Serve(lis)
		_ = lis.Close()
		close(t.ended)
	}()
	return t, nil
}
