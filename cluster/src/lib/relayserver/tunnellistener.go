package relayserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/plugins/cluster/lib/identity"
	"github.com/wandering-compiler/plugins/cluster/lib/tunnel"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// ServeTunnels accepts worker tunnels until lis is closed.
//
// A worker holds TWO connections to a relay: the Attach stream, which is its
// availability, and this one, which carries work. They are separate because
// admission happens before there is anything to carry — a machine has to be
// able to connect, be seen, and wait, without being handed a socket the relay
// would then have to police.
//
// opts are added to every tunnel's client connection AFTER the cluster's own
// (keepalive, MaxMessage — see tunnel.ClientOverConn), so they can override.
func ServeTunnels(lis net.Listener, workers *workeradmit.Registry, backends *Backends, onError func(error), opts ...grpc.DialOption) error {
	if onError == nil {
		onError = func(error) {}
	}
	for {
		c, err := lis.Accept()
		if err != nil {
			return err
		}
		go func() {
			if err := acceptTunnel(c, workers, backends, opts); err != nil {
				_ = c.Close()
				onError(err)
			}
		}()
	}
}

func acceptTunnel(c net.Conn, workers *workeradmit.Registry, backends *Backends, opts []grpc.DialOption) error {
	tc, ok := c.(*tls.Conn)
	if !ok {
		// The listener is supposed to be TLS-wrapped. A plain connection here
		// means a misconfigured relay, and a tunnel with no identity would
		// take work from anyone who found the port.
		return errors.New("relay: a tunnel arrived without TLS — the listener must be wrapped")
	}
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("relay: tunnel handshake: %w", err)
	}
	// The listener REQUIRES a certificate and verifies it against this relay's
	// CA (main wires tls.RequireAndVerifyClientCert): a tunnel carries work,
	// and unlike the attach listener there is no enrolment to let through.
	// Checked again here so a listener built without that rule fails closed.
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 || len(tc.ConnectionState().VerifiedChains) == 0 {
		return errors.New("relay: the tunnel presented no verified certificate, so it has no identity — " +
			"the tunnel listener must require and verify client certificates against the relay's CA")
	}
	// The KEY's fingerprint, as everywhere a worker is identified: the
	// certificate is renewed every few weeks, the key — and so the ban — is not.
	fp := identity.WorkerID(certs[0])

	// Checked HERE and not only at Attach, because a ban can land between the
	// two: a worker that attached a second before it was banned must not get
	// a tunnel after.
	if !workers.Admitted(fp) {
		return fmt.Errorf("relay: banned worker %s opened a tunnel", fp)
	}

	// The hook removes THIS connection, not whatever the worker holds now —
	// it fires for an old tunnel after its replacement attached.
	var conn *grpc.ClientConn
	conn, err := tunnel.ClientOverConn(tc, "passthrough:///worker", func() {
		backends.RemoveConn(fp, conn)
	}, opts...)
	if err != nil {
		return fmt.Errorf("relay: turning the tunnel around: %w", err)
	}
	backends.Add(fp, conn)
	return nil
}
