package relaydial

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
)

// workRelay is a relay's work endpoint: TLS presenting id, no client
// certificate asked (the ticket is the caller's credential); it counts calls.
type workRelay struct {
	pb.UnimplementedClusterServiceServer
	calls atomic.Int32
}

func (w *workRelay) RelayStats(_ context.Context, _ *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	w.calls.Add(1)
	return &pb.RelayStatsResp{}, nil
}

func serveWork(t *testing.T, id pair) (string, *workRelay) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &workRelay{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{id.tls}, MinVersion: tls.VersionTLS13})))
	pb.RegisterClusterServiceServer(srv, w)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), w
}

func dialGranted(t *testing.T, g *pb.TaskGranted) (*grpc.ClientConn, error) {
	t.Helper()
	cc, err := DialGranted(t.Context(), g)
	if err == nil {
		t.Cleanup(func() { _ = cc.Close() })
	}
	return cc, err
}

// Beside the relay, the internal address is the one used: it never leaves
// the host.
func TestDialGranted_PrefersTheInternalAddress(t *testing.T) {
	id := newPair(t, "relay")
	internal, in := serveWork(t, id)
	public, out := serveWork(t, id)
	cc, err := dialGranted(t, &pb.TaskGranted{InternalAddress: internal, Address: public, CertFingerprint: id.fp})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stats(t, cc); err != nil {
		t.Fatal(err)
	}
	if in.calls.Load() != 1 || out.calls.Load() != 0 {
		t.Fatalf("calls internal=%d public=%d, want the internal address", in.calls.Load(), out.calls.Load())
	}
}

// Outside the relay's network the internal name does not resolve (or the
// port does not answer, or something else is there): the public address is
// used, within the probe's bound.
func TestDialGranted_FallsBackToThePublicAddress(t *testing.T) {
	id := newPair(t, "relay")
	public, out := serveWork(t, id)
	impostor, _ := serveWork(t, newPair(t, "relay"))
	closed := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := l.Addr().String()
		_ = l.Close()
		return a
	}()
	for name, internal := range map[string]string{
		"a name that does not resolve": "relay.invalid:9000",
		"a port nobody listens on":     closed,
		"another certificate there":    impostor,
	} {
		t.Run(name, func(t *testing.T) {
			before := out.calls.Load()
			start := time.Now()
			cc, err := dialGranted(t, &pb.TaskGranted{InternalAddress: internal, Address: public, CertFingerprint: id.fp})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stats(t, cc); err != nil {
				t.Fatal(err)
			}
			if out.calls.Load() != before+1 {
				t.Fatal("the public address was not used")
			}
			if d := time.Since(start); d > GrantProbeTimeout+2*time.Second {
				t.Fatalf("fell back after %v", d)
			}
		})
	}
}

// A grant without an internal address (a relay not told one) is dialled at
// its public address as before.
func TestDialGranted_PublicAloneStillWorks(t *testing.T) {
	id := newPair(t, "relay")
	public, out := serveWork(t, id)
	cc, err := dialGranted(t, &pb.TaskGranted{Address: public, CertFingerprint: strings.ToUpper(id.fp)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stats(t, cc); err != nil || out.calls.Load() != 1 {
		t.Fatalf("err=%v calls=%d", err, out.calls.Load())
	}
}

func TestDialGranted_Refusals(t *testing.T) {
	id := newPair(t, "relay")
	impostor, _ := serveWork(t, newPair(t, "relay"))
	for name, c := range map[string]struct {
		g    *pb.TaskGranted
		want string
	}{
		"no pin":          {&pb.TaskGranted{Address: impostor}, "no cert_fingerprint"},
		"no address":      {&pb.TaskGranted{CertFingerprint: id.fp}, "names no address"},
		"nothing answers": {&pb.TaskGranted{Address: impostor, CertFingerprint: id.fp}, "no address of the grant answered"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := dialGranted(t, c.g); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}
