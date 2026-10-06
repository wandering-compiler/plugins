package relayserver

import (
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/tunnel"
)

// oneConn is a listener that hands out one connection, then blocks.
type oneConn struct {
	c    chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *oneConn) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *oneConn) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *oneConn) Addr() net.Addr { return &net.TCPAddr{} }

// tunnelTo makes a REAL tunnel the way acceptTunnel does — a client
// connection over one socket whose close hook removes the backend — with a
// gRPC server at the far end standing in for the worker. Closing that server
// is the worker hanging up.
func tunnelTo(t *testing.T, b *Backends, fp string) (worker *grpc.Server) {
	t.Helper()
	near, far := net.Pipe()
	lis := &oneConn{c: make(chan net.Conn, 1), done: make(chan struct{})}
	lis.c <- far
	// The worker's real server options: the tunnel's client pings, and a
	// default server answers that with GOAWAY too_many_pings — which closed
	// the "healthy" replacement and made this test pass or fail by timing.
	srv := grpc.NewServer(tunnel.WorkServerOptions()...)
	go func() { _ = srv.Serve(lis) }()
	var conn *grpc.ClientConn
	conn, err := tunnel.ClientOverConn(near, "passthrough:///worker", func() { b.RemoveConn(fp, conn) })
	if err != nil {
		t.Fatal(err)
	}
	b.Add(fp, conn)
	b.SetProfile(fp, b.NewAttachment(), 1, true)
	return srv
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cond() {
				done <- true
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		done <- false
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Fatalf("%s: not within 5s", what)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: the relay is DEADLOCKED — a Backends call never returned", what)
	}
}

// A worker hanging up must leave the relay working. It used to deadlock it:
// the watcher closed the dead connection while holding the backends lock,
// closing ran the tunnel's close hook, and the hook took the same lock — after
// which every tunnel, attach and RelayStats call queued behind it forever
// (found live: "0 placeable", RelayStats DeadlineExceeded, after one run).
func TestBackends_AWorkerHangingUpDoesNotDeadlockTheRelay(t *testing.T) {
	b := NewBackends()
	worker := tunnelTo(t, b, "w")
	eventually(t, "capacity 1 once attached", func() bool { return b.Capacity() == 1 })
	worker.Stop()
	eventually(t, "the dead tunnel is dropped", func() bool { return b.Count() == 0 })
}

// The close hook of a REPLACED tunnel must not remove its replacement: a worker
// opens a fresh tunnel for every run, so the old one's hook fires while the new
// one is already serving.
func TestBackends_AnOldTunnelClosingKeepsTheNewOne(t *testing.T) {
	b := NewBackends()
	old := tunnelTo(t, b, "w")
	eventually(t, "first tunnel attached", func() bool { return b.Capacity() == 1 })
	tunnelTo(t, b, "w")
	old.Stop()
	time.Sleep(300 * time.Millisecond)
	eventually(t, "the replacement still serves", func() bool { return b.Count() == 1 })
}
