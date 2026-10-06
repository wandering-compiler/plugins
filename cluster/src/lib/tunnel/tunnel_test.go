package tunnel

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/platform/plugins/cluster/gen/pb"
)

// The raw codec announces "proto": the WORKER picks its codec by that
// content-subtype, and anything else would make it decode its own real
// messages with a codec that only moves bytes.
func TestRawCodec_IsNamedProto(t *testing.T) {
	if got := (rawCodec{}).Name(); got != "proto" {
		t.Fatalf("raw codec announces %q, want proto", got)
	}
}

// Bytes go through untouched, and anything that is not a *Frame is refused
// rather than silently encoded as nothing.
func TestRawCodec_MovesFramesAndRefusesAnythingElse(t *testing.T) {
	c := rawCodec{}
	out, err := c.Marshal(&Frame{Data: []byte("acme")})
	if err != nil {
		t.Fatal(err)
	}
	var f Frame
	if err := c.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if string(f.Data) != "acme" {
		t.Errorf("round trip gave %q", f.Data)
	}
	if _, err := c.Marshal(&pb.ReserveTaskReq{}); err == nil || !strings.Contains(err.Error(), "only moves *Frame") {
		t.Errorf("a decoded message was marshalled: %v", err)
	}
	if err := c.Unmarshal(mem.BufferSlice{mem.SliceBuffer([]byte("x"))}, &pb.ReserveTaskReq{}); err == nil {
		t.Error("bytes were unmarshalled into something that is not a Frame")
	}
}

// The listener yields its one connection, then BLOCKS rather than erroring —
// grpc.Server treats an Accept error as fatal, which would kill the call
// already running on the conn — until it is closed.
func TestSingleConnListener_YieldsOnceThenBlocksUntilClosed(t *testing.T) {
	near, far := net.Pipe()
	defer func() { _ = far.Close() }()
	l := NewSingleConnListener(near)
	if l.Addr() != near.LocalAddr() {
		t.Errorf("Addr = %v, want the conn's local address", l.Addr())
	}
	c, err := l.Accept()
	if err != nil || c == nil {
		t.Fatalf("first Accept: %v, %v", c, err)
	}
	second := make(chan error, 1)
	go func() { _, err := l.Accept(); second <- err }()
	select {
	case err := <-second:
		t.Fatalf("the second Accept returned at once (%v) — a server would tear itself down", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("a second Close failed: %v", err)
	}
	select {
	case err := <-second:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("after Close: %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release the blocked Accept")
	}
}

// Closing the CONNECTION ends the listener. This is what lets a worker notice
// its tunnel died: the transport closes the socket, Serve's next Accept
// returns, and the worker's loop dials a replacement instead of sitting in a
// Serve that can never end.
func TestSingleConnListener_ClosingTheConnClosesTheListener(t *testing.T) {
	near, far := net.Pipe()
	defer func() { _ = far.Close() }()
	l := NewSingleConnListener(near)
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() { _, err := l.Accept(); second <- err }()
	_ = c.Close()
	_ = c.Close() // a second close must not re-run the hook (it would panic on a closed channel)
	select {
	case err := <-second:
		if !errors.Is(err, ErrClosed) {
			t.Errorf("after the conn closed: %v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the conn closed and Accept is still blocked — Serve would never return")
	}
}

// A gRPC server on the listener ends when its socket does, end to end.
func TestSingleConnListener_ServeReturnsWhenThePeerHangsUp(t *testing.T) {
	near, far := tcpPair(t)
	srv := grpc.NewServer(WorkServerOptions()...)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(NewSingleConnListener(far)) }()
	_ = near.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		srv.Stop()
		t.Fatal("Serve is still running on a tunnel whose peer hung up")
	}
}

// The close hook fires ONCE when the tunnel's socket goes, and the client
// never redials onto it: the socket was the worker's, and handing gRPC a
// closed one forever would keep a dead backend looking like it is connecting.
func TestClientOverConn_ADeadTunnelFiresTheHookOnceAndIsNeverRedialled(t *testing.T) {
	w := newWorker()
	var hooks atomic.Int32
	hooked := make(chan struct{}, 4)
	cc, srv := reversed(t, w, func() { hooks.Add(1); hooked <- struct{}{} })

	// Up first, so what follows is a death and not a failure to start.
	if _, err := pb.NewClusterServiceClient(cc).ReserveTask(bounded(t), &pb.ReserveTaskReq{Label: "x"}); err != nil {
		t.Fatal(err)
	}
	srv.Stop() // the worker hangs up

	select {
	case <-hooked:
	case <-time.After(10 * time.Second):
		t.Fatal("the tunnel died and the close hook never fired")
	}
	// The client keeps trying to reconnect; every attempt must be refused.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for st := cc.GetState(); st != connectivity.TransientFailure && st != connectivity.Idle; st = cc.GetState() {
		if !cc.WaitForStateChange(ctx, st) {
			t.Fatalf("a dead tunnel is stuck in %v", st)
		}
	}
	cc.Connect()
	_, err := pb.NewClusterServiceClient(cc).ReserveTask(ctx, &pb.ReserveTaskReq{}, grpc.WaitForReady(false))
	if status.Code(err) != codes.Unavailable {
		t.Errorf("a call on a dead tunnel: %v, want Unavailable", err)
	}
	if n := hooks.Load(); n != 1 {
		t.Errorf("the close hook fired %d times, want once", n)
	}
}

// The caller's options go LAST and win, so a relay can tighten a default.
func TestClientOverConn_CallerOptionsOverrideTheDefaults(t *testing.T) {
	w := newWorker()
	cc, _ := reversed(t, w, nil, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024)))
	_, err := pb.NewClusterServiceClient(cc).ReserveTask(bounded(t), &pb.ReserveTaskReq{Label: strings.Repeat("a", 4096)})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a 4 KiB answer under a 1 KiB override: %v, want ResourceExhausted — the override was ignored", err)
	}
}
