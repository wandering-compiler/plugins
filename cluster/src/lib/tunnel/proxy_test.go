package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/workerpb"
)

// worker is what sits at the far end of a tunnel. It speaks two contracts the
// relay has never seen descriptors for — ClusterService (unary and
// server-streaming) and WorkerAttach (bidirectional) — so every call shape
// the proxy claims to carry has a real method behind it.
type worker struct {
	pb.UnimplementedClusterServiceServer
	workerpb.UnimplementedWorkerAttachServer

	mu     sync.Mutex
	seenMD metadata.MD

	// started is told when RelayStats begins; cancelled when its ctx ends.
	started   chan struct{}
	cancelled chan struct{}
}

func newWorker() *worker {
	return &worker{started: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
}

func (w *worker) metadata() metadata.MD {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seenMD
}

// ReserveTask echoes the label, records the caller's metadata, and answers
// with headers and trailers of its own.
func (w *worker) ReserveTask(ctx context.Context, req *pb.ReserveTaskReq) (*pb.ReservationState, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	w.mu.Lock()
	w.seenMD = md.Copy()
	w.mu.Unlock()
	_ = grpc.SetHeader(ctx, metadata.Pairs("x-worker-header", "from-acme-worker"))
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-worker-trailer", "done"))
	return &pb.ReservationState{Reservation: req.GetLabel(), PollAfterMs: 7}, nil
}

// CheckWorkers refuses the way a worker's own admission gate does: a code, a
// message and a reason the caller branches on.
func (w *worker) CheckWorkers(ctx context.Context, _ *pb.CheckWorkersReq) (*pb.CheckWorkersResp, error) {
	_ = grpc.SetTrailer(ctx, metadata.Pairs("x-worker-trailer", "refused"))
	return nil, refusal.New(codes.ResourceExhausted, refusal.AdmissionFull, "worker: memory gate is full")
}

// RelayStats blocks until the CALLER goes away, and says when it noticed.
func (w *worker) RelayStats(ctx context.Context, _ *pb.RelayStatsReq) (*pb.RelayStatsResp, error) {
	w.started <- struct{}{}
	<-ctx.Done()
	w.cancelled <- struct{}{}
	return nil, ctx.Err()
}

// ScheduleTask streams three queue positions and a grant.
func (w *worker) ScheduleTask(_ *pb.ScheduleTaskReq, srv grpc.ServerStreamingServer[pb.ScheduleTaskEvent]) error {
	for i := int32(3); i >= 1; i-- {
		if err := srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Queued{
			Queued: &pb.TaskQueued{Position: i},
		}}); err != nil {
			return err
		}
	}
	return srv.Send(&pb.ScheduleTaskEvent{Event: &pb.ScheduleTaskEvent_Granted{
		Granted: &pb.TaskGranted{Ticket: "t-acme"},
	}})
}

// Attach reads EVERY message until the caller closes its send side and only
// then answers, with the sum of the slots it was told. A worker of this shape
// waits for end-of-stream before it says anything, so it hangs unless the
// proxy forwards the caller's CloseSend.
func (w *worker) Attach(srv grpc.BidiStreamingServer[workerpb.WorkerMessage, workerpb.AttachEvent]) error {
	var sum uint32
	for {
		m, err := srv.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		sum += m.GetAnnounce().GetSlots()
	}
	return srv.Send(&workerpb.AttachEvent{Event: &workerpb.AttachEvent_Admitted{
		Admitted: &workerpb.Admitted{Slots: sum},
	}})
}

// tcpPair is two ends of one real loopback TCP connection.
func tcpPair(t *testing.T) (near, far net.Conn) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lis.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lis.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	near, err = net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	far, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	return near, far
}

// reversed is a tunnel the way the cluster builds one: the WORKER serves on a
// socket it holds, the RELAY speaks client over the other end of it.
func reversed(t *testing.T, w *worker, onClose func(), opts ...grpc.DialOption) (*grpc.ClientConn, *grpc.Server) {
	t.Helper()
	near, far := tcpPair(t)
	srv := grpc.NewServer(WorkServerOptions()...)
	pb.RegisterClusterServiceServer(srv, w)
	workerpb.RegisterWorkerAttachServer(srv, w)
	go func() { _ = srv.Serve(NewSingleConnListener(far)) }()
	t.Cleanup(srv.Stop)
	cc, err := ClientOverConn(near, "passthrough:///worker", onClose, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc, srv
}

// releases counts how often a backend was let go, and says so on a channel.
type releases struct {
	n    atomic.Int32
	done chan struct{}
}

func newReleases() *releases { return &releases{done: make(chan struct{}, 8)} }

func (r *releases) release() { r.n.Add(1); r.done <- struct{}{} }

// await waits for the first release, then checks no second one follows the
// handler's return. Release is deferred in the handler, so the caller can see
// its answer a moment before it runs.
func (r *releases) await(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the backend was never released — the worker's slot would leak until a restart")
	}
	if n := r.n.Load(); n != 1 {
		t.Fatalf("the backend was released %d times, want exactly once", n)
	}
}

// proxy stands up a relay's proxy in front of `pick` and returns a caller's
// connection to it.
func proxy(t *testing.T, pick Picker) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(ProxyServerOptions(pick)...)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	cc, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMessage), grpc.MaxCallSendMsgSize(MaxMessage)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

// bounded is a call context that FAILS a test rather than hanging it: a proxy
// that lost the caller's end-of-stream leaves a streaming worker waiting
// forever, and that regression has to read as a failure, not as a timeout of
// the whole test binary.
func bounded(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// rig is the whole path: caller → proxy → tunnel → worker.
func rig(t *testing.T) (*worker, *grpc.ClientConn, *releases) {
	t.Helper()
	w := newWorker()
	backend, _ := reversed(t, w, nil)
	rel := newReleases()
	cc := proxy(t, func(context.Context, string) (Backend, error) {
		return Backend{Conn: backend, Release: rel.release}, nil
	})
	return w, cc, rel
}

// A unary call made to the relay is answered by the worker, and everything
// around the message travels too: the caller's metadata reaches the worker
// unedited, and the worker's headers and trailers reach the caller. A proxy
// that dropped either would be a second place the worker's contract lives.
func TestHandler_AUnaryCallRoundTripsWithItsMetadata(t *testing.T) {
	w, cc, rel := rig(t)
	ctx := metadata.AppendToOutgoingContext(bounded(t),
		"w17-cluster-ticket", "t-acme", "x-tenant", "tenant-a", "x-blob-bin", string([]byte{0, 1, 2}))
	var header, trailer metadata.MD
	resp, err := pb.NewClusterServiceClient(cc).ReserveTask(ctx, &pb.ReserveTaskReq{Label: "build acme"},
		grpc.Header(&header), grpc.Trailer(&trailer))
	if err != nil {
		t.Fatalf("a call through the proxy failed: %v", err)
	}
	if resp.GetReservation() != "build acme" || resp.GetPollAfterMs() != 7 {
		t.Errorf("the worker's answer did not survive the hop: %v", resp)
	}
	md := w.metadata()
	for k, want := range map[string]string{
		"w17-cluster-ticket": "t-acme", "x-tenant": "tenant-a", "x-blob-bin": string([]byte{0, 1, 2}),
	} {
		if got := md.Get(k); len(got) != 1 || got[0] != want {
			t.Errorf("the worker saw %s = %q, want %q", k, got, want)
		}
	}
	if got := header.Get("x-worker-header"); len(got) != 1 || got[0] != "from-acme-worker" {
		t.Errorf("the worker's header reached the caller as %q", got)
	}
	if got := trailer.Get("x-worker-trailer"); len(got) != 1 || got[0] != "done" {
		t.Errorf("the worker's trailer reached the caller as %q", got)
	}
	rel.await(t)
}

// A worker's refusal reaches the caller as the worker said it: the code, the
// message, and the reason a caller branches on. A proxy that dropped the
// trailers would turn every worker-side refusal into a bare Unknown, and a
// retryable ADMISSION_FULL into something nobody retries.
func TestHandler_AWorkerErrorKeepsItsCodeMessageAndReason(t *testing.T) {
	_, cc, rel := rig(t)
	var trailer metadata.MD
	_, err := pb.NewClusterServiceClient(cc).CheckWorkers(bounded(t), &pb.CheckWorkersReq{}, grpc.Trailer(&trailer))
	st := status.Convert(err)
	if st.Code() != codes.ResourceExhausted || st.Message() != "worker: memory gate is full" {
		t.Errorf("the worker's error arrived as %v / %q", st.Code(), st.Message())
	}
	if got := refusal.ReasonOf(err); got != refusal.AdmissionFull {
		t.Errorf("the refusal reason arrived as %q, want %s", got, refusal.AdmissionFull)
	}
	if got := trailer.Get("x-worker-trailer"); len(got) != 1 || got[0] != "refused" {
		t.Errorf("the worker's trailer on an error reached the caller as %q", got)
	}
	rel.await(t)
}

// A server stream arrives whole and in order: every queue position, then the
// grant. The proxy has no descriptor saying the method streams; it must carry
// it anyway.
func TestHandler_AServerStreamArrivesInOrder(t *testing.T) {
	_, cc, rel := rig(t)
	stream, err := pb.NewClusterServiceClient(cc).ScheduleTask(bounded(t), &pb.ScheduleTaskReq{Label: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("the stream broke after %v: %v", got, err)
		}
		switch e := ev.GetEvent().(type) {
		case *pb.ScheduleTaskEvent_Queued:
			got = append(got, "q"+strconv.Itoa(int(e.Queued.GetPosition())))
		case *pb.ScheduleTaskEvent_Granted:
			got = append(got, "granted:"+e.Granted.GetTicket())
		}
	}
	if want := "q3 q2 q1 granted:t-acme"; strings.Join(got, " ") != want {
		t.Errorf("the caller saw %v, want %s", got, want)
	}
	rel.await(t)
}

// The caller ending its send side reaches the worker as end-of-stream. A
// worker that answers only after the last message — every client-streaming
// method — would otherwise wait forever on a caller that is waiting for it.
func TestHandler_TheCallersCloseSendReachesTheWorker(t *testing.T) {
	_, cc, rel := rig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := workerpb.NewWorkerAttachClient(cc).Attach(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []uint32{1, 2, 4} {
		if err := stream.Send(&workerpb.WorkerMessage{Msg: &workerpb.WorkerMessage_Announce{
			Announce: &workerpb.AttachReq{Name: "vps-1", Slots: n},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("the worker never answered — the caller's end-of-stream did not reach it: %v", err)
	}
	if got := ev.GetAdmitted().GetSlots(); got != 7 {
		t.Errorf("the worker summed %d, want 7 — messages were lost or reordered", got)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Errorf("after the answer: %v, want a clean end", err)
	}
	rel.await(t)
}

// A message over gRPC's 4 MiB default crosses both ways — the proxy's server
// and the relay's client over the tunnel both carry MaxMessage.
func TestHandler_AMessageOverTheDefaultCapCrosses(t *testing.T) {
	_, cc, rel := rig(t)
	big := strings.Repeat("a", 6<<20)
	resp, err := pb.NewClusterServiceClient(cc).ReserveTask(bounded(t), &pb.ReserveTaskReq{Label: big})
	if err != nil {
		t.Fatalf("a 6 MiB message did not cross the proxy: %v", err)
	}
	if len(resp.GetReservation()) != len(big) {
		t.Errorf("echoed %d bytes, want %d", len(resp.GetReservation()), len(big))
	}
	rel.await(t)
}

// A caller that goes away cancels the worker's call, and the slot is given
// back. Otherwise abandoned work keeps running on a machine nobody is waiting
// for, holding a slot the pool believes is busy.
func TestHandler_CallerCancellationReachesTheWorker(t *testing.T) {
	w, cc, rel := rig(t)
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := pb.NewClusterServiceClient(cc).RelayStats(ctx, &pb.RelayStatsReq{})
		errc <- err
	}()
	select {
	case <-w.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the call never reached the worker")
	}
	cancel()
	select {
	case <-w.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the caller left and the worker's call is still running")
	}
	if err := <-errc; status.Code(err) != codes.Canceled {
		t.Errorf("the caller saw %v, want Canceled", err)
	}
	rel.await(t)
}

// What the picker refuses with is what the caller reads, untouched: the
// reasons a relay gives (no ticket, no worker) are the caller's next step.
func TestHandler_APickerRefusalReachesTheCallerAsIs(t *testing.T) {
	called := atomic.Int32{}
	cc := proxy(t, func(_ context.Context, method string) (Backend, error) {
		called.Add(1)
		if method != "/w17.contrib.cluster.ClusterService/ReserveTask" {
			return Backend{}, status.Errorf(codes.Internal, "picker saw method %q", method)
		}
		return Backend{}, refusal.New(codes.Unauthenticated, refusal.TicketMissing, "relay: no ticket")
	})
	_, err := pb.NewClusterServiceClient(cc).ReserveTask(bounded(t), &pb.ReserveTaskReq{})
	if st := status.Convert(err); st.Code() != codes.Unauthenticated || st.Message() != "relay: no ticket" {
		t.Errorf("the caller saw %v / %q", st.Code(), st.Message())
	}
	if refusal.ReasonOf(err) != refusal.TicketMissing {
		t.Errorf("the reason was lost: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("picker called %d times", called.Load())
	}
}

// A picked worker whose tunnel cannot open the call is WORKER_LOST — the relay
// failing to deliver, said with a reason — and the slot is still released.
func TestHandler_ADeadBackendIsWorkerLostAndReleased(t *testing.T) {
	dead, err := grpc.NewClient("passthrough:///gone", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.Close()
	rel := newReleases()
	cc := proxy(t, func(context.Context, string) (Backend, error) {
		return Backend{Conn: dead, Release: rel.release}, nil
	})
	_, err = pb.NewClusterServiceClient(cc).ReserveTask(bounded(t), &pb.ReserveTaskReq{})
	if got := refusal.ReasonOf(err); got != refusal.WorkerLost {
		t.Errorf("a dead backend answered %v (reason %q), want %s", err, got, refusal.WorkerLost)
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", status.Code(err))
	}
	rel.await(t)
}
