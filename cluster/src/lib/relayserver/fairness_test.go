package relayserver

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/relaycore"
	"github.com/wandering-compiler/plugins/cluster/lib/resowner"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// A caller past its share of the queue is refused CALLER_QUEUE_FULL, on a
// reservation and on a stream, while another caller still queues.
func TestServer_ACallerPastItsShareIsCallerQueueFull(t *testing.T) {
	p, err := relaycore.New(relaycore.Options{TicketTTL: time.Minute, PollTimeout: time.Minute, MaxQueue: 4, MaxQueuePerOwner: 1})
	if err != nil {
		t.Fatal(err)
	}
	c := serveManagement(t, configured(t, p))
	alice := resowner.With(t.Context(), "owner-alice")
	if r, err := c.ReserveTask(alice, &pb.ReserveTaskReq{}); err != nil || r.GetQueued() == nil {
		t.Fatalf("first place: %v, %v", r, err)
	}
	_, err = c.ReserveTask(alice, &pb.ReserveTaskReq{})
	if refusal.ReasonOf(err) != refusal.CallerQueueFull || status.Code(err) != codes.ResourceExhausted {
		t.Errorf("second place: %v, want ResourceExhausted CALLER_QUEUE_FULL", err)
	}
	stream, err := c.ScheduleTask(alice, &pb.ScheduleTaskReq{})
	if err == nil {
		_, err = stream.Recv()
	}
	if refusal.ReasonOf(err) != refusal.CallerQueueFull {
		t.Errorf("a stream past the share: %v, want CALLER_QUEUE_FULL", err)
	}
	if r, err := c.ReserveTask(resowner.With(t.Context(), "owner-bob"), &pb.ReserveTaskReq{}); err != nil || r.GetQueued() == nil {
		t.Errorf("another caller: %v, %v; want queued", r, err)
	}
}

// A call naming a ban-set version alone is served when the relay holds that
// version (and counts as a delivery), and refused BAN_SET_NEEDED — before
// the call runs — when it holds an older one or none. Every call that named a
// version is answered with the version held.
func TestBanInterceptors_AVersionAloneNeedsTheSetHeld(t *testing.T) {
	reg := workeradmit.New()
	p := poolWith(t, 4)
	c := serveManagement(t, configured(t, p), BanServerOptions(reg)...)
	stats := func(ctx context.Context) (metadata.MD, error) {
		var hdr metadata.MD
		_, err := c.RelayStats(ctx, &pb.RelayStatsReq{}, grpc.Header(&hdr))
		return hdr, err
	}

	_, err := stats(workeradmit.WithBanVersion(t.Context(), 5))
	if refusal.ReasonOf(err) != refusal.BanSetNeeded || reg.HoldsBanSet() {
		t.Fatalf("a version alone to a relay holding none: %v, want BAN_SET_NEEDED and nothing applied", err)
	}
	hdr, err := stats(workeradmit.WithBansAt(t.Context(), []string{"aa"}, 5))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := workeradmit.HeldFrom(hdr); !ok || v != 5 {
		t.Fatalf("held header %v, want 5", hdr)
	}
	before, _ := reg.LastDelivered()
	time.Sleep(10 * time.Millisecond)
	if hdr, err = stats(workeradmit.WithBanVersion(t.Context(), 5)); err != nil {
		t.Fatalf("the version held, alone: %v", err)
	}
	if after, _ := reg.LastDelivered(); !after.After(before) {
		t.Error("a confirmed version did not count as a delivery")
	}
	if v, _ := workeradmit.HeldFrom(hdr); v != 5 {
		t.Errorf("held header %v, want 5", hdr)
	}
	if _, err := stats(workeradmit.WithBanVersion(t.Context(), 4)); err != nil {
		t.Errorf("an older version alone: %v, want served (the relay holds newer)", err)
	}
	if _, err := stats(workeradmit.WithBanVersion(t.Context(), 6)); refusal.ReasonOf(err) != refusal.BanSetNeeded {
		t.Errorf("a newer version alone: %v, want BAN_SET_NEEDED", err)
	}
	if reg.Admitted("aa") {
		t.Error("the set held was lost")
	}
	// No ban header at all changes nothing and is not refused.
	hdr, err = stats(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := workeradmit.HeldFrom(hdr); ok {
		t.Error("a call naming no version was answered with one")
	}
	// The stream path refuses the same way.
	stream, err := c.ScheduleTask(workeradmit.WithBanVersion(t.Context(), 9), &pb.ScheduleTaskReq{})
	if err == nil {
		_, err = stream.Recv()
	}
	if refusal.ReasonOf(err) != refusal.BanSetNeeded {
		t.Errorf("a stream naming a newer version alone: %v, want BAN_SET_NEEDED", err)
	}
	if st := p.Stats(); st.Held()+st.Queued != 0 {
		t.Errorf("a refused stream took a place: %+v", st)
	}
}
