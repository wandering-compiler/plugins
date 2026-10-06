package main

import (
	"io"
	"log"
	"time"

	"github.com/wandering-compiler/platform/plugins/cluster/lib/relaycore"
)

// stopper is what a shutdown needs of a *grpc.Server.
type stopper interface {
	GracefulStop()
	Stop()
}

// shutdownPlan is how a relay goes away without cutting the work it carries.
//
// The ORDER is the design:
//
//  1. Drain. No new placement lands here; callers still queued are told
//     RELAY_DRAINING at once and their control plane places them elsewhere.
//  2. Wait — bounded by drainTimeout — until nothing is held: every running
//     task has ended and every granted ticket was redeemed or expired.
//     Everything stays UP meanwhile, on purpose: a granted ticket is redeemed
//     at the proxy and handed to a worker that is found through its ATTACH
//     stream, so stopping attach early would turn a promise into NO_WORKER;
//     and the management API keeps answering, so a control plane reads
//     "draining" instead of recording a failure.
//  3. Stop serving, each GracefulStop bounded by stopTimeout and cut with
//     Stop after it. Attach is Stopped outright: a worker's attach stream is
//     held for as long as the worker lives, so a graceful stop would wait for
//     the worker, not for work.
//  4. Close the tunnel listener.
//
// The process supervisor must allow drainTimeout + a few stopTimeouts before
// it kills — a stop_grace_period shorter than that cuts the runs this exists
// to protect.
type shutdownPlan struct {
	pool                      *relaycore.Pool
	proxy, management, attach stopper
	tunnels                   io.Closer
	drainTimeout, stopTimeout time.Duration
	// poll is how often the wait looks at the pool. Zero uses a second.
	poll time.Duration
}

func (s shutdownPlan) run() {
	s.pool.Drain()

	poll := s.poll
	if poll <= 0 {
		poll = time.Second
	}
	deadline := time.Now().Add(s.drainTimeout)
	for {
		st := s.pool.Stats()
		if st.Held() == 0 {
			break
		}
		if !time.Now().Before(deadline) {
			log.Printf("drain timeout (%s) with %d running and %d promised — stopping anyway",
				s.drainTimeout, st.InUse, st.Reserved)
			break
		}
		time.Sleep(poll)
	}

	boundedStop(s.proxy, s.stopTimeout)
	boundedStop(s.management, s.stopTimeout)
	s.attach.Stop()
	if s.tunnels != nil {
		_ = s.tunnels.Close()
	}
}

// boundedStop gives a server stopTimeout to finish gracefully and then stops
// it. GracefulStop alone waits for every open stream, with no limit — one
// stuck call is a relay that never exits.
func boundedStop(srv stopper, timeout time.Duration) {
	done := make(chan struct{})
	go func() { srv.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		srv.Stop()
		<-done
	}
}
