package handlers

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"

	"github.com/wandering-compiler/plugins/cluster/lib/refusal"
	"github.com/wandering-compiler/plugins/cluster/lib/workeradmit"
)

// relayConn is one relay's management connection, shared by every call this
// replica makes to that relay.
//
// # Why one connection per relay, not one per call
//
// Every placement asks every enabled relay for its load, and every poll of a
// reservation reaches its relay. A connection per call paid a full TLS
// handshake (and a TCP one) per relay per placement and per poll, so the cost
// of one placement grew with the pool in round trips and CPU. One HTTP/2
// connection carries every call to a relay concurrently, and gRPC reconnects
// it on its own when the relay restarts.
//
// It is keyed by the relay's registry id AND its url and pinned fingerprint:
// a row edited to a new address or a rotated certificate gets a new
// connection at once, and the old one is closed when the last call on it
// ends (refs), never under a call still running.
//
// It is a grpc.ClientConnInterface, so every call through it carries the ban
// set (see Invoke): the set once per version, the version alone after that.
type relayConn struct {
	cc  *grpc.ClientConn
	key string

	// held is the ban-set version the relay last said it holds
	// (workeradmit.BannedHeldHeader); 0 = not known, so the next call sends
	// the complete set.
	held atomic.Int64

	// refs and retired are guarded by ClusterServiceHandler.connsMu.
	refs    int
	retired bool
}

// banSetKey carries the ban set a call must deliver, from withBans to
// relayConn, as a context value: what goes on the wire depends on the relay
// the call reaches, which withBans does not know yet.
type banSetKey struct{}

type banSet struct {
	ids     []string
	version int64
	// full sends the complete set whatever the relay said it holds.
	full bool
}

// withBanSet stores the set for relayConn to deliver.
func withBanSet(ctx context.Context, ids []string, version int64, full bool) context.Context {
	return context.WithValue(ctx, banSetKey{}, banSet{ids: ids, version: version, full: full})
}

// outgoing puts the ban set on a call to this relay: the version alone when
// the relay said it holds that version or a newer one, the complete set
// otherwise. Version 0 (nothing was ever decided) always sends the set,
// which is then empty. versionOnly reports which.
func (c *relayConn) outgoing(ctx context.Context) (out context.Context, versionOnly bool) {
	bs, ok := ctx.Value(banSetKey{}).(banSet)
	if !ok {
		return ctx, false
	}
	if !bs.full && bs.version != 0 && c.held.Load() >= bs.version {
		return workeradmit.WithBanVersion(ctx, bs.version), true
	}
	return workeradmit.WithBansAt(ctx, bs.ids, bs.version), false
}

// learnHeld records the version a relay said it holds. A relay that says
// nothing (too old to) leaves it unknown, so it keeps getting the set.
func (c *relayConn) learnHeld(md metadata.MD) {
	if v, ok := workeradmit.HeldFrom(md); ok {
		c.held.Store(v)
	}
}

// Invoke is a unary call carrying the ban set. A relay that holds an older
// set than the version named alone refuses before the call runs
// (BAN_SET_NEEDED); the call is then sent once more with the complete set,
// which cannot be refused that way.
func (c *relayConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	out, versionOnly := c.outgoing(ctx)
	var md metadata.MD
	err := c.cc.Invoke(out, method, args, reply, append(opts, grpc.Header(&md))...)
	c.learnHeld(md)
	if versionOnly && refusal.ReasonOf(err) == refusal.BanSetNeeded {
		c.held.Store(0)
		out, _ = c.outgoing(ctx)
		md = nil
		err = c.cc.Invoke(out, method, args, reply, append(opts, grpc.Header(&md))...)
		c.learnHeld(md)
	}
	return err
}

// NewStream opens a stream carrying the ban set. A stream's refusal arrives
// with its first message, so a BAN_SET_NEEDED is the caller's to retry
// (proxyOne); forgetHeld makes the retry carry the set.
func (c *relayConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	out, _ := c.outgoing(ctx)
	return c.cc.NewStream(out, desc, method, opts...)
}

// forgetHeld makes the next call send the complete set.
func (c *relayConn) forgetHeld() { c.held.Store(0) }

// forgetHeldOnReconnect forgets the held version whenever the connection
// leaves Ready, until it is closed.
//
// gRPC reconnects a ClientConn silently, and what answers at the same url and
// pin afterwards may be another process: a relay restarted without its saved
// set, or rolled back to a version that ignores a ban-set version sent without
// the set. Either would keep its older set while being sent the version alone.
// The first call on the new transport therefore carries the complete set,
// and learns again what the relay holds.
func (c *relayConn) forgetHeldOnReconnect(ctx context.Context) {
	st := c.cc.GetState()
	for st != connectivity.Shutdown {
		if !c.cc.WaitForStateChange(ctx, st) {
			return
		}
		if st == connectivity.Ready {
			c.held.Store(0)
		}
		st = c.cc.GetState()
		if st != connectivity.Ready {
			c.held.Store(0)
		}
	}
}

var errConnsClosed = errors.New("cluster: the control plane is shutting down")

// acquire returns the relay's shared connection, opening it when there is
// none (or the relay's url or pin changed), and waits — bounded by the dial
// timeout — until it is usable. The caller must release it.
//
// grpc.NewClient is lazy, so a connection that will never come up is not an
// error until something waits for it; waiting here is what turns "relay
// unreachable" into something a placement can fall through on while its
// caller is still waiting. A connection that does not come up is retired, so
// the next call dials afresh.
func (h *ClusterServiceHandler) acquire(ctx context.Context, r Relay) (*relayConn, error) {
	key := r.URL + "\x00" + r.Fingerprint
	h.connsMu.Lock()
	if h.connsClosed {
		h.connsMu.Unlock()
		return nil, errConnsClosed
	}
	c := h.conns[r.ID]
	if c != nil && c.key != key {
		h.retireLocked(r.ID, c)
		c = nil
	}
	if c == nil {
		cc, err := h.Dial(r.URL, r.Fingerprint)
		if err != nil {
			h.connsMu.Unlock()
			return nil, err
		}
		c = &relayConn{cc: cc, key: key}
		// Outlives this call: it ends when the connection is closed.
		go c.forgetHeldOnReconnect(context.WithoutCancel(ctx))
		if h.conns == nil {
			h.conns = map[string]*relayConn{}
		}
		h.conns[r.ID] = c
	}
	c.refs++
	h.connsMu.Unlock()

	if err := h.waitReady(ctx, r, c.cc); err != nil {
		h.release(c)
		// Not when the caller left: the connection may be coming up fine,
		// and other calls may be waiting on it.
		if ctx.Err() == nil {
			h.retire(r.ID, c)
		}
		return nil, err
	}
	return c, nil
}

// waitReady waits for a connection to be usable, bounded by the dial timeout.
func (h *ClusterServiceHandler) waitReady(ctx context.Context, r Relay, cc *grpc.ClientConn) error {
	timeout := h.dialTimeout()
	wait, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if cc.GetState() == connectivity.TransientFailure {
		// A relay that was down may be back: try now, not after gRPC's
		// reconnect backoff, which grows to minutes.
		cc.ResetConnectBackoff()
	}
	cc.Connect()
	for {
		switch st := cc.GetState(); st {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return fmt.Errorf("relay %q: connection shut down before it was ready", r.Name)
		default:
			if !cc.WaitForStateChange(wait, st) {
				return fmt.Errorf("relay %q: not reachable within %s", r.Name, timeout)
			}
		}
	}
}

// release ends one call's use of a connection.
func (h *ClusterServiceHandler) release(c *relayConn) {
	h.connsMu.Lock()
	defer h.connsMu.Unlock()
	c.refs--
	if c.retired && c.refs == 0 {
		_ = c.cc.Close()
	}
}

// retire drops a relay's connection so the next call dials afresh. Calls
// still using it keep it until they release it.
func (h *ClusterServiceHandler) retire(id string, c *relayConn) {
	h.connsMu.Lock()
	defer h.connsMu.Unlock()
	h.retireLocked(id, c)
}

// retireRelay retires whatever connection relay id has.
func (h *ClusterServiceHandler) retireRelay(id string) {
	h.connsMu.Lock()
	defer h.connsMu.Unlock()
	if c := h.conns[id]; c != nil {
		h.retireLocked(id, c)
	}
}

func (h *ClusterServiceHandler) retireLocked(id string, c *relayConn) {
	if h.conns[id] == c {
		delete(h.conns, id)
	}
	if c.retired {
		return
	}
	c.retired = true
	if c.refs == 0 {
		_ = c.cc.Close()
	}
}

// pruneConns retires the connections of relays no longer registered, or
// registered under another url or pin. Called with the complete registry.
func (h *ClusterServiceHandler) pruneConns(registered []Relay) {
	keep := make(map[string]string, len(registered))
	for _, r := range registered {
		keep[r.ID] = r.URL + "\x00" + r.Fingerprint
	}
	h.connsMu.Lock()
	defer h.connsMu.Unlock()
	for id, c := range h.conns {
		if key, ok := keep[id]; !ok || key != c.key {
			h.retireLocked(id, c)
		}
	}
}

// Close closes every relay connection and waits, bounded by ctx, for the
// observed-state writes still queued. Calls already running keep their
// connection until they end; new ones are refused.
func (h *ClusterServiceHandler) Close(ctx context.Context) error {
	h.connsMu.Lock()
	h.connsClosed = true
	for id, c := range h.conns {
		h.retireLocked(id, c)
	}
	h.connsMu.Unlock()
	return h.waitObserved(ctx)
}

// observation is what a placement or a poll saw of a relay, waiting to be
// written onto its row. err nil = reached.
type observation struct {
	relay Relay
	err   error
}

// observe records what a placement or poll saw of a relay WITHOUT waiting for
// the write.
//
// The observed state on a relay row is for an operator reading a list; a
// placement must not wait for it. Writing it inline put one database write
// (with its own 5 s timeout) on the path of every placement, so a slow
// registry delayed every caller. Here it is queued, one entry per relay —
// the newest observation replaces an unwritten older one — and written by one
// background flush, so the writes in flight are bounded by the number of
// relays however many placements are under way. Throttled as well (see
// record): an unchanged state is written at most once per reachedEvery.
//
// A failure also retires the relay's connection, so the next call dials
// afresh instead of waiting on one that just failed.
//
// A failure while the CALLER's ctx is done is the caller leaving (cancel,
// deadline), not the relay failing: it is neither recorded nor allowed to
// retire a connection other calls are using.
func (h *ClusterServiceHandler) observe(ctx context.Context, r Relay, err error) {
	if err != nil && ctx.Err() != nil {
		return
	}
	if err != nil {
		h.retireRelay(r.ID)
	}
	if !h.due(r.ID, err) {
		return
	}
	h.obsMu.Lock()
	if h.obsPending == nil {
		h.obsPending = map[string]observation{}
	}
	h.obsPending[r.ID] = observation{relay: r, err: err}
	start := !h.obsRunning
	h.obsRunning = true
	h.obsMu.Unlock()
	if start {
		go h.flushObservations()
	}
}

// flushObservations writes queued observations until none is left. The
// relays of one batch are written in parallel, so a slow registry costs one
// write timeout per batch, not one per relay.
func (h *ClusterServiceHandler) flushObservations() {
	for {
		h.obsMu.Lock()
		if len(h.obsPending) == 0 {
			h.obsRunning = false
			if h.obsIdle != nil {
				h.obsIdle.Broadcast()
			}
			h.obsMu.Unlock()
			return
		}
		batch := h.obsPending
		h.obsPending = nil
		h.obsMu.Unlock()

		var wg sync.WaitGroup
		for _, o := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.record(context.Background(), o.relay, o.err, false)
			}()
		}
		wg.Wait()
	}
}

// waitObserved waits until every queued observation has been written, or
// ctx ends.
func (h *ClusterServiceHandler) waitObserved(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.obsMu.Lock()
		defer h.obsMu.Unlock()
		if h.obsIdle == nil {
			h.obsIdle = sync.NewCond(&h.obsMu)
		}
		for h.obsRunning {
			h.obsIdle.Wait()
		}
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// writtenState is what was last written onto a relay's row by this replica.
type writtenState struct {
	failed bool
	msg    string
	at     time.Time
}

func describe(err error) (failed bool, msg string) {
	if err == nil {
		return false, ""
	}
	return true, err.Error()
}

// due is whether an observation would be written now (see record).
func (h *ClusterServiceHandler) due(id string, err error) bool {
	failed, msg := describe(err)
	h.writtenMu.Lock()
	defer h.writtenMu.Unlock()
	last, ok := h.written[id]
	return !ok || last.failed != failed || last.msg != msg || time.Since(last.at) >= reachedEvery
}

// record writes an observation onto a relay's row. Unless forced, the same
// state (reached, or failed with the same message) is written at most once
// per reachedEvery: a healthy relay is reached on every placement and an
// unreachable one fails on every placement, and neither row needs saying so
// more often. A change of state is written at once. A write that did not
// land is not throttled: the next observation tries again.
//
// Errors are swallowed on purpose: this is bookkeeping for an operator
// reading a list, and a scheduling decision must not fail because a cache
// write did.
func (h *ClusterServiceHandler) record(ctx context.Context, r Relay, cause error, force bool) {
	failed, msg := describe(cause)
	h.writtenMu.Lock()
	last, ok := h.written[r.ID]
	if !force && ok && last.failed == failed && last.msg == msg && time.Since(last.at) < reachedEvery {
		h.writtenMu.Unlock()
		return
	}
	if h.written == nil {
		h.written = map[string]writtenState{}
	}
	h.written[r.ID] = writtenState{failed: failed, msg: msg, at: time.Now()}
	h.writtenMu.Unlock()

	// A fresh context: `ctx` is usually already cancelled by the time a
	// failure is being recorded, and a write on a dead context records
	// nothing — which is exactly the case an operator most needs to see.
	c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var err error
	if failed {
		err = h.Relays.RecordFailed(c, r.ID, msg)
	} else {
		err = h.Relays.RecordReached(c, r.ID)
	}
	if err != nil {
		h.writtenMu.Lock()
		if cur, ok := h.written[r.ID]; ok && cur.failed == failed && cur.msg == msg {
			delete(h.written, r.ID)
		}
		h.writtenMu.Unlock()
	}
}
