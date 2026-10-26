package handlers

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/cluster/gen/pb"
	"github.com/wandering-compiler/sdk/go/lib/principal"
)

// BanWorkers bans the selected workers; see the proto.
func (h *ClusterServiceHandler) BanWorkers(ctx context.Context, req *pb.DecideWorkersActionReq) (*pb.DecideWorkersActionResp, error) {
	return h.decide(ctx, req, true)
}

// UnbanWorkers lifts the ban on the selected workers; see the proto.
func (h *ClusterServiceHandler) UnbanWorkers(ctx context.Context, req *pb.DecideWorkersActionReq) (*pb.DecideWorkersActionResp, error) {
	return h.decide(ctx, req, false)
}

// decide records the decision under the CALLER's id. Who let a machine back in
// is the first question in an incident, so it is read from the verified
// principal and never taken from the request: a field the client filled could
// name anyone.
func (h *ClusterServiceHandler) decide(ctx context.Context, req *pb.DecideWorkersActionReq, ban bool) (*pb.DecideWorkersActionResp, error) {
	if len(req.GetIds()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cluster: select at least one worker")
	}
	var who pb.Caller
	if err := principal.Envelope(ctx, &who); err != nil || who.GetUserId() == "" {
		return nil, status.Error(codes.Unauthenticated, "cluster: a ban is recorded under the signed-in operator, and there is none")
	}
	if err := h.Workers.Decide(ctx, req.GetIds(), ban, who.GetUserId()); err != nil {
		return nil, err
	}
	h.forgetBans() // the next set sent reads the decision just made
	h.pushBans(ctx, true)
	return &pb.DecideWorkersActionResp{}, nil
}

// pushBans delivers the current ban set to every registered relay now, rather
// than with the next call that happens to reach each one. An enabled relay
// would have it before its next placement anyway; a disabled one would
// otherwise never hear of it and go on renewing the banned worker's
// certificate. Best effort: the decision is recorded, and a relay that
// cannot be reached gets the set with the next delivery (KeepBansDelivered).
//
// logFailures (a decision's push) logs every relay the set did not reach. The
// periodic delivery logs CHANGES instead (deliveryOutcome): a relay, or the
// registry read, that starts failing, with the error, and its recovery — not
// a relay that is deliberately down every few minutes. Silent, a control
// plane that could not deliver at all left a relay refusing every worker
// with nothing anywhere saying why.
//
// The registry reads are bounded (BanReadTimeout). They ran on a context
// with no deadline, so one statement that never returned — a database
// stalled on a full disk — held this call, and with it every later periodic
// delivery, for good: the loop waits for a delivery before the next.
func (h *ClusterServiceHandler) pushBans(ctx context.Context, logFailures bool) {
	if h.Relays == nil || h.Dial == nil {
		return
	}
	base := context.WithoutCancel(ctx)
	read, cancel := context.WithTimeout(base, h.banReadTimeout())
	defer cancel()
	readCtx, err := h.withFreshBans(read)
	if err != nil {
		h.deliveryOutcome(registryKey, err, logFailures,
			"cluster: cannot read the ban set, so no relay is handed one — a relay holding none refuses every worker")
		return
	}
	relays, err := h.Relays.ListAll(readCtx)
	if err != nil {
		h.deliveryOutcome(registryKey, err, logFailures,
			"cluster: cannot list the relays to hand them the ban set")
		return
	}
	h.deliveryOutcome(registryKey, nil, logFailures, "cluster: the ban set and the relay list are read again")
	h.forgetDeliveries(relays)
	// The relays get the set on a context of their own, each bounded by the
	// dial timeout below: the read deadline is not theirs.
	ctx = withBanSetFrom(base, readCtx)
	// The complete registry is in hand: connections to relays deleted since,
	// or re-registered under another url or pin, are closed here.
	h.pruneConns(relays)
	// In parallel, so the operator waits at most one dial timeout however
	// many relays there are, not one per unreachable relay.
	var wg sync.WaitGroup
	for _, r := range relays {
		wg.Add(1)
		go func(r Relay) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, h.dialTimeout())
			defer cancel()
			// The shared connection, so the periodic delivery costs no
			// handshake. Always the complete set (withFreshBans): this is
			// what corrects a relay whose report of the version it holds
			// cannot be trusted.
			conn, err := h.acquire(pctx, r)
			if err == nil {
				_, err = newRelayClient(conn).RelayStats(pctx, &pb.RelayStatsReq{})
				h.release(conn)
				if err != nil {
					h.retireRelay(r.ID)
				}
			}
			if err != nil {
				h.deliveryOutcome(r.ID, err, logFailures,
					fmt.Sprintf("cluster: relay %q did not take the ban set (it gets it with the next delivery)", r.Name))
			} else {
				h.deliveryOutcome(r.ID, nil, logFailures, fmt.Sprintf("cluster: relay %q takes the ban set again", r.Name))
			}
		}(r)
	}
	wg.Wait()
}

// registryKey is deliveryOutcome's key for the registry reads.
const registryKey = "\x00registry"

// banReadTimeout is BanReadTimeout's default.
const banReadTimeout = 30 * time.Second

func (h *ClusterServiceHandler) banReadTimeout() time.Duration {
	if h.BanReadTimeout > 0 {
		return h.BanReadTimeout
	}
	return banReadTimeout
}

// withBanSetFrom carries the ban set read under from onto to.
func withBanSetFrom(to, from context.Context) context.Context {
	if bs, ok := from.Value(banSetKey{}).(banSet); ok {
		return context.WithValue(to, banSetKey{}, bs)
	}
	return to
}

// forgetDeliveries drops the recorded outcome of relays no longer registered,
// so the map does not keep every relay id this replica ever delivered to.
func (h *ClusterServiceHandler) forgetDeliveries(registered []Relay) {
	keep := make(map[string]bool, len(registered))
	for _, r := range registered {
		keep[r.ID] = true
	}
	h.deliveredMu.Lock()
	defer h.deliveredMu.Unlock()
	for key := range h.delivered {
		if key != registryKey && !keep[key] {
			delete(h.delivered, key)
		}
	}
}

// errShape is an error's text with every run of digits masked: two failures
// that differ only in an ephemeral port, an address or a duration ("read tcp
// 10.0.0.2:51234->…: connection reset") are the same failure, and comparing
// the raw text would log a relay that stays down on every round.
func errShape(err error) string {
	var b strings.Builder
	digits := false
	for _, c := range err.Error() {
		if c >= '0' && c <= '9' {
			if !digits {
				b.WriteByte('#')
			}
			digits = true
			continue
		}
		digits = false
		b.WriteRune(c)
	}
	return b.String()
}

// deliveryOutcome records how a ban-set delivery to key went and logs line:
// every failure when always is set, otherwise only a change — the first
// failure (or a different error, by errShape) after a success or none, with
// the error, and the recovery, with the error it recovered from.
func (h *ClusterServiceHandler) deliveryOutcome(key string, err error, always bool, line string) {
	now := delivery{}
	if err != nil {
		now = delivery{shape: errShape(err), text: err.Error()}
	}
	h.deliveredMu.Lock()
	if h.delivered == nil {
		h.delivered = map[string]delivery{}
	}
	before, seen := h.delivered[key]
	h.delivered[key] = now
	h.deliveredMu.Unlock()
	switch {
	case err != nil && (always || !seen || before.shape != now.shape):
		log.Printf("%s: %v", line, err)
	case err == nil && seen && before.shape != "":
		log.Printf("%s (it failed with: %s)", line, before.text)
	}
}

// delivery is one recorded outcome: shape is errShape of the failure ("" =
// it went through), text the failure as it was.
type delivery struct{ shape, text string }

// BanRedeliveryInterval is how often every control-plane replica re-delivers
// the ban set to every registered relay, enabled or not. A relay refuses
// renewals when it has not been delivered one for --ban-set-max-age (an hour
// by default), so this keeps an idle pool's renewals flowing.
const BanRedeliveryInterval = 5 * time.Minute

// KeepBansDelivered re-delivers the ban set to every registered relay every
// interval until ctx ends.
//
// A decision is delivered when it is taken, but a relay unreachable at that
// moment, or restarted without a saved set, would otherwise wait for a
// placement — and a disabled relay gets none. Every replica runs this
// without coordination: the set is versioned and a relay ignores an older
// one, so two deliveries in any order leave the newest.
func (h *ClusterServiceHandler) KeepBansDelivered(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = BanRedeliveryInterval
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h.pushBans(ctx, false)
		}
	}
}
