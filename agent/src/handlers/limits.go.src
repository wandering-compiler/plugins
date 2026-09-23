package handlers

import (
	"context"
	"sync"
	"time"
)

// LimitDecision is what a limiter says about one scope.
type LimitDecision struct {
	// Allowed is false when the scope is over its cap.
	Allowed bool
	// Reason is surfaced to the caller when Allowed is false. Deliberately
	// free of amounts: how much a tenant has spent is not something to leak
	// through an error on somebody else's request.
	Reason string
}

// Limiter decides whether a scope may spend more.
//
// An interface, and always present, for the same reason UsageSink is: the call
// site asks unconditionally, and an activation without `usage_persistence`
// gets an implementation that always allows. A feature check at each call site
// would be a place to forget.
type Limiter interface {
	Allow(ctx context.Context, scope string) LimitDecision
}

// There is deliberately no `Spent(scope, minor)`. Advancing a running total
// after each call would need that call's COST, and nothing on the hot path
// knows it: pricing is a join against the list in force at `started_at`, and
// doing it per completion is the database round trip this design exists to
// avoid. A method nobody can feed honestly is worse than no method — it looks
// like the total is current when it is not.
//
// What bounds the error instead is the refresh interval, stated below.

// allowAllLimiter is what an activation without the feature gets — and what a
// project with the feature but no limit set gets too. Those are different
// situations with the same answer, and neither is an error.
type allowAllLimiter struct{}

func (allowAllLimiter) Allow(context.Context, string) LimitDecision {
	return LimitDecision{Allowed: true}
}

var newLimiter = func(clients any) Limiter { return allowAllLimiter{} }

// NewLimiter builds the limiter for this activation.
func NewLimiter(clients any) Limiter { return newLimiter(clients) }

// spendCache holds a database-sourced spend figure per scope, refreshed at
// most every TTL.
//
// Spend is written asynchronously, so the database is behind by whatever is
// queued, and the cache adds its own TTL on top. A scope can therefore
// overspend by at most what it can buy in (flush interval + TTL) — stated
// here because a cap whose slack is undocumented is a cap somebody will
// believe is exact.
//
// Per-process, too: two replicas each keep their own figure, so the effective
// slack multiplies by the replica count. Removing that needs a shared counter
// consulted per call, which is the round trip this avoids. The trade is the
// design, not an oversight.
type spendCache struct {
	ttl time.Duration

	mu      sync.Mutex
	minor   map[string]int64
	fetched map[string]time.Time
}

func (c *spendCache) get(scope string, now time.Time) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.fetched[scope]
	if !ok || now.Sub(at) > c.ttl {
		return 0, false
	}
	return c.minor[scope], true
}

func (c *spendCache) put(scope string, minor int64, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.minor == nil {
		c.minor = map[string]int64{}
		c.fetched = map[string]time.Time{}
	}
	c.minor[scope] = minor
	c.fetched[scope] = now
}
