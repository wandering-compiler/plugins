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
//
// Generic over what is cached because two things are, and both need their
// CURRENCY next to the amount: a figure in minor units means nothing without
// one, and comparing a limit with a spend that are in different currencies is
// the defect totalSpend exists to refuse.
//
// Bounded like idCache, and for the same reason: the key is the caller's
// scope, so one entry per scope ever asked about would otherwise stay for the
// life of the process — expired entries were never evicted.
type spendCache[V any] struct {
	ttl time.Duration
	// max caps the entries held; zero means maxCachedKeys.
	max int

	mu      sync.Mutex
	value   map[string]V
	fetched map[string]time.Time
}

func (c *spendCache[V]) get(scope string, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.fetched[scope]
	if !ok || now.Sub(at) > c.ttl {
		var zero V
		return zero, false
	}
	return c.value[scope], true
}

func (c *spendCache[V]) put(scope string, v V, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.value[scope]; c.value == nil || (!known && len(c.value) >= capOf(c.max)) {
		// Full: start over rather than track recency. See idCache.
		c.value = map[string]V{}
		c.fetched = map[string]time.Time{}
	}
	c.value[scope] = v
	c.fetched[scope] = now
}

// maxCachedKeys bounds every per-key cache in this package.
//
// The keys are the CALLER's — a scope, a model name, a label pair — so a cache
// that keeps one entry per key ever seen grows for the life of the process
// with whatever callers choose to send: a label carrying a run id is a new key
// on every run. Ten thousand entries is far beyond any steady working set the
// caches exist to serve, and small enough not to matter if it is reached.
const maxCachedKeys = 10_000

func capOf(max int) int {
	if max <= 0 {
		return maxCachedKeys
	}
	return max
}

// idCache maps a key to a database id, bounded.
//
// When full it is RESET, not evicted entry by entry: an id is a cheap thing to
// ask for again (one idempotent intern), so the only cost of a reset is a
// burst of re-interning, while an LRU would cost bookkeeping on every hit to
// save that burst. What matters is that the size has a ceiling.
type idCache[K comparable] struct {
	// max caps the entries held; zero means maxCachedKeys.
	max int

	mu  sync.Mutex
	ids map[K]int64
}

func (c *idCache[K]) get(k K) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.ids[k]
	return id, ok
}

func (c *idCache[K]) put(k K, id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, known := c.ids[k]; c.ids == nil || (!known && len(c.ids) >= capOf(c.max)) {
		c.ids = map[K]int64{}
	}
	c.ids[k] = id
}

func (c *idCache[K]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.ids)
}
