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
	// max caps the entries held per generation; zero means maxCachedKeys.
	max int

	mu      sync.Mutex
	entries generations[string, fetchedValue[V]]
}

// fetchedValue is a cached figure and when it was read.
type fetchedValue[V any] struct {
	v  V
	at time.Time
}

func (c *spendCache[V]) get(scope string, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// The TTL is checked BEFORE a previous-generation entry is promoted. It
	// used to be checked after: an expired entry was copied back into the
	// current generation first — taking a slot there, and when current was
	// full, ROTATING it, which dropped the whole previous generation of live
	// entries — only to be reported a miss and overwritten by the refetch.
	e, ok := c.entries.getIf(scope, capOf(c.max), func(e fetchedValue[V]) bool {
		return now.Sub(e.at) <= c.ttl
	})
	if !ok {
		var zero V
		return zero, false
	}
	return e.v, true
}

func (c *spendCache[V]) put(scope string, v V, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries.put(scope, fetchedValue[V]{v: v, at: now}, capOf(c.max))
}

func (c *spendCache[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.entries.len()
}

// maxCachedKeys bounds every per-key cache in this package, per generation (see
// generations: a cache holds at most twice this).
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

// generations is a bounded map that keeps what is USED: two generations,
// current and previous. Writes go to current; when current is full, it becomes
// previous (the old previous is dropped whole) and a new current starts. A
// read that finds its key only in previous promotes it back into current.
//
// It replaced a reset-at-cap map, which dropped EVERY entry the moment the
// cap was reached. Past ten thousand active keys that was a reset every ten
// thousand new keys — and because the keys are the callers', anyone sending
// random scopes could keep emptying the cache under every legitimate tenant,
// turning each of their calls into a database round trip. Here a key in use
// survives any flood of new ones as long as it is read once per generation,
// and the size is still bounded: at most 2×max.
//
// A miss costs only a refetch from the database; an LRU would cost bookkeeping
// on every hit to save that, and this needs none. Not safe for concurrent use:
// the owning cache holds the lock.
type generations[K comparable, V any] struct {
	cur, prev map[K]V
}

func (g *generations[K, V]) get(k K, max int) (V, bool) {
	return g.getIf(k, max, nil)
}

// getIf is get for values that can go stale: a value `fresh` rejects is a miss,
// and one found in the previous generation is DROPPED rather than promoted —
// promoting it would spend a slot in current (and possibly rotate it) on an
// entry about to be replaced. A nil `fresh` accepts everything.
func (g *generations[K, V]) getIf(k K, max int, fresh func(V) bool) (V, bool) {
	var zero V
	if v, ok := g.cur[k]; ok {
		if fresh != nil && !fresh(v) {
			return zero, false
		}
		return v, true
	}
	v, ok := g.prev[k]
	if !ok {
		return zero, false
	}
	delete(g.prev, k)
	if fresh != nil && !fresh(v) {
		return zero, false
	}
	g.put(k, v, max)
	return v, true
}

func (g *generations[K, V]) put(k K, v V, max int) {
	if g.cur == nil {
		g.cur = map[K]V{}
	}
	if _, known := g.cur[k]; !known && len(g.cur) >= max {
		g.prev, g.cur = g.cur, map[K]V{}
	}
	// A newer value supersedes any copy left in the previous generation, which
	// a later promotion would otherwise resurrect.
	delete(g.prev, k)
	g.cur[k] = v
}

func (g *generations[K, V]) len() int { return len(g.cur) + len(g.prev) }

// idCache maps a key to a database id, bounded by generations: an id is a
// cheap thing to ask for again (one idempotent intern), so a dropped one costs
// a single re-intern, and one in use is never dropped.
type idCache[K comparable] struct {
	// max caps the entries held per generation; zero means maxCachedKeys.
	max int

	mu  sync.Mutex
	ids generations[K, int64]
}

func (c *idCache[K]) get(k K) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ids.get(k, capOf(c.max))
}

func (c *idCache[K]) put(k K, id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids.put(k, id, capOf(c.max))
}

func (c *idCache[K]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ids.len()
}
