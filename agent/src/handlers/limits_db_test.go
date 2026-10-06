package handlers

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
)

func newTestLimiter(t *testing.T) (*usageStore, *dbLimiter) {
	t.Helper()
	store, clients := serveUsageStore(t)
	return store, newDBLimiter(clients.UsageQuery(), clients.UsageMutation())
}

func usd(v int64) *pb.ScopeSpendLine { return line(minor(v), "USD", 1) }

// Under the cap is allowed; AT the cap is refused (the cap is what may be
// spent, so reaching it spends it); over is refused. A cap of zero is a real
// value — "this scope may not spend" — and refuses the first call.
func TestDBLimiter_TheCapItself(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limit   int64
		spent   []*pb.ScopeSpendLine
		allowed bool
	}{
		{"under", 1000, []*pb.ScopeSpendLine{usd(400), usd(599)}, true},
		{"exactly at", 1000, []*pb.ScopeSpendLine{usd(400), usd(600)}, false},
		{"over", 1000, []*pb.ScopeSpendLine{usd(5000)}, false},
		{"zero cap, nothing spent", 0, nil, false},
		{"nothing priced yet", 1000, []*pb.ScopeSpendLine{line(nil, "", 0)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, l := newTestLimiter(t)
			store.setLimit("tenant-a", tc.limit, "USD")
			store.setSpend("tenant-a", tc.spent...)
			d := l.Allow(context.Background(), "tenant-a")
			if d.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (%s)", d.Allowed, tc.allowed, d.Reason)
			}
			if !d.Allowed && d.Reason != reasonOverLimit {
				t.Errorf("reason = %q", d.Reason)
			}
		})
	}
}

// The refusal travels back on somebody's request, so it says THAT the cap was
// reached and never by how much: what a tenant spent is not another caller's
// business.
func TestDBLimiter_TheRefusalCarriesNoAmounts(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 12345, "USD")
	store.setSpend("tenant-a", usd(67890))
	d := l.Allow(context.Background(), "tenant-a")
	if d.Allowed {
		t.Fatal("allowed over the cap")
	}
	for _, leak := range []string{"12345", "67890", "123.45", "678.90", "USD"} {
		if strings.Contains(d.Reason, leak) {
			t.Errorf("reason %q leaks %q", d.Reason, leak)
		}
	}
}

// Caps are per scope. One tenant over its cap must not refuse another, and the
// caches that make the limiter cheap are keyed so they cannot cross either.
func TestDBLimiter_TenantsAreIsolated(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 100, "USD")
	store.setSpend("tenant-a", usd(100))
	store.setLimit("tenant-b", 100, "USD")
	store.setSpend("tenant-b", usd(1))

	for i := 0; i < 3; i++ {
		if l.Allow(context.Background(), "tenant-a").Allowed {
			t.Fatal("tenant-a is over its cap and was allowed")
		}
		if !l.Allow(context.Background(), "tenant-b").Allowed {
			t.Fatal("tenant-b was refused for tenant-a's spend")
		}
		if !l.Allow(context.Background(), "tenant-c").Allowed {
			t.Fatal("tenant-c, with no cap at all, was refused")
		}
	}
}

// The limiter sits in front of EVERY model call, so its steady state must cost
// no database round trip: the scope id, the limit (or its absence) and the
// spend are each fetched once and then served from cache.
//
// The scope id was not cached at all: every call ran InternScope — an UPSERT,
// a write — before the provider was reached.
func TestDBLimiter_TheSteadyStateAsksTheDatabaseNothing(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 1000, "USD")
	store.setSpend("tenant-a", usd(1))
	for i := 0; i < 20; i++ {
		if !l.Allow(context.Background(), "tenant-a").Allowed {
			t.Fatal("refused under the cap")
		}
		l.Allow(context.Background(), "tenant-uncapped")
	}
	if n := store.count("InternScope"); n != 2 {
		t.Errorf("InternScope ran %d times for 2 scopes over 40 calls — a write in front of every completion", n)
	}
	if n := store.count("GetScopeLimit"); n != 2 {
		t.Errorf("GetScopeLimit ran %d times — the limit, and the ABSENCE of one, are cached", n)
	}
	if n := store.count("GetScopeSpend"); n != 1 {
		t.Errorf("GetScopeSpend ran %d times — only the capped scope needs its spend, and once per TTL", n)
	}
}

// A transient failure reading the limit fails OPEN — the limiter must not be a
// second outage — but it must not be CACHED as "no limit". It used to be: one
// blip switched a scope's cap off for five minutes, silently. Only NotFound
// means "no cap".
func TestDBLimiter_ATransientLimitErrorDoesNotSwitchTheCapOff(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 100, "USD")
	store.setSpend("tenant-a", usd(500))

	store.failWith("GetScopeLimit", status.Error(codes.Unavailable, "db restarting"), 1)
	if !l.Allow(context.Background(), "tenant-a").Allowed {
		t.Error("an unreachable limit table refused the call — the guard rail became an outage")
	}
	if d := l.Allow(context.Background(), "tenant-a"); d.Allowed {
		t.Error("the call after a transient error was allowed past the cap — the error was cached as \"no limit\"")
	}
}

// …whereas NotFound IS an answer, and is cached.
func TestDBLimiter_NoLimitIsCachedAsAnAnswer(t *testing.T) {
	store, l := newTestLimiter(t)
	for i := 0; i < 5; i++ {
		if !l.Allow(context.Background(), "tenant-a").Allowed {
			t.Fatal("a scope with no cap was refused")
		}
	}
	if n := store.count("GetScopeLimit"); n != 1 {
		t.Errorf("asked for a missing limit %d times", n)
	}
	if n := store.count("GetScopeSpend"); n != 0 {
		t.Errorf("read spend %d times for a scope with no cap", n)
	}
}

// The other database failures fail open too, and are not cached.
func TestDBLimiter_FailsOpenWhenTheDatabaseIsDown(t *testing.T) {
	for _, method := range []string{"InternScope", "GetScopeSpend"} {
		t.Run(method, func(t *testing.T) {
			store, l := newTestLimiter(t)
			store.setLimit("tenant-a", 100, "USD")
			store.setSpend("tenant-a", usd(500))
			store.failWith(method, status.Error(codes.Unavailable, "down"), 1)
			if !l.Allow(context.Background(), "tenant-a").Allowed {
				t.Errorf("%s failing refused the call", method)
			}
			if l.Allow(context.Background(), "tenant-a").Allowed {
				t.Errorf("after %s recovered the cap was not enforced", method)
			}
		})
	}
}

// Spend that cannot be totalled — two currencies — fails CLOSED, with a reason
// an operator can act on.
func TestDBLimiter_MixedCurrencySpendFailsClosed(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 1_000_000, "USD")
	store.setSpend("tenant-a", usd(1), line(minor(1), "EUR", 1))
	d := l.Allow(context.Background(), "tenant-a")
	if d.Allowed || d.Reason != reasonMixedCurrency {
		t.Errorf("decision = %+v, want a refusal naming the currencies", d)
	}
}

// A limit in one currency against spend priced in another cannot be compared —
// minor units are only comparable within a currency.
//
// Nothing compared them: GetScopeLimit returns the limit's currency and the
// limiter dropped it, so a cap of 100.00 EUR (10000 minor) against spend priced
// in a currency with 100× more minor units per euro was crossed a hundredfold
// before refusing — and the other way round, a tenant who had spent nearly
// nothing was refused.
func TestDBLimiter_ALimitInAnotherCurrencyIsNotComparedBlindly(t *testing.T) {
	for _, tc := range []struct {
		name          string
		limitCurrency string
		spend         *pb.ScopeSpendLine
		allowed       bool
		reason        string
	}{
		{"would have passed blindly", "EUR", line(minor(9_000), "JPY", 3), false, reasonLimitCurrency},
		{"would have refused blindly", "JPY", line(minor(20_000), "EUR", 3), false, reasonLimitCurrency},
		{"same currency, any case", "usd", line(minor(9_000), "USD", 3), true, ""},
		{"nothing priced yet", "EUR", line(nil, "", 0), true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, l := newTestLimiter(t)
			store.setLimit("tenant-a", 10_000, tc.limitCurrency)
			store.setSpend("tenant-a", tc.spend)
			d := l.Allow(context.Background(), "tenant-a")
			if d.Allowed != tc.allowed || d.Reason != tc.reason {
				t.Errorf("decision = %+v, want allowed=%v reason=%q", d, tc.allowed, tc.reason)
			}
		})
	}
}

// The cap is MONTHLY: the limit is asked for the month window as of now, and
// spend is summed from the first instant of the current UTC month to now.
func TestDBLimiter_AsksForThisMonth(t *testing.T) {
	store, l := newTestLimiter(t)
	store.setLimit("tenant-a", 100, "USD")
	before := time.Now().UTC()
	l.Allow(context.Background(), "tenant-a")
	after := time.Now().UTC()

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.limitReqs) != 1 || len(store.spendReqs) != 1 {
		t.Fatalf("limit asked %d times, spend %d times", len(store.limitReqs), len(store.spendReqs))
	}
	lr, sr := store.limitReqs[0], store.spendReqs[0]
	id := store.scopes["tenant-a"]
	if lr.GetScopeId() != id || sr.GetScopeId() != id {
		t.Errorf("asked about scope %d / %d, want %d", lr.GetScopeId(), sr.GetScopeId(), id)
	}
	if lr.GetWindow() != pb.LimitWindow_LIMIT_WINDOW_MONTH {
		t.Errorf("window = %v", lr.GetWindow())
	}
	if at := lr.GetAt().AsTime(); at.Before(before) || at.After(after) {
		t.Errorf("limit asked as of %v, want now", at)
	}
	from := sr.GetFrom().AsTime()
	if from.Day() != 1 || from.Hour() != 0 || from.Minute() != 0 || from.Month() != before.Month() || from.Location() != time.UTC {
		t.Errorf("spend summed from %v, want the first instant of this UTC month", from)
	}
	if to := sr.GetTo().AsTime(); !to.After(before) {
		t.Errorf("spend summed to %v — the call that just happened is excluded", to)
	}
}

// No scope, or a blank one, is nothing to cap — and costs no round trip. The
// usage path files a blank scope under ScopeUnattributed; the limiter used to
// intern the literal blank string and check a cap nothing could ever reach.
func TestDBLimiter_ABlankScopeIsNotCapped(t *testing.T) {
	store, l := newTestLimiter(t)
	for _, scope := range []string{"", "   ", "\t"} {
		if !l.Allow(context.Background(), scope).Allowed {
			t.Errorf("scope %q refused", scope)
		}
	}
	if n := store.count("InternScope"); n != 0 {
		t.Errorf("InternScope ran %d times for blank scopes — it interned junk scope rows", n)
	}
}

// The spend figure is cached for its TTL and re-read after it: a scope that
// crosses its cap is refused once the cache turns over, not never.
func TestDBLimiter_SpendIsReReadAfterItsTTL(t *testing.T) {
	store, l := newTestLimiter(t)
	l.spend.ttl = 0 // every call re-reads
	store.setLimit("tenant-a", 100, "USD")
	store.setSpend("tenant-a", usd(10))
	if !l.Allow(context.Background(), "tenant-a").Allowed {
		t.Fatal("refused under the cap")
	}
	store.setSpend("tenant-a", usd(10), usd(95))
	if l.Allow(context.Background(), "tenant-a").Allowed {
		t.Error("the new spend was never read")
	}
}

func TestSpendCacheExpires(t *testing.T) {
	c := &spendCache[int64]{ttl: time.Minute}
	now := time.Now()
	if _, ok := c.get("s", now); ok {
		t.Error("an empty cache answered")
	}
	c.put("s", 7, now)
	if v, ok := c.get("s", now.Add(time.Minute)); !ok || v != 7 {
		t.Errorf("at the TTL: %d, %v", v, ok)
	}
	if _, ok := c.get("s", now.Add(time.Minute+time.Nanosecond)); ok {
		t.Error("an expired figure was served")
	}
	if _, ok := c.get("other", now); ok {
		t.Error("one scope's figure answered for another")
	}
}

// Many goroutines asking at once: every answer is right, and -race is clean.
func TestDBLimiter_ConcurrentCallers(t *testing.T) {
	store, l := newTestLimiter(t)
	for i := 0; i < 4; i++ {
		s := "tenant-" + strconv.Itoa(i)
		store.setLimit(s, 100, "USD")
		store.setSpend(s, usd(int64(i*50)))
	}
	done := make(chan string, 64)
	for g := 0; g < 16; g++ {
		go func() {
			for i := 0; i < 4; i++ {
				s := "tenant-" + strconv.Itoa(i)
				want := i*50 < 100
				if got := l.Allow(context.Background(), s).Allowed; got != want {
					done <- s
					return
				}
			}
			done <- ""
		}()
	}
	for g := 0; g < 16; g++ {
		if s := <-done; s != "" {
			t.Errorf("%s got the wrong answer under concurrency", s)
		}
	}
}

// The scope-id cache is BOUNDED. Its key is whatever scope a caller sends, and
// it used to keep one entry per distinct scope for the life of the process.
// It holds at most two generations of the cap, and a scope it has dropped is
// simply interned again — the answer stays right.
func TestDBLimiter_TheScopeIDCacheIsBounded(t *testing.T) {
	store, l := newTestLimiter(t)
	l.ids.max = 3
	store.setLimit("tenant-0", 0, "USD")
	for i := 0; i < 20; i++ {
		l.Allow(context.Background(), "tenant-"+strconv.Itoa(i))
		if n := l.ids.len(); n > 6 {
			t.Fatalf("after %d scopes the id cache holds %d, want at most 6 (two generations of 3)", i+1, n)
		}
	}
	// Dropped by the generations rolling over, and still answered correctly.
	if l.Allow(context.Background(), "tenant-0").Allowed {
		t.Error("a scope re-interned after being dropped lost its cap")
	}
	// Within the cap the steady state still asks nothing.
	before := store.count("InternScope")
	l.Allow(context.Background(), "tenant-0")
	if store.count("InternScope") != before {
		t.Error("a cached scope was interned again")
	}
}

// The spend and limit caches are bounded the same way: expired entries were
// never evicted, so every scope ever asked about stayed.
func TestSpendCacheIsBounded(t *testing.T) {
	c := &spendCache[int64]{ttl: time.Minute, max: 2}
	now := time.Now()
	for i := 0; i < 10; i++ {
		c.put("s"+strconv.Itoa(i), int64(i), now)
		if n := c.len(); n > 4 {
			t.Fatalf("after %d puts the cache holds %d, want at most 4 (two generations of 2)", i+1, n)
		}
	}
	if v, ok := c.get("s9", now); !ok || v != 9 {
		t.Errorf("the newest entry was lost: %d, %v", v, ok)
	}
	// Re-putting a key it holds is not growth and does not reset.
	c.put("s9", 10, now)
	if v, ok := c.get("s8", now); !ok || v != 8 {
		t.Errorf("updating a held key reset the cache: %d, %v", v, ok)
	}
}

// A key in USE survives a flood of new ones, and the size stays bounded.
//
// The caches used to RESET at the cap: past it, every new key emptied the
// whole map once per cap's worth of keys — and since the keys are the
// callers', anyone sending random scopes could keep evicting every legitimate
// tenant's entry, turning each of their calls into a database round trip.
func TestCaches_AHotKeySurvivesAFlood(t *testing.T) {
	const max = 3
	ids := &idCache[string]{max: max}
	spend := &spendCache[int64]{ttl: time.Hour, max: max}
	now := time.Now()
	ids.put("hot", 42)
	spend.put("hot", 42, now)
	for i := 0; i < 1000; i++ {
		k := "flood-" + strconv.Itoa(i)
		ids.put(k, int64(i))
		spend.put(k, int64(i), now)
		if id, ok := ids.get("hot"); !ok || id != 42 {
			t.Fatalf("idCache: the hot key was evicted after %d flood keys (%d, %v)", i+1, id, ok)
		}
		if v, ok := spend.get("hot", now); !ok || v != 42 {
			t.Fatalf("spendCache: the hot key was evicted after %d flood keys (%d, %v)", i+1, v, ok)
		}
		if n := ids.len(); n > 2*max {
			t.Fatalf("idCache holds %d after %d flood keys, want at most %d", n, i+1, 2*max)
		}
		if n := spend.len(); n > 2*max {
			t.Fatalf("spendCache holds %d after %d flood keys, want at most %d", n, i+1, 2*max)
		}
	}
	// A cold key does fall out: bounded means something is dropped.
	if _, ok := ids.get("flood-0"); ok {
		t.Error("a key never read again survived a thousand newer ones — the cache is not bounded")
	}
}

// A promoted key keeps the value it was last PUT with: an update that lands in
// the current generation is not undone by an older copy in the previous one.
func TestGenerations_AnUpdateIsNotResurrectedByPromotion(t *testing.T) {
	var g generations[string, int]
	g.put("k", 1, 2)
	g.put("a", 0, 2)
	g.put("b", 0, 2) // rotates: k is now in the previous generation
	g.put("k", 2, 2)
	if v, ok := g.get("k", 2); !ok || v != 2 {
		t.Errorf("get = %d, %v — want the updated 2", v, ok)
	}
}

// An EXPIRED entry in the previous generation is a miss and is not promoted.
//
// get used to promote first and check the TTL after, so reading a stale key
// copied it into a FULL current generation — rotating it, which threw away the
// whole previous generation of live entries — only to answer "miss" anyway.
func TestSpendCache_AnExpiredEntryIsNotPromoted(t *testing.T) {
	c := &spendCache[int64]{ttl: time.Minute, max: 2}
	old := time.Now()
	now := old.Add(time.Hour)
	c.put("stale", 1, old)
	c.put("live-a", 2, now) // current: stale, live-a
	c.put("live-b", 3, now) // rotates: previous = {stale, live-a}, current = {live-b}
	c.put("live-c", 4, now) // current: live-b, live-c — full

	if _, ok := c.get("stale", now); ok {
		t.Fatal("an expired entry was served")
	}
	// Had "stale" been promoted into the full current generation, current would
	// have rotated into previous and live-a — still fresh — would be gone.
	if v, ok := c.get("live-a", now); !ok || v != 2 {
		t.Errorf("live-a = %d, %v — reading an expired key evicted a live one", v, ok)
	}
	if v, ok := c.get("live-b", now); !ok || v != 3 {
		t.Errorf("live-b = %d, %v", v, ok)
	}
	if n := c.len(); n != 3 {
		t.Errorf("the cache holds %d entries, want 3 — the expired one dropped, nothing else", n)
	}
}
