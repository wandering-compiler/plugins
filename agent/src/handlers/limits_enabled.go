package handlers

import (
	"context"
	"strconv"
	"strings"
	"time"

	pb "github.com/wandering-compiler/plugins/agent/gen/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Staged only when `usage_persistence` is active — the limit lives in a table
// that otherwise does not exist. See handlers/limits.go for why the seam is a
// package variable rather than two declarations of one function.
func init() {
	newLimiter = func(clients any) Limiter {
		qc, ok := clients.(interface {
			UsageQuery() pb.UsageQueryClient
		})
		mc, ok2 := clients.(interface {
			UsageMutation() pb.UsageMutationClient
		})
		if !ok || !ok2 {
			return allowAllLimiter{}
		}
		return newDBLimiter(qc.UsageQuery(), mc.UsageMutation())
	}
}

func newDBLimiter(q pb.UsageQueryClient, m pb.UsageMutationClient) *dbLimiter {
	return &dbLimiter{
		q:      q,
		m:      m,
		spend:  &spendCache[scopeSpend]{ttl: 30 * time.Second},
		limits: &spendCache[scopeLimit]{ttl: 5 * time.Minute},
	}
}

// scopeLimit is one scope's cap as last read. `none` is the cached ABSENCE of a
// cap — most scopes have none, and asking again on every call to learn that is
// the round trip the cache exists to save.
type scopeLimit struct {
	minor    int64
	currency string
	none     bool
}

// scopeSpend is one scope's spend within one window as last read. currency is
// empty when nothing priced was spent. refused is the fail-closed reason when
// the spend could not be totalled at all; it is cached like a figure, so a
// refused scope does not cost a spend read on every call it makes.
type scopeSpend struct {
	minor    int64
	currency string
	refused  string
}

// dbLimiter enforces a per-scope cap in every window a limit can be set in:
// the UTC day, the UTC month and all time (limitWindows).
type dbLimiter struct {
	q pb.UsageQueryClient
	m pb.UsageMutationClient

	spend  *spendCache[scopeSpend]
	limits *spendCache[scopeLimit]

	// Scope ids, cached: an id is stable for the life of its row. Without this
	// every model call ran an UPSERT — a write — in front of the provider,
	// which is the per-call database round trip this whole design exists to
	// avoid; the comment on scopeID claimed the id was cached "by that path
	// too", and the path it meant was the writer's, a different cache this one
	// never reads.
	//
	// BOUNDED (idCache): the key is whatever scope a caller sends, so an
	// unbounded map grew by one entry per distinct scope for the life of the
	// process.
	ids idCache[string]
}

const (
	reasonOverLimit = "agent: this scope has reached its spending limit"

	reasonUnpriced = "agent: this scope has a spending limit and has made calls on a model with no " +
		"price, so its spending cannot be totalled. Price the model from before those calls (a price " +
		"reaches only calls made after its valid_from), or lift the limit."

	reasonMixedCurrency = "agent: this scope's spending cannot be totalled — its models are priced in " +
		"more than one currency, and a limit is a single amount. Price them alike, or lift the limit."

	reasonLimitCurrency = "agent: this scope's limit is set in a different currency from the one its " +
		"models are priced in, so the two cannot be compared. Set the limit in the pricing currency, or lift it."
)

func (l *dbLimiter) Allow(ctx context.Context, scope string) LimitDecision {
	if strings.TrimSpace(scope) == "" {
		// Nothing to charge means nothing to cap. Refusing here would make a
		// caller that does not use scopes unable to call the model at all.
		//
		// BLANK, not only empty: the usage path files a whitespace scope under
		// ScopeUnattributed, so asking about the literal "  " interned a scope
		// row nothing is ever recorded against and checked a limit nothing can
		// ever reach.
		return LimitDecision{Allowed: true}
	}
	now := time.Now().UTC()

	scopeID, err := l.scopeID(ctx, scope)
	if err != nil {
		// A limiter that cannot reach the database must not become a second
		// outage: the cap is a guard rail, and taking the service down to
		// enforce it trades a bounded overspend for a total one.
		return LimitDecision{Allowed: true}
	}

	// Every window a limit can be set in is enforced. Only MONTH used to be
	// asked, so a DAY or TOTAL limit was accepted, read back and enforced
	// nothing. The first window that refuses answers.
	for _, w := range limitWindows {
		if d := l.allowIn(ctx, scope, scopeID, w, now); !d.Allowed {
			return d
		}
	}
	return LimitDecision{Allowed: true}
}

// limitWindows are the windows Allow checks, each with where it starts.
var limitWindows = []pb.LimitWindow{
	pb.LimitWindow_LIMIT_WINDOW_DAY,
	pb.LimitWindow_LIMIT_WINDOW_MONTH,
	pb.LimitWindow_LIMIT_WINDOW_TOTAL,
}

// windowStart is the first instant a window counts spend from.
func windowStart(w pb.LimitWindow, now time.Time) time.Time {
	switch w {
	case pb.LimitWindow_LIMIT_WINDOW_DAY:
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	case pb.LimitWindow_LIMIT_WINDOW_MONTH:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Unix(0, 0).UTC()
	}
}

// allowIn decides one window: its limit, then the scope's spend within it.
func (l *dbLimiter) allowIn(ctx context.Context, scope string, scopeID int64, w pb.LimitWindow, now time.Time) LimitDecision {
	key := scope + "\x00" + w.String()
	limit, ok := l.limits.get(key, now)
	if !ok {
		resp, lErr := l.q.GetScopeLimit(ctx, &pb.GetScopeLimitReq{
			ScopeId: scopeID,
			Window:  w,
			At:      timestamppb.New(now),
		})
		switch {
		case status.Code(lErr) == codes.NotFound:
			// No row is the common case — most scopes have no cap — and it
			// arrives as NotFound. Cache the absence so a scope without a
			// limit does not ask on every call.
			l.limits.put(key, scopeLimit{none: true}, now)
			return LimitDecision{Allowed: true}
		case lErr != nil:
			// Any OTHER failure is the database, not an answer. Fail open as
			// everywhere else — but do not CACHE it: this used to store "no
			// limit" for every error, so one transient blip switched a scope's
			// cap off for the limit cache's whole TTL (five minutes) with
			// nothing to say so.
			return LimitDecision{Allowed: true}
		}
		limit = scopeLimit{minor: resp.GetLimitMinor(), currency: resp.GetCurrency()}
		l.limits.put(key, limit, now)
	}
	if limit.none || limit.minor < 0 {
		return LimitDecision{Allowed: true}
	}

	// The window's start is part of the spend key: a figure read just before
	// midnight UTC (or the month's end) is yesterday's total, and reusing it
	// for its TTL into the new window refused a scope that had spent nothing
	// in it yet.
	spendKey := key + "\x00" + strconv.FormatInt(windowStart(w, now).Unix(), 10)
	spent, ok := l.spend.get(spendKey, now)
	if !ok {
		resp, sErr := l.q.GetScopeSpend(ctx, &pb.GetScopeSpendReq{
			ScopeId: scopeID,
			From:    timestamppb.New(windowStart(w, now)),
			To:      timestamppb.New(now.Add(time.Second)),
		})
		if sErr != nil {
			return LimitDecision{Allowed: true}
		}
		total, currency, verdict := totalSpend(resp.GetLines())
		if verdict != "" {
			// Fail CLOSED, and this is one of the two places in this file
			// that does. Everywhere else the limiter fails open on purpose —
			// an unreachable database must not become a second outage —
			// because there the uncertainty is infrastructure and it passes.
			// Here the data arrived and says the cap cannot be evaluated at
			// all: the spend exists, and letting it through is an unbounded
			// overspend against a limit somebody set deliberately. An
			// operator fixes it by pricing the scope's models (alike); a
			// caller cannot fix it by retrying, so the reason says which it is.
			//
			// Cached for the spend TTL like any figure: the reason does not
			// change between calls, and re-reading the spend on every refused
			// call put a database round trip in front of each retry.
			l.spend.put(spendKey, scopeSpend{refused: verdict}, now)
			return LimitDecision{Allowed: false, Reason: verdict}
		}
		spent = scopeSpend{minor: total, currency: currency}
		l.spend.put(spendKey, spent, now)
	}
	if spent.refused != "" {
		return LimitDecision{Allowed: false, Reason: spent.refused}
	}

	// The other place, for the same reason. The spend was totalled within ONE
	// currency and the limit carries its own, and nothing compared the two: a
	// cap of 100.00 EUR against spend priced in a currency with a hundred
	// times more minor units per euro let the scope run a hundredfold past
	// it — and the reverse refused a tenant who had spent almost nothing.
	// Minor units are only comparable within a currency.
	if spent.currency != "" && limit.currency != "" && !strings.EqualFold(spent.currency, limit.currency) {
		return LimitDecision{Allowed: false, Reason: reasonLimitCurrency}
	}

	if spent.minor >= limit.minor {
		return LimitDecision{Allowed: false, Reason: reasonOverLimit}
	}
	return LimitDecision{Allowed: true}
}

// scopeID interns the scope so a limit can be looked up by id, once per scope
// while the bounded cache holds it. A failure is not cached: the next call asks
// again.
func (l *dbLimiter) scopeID(ctx context.Context, scope string) (int64, error) {
	if id, ok := l.ids.get(scope); ok {
		return id, nil
	}
	resp, err := l.m.InternScope(ctx, &pb.InternScopeReq{ExternalId: scope})
	if err != nil {
		return 0, err
	}
	l.ids.put(scope, resp.GetId())
	return resp.GetId(), nil
}

// totalSpend reduces a scope's spend lines to ONE comparable amount and the
// currency it is in, or the refusal reason when no such amount exists.
//
// Minor units are only comparable within a currency, and a cap is one integer
// with no currency of its own. The loop this replaced added them flat — dollars
// to euros — the defect fixed INSIDE a rollup, still present across the
// rollups being summed here.
//
// Three kinds of line, and the middle one is the easy one to miss:
//
//	cost present            counted, under its own currency
//	cost absent, priced > 0 UNTOTALLABLE. The usage rollup gave absence a
//	                        second meaning — the currencies inside this line
//	                        disagreed, so no single amount exists — and the
//	                        old `if CostMinor != nil` skipped it, so real spend
//	                        vanished and a scope priced in two currencies never
//	                        reached its cap.
//	calls > priced_calls    UNTOTALLABLE: some calls had no price. This used
//	                        to contribute nothing, so a capped scope that used
//	                        only unpriced models was never refused, however
//	                        much it spent. Tokens nobody priced are not free.
//	priced = 0, no tokens   contributes nothing: those calls spent nothing.
//	                        A failed call is recorded under the model the
//	                        CALLER asked for, so refusing here let one typo in
//	                        a model name lock the scope out — for the rest of
//	                        the window, and for good under a TOTAL limit.
//
// A pure function because the decision is the thing worth pinning, and the
// generated clients around it are not: there was no test on this file at all
// when the rollup started leaving mixed-currency lines without a cost, which is
// how two correct changes met and nobody noticed.
func totalSpend(lines []*pb.ScopeSpendLine) (int64, string, string) {
	byCurrency := map[string]int64{}
	for _, line := range lines {
		switch {
		case line.GetPricedCalls() == 0 && line.GetInputTokens() == 0 && line.GetOutputTokens() == 0 &&
			line.GetCachedInputTokens() == 0 && line.GetReasoningTokens() == 0:
		case line.GetCalls() > line.GetPricedCalls():
			return 0, "", reasonUnpriced
		case line.CostMinor != nil:
			byCurrency[strings.ToUpper(line.GetCurrency())] += line.GetCostMinor()
		case line.GetPricedCalls() > 0:
			return 0, "", reasonMixedCurrency
		}
	}
	if len(byCurrency) > 1 {
		return 0, "", reasonMixedCurrency
	}
	for currency, total := range byCurrency {
		return total, currency, ""
	}
	return 0, "", ""
}
