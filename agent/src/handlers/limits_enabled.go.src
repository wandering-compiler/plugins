package handlers

import (
	"context"
	"time"

	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
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
		return &dbLimiter{
			q:      qc.UsageQuery(),
			m:      mc.UsageMutation(),
			spend:  &spendCache{ttl: 30 * time.Second},
			limits: &spendCache{ttl: 5 * time.Minute},
		}
	}
}

// dbLimiter enforces a per-scope monthly cap.
//
// MONTH is the only window enforced today, and that is a choice rather than an
// omission: it is the one every consumer asked for, and a window nobody
// exercises is a window whose arithmetic nobody has checked. DAY and TOTAL are
// in the schema and readable; enforcing them is a small step once something
// needs it.
type dbLimiter struct {
	q pb.UsageQueryClient
	m pb.UsageMutationClient

	spend  *spendCache
	limits *spendCache
}

func (l *dbLimiter) Allow(ctx context.Context, scope string) LimitDecision {
	if scope == "" {
		// Nothing to charge means nothing to cap. Refusing here would make a
		// caller that does not use scopes unable to call the model at all.
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

	limit, ok := l.limits.get(scope, now)
	if !ok {
		resp, lErr := l.q.GetScopeLimit(ctx, &pb.GetScopeLimitReq{
			ScopeId: scopeID,
			Window:  pb.LimitWindow_LIMIT_WINDOW_MONTH,
			At:      timestamppb.New(now),
		})
		if lErr != nil {
			// No row is the common case — most scopes have no cap — and it
			// arrives as an error. Cache the absence so a scope without a
			// limit does not ask on every call.
			l.limits.put(scope, -1, now)
			return LimitDecision{Allowed: true}
		}
		limit = resp.GetLimitMinor()
		l.limits.put(scope, limit, now)
	}
	if limit < 0 {
		return LimitDecision{Allowed: true}
	}

	spent, ok := l.spend.get(scope, now)
	if !ok {
		from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		resp, sErr := l.q.GetScopeSpend(ctx, &pb.GetScopeSpendReq{
			ScopeId: scopeID,
			From:    timestamppb.New(from),
			To:      timestamppb.New(now.Add(time.Second)),
		})
		if sErr != nil {
			return LimitDecision{Allowed: true}
		}
		var total int64
		for _, line := range resp.GetLines() {
			// An unpriced line contributes NOTHING to the total rather than
			// zero-by-assumption: a model nobody priced must not make a scope
			// look cheap, and it must not make it look expensive either. The
			// bill says `priced=false` elsewhere; here it simply cannot be
			// counted.
			if line.CostMinor != nil {
				total += line.GetCostMinor()
			}
		}
		spent = total
		l.spend.put(scope, spent, now)
	}

	if spent >= limit {
		return LimitDecision{
			Allowed: false,
			Reason:  "agent: this scope has reached its spending limit for the current month",
		}
	}
	return LimitDecision{Allowed: true}
}

// scopeID interns the scope so a limit can be looked up by id. The upsert is
// the same one the writer uses, and the id is cached by that path too.
func (l *dbLimiter) scopeID(ctx context.Context, scope string) (int64, error) {
	resp, err := l.m.InternScope(ctx, &pb.InternScopeReq{ExternalId: scope})
	if err != nil {
		return 0, err
	}
	return resp.GetId(), nil
}
