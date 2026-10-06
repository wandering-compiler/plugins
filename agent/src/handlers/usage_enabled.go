package handlers

import (
	"context"

	gen "github.com/wandering-compiler/platform/plugins/agent/gen"
	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/lib/usage"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This file is staged ONLY when `usage_persistence` is active — see
// plugin.yaml `go_files`. With the feature off it is absent, the tables do
// not exist, and handlers/usage.go's no-op sink stands.
//
// It installs the real sink from init() rather than by being called, because
// the plugin's own module holds this file AND its no-op default: two files
// declaring the same function would not compile outside a bundle. An init
// with nothing to protect it is a hazard this codebase knows, which is why
// handlers/usage.go refuses to boot when the activation says the feature is
// on and the sink is still the no-op.
func init() {
	newUsageSink = func(clients gen.ClientSet) UsageSink {
		// The bundle's ClientSet gains UsageMutation() only when this feature
		// is active, so the author-side ClientSet interface cannot require it
		// — a plugin compiled with the feature off would stop satisfying its
		// own contract. Asserting here is safe precisely because this file is
		// staged only in the activation that has the method.
		uc, ok := clients.(interface {
			UsageMutation() pb.UsageMutationClient
		})
		if !ok {
			// Leaves the no-op in place, and VerifyUsageWiring then refuses
			// the boot with a name — rather than recording nothing quietly.
			return noopUsageSink{}
		}
		return &dbUsageSink{
			writer: usage.New(usage.Config{}, &dbFlusher{mut: uc.UsageMutation()}),
		}
	}
}

// The outcome values handlers/usage.go declares must equal the proto's. That
// file cannot name the enum (it is staged into activations that do not have
// it), so the two are pinned HERE, where both exist — a renumbered proto stops
// this file compiling instead of quietly recording the wrong outcome.
const (
	_ = uint(pb.CallStatus_CALL_STATUS_OK - pb.CallStatus(OutcomeOK))
	_ = uint(pb.CallStatus_CALL_STATUS_FAILED - pb.CallStatus(OutcomeFailed))
	_ = uint(pb.CallStatus_CALL_STATUS_UNKNOWN - pb.CallStatus(OutcomeUnknown))
)

type dbUsageSink struct{ writer *usage.Writer }

func (s *dbUsageSink) Record(ev UsageEvent) {
	s.writer.Record(usage.Event{
		Scope:             ev.Scope,
		Model:             ev.Model,
		Labels:            ev.Labels,
		Measured:          ev.Measured,
		InputTokens:       ev.InputTokens,
		OutputTokens:      ev.OutputTokens,
		CachedInputTokens: ev.CachedInputTokens,
		ReasoningTokens:   ev.ReasoningTokens,
		Status:            int32(ev.Status),
		StartedAt:         ev.StartedAt,
		DurationMs:        ev.Duration.Milliseconds(),
	})
}

func (s *dbUsageSink) Close(ctx context.Context) { s.writer.Close(ctx) }

// dbFlusher turns a batch into rows.
//
// Interning happens HERE, in the flush, never on the model call's path: a
// lookup per call would put a database round trip in front of every
// completion, which is what an async writer exists to avoid.
type dbFlusher struct {
	mut pb.UsageMutationClient

	// Ids are stable for the life of a row, so a resolved one is cached. The
	// cache is what keeps a steady stream of calls from the same tenant on the
	// same model down to ONE insert per call rather than three.
	//
	// Bounded (idCache): every key here is the caller's, and a label carrying
	// a run id is a new key on every run — unbounded, these maps grew for the
	// life of the process.
	scopes idCache[string]
	models idCache[string]
	labels idCache[[2]string]
}

// Flush records every event it CAN, and reports the ones it could not.
//
// It used to return at the first failure, which dropped the rest of the batch
// unwritten — and a batch is up to 64 calls from every tenant the process
// served. One caller's scope longer than the column allows, one model id the
// table refuses, sank the spend of everybody queued behind it, and the writer
// then counted the whole batch as lost, including the rows that HAD landed.
// That is the "empty scope took its whole batch down" failure again, one
// constraint over.
func (f *dbFlusher) Flush(ctx context.Context, batch []usage.Event) error {
	failed, unlabelled := 0, 0
	var first error
	for _, ev := range batch {
		rowErr, labelErr := f.flushOne(ctx, ev)
		switch {
		case rowErr != nil:
			failed++
			if first == nil {
				first = rowErr
			}
		case labelErr != nil:
			unlabelled++
			if first == nil {
				first = labelErr
			}
		}
	}
	if failed == 0 && unlabelled == 0 {
		return nil
	}
	return &usage.PartialFlushError{Failed: failed, Unlabelled: unlabelled, Err: first}
}

// flushOne writes one event: its row, then its labels.
//
// The two errors are kept apart because they mean different things to whoever
// reads the count. rowErr is "this spend is not in the table". labelErr is
// "the spend IS in the table, some attribution is not" — and reporting that as
// a failed event told the operator the call was not recorded, which is the cue
// to re-enter it and bill it twice. The remaining labels are still attached
// after a bad one, because a partial attribution is worth more than none.
func (f *dbFlusher) flushOne(ctx context.Context, ev usage.Event) (rowErr, labelErr error) {
	scopeID, err := f.internScope(ctx, ev.Scope)
	if err != nil {
		return err, nil
	}
	modelID, err := f.internModel(ctx, ev.Model)
	if err != nil {
		return err, nil
	}
	resp, err := f.mut.RecordUsage(ctx, &pb.RecordUsageReq{
		ScopeId:           scopeID,
		ModelId:           modelID,
		Measured:          ev.Measured,
		InputTokens:       ev.InputTokens,
		OutputTokens:      ev.OutputTokens,
		CachedInputTokens: ev.CachedInputTokens,
		ReasoningTokens:   ev.ReasoningTokens,
		Status:            pb.CallStatus(ev.Status),
		StartedAt:         timestamppb.New(ev.StartedAt),
		DurationMs:        ev.DurationMs,
	})
	if err != nil {
		return err, nil
	}
	for k, v := range ev.Labels {
		labelID, lErr := f.internLabel(ctx, k, v)
		if lErr != nil {
			if labelErr == nil {
				labelErr = lErr
			}
			continue
		}
		if _, aErr := f.mut.AttachUsageLabel(ctx, &pb.AttachUsageLabelReq{
			UsageId: resp.GetId(),
			LabelId: labelID,
		}); aErr != nil && labelErr == nil {
			labelErr = aErr
		}
	}
	return nil, labelErr
}

func (f *dbFlusher) internScope(ctx context.Context, name string) (int64, error) {
	return intern(&f.scopes, name, func() (int64, error) {
		resp, err := f.mut.InternScope(ctx, &pb.InternScopeReq{ExternalId: name})
		return resp.GetId(), err
	})
}

func (f *dbFlusher) internModel(ctx context.Context, name string) (int64, error) {
	return intern(&f.models, name, func() (int64, error) {
		resp, err := f.mut.InternModel(ctx, &pb.InternModelReq{Name: name})
		return resp.GetId(), err
	})
}

func (f *dbFlusher) internLabel(ctx context.Context, k, v string) (int64, error) {
	return intern(&f.labels, [2]string{k, v}, func() (int64, error) {
		resp, err := f.mut.InternLabel(ctx, &pb.InternLabelReq{Key: k, Value: v})
		return resp.GetId(), err
	})
}

// intern serves an id from the cache or asks for it. A failure is not cached:
// the next flush asks again.
func intern[K comparable](c *idCache[K], k K, ask func() (int64, error)) (int64, error) {
	if id, ok := c.get(k); ok {
		return id, nil
	}
	id, err := ask()
	if err != nil {
		return 0, err
	}
	c.put(k, id)
	return id, nil
}
