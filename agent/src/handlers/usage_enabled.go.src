package handlers

import (
	"context"
	"sync"

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

	// Ids are stable for the life of a row, so a resolved one is cached for
	// the life of the process. The cache is what keeps a steady stream of
	// calls from the same tenant on the same model down to ONE insert per
	// call rather than three.
	mu     sync.Mutex
	scopes map[string]int64
	models map[string]int64
	labels map[[2]string]int64
}

func (f *dbFlusher) Flush(ctx context.Context, batch []usage.Event) error {
	for _, ev := range batch {
		scopeID, err := f.internScope(ctx, ev.Scope)
		if err != nil {
			return err
		}
		modelID, err := f.internModel(ctx, ev.Model)
		if err != nil {
			return err
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
			return err
		}
		for k, v := range ev.Labels {
			labelID, lErr := f.internLabel(ctx, k, v)
			if lErr != nil {
				return lErr
			}
			if _, aErr := f.mut.AttachUsageLabel(ctx, &pb.AttachUsageLabelReq{
				UsageId: resp.GetId(),
				LabelId: labelID,
			}); aErr != nil {
				return aErr
			}
		}
	}
	return nil
}

func (f *dbFlusher) internScope(ctx context.Context, name string) (int64, error) {
	f.mu.Lock()
	if f.scopes == nil {
		f.scopes = map[string]int64{}
	}
	if id, ok := f.scopes[name]; ok {
		f.mu.Unlock()
		return id, nil
	}
	f.mu.Unlock()
	resp, err := f.mut.InternScope(ctx, &pb.InternScopeReq{ExternalId: name})
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.scopes[name] = resp.GetId()
	f.mu.Unlock()
	return resp.GetId(), nil
}

func (f *dbFlusher) internModel(ctx context.Context, name string) (int64, error) {
	f.mu.Lock()
	if f.models == nil {
		f.models = map[string]int64{}
	}
	if id, ok := f.models[name]; ok {
		f.mu.Unlock()
		return id, nil
	}
	f.mu.Unlock()
	resp, err := f.mut.InternModel(ctx, &pb.InternModelReq{Name: name})
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.models[name] = resp.GetId()
	f.mu.Unlock()
	return resp.GetId(), nil
}

func (f *dbFlusher) internLabel(ctx context.Context, k, v string) (int64, error) {
	key := [2]string{k, v}
	f.mu.Lock()
	if f.labels == nil {
		f.labels = map[[2]string]int64{}
	}
	if id, ok := f.labels[key]; ok {
		f.mu.Unlock()
		return id, nil
	}
	f.mu.Unlock()
	resp, err := f.mut.InternLabel(ctx, &pb.InternLabelReq{Key: k, Value: v})
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	f.labels[key] = resp.GetId()
	f.mu.Unlock()
	return resp.GetId(), nil
}
