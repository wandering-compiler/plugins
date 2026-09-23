package agent

import (
	"context"
	"testing"

	gen "github.com/wandering-compiler/platform/plugins/agent/gen"
	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/sdk/go/service/secret"
)

// recordingRegistry captures what RegisterPlugin hands the bundle.
type recordingRegistry struct {
	served    bool
	shutdowns []func(ctx context.Context) error
}

func (r *recordingRegistry) RegisterAgentServiceServer(pb.AgentServiceServer) { r.served = true }
func (r *recordingRegistry) RegisterShutdown(fn func(ctx context.Context) error) {
	r.shutdowns = append(r.shutdowns, fn)
}

// TestRegisterPlugin_RegistersAUsageDrain — the usage writer is asynchronous,
// so anything not yet flushed lives only in its queue, and the bundle's
// teardown is the one moment that queue can still be written.
//
// Without this hook the queue dies with the process, and the shorter the
// process the more of the bill it takes: a consumer measured a run of hundreds
// of model calls that ended before the first flush interval and left ZERO
// rows, then a longer one that kept only the batches which happened to tick in
// time. A long-lived server hides it; a CLI, an eval or a batch job is
// entirely this case — and those are the shapes where spend gets accounted.
//
// Asserting the REGISTRATION rather than the flush is deliberate: the writer's
// own drain is tested in lib/usage, and what was missing here was nobody
// calling it.
func TestRegisterPlugin_RegistersAUsageDrain(t *testing.T) {
	reg := &recordingRegistry{}

	if err := RegisterPlugin(&gen.EnvConfig{Provider: "azure_openai", Endpoint: "https://example.invalid", APIVersion: "2024-10-21", APIKey: secret.New("k")}, reg, nil); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if !reg.served {
		t.Fatal("RegisterPlugin did not register the service — this test would then be asserting about a plugin that never booted")
	}
	if len(reg.shutdowns) == 0 {
		t.Fatal("RegisterPlugin registered no shutdown hook — whatever the usage writer has queued dies with the process")
	}
	for i, fn := range reg.shutdowns {
		if err := fn(context.Background()); err != nil {
			t.Errorf("shutdown hook %d returned %v — teardown must not fail on bookkeeping", i, err)
		}
	}
}
