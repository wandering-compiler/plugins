// Package agent is the plugin's root package — the v4 entry point
// RegisterPlugin(*gen.EnvConfig, gen.HandlerRegistry, gen.ClientSet) the
// bundle's generated main.go invokes once per activation.
//
// Staging text-rewrites the self-imports (`<go_module>/gen`,
// `<go_module>/handlers`, `<go_module>/lib/...`) to the per-activation staged
// paths so the staged copy compiles inside the bundle without a shared srcgo
// dependency.
//
// # This file is STAGED, so it may not import a third party
//
// It compiles inside the CONSUMER's bundle module, whose go.mod knows about
// grpc, protobuf and the sdk — and nothing else. Every provider dependency
// therefore lives in `lib/`, which stays in this module and is reached through
// the bundle's `replace`. The same rule governs `handlers/`.
package agent

import (
	"context"
	"strings"
	"time"

	"github.com/wandering-compiler/platform/plugins/agent/gen"
	"github.com/wandering-compiler/platform/plugins/agent/handlers"
	"github.com/wandering-compiler/platform/plugins/agent/lib/llm"
)

// defaultMaxOutputTokens mirrors plugin.yaml's default so a bundle whose env
// omits the knob behaves the same as one that sets it to the documented value.
const defaultMaxOutputTokens = 4096

// RegisterPlugin wires the AgentService handler.
//
// `clients` is unused: this plugin owns no tables and calls nothing in the
// consuming project. It is in the signature because the v4 contract puts it
// there for every plugin — see gen.ClientSet.
//
// Every configuration error is returned HERE rather than tolerated, so a
// misconfigured bundle fails at boot instead of on the first user's request.
func RegisterPlugin(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if cfg == nil {
		cfg = &gen.EnvConfig{}
	}
	client, err := llm.NewClient(llm.Config{
		Provider:   cfg.Provider,
		Endpoint:   cfg.Endpoint,
		APIKey:     cfg.APIKey.Reveal(),
		APIVersion: cfg.APIVersion,
		Timeout:    time.Duration(cfg.RequestTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return err
	}

	maxTokens := int64(cfg.MaxOutputTokens)
	if maxTokens <= 0 {
		maxTokens = defaultMaxOutputTokens
	}

	// The usage sink is a no-op unless this activation enabled
	// `usage_persistence`; see handlers/usage.go. VerifyUsageWiring is what
	// keeps "the activation says it is on" and "a real sink got installed"
	// from drifting apart — they come from different places (a generated
	// constant and a staged file), and when they disagree every call still
	// succeeds while nothing is recorded. That looks exactly like a quiet
	// month, which is the worst way for a billing layer to fail.
	sink := handlers.NewUsageSink(clients)
	if err := handlers.VerifyUsageWiring(sink); err != nil {
		return err
	}

	// Drain the usage queue at teardown.
	//
	// The writer is asynchronous on purpose — a model call must not wait on a
	// database write — which means everything not yet flushed lives only in
	// its queue. Without this hook that queue dies with the process, and the
	// shorter the process the more of the bill it takes: a consumer measured a
	// run of hundreds of calls that ended before the first flush tick and left
	// ZERO rows, and a longer one that kept only the batches which happened to
	// tick in time. A server hides it; a CLI, an eval or a batch job is mostly
	// this case, and those are exactly the shapes where spend gets accounted.

	registry.RegisterShutdown(func(ctx context.Context) error {
		sink.Close(ctx)
		return nil
	})

	registry.RegisterAgentServiceServer(&handlers.AgentServiceHandler{
		Usage:  sink,
		Limits: handlers.NewLimiter(clients),
		// One object satisfies both halves of the seam; they are separate
		// interfaces so a test can fake either alone.
		Client:           client,
		StreamClient:     client,
		DefaultModel:     strings.TrimSpace(cfg.DefaultModel),
		DefaultMaxTokens: maxTokens,
	})
	return nil
}
