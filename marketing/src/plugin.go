// Package marketing is the plugin's root package — the entry point
// RegisterPlugin(*gen.EnvConfig, gen.HandlerRegistry, gen.ClientSet) the
// bundle invokes once per activation.
//
// The plugin serves nothing: it consumes. The gateway's marketing records
// and the auth plugin's account events reach it through its registry
// (plugin.yaml request_consumers / subscriptions), and it hands them to the
// marketing tool its features enable.
package marketing

import (
	"github.com/wandering-compiler/plugins/marketing/gen"
	"github.com/wandering-compiler/plugins/marketing/handlers"
)

// RegisterPlugin registers the consumers of the features this activation
// enables. With none, the plugin does nothing.
func RegisterPlugin(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if cfg == nil {
		cfg = &gen.EnvConfig{}
	}
	return handlers.Register(cfg, registry, clients)
}
