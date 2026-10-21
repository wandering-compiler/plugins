// Package grant is the plugin's root package — the entry point
// RegisterPlugin(*gen.EnvConfig, gen.HandlerRegistry, gen.ClientSet) the
// bundle's generated main.go invokes once per activation.
package grant

import (
	"github.com/wandering-compiler/plugins/grant/gen"
	"github.com/wandering-compiler/plugins/grant/handlers"
)

// RegisterPlugin wires the GrantService handler over the in-process storage
// clients.
func RegisterPlugin(_ *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	registry.RegisterGrantServiceServer(&handlers.GrantServiceHandler{
		Query:    clients.GrantQuery(),
		Mutation: clients.GrantMutation(),
	})
	return nil
}
