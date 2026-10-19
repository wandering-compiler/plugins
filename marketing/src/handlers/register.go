// Package handlers holds the marketing plugin's consumers: one file set per
// tool, staged only with that tool's feature (plugin.yaml go_files).
package handlers

import "github.com/wandering-compiler/plugins/marketing/gen"

// registerBrevo is the brevo feature's registration, set by its init; nil in
// a build without the feature, whose tables and types do not exist.
var registerBrevo func(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error

// Register registers every enabled tool's consumers.
func Register(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if registerBrevo == nil {
		return nil
	}
	return registerBrevo(cfg, registry, clients)
}
