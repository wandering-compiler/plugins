// Package payment is the plugin's root package — the v4 entry point
// RegisterPlugin(*gen.EnvConfig, gen.HandlerRegistry, gen.ClientSet)
// the bundle's generated main.go invokes once per activation.
//
// Staging text-rewrites the self-imports (`<go_module>/gen`,
// `<go_module>/handlers`, `<go_module>/lib/...`) to the per-activation
// staged paths so the staged copy compiles inside the bundle without a
// shared srcgo dependency.
package payment

import (
	"fmt"
	"strings"

	"github.com/wandering-compiler/platform/plugins/payment/gen"
	"github.com/wandering-compiler/platform/plugins/payment/handlers"
	"github.com/wandering-compiler/platform/plugins/payment/lib/backend"
	"github.com/wandering-compiler/platform/plugins/payment/lib/backend/stripe"
)

// RegisterPlugin wires the PaymentService handler:
//
//  1. Resolve the backend driver from `payment_provider` (Slice 1:
//     stripe only) with its API key from the secret env.
//  2. Construct PaymentServiceHandler with the in-process storage
//     clients + the backend + the webhook signing secret.
//  3. Register the handler + its drain hook with the bundle.
func RegisterPlugin(cfg *gen.EnvConfig, registry gen.HandlerRegistry, clients gen.ClientSet) error {
	if cfg == nil {
		cfg = &gen.EnvConfig{}
	}
	be, err := resolveBackend(cfg)
	if err != nil {
		return err
	}
	h := &handlers.PaymentServiceHandler{
		Query:           clients.PaymentQuery(),
		Mutation:        clients.PaymentMutation(),
		Backend:         be,
		WebhookSecret:   cfg.WebhookSigningSecret.Reveal(),
		DefaultCurrency: defaultCurrency(cfg),
	}
	if err := handlers.ValidateConfig(h); err != nil {
		return err
	}
	registry.RegisterPaymentServiceServer(h)
	registry.RegisterShutdown(h.Shutdown)
	return nil
}

// resolveBackend selects the provider driver. Unknown provider → loud
// failure at startup so a misconfigured bundle never boots half-wired.
func resolveBackend(cfg *gen.EnvConfig) (backend.Backend, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.PaymentProvider))
	if provider == "" {
		provider = "stripe"
	}
	switch provider {
	case "stripe":
		key := cfg.ProviderApiKey.Reveal()
		if key == "" {
			return nil, fmt.Errorf("payment plugin: provider_api_key is required for the stripe backend")
		}
		return stripe.New(key), nil
	default:
		return nil, fmt.Errorf("payment plugin: unknown payment_provider %q (v1 supports: stripe)", provider)
	}
}

func defaultCurrency(cfg *gen.EnvConfig) string {
	if c := strings.ToLower(strings.TrimSpace(cfg.DefaultCurrency)); c != "" {
		return c
	}
	return "usd"
}
