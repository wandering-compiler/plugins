package payment

import (
	distxpb "github.com/wandering-compiler/sdk/go/pb/common/distx"
	"testing"

	"github.com/wandering-compiler/sdk/go/service/secret"

	"github.com/wandering-compiler/plugins/payment/gen"
	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/handlers"
)

// The registered handler must carry exactly the configured secrets and
// currency: a webhook secret that did not arrive would fail every
// webhook closed; a default currency left un-normalised ("EUR ") would
// fail the 3-letter check on every charge that omits one.
func TestRegisterPlugin_WiresConfigIntoTheHandler(t *testing.T) {
	reg := &fakeRegistry{}
	cfg := &gen.EnvConfig{
		PaymentProvider:      " Stripe ",
		ProviderAPIKey:       secret.New("sk_test_fake"),
		WebhookSigningSecret: secret.New("whsec_test_fake"),
		DefaultCurrency:      " EUR ",
	}
	if err := RegisterPlugin(cfg, reg, fakeClients{}); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	h, ok := reg.server.(*handlers.PaymentServiceHandler)
	if !ok {
		t.Fatalf("registered %T", reg.server)
	}
	if h.WebhookSecret != "whsec_test_fake" {
		t.Errorf("webhook secret = %q", h.WebhookSecret)
	}
	if h.DefaultCurrency != "eur" {
		t.Errorf("default currency = %q, want eur", h.DefaultCurrency)
	}
	if h.Backend == nil || h.Backend.Name() != "stripe" {
		t.Errorf("backend = %v", h.Backend)
	}
	if h.Query == nil || h.Mutation == nil {
		t.Error("storage clients not wired")
	}
	if err := reg.shutdownFn(t.Context()); err != nil {
		t.Errorf("shutdown hook: %v", err)
	}
}

// A nil config is not a panic: it is the empty config, which (stripe by
// default) needs an API key.
func TestRegisterPlugin_NilConfigFailsLoud(t *testing.T) {
	reg := &fakeRegistry{}
	if err := RegisterPlugin(nil, reg, fakeClients{}); err == nil {
		t.Fatal("nil config registered a handler with no API key")
	}
	if reg.server != nil {
		t.Error("a failed registration must not register the service")
	}
}

// nilClients returns nil storage clients; the rest of gen.ClientSet is embedded
// as nil, since the plugin does not call it.
type nilClients struct{ gen.ClientSet }

func (nilClients) PaymentQuery() pb.PaymentQueryClient       { return nil }
func (nilClients) PaymentMutation() pb.PaymentMutationClient { return nil }
func (nilClients) DistributedTransaction() distxpb.W17DistributedTransactionClient {
	return nil
}
func (nilClients) Connection() string { return "" }

// Unwired storage clients fail at boot, not on the first request.
func TestRegisterPlugin_UnwiredClientsFailLoud(t *testing.T) {
	reg := &fakeRegistry{}
	cfg := &gen.EnvConfig{ProviderAPIKey: secret.New("sk_test_fake")}
	if err := RegisterPlugin(cfg, reg, nilClients{}); err == nil {
		t.Fatal("registered with nil storage clients")
	}
	if reg.server != nil || reg.shutdownFn != nil {
		t.Error("a failed registration must register nothing")
	}
}
