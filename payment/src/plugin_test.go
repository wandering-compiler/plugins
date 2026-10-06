package payment

import (
	"context"
	"testing"

	"github.com/wandering-compiler/sdk/go/service/secret"

	"github.com/wandering-compiler/platform/plugins/payment/gen"
	pb "github.com/wandering-compiler/platform/plugins/payment/gen/pb"
)

// fake DI surface — non-nil typed clients so ValidateConfig passes.
type fakeClients struct{}

func (fakeClients) PaymentQuery() pb.PaymentQueryClient {
	return struct{ pb.PaymentQueryClient }{}
}
func (fakeClients) PaymentMutation() pb.PaymentMutationClient {
	return struct{ pb.PaymentMutationClient }{}
}

type fakeRegistry struct {
	server     pb.PaymentServiceServer
	shutdownFn func(context.Context) error
}

func (r *fakeRegistry) RegisterPaymentServiceServer(impl pb.PaymentServiceServer) { r.server = impl }
func (r *fakeRegistry) RegisterShutdown(fn func(context.Context) error)           { r.shutdownFn = fn }

func TestRegisterPlugin_Stripe(t *testing.T) {
	reg := &fakeRegistry{}
	cfg := &gen.EnvConfig{
		PaymentProvider: "stripe",
		ProviderApiKey:  secret.New("sk_test_123"),
		DefaultCurrency: "eur",
	}
	if err := RegisterPlugin(cfg, reg, fakeClients{}); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if reg.server == nil {
		t.Fatal("PaymentService not registered")
	}
	if reg.shutdownFn == nil {
		t.Error("shutdown hook not registered")
	}
}

func TestRegisterPlugin_DefaultsToStripe(t *testing.T) {
	reg := &fakeRegistry{}
	// no PaymentProvider → defaults to stripe; api key still required.
	cfg := &gen.EnvConfig{ProviderApiKey: secret.New("sk_test")}
	if err := RegisterPlugin(cfg, reg, fakeClients{}); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	if reg.server == nil {
		t.Fatal("PaymentService not registered")
	}
}

func TestRegisterPlugin_MissingAPIKey(t *testing.T) {
	if err := RegisterPlugin(&gen.EnvConfig{PaymentProvider: "stripe"}, &fakeRegistry{}, fakeClients{}); err == nil {
		t.Fatal("want error when provider_api_key empty")
	}
}

func TestRegisterPlugin_UnknownProvider(t *testing.T) {
	cfg := &gen.EnvConfig{PaymentProvider: "paddle", ProviderApiKey: secret.New("x")}
	if err := RegisterPlugin(cfg, &fakeRegistry{}, fakeClients{}); err == nil {
		t.Fatal("want error for unknown provider")
	}
}

func TestDefaultCurrency(t *testing.T) {
	if got := defaultCurrency(&gen.EnvConfig{}); got != "usd" {
		t.Errorf("default = %q, want usd", got)
	}
	if got := defaultCurrency(&gen.EnvConfig{DefaultCurrency: "GBP"}); got != "gbp" {
		t.Errorf("got %q, want gbp (lowercased)", got)
	}
}
