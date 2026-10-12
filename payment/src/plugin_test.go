package payment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wandering-compiler/sdk/go/service/secret"

	"github.com/wandering-compiler/plugins/payment/gen"
	pb "github.com/wandering-compiler/plugins/payment/gen/pb"
	"github.com/wandering-compiler/plugins/payment/lib/backend"
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
		PaymentProvider:      "stripe",
		ProviderAPIKey:       secret.New("sk_test_123"),
		WebhookSigningSecret: secret.New("whsec_test"),
		DefaultCurrency:      "eur",
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
	cfg := &gen.EnvConfig{ProviderAPIKey: secret.New("sk_test"), WebhookSigningSecret: secret.New("whsec_test")}
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
	cfg := &gen.EnvConfig{PaymentProvider: "paddle", ProviderAPIKey: secret.New("x")}
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

// provider_api_base sends the driver's calls to another Stripe-compatible
// root (the stripe-mock sandbox, a test server) instead of the real API.
func TestResolveBackend_ProviderAPIBase(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`{"id":"cus_mock"}`))
	}))
	defer srv.Close()
	be, err := resolveBackend(&gen.EnvConfig{ProviderAPIKey: secret.New("sk_test_x"), ProviderAPIBase: srv.URL})
	if err != nil {
		t.Fatalf("resolveBackend: %v", err)
	}
	id, err := be.EnsureCustomer(context.Background(), backend.CustomerSpec{Email: "a@example.com"})
	if err != nil || id != "cus_mock" {
		t.Fatalf("EnsureCustomer = %q, %v; want the mock's cus_mock", id, err)
	}
	if path != "/v1/customers" {
		t.Errorf("the mock got %q, want /v1/customers", path)
	}
}

// A provider_api_base that is not an http(s) URL is refused at startup, not
// discovered at the first charge.
func TestResolveBackend_ProviderAPIBaseMustBeAURL(t *testing.T) {
	for _, base := range []string{"stripe-mock:12111", "ftp://x", "http://", "http://u:p@stripemock:12111", "http://stripemock:12111?x=1", "http://stripemock:12111#f", "http://%zz"} {
		if _, err := resolveBackend(&gen.EnvConfig{ProviderAPIKey: secret.New("sk_test_x"), ProviderAPIBase: base}); err == nil {
			t.Errorf("provider_api_base %q accepted", base)
		}
	}
}

// A live key is never sent to a non-Stripe root.
func TestResolveBackend_ProviderAPIBaseRefusesLiveKey(t *testing.T) {
	for _, key := range []string{"sk_live_x", "rk_live_x"} {
		if _, err := resolveBackend(&gen.EnvConfig{ProviderAPIKey: secret.New(key), ProviderAPIBase: "http://stripemock:12111"}); err == nil {
			t.Errorf("live key %q accepted with provider_api_base", key)
		}
	}
}

// A provider_api_base that does not parse is refused without echoing it: it
// may carry credentials.
func TestResolveBackend_AnUnparsableBaseIsNotEchoed(t *testing.T) {
	_, err := resolveBackend(&gen.EnvConfig{ProviderAPIKey: secret.New("sk_test_x"), ProviderAPIBase: "http://u:hunter2@mock:%zz"})
	if err == nil {
		t.Fatal("an unparsable provider_api_base was accepted")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the error repeats the credentials: %v", err)
	}
}
