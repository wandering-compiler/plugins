package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gen "github.com/wandering-compiler/platform/plugins/agent/gen"
	pb "github.com/wandering-compiler/platform/plugins/agent/gen/pb"
	"github.com/wandering-compiler/platform/plugins/agent/handlers"
	"github.com/wandering-compiler/sdk/go/service/secret"
)

type capturingRegistry struct {
	impl      pb.AgentServiceServer
	shutdowns int
}

func (r *capturingRegistry) RegisterAgentServiceServer(impl pb.AgentServiceServer) { r.impl = impl }
func (r *capturingRegistry) RegisterShutdown(func(context.Context) error)          { r.shutdowns++ }

func validEnv(endpoint string) *gen.EnvConfig {
	return &gen.EnvConfig{Provider: "azure_openai", Endpoint: endpoint, APIVersion: "2025-04-01-preview",
		APIKey: secret.New("k")}
}

// A misconfigured bundle fails at BOOT and registers nothing: a service that
// cannot answer must not be served, or the first user finds out instead of the
// operator.
func TestRegisterPlugin_RefusesABadConfigAndServesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *gen.EnvConfig
		want string
	}{
		{"nil config", nil, "no endpoint"},
		{"another provider", func() *gen.EnvConfig { c := validEnv("https://acme.example.com"); c.Provider = "acme-llm"; return c }(), "unsupported provider"},
		{"no endpoint", validEnv(""), "no endpoint"},
		{"no key", func() *gen.EnvConfig { c := validEnv("https://acme.example.com"); c.APIKey = secret.New(""); return c }(), "no api key"},
		{"no api version", func() *gen.EnvConfig { c := validEnv("https://acme.example.com"); c.APIVersion = " "; return c }(), "no api version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := &capturingRegistry{}
			err := RegisterPlugin(tc.cfg, reg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
			if reg.impl != nil || reg.shutdowns != 0 {
				t.Error("a refused config still registered the service or a hook")
			}
		})
	}
}

// The deployment defaults: an unset max_output_tokens is the documented 4096,
// not zero (which every call would refuse as "no token budget"), and the
// default model is trimmed.
func TestRegisterPlugin_AppliesTheDocumentedDefaults(t *testing.T) {
	for _, tc := range []struct {
		maxTokens int
		want      int64
	}{{0, 4096}, {-5, 4096}, {512, 512}} {
		reg := &capturingRegistry{}
		cfg := validEnv("https://acme.example.com")
		cfg.MaxOutputTokens = tc.maxTokens
		cfg.DefaultModel = "  gpt-4o \n"
		if err := RegisterPlugin(cfg, reg, nil); err != nil {
			t.Fatalf("RegisterPlugin: %v", err)
		}
		h, ok := reg.impl.(*handlers.AgentServiceHandler)
		if !ok {
			t.Fatalf("registered %T", reg.impl)
		}
		if h.DefaultMaxTokens != tc.want || h.DefaultModel != "gpt-4o" {
			t.Errorf("MaxOutputTokens %d → %d / %q, want %d / gpt-4o", tc.maxTokens, h.DefaultMaxTokens, h.DefaultModel, tc.want)
		}
		if h.Client == nil || h.StreamClient == nil || h.Usage == nil || h.Limits == nil {
			t.Error("a seam was left nil — the handlers rely on all four being set")
		}
	}
}

// End to end from the env a bundle passes: the registered service answers a
// request that names nothing, against the configured endpoint, with the
// deployment's model and budget.
func TestRegisterPlugin_TheRegisteredServiceCallsTheConfiguredProvider(t *testing.T) {
	var got map[string]any
	var path, key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		path, key = r.URL.Path, r.Header.Get("Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"completed","model":"gpt-4o","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`)
	}))
	defer srv.Close()

	reg := &capturingRegistry{}
	cfg := validEnv(srv.URL)
	cfg.DefaultModel = "gpt-4o"
	if err := RegisterPlugin(cfg, reg, nil); err != nil {
		t.Fatalf("RegisterPlugin: %v", err)
	}
	out, err := reg.impl.Complete(context.Background(), &pb.CompleteReq{Messages: []*pb.Message{{Text: "hi"}}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.GetText() != "ok" {
		t.Errorf("text = %q", out.GetText())
	}
	if path != "/openai/responses" || key != "k" {
		t.Errorf("request went to %q with key %q", path, key)
	}
	if got["model"] != "gpt-4o" || got["max_output_tokens"] != float64(4096) {
		t.Errorf("model/budget = %v / %v, want the deployment defaults", got["model"], got["max_output_tokens"])
	}
}
