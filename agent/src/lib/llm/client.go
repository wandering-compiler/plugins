package llm

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openai/openai-go/v2/azure"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/responses"
)

// Client is both halves of the model seam at once. *responses.ResponseService
// satisfies it, which is what NewClient returns.
type Client interface {
	Completer
	StreamCompleter
}

// Config is what a deployment must supply to reach a provider.
type Config struct {
	Provider   string
	Endpoint   string
	APIKey     string
	APIVersion string
	Timeout    time.Duration
}

const defaultRequestTimeout = 120 * time.Second

// NewClient builds the provider client.
//
// It lives HERE and not in the plugin's root package for a reason that is easy
// to get wrong: the root package and `handlers/` are STAGED into the
// consumer's bundle and compile inside the bundle's module, so anything they
// import must already be in the bundle's go.mod. `lib/` is not staged — it
// stays in the plugin's own module and is reached through the bundle's
// `replace`, which is what makes it the only place a third-party dependency
// may be named.
//
// Getting that backwards is not a style problem. The bundle compiles with
// "imports … from implicitly required module", after codegen has reported
// success, in the consumer's tree.
func NewClient(cfg Config) (Client, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "azure_openai"
	}
	if provider != "azure_openai" {
		return nil, fmt.Errorf("agent: unsupported provider %q — v1 supports azure_openai only", cfg.Provider)
	}
	// These messages name the SETTING, never the environment variable.
	// The variable is `<domain>_AGENT_ENDPOINT`, and a plugin cannot know
	// the domain — it is the consumer's, chosen at activation. Writing
	// `<DOMAIN>_AGENT_ENDPOINT` here shipped that placeholder verbatim to
	// an operator as the first line of a failed boot, which is a riddle
	// where an instruction belongs. The generated wire layer appends the
	// real names, because it is the layer that knows them.
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		return nil, errors.New("agent: no endpoint configured — the provider base URL is required before the first request")
	}
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return nil, errors.New("agent: no api key configured — the provider rejects unauthenticated calls")
	}
	apiVersion := strings.TrimSpace(cfg.APIVersion)
	if apiVersion == "" {
		return nil, errors.New("agent: no api version configured — the Responses API is version-gated")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	svc := responses.NewResponseService(
		azure.WithEndpoint(endpoint, apiVersion),
		azure.WithAPIKey(key),
		option.WithRequestTimeout(timeout),
	)
	return &svc, nil
}

// NewCallID mints the id a tool call is answered under. Here rather than in
// handlers/ for the staging reason above: uuid is a third-party import.
func NewCallID() string { return uuid.NewString() }
