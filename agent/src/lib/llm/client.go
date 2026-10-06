package llm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/openai/openai-go/v2/azure"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
)

// Client is both halves of the model seam at once. *responses.ResponseService
// satisfies it; NewClient returns one wrapped in the per-call deadline.
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
	return &deadlineClient{svc: &svc, timeout: timeout}, nil
}

// deadlineClient makes the configured timeout a deadline for the whole CALL.
//
// The SDK's request timeout is per ATTEMPT, and it retries a 5xx, a 429 or a
// dropped connection twice on its own — so a provider failing slowly held one
// call for three timeouts plus backoff: six minutes on the default, for a knob
// the manifest documents as a per-call deadline. The per-attempt option stays
// (it can only be the shorter of the two); this adds the bound around all of
// them.
//
// One gap it cannot close: the SDK sleeps between retries without watching the
// context, so a provider's Retry-After (honoured up to a minute) can still
// overrun the deadline by that sleep before the next attempt fails at once.
type deadlineClient struct {
	svc     *responses.ResponseService
	timeout time.Duration
}

func (c *deadlineClient) New(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) (*responses.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.svc.New(ctx, body, opts...)
}

// NewStreaming bounds the stream the same way, which takes more care: the
// stream is READ after this returns, so the deadline cannot be released here.
// It is handed to the successful response's body and released when the stream
// is closed — every caller closes it (streamTurn defers it). A failed attempt's
// body is closed by the SDK before it retries, so only a 2xx carries it;
// anything else releases it before returning.
func (c *deadlineClient) NewStreaming(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion] {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	var handedOff atomic.Bool
	carry := option.WithMiddleware(func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		res, err := next(r)
		if err == nil && res != nil && res.StatusCode < http.StatusMultipleChoices {
			res.Body = &releaseOnClose{ReadCloser: res.Body, release: cancel}
			handedOff.Store(true)
		}
		return res, err
	})
	stream := c.svc.NewStreaming(ctx, body, append(append([]option.RequestOption(nil), opts...), carry)...)
	if !handedOff.Load() || stream.Err() != nil {
		cancel()
	}
	return stream
}

// releaseOnClose ends a stream's deadline when its body is closed.
type releaseOnClose struct {
	io.ReadCloser
	release context.CancelFunc
}

func (b *releaseOnClose) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// NewCallID mints the id a tool call is answered under. Here rather than in
// handlers/ for the staging reason above: uuid is a third-party import.
func NewCallID() string { return uuid.NewString() }
