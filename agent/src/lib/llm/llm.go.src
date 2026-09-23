// Package llm is one model call: parameters in, text and token counts out.
//
// # Provenance
//
// Ported from `lib/chatengine/llm.go` in Marb-AI/platform, which has run this
// in production. The parameter shaping, the reasoning-family table and the
// status handling are theirs, and the comments explaining WHY each one is the
// way it is were kept — a threshold whose reason is lost is a number nobody
// can safely change.
//
// Their copy carries a note beside the family table saying it is "a deliberate
// fork … the fix when a second domain needs it is a shared package". This is
// that package.
//
// # Why the Responses API and not Chat Completions
//
// Because Chat Completions does not stream. Measured on their side, four runs,
// same prompt and deployment with only the URL changing: `chat/completions`
// delivers the whole answer in 0.06–0.10 s after several seconds of silence,
// while `responses` delivers it over 2.6–4.7 s, as it is written. Phase 1 does
// not stream, but the phase after it does, and choosing the other API now
// would have to be undone then.
package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/packages/ssestream"
	"github.com/openai/openai-go/v2/responses"
	"github.com/openai/openai-go/v2/shared"
)

// Completer is the model seam. *openai.ResponseService satisfies it, and so
// does a fake in a test — which is the whole reason it is an interface.
//
// The two halves are separate interfaces on purpose: a caller that only ever
// completes should not have to supply a streaming fake, and vice versa.
// *responses.ResponseService satisfies both.
type Completer interface {
	New(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) (*responses.Response, error)
}

// StreamCompleter is the streaming half of the model seam.
type StreamCompleter interface {
	NewStreaming(ctx context.Context, body responses.ResponseNewParams, opts ...option.RequestOption) *ssestream.Stream[responses.ResponseStreamEventUnion]
}

// reasoningModelPrefixes are the families that take a reasoning_effort and
// reject any temperature but the default. Sending the wrong set is a 400 from
// the provider rather than an ignored field, so the shape is chosen per call
// from the model name.
//
// Prefix rather than equality: a response carries a dated id back
// (gpt-5-nano-2025-08-07), and an equality check would miss every one of them.
//
// This table is the half that drifts. A family added by the provider and not
// added here surfaces as a 400 on the first call with the new model — loud and
// immediate, but only once somebody tries it.
var reasoningModelPrefixes = []string{"gpt-5", "o1", "o3", "o4"}

// IsReasoningModel reports whether a model id names a reasoning family.
func IsReasoningModel(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	// The -chat variants (gpt-5-chat, gpt-5.2-chat) are ordinary sampling
	// models despite sitting inside a reasoning family.
	if strings.Contains(m, "-chat") {
		return false
	}
	for _, prefix := range reasoningModelPrefixes {
		if strings.HasPrefix(m, prefix) {
			return true
		}
	}
	return false
}

const (
	// reasoningHeadroomShare gives thinking room beneath MaxTokens without
	// letting it eat the answer. Reasoning and answer share ONE budget, so a
	// fixed floor would not be a reasoning allowance — nothing stops the answer
	// from spending it — and the overshoot has to be bounded as a fraction of
	// what the caller asked for.
	reasoningHeadroomShare = 4
	// reasoningHeadroomMax stops the cushion from outgrowing most answers.
	reasoningHeadroomMax = 1024
)

func reasoningHeadroom(maxTokens int64) int64 {
	h := maxTokens / reasoningHeadroomShare
	if h > reasoningHeadroomMax {
		return reasoningHeadroomMax
	}
	return h
}

// Model is what to ask and how hard to think.
type Model struct {
	// ID is the model / deployment name.
	ID string
	// MaxTokens is room for the ANSWER. On a reasoning model a headroom is
	// added beneath it, because thinking and answer share one budget.
	MaxTokens int64
	// Effort is the reasoning budget: "none", "low", "medium", "high". Ignored
	// by sampling models.
	Effort string
	// Temperature is a pointer because reasoning models reject any value but
	// the default, with a 400 rather than a silently ignored field. Nil on a
	// sampling model means the provider default.
	Temperature *float64

	// JSONObject asks the PROVIDER to enforce that the answer is a JSON object.
	//
	// Not the same thing as saying so in the prompt. An instruction is a
	// request the model may decline, and the decline surfaces as a parse error
	// at the far end of whatever the answer was feeding — a consumer who lost
	// this had to add a markdown-fence stripper to get it back, and said so:
	// anything more than that is repairing model output, which is where a wrong
	// answer stops looking wrong.
	JSONObject bool
}

// Message is one thing somebody said.
type Message struct {
	// Assistant reports whether the model said it; false means the user did.
	Assistant bool
	Text      string
}

// Usage is what a call cost in tokens. Deliberately not money: prices change
// without the code changing and belong to whoever is billed.
type Usage struct {
	Model string
	// Measured is false when the provider reported nothing, so a caller summing
	// these can tell a free call from an unreported one.
	Measured          bool
	InputTokens       int64
	OutputTokens      int64
	TotalTokens       int64
	CachedInputTokens int64
	ReasoningTokens   int64
}

// Completion is one assistant turn.
type Completion struct {
	Text string
	// Status is the provider's own word for how the response ended, and
	// IncompleteReason the detail beneath it. Without them a TRUNCATED answer
	// is indistinguishable from a finished one.
	Status           string
	IncompleteReason string
	Usage            Usage
}

// The Responses API's status vocabulary. A response carries a STATUS, and an
// unfinished one carries a reason beneath it. The pair replaces `finish_reason`
// and is not merely a rename: `stop` and `tool_calls` were two values both
// meaning "finished".
const (
	StatusCompleted  = "completed"
	StatusIncomplete = "incomplete"

	// ReasonMaxOutputTokens is an ordinary outcome on a reasoning model rather
	// than a broken response: thinking and answering share one budget.
	ReasonMaxOutputTokens = "max_output_tokens"
	ReasonContentFilter   = "content_filter"
)

// itemOutputText is the output-item kind carrying assistant text.
const itemOutputText = "output_text"

// ErrNoResponse is returned when the provider answers with nothing at all —
// distinct from an empty answer, which is a Completion with empty Text.
var ErrNoResponse = errors.New("agent: model returned no response")

// applyModelParams sets the parameters that differ between the two families.
//
// On Responses both budget with `max_output_tokens`, so the fork is down to the
// two things that genuinely differ: a reasoning model takes an effort and
// refuses a temperature, and a sampling model the other way round.
func applyModelParams(params *responses.ResponseNewParams, m Model) {
	if m.JSONObject {
		// The provider enforces it. `instructions` still says what the object
		// should CONTAIN; this only guarantees that what comes back parses.
		params.Text = responses.ResponseTextConfigParam{
			Format: responses.ResponseFormatTextConfigUnionParam{
				OfJSONObject: &shared.ResponseFormatJSONObjectParam{},
			},
		}
	}
	// A negative budget means NO CAP: the field is omitted and the provider's
	// own default applies. Omitting is the only way to say it — every number,
	// including a very large one, is still a cap, and a caller whose answer
	// size is variable cannot pick one honestly.
	noCap := m.MaxTokens < 0

	if IsReasoningModel(m.ID) {
		if !noCap {
			// The headroom is needed because reasoning and answer share ONE
			// budget, so the cap has to cover both or the answer is truncated
			// by thinking.
			params.MaxOutputTokens = openai.Int(m.MaxTokens + reasoningHeadroom(m.MaxTokens))
		}
		if m.Effort != "" {
			params.Reasoning = shared.ReasoningParam{Effort: shared.ReasoningEffort(m.Effort)}
		}
		// No Temperature: rejected outright. No Seed either — and on this API
		// that is not a choice we are making. The Responses API carries NO seed
		// field at all, for either family; a caller who needs determinism has
		// temperature and their own de-duplication, and nothing here can add a
		// third.
		return
	}
	if !noCap {
		params.MaxOutputTokens = openai.Int(m.MaxTokens)
	}
	if m.Temperature != nil {
		params.Temperature = openai.Float(*m.Temperature)
	}
}

// Complete runs one model call and returns the whole answer.
//
// `instructions` is the system prompt. On Responses it is a field of its own
// rather than a message at the head of the list, which is where it belonged all
// along — the history is then only what was actually said.
func Complete(ctx context.Context, client Completer, m Model, instructions string, history []Message) (*Completion, error) {
	if client == nil {
		return nil, errors.New("agent: no model client")
	}
	params, err := paramsFor(m, instructions, history)
	if err != nil {
		return nil, err
	}

	res, err := client.New(ctx, *params)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, ErrNoResponse
	}
	return &Completion{
		Text:             textOf(res),
		Status:           string(res.Status),
		IncompleteReason: res.IncompleteDetails.Reason,
		Usage:            usageFrom(res),
	}, nil
}

// inputFrom turns the caller's history into provider input items.
func inputFrom(history []Message) []responses.ResponseInputItemUnionParam {
	out := make([]responses.ResponseInputItemUnionParam, 0, len(history))
	for _, msg := range history {
		role := responses.EasyInputMessageRoleUser
		if msg.Assistant {
			role = responses.EasyInputMessageRoleAssistant
		}
		out = append(out, responses.ResponseInputItemParamOfMessage(msg.Text, role))
	}
	return out
}

func textOf(res *responses.Response) string {
	var b strings.Builder
	for _, item := range res.Output {
		for _, part := range item.Content {
			if part.Type == itemOutputText {
				b.WriteString(part.Text)
			}
		}
	}
	return b.String()
}

func usageFrom(res *responses.Response) Usage {
	u := res.Usage
	return Usage{
		Model: res.Model,
		// A call the provider reported nothing for stays Measured:false.
		Measured:          u.TotalTokens != 0,
		InputTokens:       u.InputTokens,
		OutputTokens:      u.OutputTokens,
		TotalTokens:       u.TotalTokens,
		CachedInputTokens: u.InputTokensDetails.CachedTokens,
		ReasoningTokens:   u.OutputTokensDetails.ReasoningTokens,
	}
}

// ProviderFault summarises a provider error for a caller who must not see the
// whole of it.
//
// The full text names the deployment URL and carries the response body, which
// on some failures quotes the prompt — neither belongs in an answer travelling
// back to whoever asked. But the provider's own CLASSIFICATION does: an HTTP
// status, its error type and code, and `param`, which names the request field
// it objected to.
//
// Returning nothing but "the model call failed" was the previous behaviour,
// and the comment justifying it claimed the detail was in the bundle's logs.
// Nothing logged it. A consumer bisected a one-field regression with two PAID
// runs against a live model because the failure named neither the field nor
// the status — so the summary is now built here, where the provider's type is
// known, and the full error is logged by the caller.
func ProviderFault(err error) (summary string, ok bool) {
	var apiErr *openai.Error
	if !errors.As(err, &apiErr) {
		return "", false
	}
	parts := make([]string, 0, 4)
	if apiErr.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", apiErr.StatusCode))
	}
	if apiErr.Type != "" {
		parts = append(parts, apiErr.Type)
	}
	if apiErr.Code != "" {
		parts = append(parts, "code "+apiErr.Code)
	}
	if apiErr.Param != "" {
		// The field the provider objected to. This is the one that turns a
		// bisect into a reading.
		parts = append(parts, "param "+apiErr.Param)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ", "), true
}
