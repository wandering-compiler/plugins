package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v2"
	"github.com/openai/openai-go/v2/responses"
)

// maxStreamOutput caps accumulated streamed text. A model that loops produces
// tokens until something stops it, and the deadline is a poor stop: it arrives
// after the tokens are paid for.
const maxStreamOutput = 20000

// The stream events this layer reads. Everything else the Responses API emits —
// the item and content-part lifecycle, refusal deltas, reasoning summaries — is
// real and deliberately ignored: this layer wants the text and how it ended.
// itemFunctionCall is the output-item kind carrying a tool call.
const itemFunctionCall = "function_call"

const (
	eventOutputTextDelta   = "response.output_text.delta"
	eventFunctionArgsDelta = "response.function_call_arguments.delta"
	eventCompleted         = "response.completed"
	eventIncomplete        = "response.incomplete"
	eventFailed            = "response.failed"
)

// ErrRunawayOutput is returned when a stream exceeds maxStreamOutput. Distinct
// from a truncated answer: the caller may want to keep a truncated one and must
// not keep this.
var ErrRunawayOutput = errors.New("agent: runaway model output")

// ErrNoTerminalEvent is returned when a stream ends without saying how.
var ErrNoTerminalEvent = errors.New("agent: the stream ended without a terminal event")

// CompleteStream runs one model call, forwarding content fragments through
// onDelta as they arrive, and returns the whole answer when it ends.
//
// onDelta is called from this goroutine, in order. Returning an error from it
// aborts the call — that is how a caller whose client has gone away stops
// paying for tokens nobody will read.
func CompleteStream(
	ctx context.Context,
	client StreamCompleter,
	m Model,
	instructions string,
	history []Message,
	onDelta func(string) error,
) (*Completion, error) {
	if client == nil {
		return nil, errors.New("agent: no model client")
	}
	if onDelta == nil {
		return nil, errors.New("agent: no delta sink — use Complete for a non-streaming call")
	}
	params, err := paramsFor(m, instructions, history)
	if err != nil {
		return nil, err
	}

	res, _, err := streamTurn(ctx, client, *params, onDelta)
	return res, err
}

// streamTurn is the SSE loop, shared by CompleteStream and the tool-calling
// loop. It streams text through onDelta and returns both the completion and any
// tool calls the model asked for — the two callers want different halves of the
// same read, and a second copy of this loop is how one of them would quietly
// stop matching the other.
func streamTurn(
	ctx context.Context,
	client StreamCompleter,
	params responses.ResponseNewParams,
	onDelta func(string) error,
) (*Completion, []toolCall, error) {
	stream := client.NewStreaming(ctx, params)
	// Release the SSE body on every path, including the early returns below.
	//
	// The close error is dropped deliberately: it reports trouble finishing
	// with a body we have already read everything we wanted from, and
	// returning it would replace a good answer — or a more informative failure
	// — with a plumbing detail nobody can act on.
	defer func() { _ = stream.Close() }()

	var content strings.Builder
	var final *responses.Response
	argsBytes := 0
	// How much of the content the stuck-model guard has already seen, so the
	// check runs on new output rather than on every fragment.
	checkedAt := 0

	for stream.Next() {
		ev := stream.Current()
		switch ev.Type {
		case eventOutputTextDelta:
			if ev.Delta == "" {
				continue
			}
			content.WriteString(ev.Delta)
			if content.Len() > maxStreamOutput {
				return nil, nil, fmt.Errorf("%w: %d bytes of content", ErrRunawayOutput, maxStreamOutput)
			}
			if onDelta != nil {
				if err := onDelta(ev.Delta); err != nil {
					return nil, nil, err
				}
			}
			// The stuck-model guard, and it runs AFTER the fragment has gone
			// out. What is on the wire cannot be recalled, and holding each
			// fragment back until the next one proved it innocent would put a
			// delay on every answer to save a tail on almost none.
			//
			// Stopping here does NOT fail the call: `final` stays nil, so
			// Status is empty, and the reader is given what was written before
			// the model got stuck. A looping answer is usually right up until
			// it starts looping, and throwing that away to report a clean
			// failure would serve us rather than the person who asked.
			//
			// What it costs: usage arrives on the terminal event, so a stopped
			// stream reports no tokens at all. Reading on to collect it would
			// mean paying for the loop we just refused.
			if content.Len()-checkedAt > repetitionCheckInterval {
				checkedAt = content.Len()
				if repeating(content.String()) {
					return &Completion{Text: content.String()}, nil, nil
				}
			}
		case eventFunctionArgsDelta:
			// The guard has to cover arguments too: a model streaming endless
			// arguments otherwise walks straight past a content-only cap. The
			// calls themselves are read off the finished response rather than
			// reassembled here — the Responses API hands them over whole.
			argsBytes += len(ev.Delta)
			if argsBytes > maxStreamOutput {
				return nil, nil, fmt.Errorf("%w: %d bytes of tool-call arguments", ErrRunawayOutput, maxStreamOutput)
			}
		case eventCompleted, eventIncomplete, eventFailed:
			// One of these ends every response. ev.Response is the whole object
			// — status, usage and every output item — so nothing has to be
			// stitched together from the fragments that preceded it.
			r := ev.Response
			final = &r
		}
	}
	if err := stream.Err(); err != nil {
		return nil, nil, err
	}
	if final == nil {
		// The stream ended without saying how. NOT treated as a finished
		// answer: an empty status is read as "nothing to object to", and that
		// is a licence this path has not earned — only the guard above may take
		// it, and it returns directly.
		return nil, nil, ErrNoTerminalEvent
	}
	return &Completion{
		// OUR accumulation, not the finished response's text. They agree,
		// except in the one case that matters: the answer is what the reader
		// was actually shown.
		Text:             content.String(),
		Status:           string(final.Status),
		IncompleteReason: final.IncompleteDetails.Reason,
		Usage:            usageFrom(final),
	}, toolCallsOf(final), nil
}

// toolCallsOf collects the function calls a finished response asked for, in the
// order the model put them in.
func toolCallsOf(res *responses.Response) []toolCall {
	var out []toolCall
	for _, item := range res.Output {
		if item.Type != itemFunctionCall {
			continue
		}
		out = append(out, toolCall{ID: item.CallID, Name: item.Name, Arguments: item.Arguments})
	}
	return out
}

// paramsFor builds the request both call paths share, so a parameter added for
// one cannot go missing from the other.
func paramsFor(m Model, instructions string, history []Message) (*responses.ResponseNewParams, error) {
	if strings.TrimSpace(m.ID) == "" {
		return nil, errors.New("agent: no model id")
	}
	// Zero is "unstated" and is the caller's to resolve before reaching here;
	// negative is a deliberate "no cap" and passes through.
	if m.MaxTokens == 0 {
		return nil, errors.New("agent: model has no token budget")
	}
	params := responses.ResponseNewParams{
		Model: m.ID,
		Input: responses.ResponseNewParamsInputUnion{OfInputItemList: inputFrom(history)},
		Store: openai.Bool(false),
	}
	if instructions != "" {
		params.Instructions = openai.String(instructions)
	}
	if err := checkJSONObjectPrecondition(m, instructions, history); err != nil {
		return nil, err
	}
	applyModelParams(&params, m)
	return &params, nil
}

// checkJSONObjectPrecondition refuses a JSON-object request the provider is
// documented to reject, BEFORE it costs a call.
//
// The provider's own note on this format: "the model will not generate JSON
// without a system or user message instructing it to do so", and its API
// enforces that by refusing a request whose prompt never says the word. The
// refusal arrives as a plain 400 with no hint of which field caused it.
//
// This plugin makes that trap easier to fall into than the older surface did:
// the system prompt travels in `instructions`, a field of its own, so a caller
// who put "reply with JSON" there has said it — and a caller who said it
// nowhere has a request that cannot succeed. Catching it here costs nothing
// and names the cause; the alternative is what a consumer actually got, which
// was an unexplained `Unavailable` bisected over two paid runs.
//
// Deliberately NARROW: it fires only when the word is absent everywhere. It is
// not a claim about what else may make this format fail on a given model or
// api-version — that answer now comes from the provider itself, quoted in the
// failure.
func checkJSONObjectPrecondition(m Model, instructions string, history []Message) error {
	if !m.JSONObject {
		return nil
	}
	if mentionsJSON(instructions) {
		return nil
	}
	for _, msg := range history {
		if mentionsJSON(msg.Text) {
			return nil
		}
	}
	return errors.New("agent: response_format JSON_OBJECT needs the prompt to ask for JSON — " +
		"the provider refuses this format unless the instructions or one of the messages says the word, " +
		"and it refuses with a bare 400 that names nothing. Say what the object should contain " +
		"(`reply with a JSON object of …`) in `instructions`")
}

// mentionsJSON reports whether a prompt asks for JSON, case-insensitively.
func mentionsJSON(s string) bool {
	return strings.Contains(strings.ToLower(s), "json")
}
