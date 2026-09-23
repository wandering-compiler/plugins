package llm

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openai/openai-go/v2/option"
	"github.com/openai/openai-go/v2/responses"
)

// fake is the reason Completer is an interface.
type fake struct {
	got responses.ResponseNewParams
	res *responses.Response
	err error
}

func (f *fake) New(_ context.Context, body responses.ResponseNewParams, _ ...option.RequestOption) (*responses.Response, error) {
	f.got = body
	return f.res, f.err
}

// The family table decides which parameters are legal, and the wrong set is a
// 400 rather than an ignored field. The dated-id rows are the ones an equality
// check would get wrong — a response carries `gpt-5-nano-2025-08-07` back.
func TestIsReasoningModel(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
	}{
		{"gpt-5.6-luna", true},
		{"gpt-5-nano-2025-08-07", true}, // dated id: prefix, not equality
		{"o1", true},
		{"o3-mini", true},
		{"o4", true},
		{"GPT-5", true},   // case
		{" gpt-5 ", true}, // whitespace
		// The -chat variants are ordinary sampling models despite sitting
		// inside a reasoning family. Getting this wrong sends a
		// reasoning_effort to a model that refuses it.
		{"gpt-5-chat", false},
		{"gpt-5.2-chat", false},
		{"gpt-4o", false},
		{"", false},
	} {
		if got := IsReasoningModel(tc.id); got != tc.want {
			t.Errorf("IsReasoningModel(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// A reasoning model gets headroom ON TOP of the caller's budget, because
// thinking and answering share one allowance — a cap covering only the answer
// would have the thinking truncate it.
func TestReasoningModelGetsHeadroomAndEffortButNoTemperature(t *testing.T) {
	temp := 0.7
	f := &fake{res: &responses.Response{}}
	_, err := Complete(context.Background(), f,
		Model{ID: "gpt-5.6-luna", MaxTokens: 1000, Effort: "medium", Temperature: &temp},
		"", []Message{{Text: "hi"}})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := f.got.MaxOutputTokens.Value; got != 1250 {
		t.Errorf("MaxOutputTokens = %d, want 1250 (1000 + a quarter)", got)
	}
	if got := string(f.got.Reasoning.Effort); got != "medium" {
		t.Errorf("Effort = %q, want medium", got)
	}
	// Temperature was SET by the caller and must not reach a reasoning model:
	// the provider rejects it outright.
	if f.got.Temperature.Valid() {
		t.Errorf("temperature %v was sent to a reasoning model, which refuses it", f.got.Temperature.Value)
	}
}

// The headroom is a fraction, so a large budget does not get a proportionally
// vast cushion.
func TestReasoningHeadroomIsCapped(t *testing.T) {
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "o3", MaxTokens: 100000, Effort: "low"}, "", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := f.got.MaxOutputTokens.Value; got != 101024 {
		t.Errorf("MaxOutputTokens = %d, want 101024 (capped cushion)", got)
	}
}

// A sampling model is the mirror: the budget verbatim, a temperature honoured,
// and no reasoning effort.
func TestSamplingModelGetsTemperatureAndNoEffort(t *testing.T) {
	temp := 0.3
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 500, Temperature: &temp}, "", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := f.got.MaxOutputTokens.Value; got != 500 {
		t.Errorf("MaxOutputTokens = %d, want 500 verbatim", got)
	}
	if got := f.got.Temperature.Value; got != 0.3 {
		t.Errorf("Temperature = %v, want 0.3", got)
	}
	if f.got.Reasoning.Effort != "" {
		t.Errorf("effort %q sent to a sampling model", f.got.Reasoning.Effort)
	}
}

// The conversation is not left on the provider's side. A second copy of it in
// somebody else's database is a liability, and this is the field that declines
// it — a silent flip would be invisible until somebody audited the vendor.
func TestNothingIsStoredProviderSide(t *testing.T) {
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 10}, "", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !f.got.Store.Valid() || f.got.Store.Value {
		t.Error("Store must be explicitly false — the transcript stays ours")
	}
}

// The system prompt is a FIELD, not the first message. History is then only
// what was actually said.
func TestInstructionsAreAFieldNotAMessage(t *testing.T) {
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 10}, "be terse",
		[]Message{{Text: "hello"}, {Assistant: true, Text: "hi"}}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := f.got.Instructions.Value; got != "be terse" {
		t.Errorf("Instructions = %q", got)
	}
	if n := len(f.got.Input.OfInputItemList); n != 2 {
		t.Errorf("input items = %d, want 2 — the system prompt must not be one of them", n)
	}
}

// A budget of zero is refused rather than defaulted: a silent default here is a
// quiet decision about somebody else's bill.
func TestRefusesAModelWithoutABudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    Model
	}{
		// Zero is UNSTATED and the caller's to resolve — a silent default here
		// would be a quiet decision about somebody else's bill. A NEGATIVE
		// value is deliberately absent from this list: it means "no cap" and
		// is tested below.
		{"no budget", Model{ID: "gpt-4o"}},
		{"no id", Model{MaxTokens: 10}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Complete(context.Background(), &fake{res: &responses.Response{}}, tc.m, "", nil); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := Complete(context.Background(), nil, Model{ID: "gpt-4o", MaxTokens: 10}, "", nil); err == nil {
		t.Error("accepted a nil client")
	}
}

// A provider that answers with nothing is distinct from one that answers with
// an empty string — the caller can retry the first and must not retry the
// second.
func TestNilResponseIsNotAnEmptyAnswer(t *testing.T) {
	_, err := Complete(context.Background(), &fake{res: nil},
		Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if !errors.Is(err, ErrNoResponse) {
		t.Errorf("err = %v, want ErrNoResponse", err)
	}
}

func TestProviderErrorIsReturned(t *testing.T) {
	want := errors.New("boom")
	if _, err := Complete(context.Background(), &fake{err: want},
		Model{ID: "gpt-4o", MaxTokens: 10}, "", nil); !errors.Is(err, want) {
		t.Errorf("err = %v, want the provider's", err)
	}
}

// Usage the provider did not report leaves Measured false, so a caller summing
// these can tell a free call from an unreported one. A zero row that claimed to
// be measured would understate a bill silently.
func TestUnreportedUsageIsNotMeasuredZero(t *testing.T) {
	c, err := Complete(context.Background(), &fake{res: &responses.Response{Model: "gpt-4o-2024"}},
		Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if c.Usage.Measured {
		t.Error("Measured true for a response the provider reported no usage for")
	}
	// The model the PROVIDER named, not the one asked for.
	if c.Usage.Model != "gpt-4o-2024" {
		t.Errorf("Usage.Model = %q, want the provider's answer", c.Usage.Model)
	}
}

// Status and reason survive to the caller. Without them a truncated answer is
// indistinguishable from a finished one, and gets stored as if it were.
func TestTruncationIsVisibleToTheCaller(t *testing.T) {
	res := &responses.Response{Status: StatusIncomplete}
	res.IncompleteDetails.Reason = ReasonMaxOutputTokens
	c, err := Complete(context.Background(), &fake{res: res},
		Model{ID: "gpt-4o", MaxTokens: 10}, "", nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if c.Status != StatusIncomplete || c.IncompleteReason != ReasonMaxOutputTokens {
		t.Errorf("status=%q reason=%q — a truncated answer must say so", c.Status, c.IncompleteReason)
	}
	if strings.TrimSpace(c.Text) != "" {
		t.Errorf("unexpected text %q", c.Text)
	}
}

// A negative budget means NO CAP: the field is omitted entirely and the
// provider's own default applies.
//
// Omitting is the only way to say it. Every number is still a cap, including a
// very large one, and a caller whose answer size is variable — fifty records in
// one reply — cannot pick one honestly. A consumer hit exactly that: their old
// code passed zero to mean "provider default", the plugin read zero as its own
// 4096, and they had to compute an estimate they described in their own code as
// a guess.
func TestANegativeBudgetOmitsTheCapEntirely(t *testing.T) {
	for _, id := range []string{"gpt-4o", "gpt-5.6-luna"} {
		t.Run(id, func(t *testing.T) {
			f := &fake{res: &responses.Response{}}
			if _, err := Complete(context.Background(), f,
				Model{ID: id, MaxTokens: -1}, "", nil); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if f.got.MaxOutputTokens.Valid() {
				t.Errorf("MaxOutputTokens was sent (%d) — a cap of any size is not \"no cap\"",
					f.got.MaxOutputTokens.Value)
			}
		})
	}
}

// Asking for JSON is a PROVIDER constraint, not a sentence in the prompt. An
// instruction is a request the model may decline; this is not.
func TestJSONObjectIsEnforcedByTheProvider(t *testing.T) {
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 100, JSONObject: true}, "answer as JSON", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if f.got.Text.Format.OfJSONObject == nil {
		t.Error("the JSON-object format was not sent — the guarantee is back to being a prompt")
	}
}

// …and a caller who does not ask for it gets prose, with no format field at all.
func TestNoFormatIsSentUnlessAsked(t *testing.T) {
	f := &fake{res: &responses.Response{}}
	if _, err := Complete(context.Background(), f,
		Model{ID: "gpt-4o", MaxTokens: 100}, "", nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if f.got.Text.Format.OfJSONObject != nil {
		t.Error("a JSON format was imposed on a caller who did not ask")
	}
}

// TestJSONObject_RefusedLocallyWhenThePromptNeverAsksForJSON — the provider
// refuses this format unless the prompt says the word, and refuses with a bare
// 400 that names nothing. A consumer paid for two runs to find out which field
// was at fault.
//
// The check is narrow on purpose: absent everywhere → refuse here, for free,
// naming the cause; present anywhere → send it, and whatever the provider
// then says about the model or the api-version is quoted back rather than
// guessed at.
func TestJSONObject_RefusedLocallyWhenThePromptNeverAsksForJSON(t *testing.T) {
	m := Model{ID: "gpt-4.1", MaxTokens: 256, JSONObject: true}

	_, err := paramsFor(m, "classify these transactions", []Message{{Text: "hello"}})
	if err == nil {
		t.Fatal("a JSON-object request whose prompt never says the word was sent — the provider refuses it and names nothing")
	}
	if !strings.Contains(err.Error(), "JSON") {
		t.Errorf("the refusal does not name the format: %v", err)
	}

	// The instructions saying it is enough — that is where a system prompt
	// lives on this API.
	if _, err := paramsFor(m, "reply with a JSON object", nil); err != nil {
		t.Errorf("instructions asking for JSON were refused: %v", err)
	}
	// So is a message saying it.
	if _, err := paramsFor(m, "classify", []Message{{Text: "answer in json please"}}); err != nil {
		t.Errorf("a message asking for JSON was refused: %v", err)
	}
	// And the check must not fire when the format was never requested.
	if _, err := paramsFor(Model{ID: "gpt-4.1", MaxTokens: 256}, "no json here", nil); err != nil {
		t.Errorf("a request that never asked for JSON was refused: %v", err)
	}
}
