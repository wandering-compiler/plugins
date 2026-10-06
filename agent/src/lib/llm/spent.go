package llm

import (
	"errors"

	"github.com/openai/openai-go/v2/responses"
)

// StatusFailed is the provider's word for a response it gave up on. It arrives
// as a terminal event like any other — `response.failed` — and carries usage,
// which is why it cannot simply be treated as a transport error.
const StatusFailed = "failed"

// ErrResponseFailed is returned when the provider ends a response with status
// "failed".
//
// It used to come back as an ordinary answer: the stream's terminal event was
// read, its status copied into the Completion, and nothing objected — so the
// handler recorded an OK call and handed the caller a Finished event whose
// status was UNSPECIFIED and whose text was whatever arrived before the
// failure. A bill that marks a failed call OK and an answer that does not say
// it failed are the two things this layer exists to prevent.
var ErrResponseFailed = errors.New("agent: the provider reported the response as failed")

// failedResponse is the error for a failed response. The provider's CODE is
// kept — it is a fixed vocabulary (server_error, rate_limit_exceeded, …) — and
// its message is not, for the reason ProviderFault gives: provider text can
// quote the prompt.
type failedResponse struct{ code string }

func (f *failedResponse) Error() string {
	if f.code == "" {
		return ErrResponseFailed.Error()
	}
	return ErrResponseFailed.Error() + " (code " + f.code + ")"
}

func (f *failedResponse) Is(target error) bool { return target == ErrResponseFailed }

func responseFailed(r *responses.Response) error {
	return &failedResponse{code: string(r.Error.Code)}
}

// spentError is a failure that nevertheless SPENT tokens: a run that died on
// its third turn paid for the first two, and a failed response still reports
// its usage.
//
// The usage rides on the error rather than on a Completion returned beside it,
// because a non-nil Completion next to an error invites a caller to show it —
// and what it would show is a tool request or a failed answer.
type spentError struct {
	err   error
	usage Usage
}

func (e *spentError) Error() string { return e.err.Error() }
func (e *spentError) Unwrap() error { return e.err }

// withSpent attaches what was spent to err. Nothing is attached when nothing is
// known — no turn finished, so there is no usage to report — which keeps
// "unmeasured" the honest answer for a call that reached no terminal event.
func withSpent(err error, u Usage) error {
	if err == nil || (!u.Measured && u.Model == "") {
		return err
	}
	return &spentError{err: err, usage: u}
}

// SpentBy reports the usage a FAILED call still incurred, when the provider
// reported any. A caller recording spend reads it on the error path, where no
// Completion is returned.
func SpentBy(err error) (Usage, bool) {
	var s *spentError
	if errors.As(err, &s) {
		return s.usage, true
	}
	return Usage{}, false
}

// addUsage folds one turn's usage into a run's total.
//
// Measured is true when ANY turn was measured: a run whose last turn was cut
// short by the repetition guard still paid for the turns before it, and saying
// "unmeasured" would drop those from the bill entirely. The run's own outcome
// (UNKNOWN for a guard stop) is what tells a reader the total is a floor.
//
// Model is the latest one the provider named — every turn of a run asks for the
// same model, so they differ only when the provider answers with a dated id.
func addUsage(total, turn Usage) Usage {
	if turn.Model != "" {
		total.Model = turn.Model
	}
	total.Measured = total.Measured || turn.Measured
	total.InputTokens += turn.InputTokens
	total.OutputTokens += turn.OutputTokens
	total.TotalTokens += turn.TotalTokens
	total.CachedInputTokens += turn.CachedInputTokens
	total.ReasoningTokens += turn.ReasoningTokens
	return total
}
