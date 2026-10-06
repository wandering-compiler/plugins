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

// runSpend is what a run has spent so far, across turns.
//
// Measured is true only when EVERY turn that reached the provider reported its
// usage. It used to be true when ANY turn had: a run whose second turn's
// stream dropped before its terminal event was recorded measured=true with
// only the first turn's tokens — a floor presented as the full measure, which
// is exactly the "complete bill for tokens it actually spent" that `measured`
// exists to rule out. Now one unreported turn makes the whole run unmeasured,
// and the tokens that WERE reported are still summed: measured=false with
// non-zero tokens reads "at least this much", never "this much" and never
// "nothing".
type runSpend struct {
	total Usage
	// turns is how many turns were folded in; unreported is how many of them
	// the provider reported no usage for.
	turns      int
	unreported int
}

// add folds one turn's usage in. Call it once per turn that was SENT — a turn
// refused before the request (a preflight error) cost nothing and is not a
// turn.
//
// Model is the latest one the provider named — every turn of a run asks for the
// same model, so they differ only when the provider answers with a dated id.
func (r *runSpend) add(turn Usage) {
	r.turns++
	if !turn.Measured {
		r.unreported++
	}
	if turn.Model != "" {
		r.total.Model = turn.Model
	}
	r.total.InputTokens += turn.InputTokens
	r.total.OutputTokens += turn.OutputTokens
	r.total.TotalTokens += turn.TotalTokens
	r.total.CachedInputTokens += turn.CachedInputTokens
	r.total.ReasoningTokens += turn.ReasoningTokens
}

// usage is the run's total so far.
func (r *runSpend) usage() Usage {
	u := r.total
	u.Measured = r.turns > 0 && r.unreported == 0
	return u
}
