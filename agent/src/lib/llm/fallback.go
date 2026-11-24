package llm

import (
	"context"
	"errors"
	"fmt"

	"github.com/openai/openai-go/v2"
)

// Fallbackable reports whether a failed model call should be tried on the
// next model of the spec's fallbacks: the PROVIDER was rate-limited (429),
// failing (5xx, or a response it marked server_error / rate_limit_exceeded),
// or unreachable (a transport error). Not a request it refused — another 4xx
// would be refused by the next model too —, not a refusal before the request
// (preflight), not the caller's own context ending, and not one of the run's
// own limits.
func Fallbackable(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || IsPreflight(err) || isFatal(err) {
		return false
	}
	for _, own := range []error{ErrRunawayOutput, ErrBudgetExhausted, ErrTurnsExhausted, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, own) {
			return false
		}
	}
	var failed *failedResponseError
	if errors.As(err, &failed) {
		return failed.code == "server_error" || failed.code == "rate_limit_exceeded"
	}
	var apiErr *openai.Error
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 429 || apiErr.StatusCode >= 500
	}
	return true
}

// FallbackReason is the display-safe why of a fallback: the provider's
// classification, never its body (which can quote the prompt).
func FallbackReason(err error) string {
	var apiErr *openai.Error
	if errors.As(err, &apiErr) && apiErr.StatusCode == 429 {
		return "rate limited (HTTP 429)"
	}
	if s, ok := ProviderFault(err); ok {
		return s
	}
	return "connection failed"
}

// Attempts is the model and its fallbacks, in the order they are tried.
func (m Model) Attempts() []Model {
	out := []Model{m}
	for _, f := range m.Fallbacks {
		f.Fallbacks = nil
		out = append(out, f)
	}
	return out
}

// errNestedFallbacks refuses a fallback that names fallbacks of its own: one
// level, so the order of attempts is the list as written.
func checkFallbacks(m Model) error {
	for i, f := range m.Fallbacks {
		if len(f.Fallbacks) > 0 {
			return preflight(fmt.Sprintf("fallback %d (%q) has fallbacks of its own — list every model in the first spec's fallbacks", i+1, f.ID))
		}
		if f.ID == "" {
			return preflight(fmt.Sprintf("fallback %d names no model", i+1))
		}
	}
	return nil
}

// CheckFallbacks is checkFallbacks for a handler that runs the attempts
// itself (Complete, CompleteStream).
func CheckFallbacks(m Model) error { return checkFallbacks(m) }
