package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// Tool is one thing an agent may call.
//
// It carries no deps type parameter: a tool here is a call OUT of this process,
// so there is no shared mutable state for a deps bag to thread, and anything
// run-scoped travels in ctx.
type Tool interface {
	// Name is what the model calls. It must be stable: it travels into the
	// transcript, so renaming it mid-conversation makes earlier turns
	// unreadable.
	Name() string

	// Purpose tells the model what the tool is for and when to reach for it.
	// Named for who reads it — it is written for a model, which in practice
	// means it says when NOT to call the tool as well as when to.
	Purpose() string

	// Params is the JSON Schema of the arguments. Empty means no arguments.
	Params() json.RawMessage

	// Mutating reports whether the call has side effects.
	//
	// It is not documentation. Within one round the loop runs mutating tools
	// serially and FIRST, then read-only ones in parallel, so a read never
	// observes a half-applied write. Declaring a mutating tool read-only loses
	// that guarantee silently.
	Mutating() bool

	// Call runs the tool. args is the raw JSON the model produced and may be
	// invalid or carry unknown keys; the returned string is fed back to the
	// model as the result.
	Call(ctx context.Context, args string) (string, error)
}

// Limits bound one run.
type Limits struct {
	MaxTurns     int
	MaxToolCalls int
	MaxParallel  int
}

const (
	defaultMaxTurns = 6
	// defaultMaxParallel bounds how many read-only calls run at once.
	defaultMaxParallel = 8
	// defaultMaxToolCalls bounds the whole run's fan-out, and it is the one
	// that bounds work against the CALLER's database. Untrusted text reaches
	// the model, and a model told to "look up three hundred places" emits three
	// hundred calls in one round; MaxParallel bounds how many run at once, not
	// how many run. 24 is three rounds of a full parallel batch — more than any
	// sane turn and far less than a fan-out.
	defaultMaxToolCalls = 24
)

func (l Limits) maxTurns() int {
	if l.MaxTurns > 0 {
		return l.MaxTurns
	}
	return defaultMaxTurns
}

func (l Limits) maxParallel() int {
	if l.MaxParallel > 0 {
		return l.MaxParallel
	}
	return defaultMaxParallel
}

func (l Limits) maxToolCalls() int {
	if l.MaxToolCalls > 0 {
		return l.MaxToolCalls
	}
	return defaultMaxToolCalls
}

// ErrBudgetExhausted ends a run that has spent its allowance.
var ErrBudgetExhausted = errors.New("agent: budget exhausted")

// budget is what a run has spent. Shared, so a delegation tree cannot spend
// each of its branches' allowance in turn.
type budget struct {
	maxToolCalls int
	toolCalls    atomic.Int32
}

// reserve claims a whole round up front.
//
// Spending per call as each one executes means an over-budget round applies as
// many writes as the allowance covers — mutating tools run first — and then
// kills the run with an error the model never sees. Partial mutation,
// invisible, and re-applied by a retried turn.
func (b *budget) reserve(n int) error {
	if b.maxToolCalls <= 0 || n <= 0 {
		return nil
	}
	if total := b.toolCalls.Add(int32(n)); int(total) > b.maxToolCalls {
		return fmt.Errorf("%w: at most %d tool calls", ErrBudgetExhausted, b.maxToolCalls)
	}
	return nil
}

// fatalError marks an error that must end the RUN rather than become a tool
// result. A tool failing is information the model can act on; the loop's own
// failures are not.
type fatalError struct{ err error }

func (f fatalError) Error() string { return f.err.Error() }
func (f fatalError) Unwrap() error { return f.err }

// Fatal marks an error as ending the run. A Tool.Call that returns one stops
// everything — which is what a tool bridging to a caller who has gone away
// must do, because otherwise the loop keeps buying tokens for nobody.
func Fatal(err error) error { return fatalError{err} }

func isFatal(err error) bool {
	if err == nil {
		return false
	}
	var f fatalError
	return errors.As(err, &f)
}

// results collects tool output by index without the callers sharing a slice
// header across goroutines.
type results struct {
	mu   sync.Mutex
	out  []string
	errs []error
}

func newResults(n int) *results {
	return &results{out: make([]string, n), errs: make([]error, n)}
}

func (r *results) set(i int, out string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.out[i] = out
	r.errs[i] = err
}
