package usage

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"
	"time"
)

// An event recorded AFTER Close — a call finishing while the bundle shuts down —
// used to go into the channel the loop had already drained and stopped reading:
// counted as neither written nor dropped, and absent from the teardown line. It
// is now counted as dropped, which is what it is.
func TestRecordAfterCloseIsCountedNotLost(t *testing.T) {
	f := newRecordingFlusher()
	w := New(Config{BatchSize: 100, FlushInterval: time.Hour}, f)
	w.Record(Event{Scope: "tenant-a"})
	w.Close(context.Background())

	w.Record(Event{Scope: "tenant-a"})
	w.Record(Event{Scope: "tenant-b"})

	st := w.Stats()
	if st.Written != 1 || st.Dropped != 2 {
		t.Errorf("stats = %+v, want 1 written and the 2 late events dropped — every event must land in exactly one counter", st)
	}
	if got := f.total(); got != 1 {
		t.Errorf("flushed %d events, want 1", got)
	}
}

// Record racing Close: every event ends up in exactly one counter, however the
// two interleave. Run under -race this is also the data-race check for the
// closed flag.
func TestRecordRacingCloseLosesNothingUncounted(t *testing.T) {
	for round := 0; round < 20; round++ {
		f := newRecordingFlusher()
		w := New(Config{QueueSize: 10000, BatchSize: 7, FlushInterval: time.Hour}, f)
		const writers, each = 8, 50
		var wg sync.WaitGroup
		for i := 0; i < writers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < each; j++ {
					w.Record(Event{Scope: "tenant-a"})
				}
			}()
		}
		w.Close(context.Background())
		wg.Wait()
		st := w.Stats()
		if got := st.Written + st.Dropped; got != writers*each {
			t.Fatalf("round %d: written %d + dropped %d = %d of %d — the rest vanished uncounted",
				round, st.Written, st.Dropped, got, writers*each)
		}
		if uint64(f.total()) != st.Written {
			t.Fatalf("round %d: flusher saw %d, Written says %d", round, f.total(), st.Written)
		}
	}
}

// partialFlusher writes all but `fail` events of every batch.
type partialFlusher struct {
	fail  int
	calls chan struct{}
}

func (p *partialFlusher) Flush(_ context.Context, batch []Event) error {
	defer func() { p.calls <- struct{}{} }()
	return &PartialFlushError{Failed: p.fail, Err: errors.New("scope too long")}
}

// A flusher that wrote PART of a batch says how much, and the counters follow:
// the rows that landed are Written, only the rest are FailedEvents.
func TestAPartialFlushCountsOnlyWhatFailed(t *testing.T) {
	p := &partialFlusher{fail: 1, calls: make(chan struct{}, 4)}
	w := New(Config{BatchSize: 3, FlushInterval: time.Hour}, p)
	for i := 0; i < 3; i++ {
		w.Record(Event{Scope: "tenant-a"})
	}
	<-p.calls
	w.Close(context.Background())

	st := w.Stats()
	if st.Written != 2 || st.FailedEvents != 1 || st.FailedBatches != 1 {
		t.Errorf("stats = %+v, want 2 written, 1 failed event in 1 failed batch", st)
	}
}

// A Flusher that claims more failures than its batch held is not believed:
// the whole batch counts as failed, never a negative Written.
func TestAnImpossiblePartialCountFallsBackToTheWholeBatch(t *testing.T) {
	p := &partialFlusher{fail: 99, calls: make(chan struct{}, 4)}
	w := New(Config{BatchSize: 2, FlushInterval: time.Hour}, p)
	w.Record(Event{})
	w.Record(Event{})
	<-p.calls
	w.Close(context.Background())
	if st := w.Stats(); st.Written != 0 || st.FailedEvents != 2 {
		t.Errorf("stats = %+v, want the whole batch of 2 failed", st)
	}
}

// A flush that hangs must not hang teardown: Close is bounded by its context.
func TestCloseIsBoundedByItsContext(t *testing.T) {
	b := &blockingFlusher{release: make(chan struct{})}
	defer close(b.release)
	w := New(Config{BatchSize: 1, FlushInterval: time.Hour}, b)
	w.Record(Event{})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	w.Close(ctx)
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("Close took %v with a hung flusher — teardown waited on bookkeeping", took)
	}
	// Twice is safe.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel2()
	w.Close(ctx2)
}

// Teardown SAYS what was lost — silence is indistinguishable from a quiet month.
func TestCloseReportsLossInOneLine(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	f := newRecordingFlusher()
	f.err = errors.New("db down")
	w := New(Config{QueueSize: 1, BatchSize: 100, FlushInterval: time.Hour}, f)
	w.Record(Event{})
	w.Record(Event{}) // queue of 1: dropped, unless the loop already took the first
	w.Close(context.Background())

	st := w.Stats()
	if st.FailedEvents == 0 {
		t.Fatalf("stats = %+v", st)
	}
	out := buf.String()
	if !strings.Contains(out, "agent usage:") || !strings.Contains(out, "lost in") {
		t.Errorf("teardown did not report the loss:\n%s", out)
	}
}

// A clean run says nothing at teardown.
func TestCloseIsQuietWhenNothingWasLost(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	w := New(Config{}, newRecordingFlusher())
	w.Record(Event{})
	w.Close(context.Background())
	if buf.Len() != 0 {
		t.Errorf("a loss-free teardown logged:\n%s", buf.String())
	}
	if st := w.Stats(); st.Written != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestConfigDefaults(t *testing.T) {
	c := Config{}.withDefaults()
	if c.QueueSize != 4096 || c.BatchSize != 64 || c.FlushInterval != 5*time.Second || c.FlushTimeout != 30*time.Second {
		t.Errorf("defaults = %+v", c)
	}
	c = Config{QueueSize: 1, BatchSize: 2, FlushInterval: time.Second, FlushTimeout: time.Second}.withDefaults()
	if c.QueueSize != 1 || c.BatchSize != 2 {
		t.Errorf("stated values were overridden: %+v", c)
	}
}

// The flush runs under its own deadline, not without one: a flusher that waits
// on ctx is released by FlushTimeout.
func TestAFlushHasADeadline(t *testing.T) {
	got := make(chan bool, 1)
	f := flusherFunc(func(ctx context.Context, _ []Event) error {
		_, has := ctx.Deadline()
		<-ctx.Done()
		got <- has
		return ctx.Err()
	})
	w := New(Config{BatchSize: 1, FlushInterval: time.Hour, FlushTimeout: 50 * time.Millisecond}, f)
	w.Record(Event{})
	select {
	case has := <-got:
		if !has {
			t.Error("the flush context had no deadline")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the flush was never released by FlushTimeout")
	}
	w.Close(context.Background())
	if st := w.Stats(); st.FailedEvents != 1 {
		t.Errorf("a timed-out flush was not counted: %+v", st)
	}
}

type flusherFunc func(context.Context, []Event) error

func (f flusherFunc) Flush(ctx context.Context, b []Event) error { return f(ctx, b) }
