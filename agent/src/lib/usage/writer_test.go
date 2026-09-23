package usage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingFlusher struct {
	mu      sync.Mutex
	batches [][]Event
	err     error
	calls   chan struct{}
}

func newRecordingFlusher() *recordingFlusher {
	return &recordingFlusher{calls: make(chan struct{}, 64)}
}

func (f *recordingFlusher) Flush(_ context.Context, batch []Event) error {
	f.mu.Lock()
	cp := append([]Event(nil), batch...)
	f.batches = append(f.batches, cp)
	err := f.err
	f.mu.Unlock()
	select {
	case f.calls <- struct{}{}:
	default:
	}
	return err
}

func (f *recordingFlusher) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func TestFlushesOnBatchSize(t *testing.T) {
	f := newRecordingFlusher()
	w := New(Config{BatchSize: 3, FlushInterval: time.Hour}, f)
	defer w.Close(context.Background())

	for i := 0; i < 3; i++ {
		w.Record(Event{Scope: "t1"})
	}
	select {
	case <-f.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("a full batch did not flush — the size trigger is what keeps a busy service from holding spend in memory")
	}
	if got := f.total(); got != 3 {
		t.Errorf("flushed %d events, want 3", got)
	}
}

// The other trigger, and the one a quiet service depends on: without it a
// handful of calls would sit in the queue until the batch filled, which on a
// low-traffic tenant could be never.
func TestFlushesOnInterval(t *testing.T) {
	f := newRecordingFlusher()
	w := New(Config{BatchSize: 1000, FlushInterval: 50 * time.Millisecond}, f)
	defer w.Close(context.Background())

	w.Record(Event{Scope: "t1"})
	select {
	case <-f.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("a partial batch never flushed — a quiet service would record nothing")
	}
}

// Recording must never block a model call. A full queue is a real state (the
// database is behind), and the one thing worse than losing bookkeeping is
// stalling the calls that produce it.
func TestAFullQueueDropsRatherThanBlocks(t *testing.T) {
	blocked := make(chan struct{})
	f := &blockingFlusher{release: blocked}
	w := New(Config{QueueSize: 2, BatchSize: 1, FlushInterval: time.Hour}, f)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			w.Record(Event{Scope: "t1"})
		}
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Record blocked — a model call would now be waiting on bookkeeping")
	}
	close(blocked)
	w.Close(context.Background())

	if w.Stats().Dropped == 0 {
		t.Error("nothing was counted as dropped, yet the queue was far too small to hold 200 events — " +
			"silent loss is the confusion this layer exists to remove, one level down")
	}
}

type blockingFlusher struct{ release chan struct{} }

func (b *blockingFlusher) Flush(context.Context, []Event) error {
	<-b.release
	return nil
}

// A failing flush must be COUNTED, not swallowed. "Spend happened and was
// never recorded" has to stay distinguishable from "nothing was spent".
func TestAFailedFlushIsCounted(t *testing.T) {
	f := newRecordingFlusher()
	f.err = errors.New("db down")
	w := New(Config{BatchSize: 2, FlushInterval: time.Hour}, f)

	w.Record(Event{Scope: "t1"})
	w.Record(Event{Scope: "t1"})
	select {
	case <-f.calls:
	case <-time.After(2 * time.Second):
		t.Fatal("no flush attempt")
	}
	w.Close(context.Background())

	st := w.Stats()
	if st.FailedBatches == 0 || st.FailedEvents < 2 {
		t.Errorf("a failed flush was not counted: %+v", st)
	}
	if st.Written != 0 {
		t.Errorf("events the flusher rejected were counted as written: %+v", st)
	}
}

// Close drains. Events Record accepted are neither written nor dropped until
// they land, so leaving them in the channel would make them vanish from BOTH
// counters — untraceable loss, which is worse than loss you can see.
func TestCloseDrainsWhatWasAccepted(t *testing.T) {
	f := newRecordingFlusher()
	w := New(Config{BatchSize: 1000, FlushInterval: time.Hour}, f)

	for i := 0; i < 7; i++ {
		w.Record(Event{Scope: "t1"})
	}
	w.Close(context.Background())

	if got := f.total(); got != 7 {
		t.Errorf("Close flushed %d of 7 accepted events — the rest are in neither counter", got)
	}
	if st := w.Stats(); st.Written != 7 {
		t.Errorf("Written = %d, want 7: %+v", st.Written, st)
	}
}
