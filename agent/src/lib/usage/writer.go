// Package usage is the agent plugin's asynchronous usage writer.
//
// It lives in lib/ rather than handlers/ because lib/ is NOT staged into a
// bundle — it stays in the plugin's own module, so it may depend on whatever
// it needs without putting those dependencies into every consumer's bundle.
//
// The shape is a bounded queue with a flush on either size or age. Recording
// what a call cost is bookkeeping: losing some of it is survivable, and making
// a model call wait on a database write is not. So Record never blocks and
// never fails — and the two ways that can go wrong are counted rather than
// hidden.
package usage

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Event is what the writer queues. Deliberately the caller's vocabulary: the
// writer knows nothing about interning or SQL.
type Event struct {
	Scope             string
	Model             string
	Labels            map[string]string
	Measured          bool
	InputTokens       int64
	OutputTokens      int64
	CachedInputTokens int64
	ReasoningTokens   int64
	Status            int32
	StartedAt         time.Time
	DurationMs        int64
}

// Flusher persists one batch. It returns an error so the writer can COUNT
// failures; it cannot make the caller's model call fail, because by the time
// this runs that call has long since answered.
type Flusher interface {
	Flush(ctx context.Context, batch []Event) error
}

// Config bounds the queue and the wait.
type Config struct {
	// QueueSize caps what may be in flight. Reached, Record DROPS rather than
	// blocking: a full queue means persistence is behind, and the one thing
	// worse than losing bookkeeping is stalling the calls that produce it.
	QueueSize int
	// BatchSize flushes as soon as this many events are queued.
	BatchSize int
	// FlushInterval flushes a partial batch this often, so a quiet service
	// still records what little it did rather than holding it indefinitely.
	FlushInterval time.Duration
	// FlushTimeout bounds one flush attempt.
	FlushTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.QueueSize <= 0 {
		c.QueueSize = 4096
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 64
	}
	if c.FlushInterval <= 0 {
		c.FlushInterval = 5 * time.Second
	}
	if c.FlushTimeout <= 0 {
		c.FlushTimeout = 30 * time.Second
	}
	return c
}

// Stats is what the writer could not do. Both counters exist because a usage
// layer that silently loses rows reproduces, one level down, the exact
// confusion it was built to remove: spend that happened and was never
// recorded, indistinguishable from spend that never happened.
type Stats struct {
	// Dropped — events Record threw away because the queue was full.
	Dropped uint64
	// FailedBatches — flushes the Flusher returned an error for.
	FailedBatches uint64
	// FailedEvents — events in those batches.
	FailedEvents uint64
	// Written — events a flush accepted.
	Written uint64
}

// Writer is the queue. The zero value is not usable; call New.
type Writer struct {
	cfg     Config
	flusher Flusher
	ch      chan Event

	dropped       atomic.Uint64
	failedBatches atomic.Uint64
	failedEvents  atomic.Uint64
	written       atomic.Uint64

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// New starts the writer's loop. Call Close to drain it.
func New(cfg Config, f Flusher) *Writer {
	cfg = cfg.withDefaults()
	w := &Writer{
		cfg:     cfg,
		flusher: f,
		ch:      make(chan Event, cfg.QueueSize),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go w.loop()
	return w
}

// Record queues one event. Never blocks, never fails: a full queue increments
// Dropped and returns.
func (w *Writer) Record(ev Event) {
	select {
	case w.ch <- ev:
	default:
		w.dropped.Add(1)
	}
}

// Stats reports what could not be done, for a caller that wants to alarm on it.
func (w *Writer) Stats() Stats {
	return Stats{
		Dropped:       w.dropped.Load(),
		FailedBatches: w.failedBatches.Load(),
		FailedEvents:  w.failedEvents.Load(),
		Written:       w.written.Load(),
	}
}

// Close stops the loop and flushes what is queued, bounded by ctx. Safe to
// call more than once.
func (w *Writer) Close(ctx context.Context) {
	w.stopOnce.Do(func() { close(w.stop) })
	select {
	case <-w.done:
	case <-ctx.Done():
		// The deadline is the caller's; a shutdown that hangs on bookkeeping
		// is worse than one that loses a batch of it.
	}
	// One line at teardown saying what was and was not recorded. Silence here
	// is indistinguishable from a quiet month, which is the failure this whole
	// layer exists to make impossible.
	if st := w.Stats(); st.Dropped > 0 || st.FailedEvents > 0 {
		log.Printf("agent usage: %d event(s) written, %d dropped (queue full), %d lost in %d failed flush(es)",
			st.Written, st.Dropped, st.FailedEvents, st.FailedBatches)
	}
}

func (w *Writer) loop() {
	defer close(w.done)
	ticker := time.NewTicker(w.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]Event, 0, w.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), w.cfg.FlushTimeout)
		err := w.flusher.Flush(ctx, batch)
		cancel()
		if err != nil {
			w.failedBatches.Add(1)
			w.failedEvents.Add(uint64(len(batch)))
			// SAY so. The counters existed and nothing read them, so the only
			// way to learn that a bill had a hole in it was to query the table
			// and find it empty — which is what a consumer did, after
			// hundreds of calls, with no error anywhere. A best-effort layer
			// may lose a batch; it may not lose it quietly.
			log.Printf("agent usage: flush of %d event(s) failed: %v (%d batch(es) lost so far)",
				len(batch), err, w.failedBatches.Load())
		} else {
			w.written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case ev := <-w.ch:
			batch = append(batch, ev)
			if len(batch) >= w.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-w.stop:
			// Drain what is already queued before the last flush — events
			// accepted by Record have been counted as neither written nor
			// dropped, and leaving them in the channel makes them vanish
			// without appearing in either number.
			for {
				select {
				case ev := <-w.ch:
					batch = append(batch, ev)
					if len(batch) >= w.cfg.BatchSize {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			return
		}
	}
}
