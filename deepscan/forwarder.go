package deepscan

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds Forwarder settings. Zero values get sane defaults in
// NewForwarder.
type Config struct {
	// QueueCapacity bounds the in-memory task queue. When full, Enqueue drops
	// the task and counts it (never blocks). Default 256 — deliberately smaller
	// than intake's queue because each task holds a full prompt, so worst-case
	// memory ≈ QueueCapacity × average prompt size.
	QueueCapacity int

	// SendTimeout bounds a single Sink.Send so a wedged endpoint can't stall
	// the worker forever. Default 2s. (Even an unbounded stall would only fill
	// the queue → drop, never block the hot path — this just bounds recovery.)
	SendTimeout time.Duration
}

// Forwarder is the background deep-scan forwarding goroutine.
//
// Lifecycle: NewForwarder → Start → Enqueue (many) → Close.
type Forwarder struct {
	cfg  Config
	sink Sink

	queue  chan task
	stopCh chan struct{}
	doneCh chan struct{}

	// Metrics — atomics, safe to read from any goroutine (e.g. /status).
	enqueued  atomic.Uint64
	dropped   atomic.Uint64
	forwarded atomic.Uint64
	failed    atomic.Uint64

	closeOnce sync.Once
}

// task is one queued deep-scan unit: the raw prompt + a snapshot of the fast
// layer's spans (already projected off engine structs by the caller, so we
// retain no Finding references and no Evidence).
type task struct {
	prompt string
	spans  []Span
}

// NewForwarder returns a configured (but not started) Forwarder that writes to
// sink. Call Start to begin the background loop.
func NewForwarder(cfg Config, sink Sink) *Forwarder {
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 256
	}
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = 2 * time.Second
	}
	return &Forwarder{
		cfg:    cfg,
		sink:   sink,
		queue:  make(chan task, cfg.QueueCapacity),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Start launches the background forwarding goroutine. Call exactly once.
func (f *Forwarder) Start() {
	go f.loop()
}

// Enqueue queues one deep-scan task. It NEVER blocks: if the queue is full
// (receiver slow / down), the task is dropped and counted. Safe to call on a nil
// *Forwarder (deep-scan disabled) — it's a no-op, so callers don't need to branch.
//
// 🔴 The signature takes []Span, not the detector's []types.Finding, because this
// package is imported by aikey-proxy and mirrored by ai-compliance-workers and
// must depend on nothing but the standard library. The detector keeps its
// findings→Span projection in its own thin wrapper (internal/deepscan), which is
// the only place that has ever needed it.
//
// spans MUST already be in the RAW prompt frame (the caller remaps normalized
// offsets first) so their offsets index prompt.
func (f *Forwarder) Enqueue(prompt string, spans []Span) {
	if f == nil {
		return
	}
	t := task{prompt: prompt, spans: spans}
	select {
	case f.queue <- t:
		f.enqueued.Add(1)
	default:
		f.dropped.Add(1)
	}
}

// Close signals shutdown, drains/forwards what's queued (best-effort), and
// waits for the worker to exit — bounded by ctx so process shutdown isn't held
// up by a wedged endpoint. Safe to call on a nil *Forwarder.
func (f *Forwarder) Close(ctx context.Context) error {
	if f == nil {
		return nil
	}
	f.closeOnce.Do(func() { close(f.stopCh) })
	select {
	case <-f.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats snapshots the forwarder counters for /status / debug / tests.
type Stats struct {
	Enqueued  uint64
	Dropped   uint64
	Forwarded uint64
	Failed    uint64
	QueueLen  int
}

func (f *Forwarder) Stats() Stats {
	if f == nil {
		return Stats{}
	}
	return Stats{
		Enqueued:  f.enqueued.Load(),
		Dropped:   f.dropped.Load(),
		Forwarded: f.forwarded.Load(),
		Failed:    f.failed.Load(),
		QueueLen:  len(f.queue),
	}
}

// loop is the background worker: one task at a time (deep-scan is best-effort,
// and single-flight keeps the Sink connection simple). It exits when stopCh
// closes, draining whatever is still queued first, then closes the sink.
func (f *Forwarder) loop() {
	defer close(f.doneCh)
	defer func() { _ = f.sink.Close() }()

	for {
		select {
		case <-f.stopCh:
		drain:
			for {
				select {
				case t := <-f.queue:
					f.forward(t)
				default:
					break drain
				}
			}
			return
		case t := <-f.queue:
			f.forward(t)
		}
	}
}

// forward encodes one task and writes it to the sink, bounded by SendTimeout.
// Failures are counted + logged to stderr (matching the detector's logging
// convention) and swallowed — a dead deep-scan must never crash or stall the
// detector.
func (f *Forwarder) forward(t task) {
	body, err := EncodePayloadV1(t.prompt, t.spans)
	if err != nil {
		f.failed.Add(1)
		fmt.Fprintf(os.Stderr, "warn: deepscan encode failed: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.cfg.SendTimeout)
	defer cancel()
	if err := f.sink.Send(ctx, encodeFrame(body)); err != nil {
		f.failed.Add(1)
		fmt.Fprintf(os.Stderr, "warn: deepscan forward failed: %v\n", err)
		return
	}
	f.forwarded.Add(1)
}
