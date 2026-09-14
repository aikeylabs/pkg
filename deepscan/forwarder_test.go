package deepscan

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingSink blocks each Send until ctx fires — simulates a slow/wedged
// deep-scan endpoint. Used to prove the hot path (Enqueue) never blocks on it.
type blockingSink struct{ sends atomic.Int64 }

func (s *blockingSink) Send(ctx context.Context, _ []byte) error {
	s.sends.Add(1)
	<-ctx.Done()
	return ctx.Err()
}
func (s *blockingSink) Close() error { return nil }

// errorSink fails every Send immediately — simulates a deep-scan that's up but
// rejecting. Proves the worker keeps draining and never deadlocks.
type errorSink struct{}

func (errorSink) Send(context.Context, []byte) error { return errors.New("sink down") }
func (errorSink) Close() error                       { return nil }

// countingSink accepts every Send. Proves drain-on-close forwards everything.
type countingSink struct{ count atomic.Int64 }

func (s *countingSink) Send(context.Context, []byte) error { s.count.Add(1); return nil }
func (s *countingSink) Close() error                       { return nil }

// Enqueue must drop (not block, not grow) once the bounded queue is full. With
// no worker started, the queue fills to capacity and every extra Enqueue drops.
func TestForwarder_EnqueueDropsWhenFull(t *testing.T) {
	const cap, extra = 4, 6
	f := NewForwarder(Config{QueueCapacity: cap}, &countingSink{})
	for i := 0; i < cap+extra; i++ {
		f.Enqueue("prompt", nil)
	}
	st := f.Stats()
	if st.Enqueued != cap {
		t.Errorf("enqueued = %d, want %d (capacity)", st.Enqueued, cap)
	}
	if st.Dropped != extra {
		t.Errorf("dropped = %d, want %d", st.Dropped, extra)
	}
}

// The I3 core assertion: even with the worker stuck on a blocking Send, every
// Enqueue returns ~instantly. Enqueue is a pure channel op — it must be fully
// decoupled from sink latency.
func TestForwarder_EnqueueNeverBlocksWhileSinkStuck(t *testing.T) {
	sink := &blockingSink{}
	f := NewForwarder(Config{QueueCapacity: 8, SendTimeout: 500 * time.Millisecond}, sink)
	f.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = f.Close(ctx)
	})

	for i := 0; i < 100; i++ {
		start := time.Now()
		f.Enqueue("prompt", nil)
		if d := time.Since(start); d > 20*time.Millisecond {
			t.Fatalf("Enqueue blocked %v on iter %d (must be ~instant regardless of sink)", d, i)
		}
	}
	if st := f.Stats(); st.Dropped == 0 {
		t.Errorf("expected drops with a stuck sink, got %+v", st)
	}
}

// A sink that errors on every Send must not deadlock the worker; Close drains
// and returns promptly, and every task is counted as failed.
func TestForwarder_SinkErrorNoDeadlock(t *testing.T) {
	const n = 10
	f := NewForwarder(Config{QueueCapacity: 16}, errorSink{})
	f.Start()
	for i := 0; i < n; i++ {
		f.Enqueue("prompt", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.Close(ctx); err != nil {
		t.Fatalf("Close = %v (worker deadlocked on erroring sink?)", err)
	}
	if st := f.Stats(); st.Failed != n {
		t.Errorf("failed = %d, want %d", st.Failed, n)
	}
}

// Close drains the queue: every enqueued task reaches the sink, none lost.
func TestForwarder_CloseDrainsAll(t *testing.T) {
	const n = 20
	sink := &countingSink{}
	f := NewForwarder(Config{QueueCapacity: 64}, sink)
	f.Start()
	for i := 0; i < n; i++ {
		f.Enqueue("prompt", nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := f.Close(ctx); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if st := f.Stats(); st.Forwarded != n {
		t.Errorf("forwarded = %d, want %d (drain lost tasks?)", st.Forwarded, n)
	}
	if got := sink.count.Load(); got != int64(n) {
		t.Errorf("sink received %d, want %d", got, n)
	}
}

// A nil *Forwarder (deep-scan disabled) must be safe for every method so
// callers never branch.
func TestForwarder_NilSafe(t *testing.T) {
	var f *Forwarder
	f.Enqueue("prompt", nil) // must not panic
	if err := f.Close(context.Background()); err != nil {
		t.Errorf("nil Close = %v, want nil", err)
	}
	if st := f.Stats(); st != (Stats{}) {
		t.Errorf("nil Stats = %+v, want zero", st)
	}
}

// Close is idempotent / ctx-bounded: a second Close (or one racing the worker)
// must not panic on a double channel close.
func TestForwarder_CloseIdempotent(t *testing.T) {
	f := NewForwarder(Config{}, &countingSink{})
	f.Start()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = f.Close(ctx)
		}()
	}
	wg.Wait()
}
