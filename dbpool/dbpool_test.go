package dbpool

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// captureLogs collects slog output so a test can assert on what an operator
// would actually read, not on internal state.
type capture struct {
	mu    sync.Mutex
	lines []string
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *capture) WithGroup(string) slog.Handler            { return c }
func (c *capture) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Level.String() + " " + r.Message)
	r.Attrs(func(a slog.Attr) bool { b.WriteString(" " + a.Key + "=" + a.Value.String()); return true })
	c.mu.Lock()
	c.lines = append(c.lines, b.String())
	c.mu.Unlock()
	return nil
}
func (c *capture) all() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// === Pool exhaustion must be visible (需求 2026-08-24) ===
//
// The bound on the pool is deliberate; the SILENCE around it was not. A caller
// blocked acquiring a connection writes no response headers, so from outside the
// server looks like it accepted the connection and went quiet — which is exactly
// how the 2026-08-24 team-usage 502s presented (tcp_connect_ms=10,
// elapsed_ms=15011). Nothing in the system could confirm or refute pool
// exhaustion, because nothing reported it.
//
// This fence drives a REAL *sql.DB to a REAL exhaustion (MaxOpenConns=1, one
// connection held open while others queue) rather than asserting on a hand-made
// DBStats: the whole point is that the condition is observable through the same
// API a service actually has.
func exhaustedDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(1)
	return db, func() { _ = db.Close() }
}

func TestMonitor_ReportsRealExhaustion(t *testing.T) {
	db, done := exhaustedDB(t)
	defer done()
	cap := &capture{}
	m := New("test", db, slog.New(cap))

	// Hold the only connection, then make others queue for it.
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = db.Exec("SELECT 1") }()
	}
	// Give the waiters time to actually block inside the pool.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && db.Stats().WaitCount == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if db.Stats().WaitCount == 0 {
		t.Fatal("could not produce a real pool wait — the fence would prove nothing")
	}

	m.sample()

	if got := m.Status().Level; got != "CRIT" {
		t.Fatalf("exhausted pool reported %q, want CRIT", got)
	}
	logs := cap.all()
	for _, want := range []string{EventPoolExhausted, ErrCodePoolExhausted, "in_use=1", "max_open=1", "impact=", "remedy="} {
		if !strings.Contains(logs, want) {
			t.Errorf("log is missing %q; an operator holding a 502 report needs it\n%s", want, logs)
		}
	}

	// Release and confirm the recovery edge fires — an outage that starts and
	// never ends in the log cannot be measured.
	_ = tx.Rollback()
	wg.Wait()
	m.sample()
	if got := m.Status().Level; got == "CRIT" {
		t.Fatal("pool still reported CRIT after the holder released")
	}
	if !strings.Contains(cap.all(), EventPoolRecovered) {
		t.Errorf("no recovery line; the log shows an outage with no end\n%s", cap.all())
	}
}

// Anti-hollow control: a pool that is merely BUSY (at max, nobody queuing) is
// healthy. Reporting CRIT there would train operators to ignore the signal.
func TestMonitor_BusyButNotQueuingIsNotCritical(t *testing.T) {
	db, done := exhaustedDB(t)
	defer done()
	cap := &capture{}
	m := New("test", db, slog.New(cap))

	tx, err := db.Begin() // occupies the only connection; nobody waits
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	m.sample()
	if got := m.Status().Level; got == "CRIT" {
		t.Fatalf("a busy-but-unqueued pool must not be CRIT, got %q", got)
	}
	if strings.Contains(cap.all(), EventPoolExhausted) {
		t.Errorf("exhaustion reported without any caller queuing:\n%s", cap.all())
	}
}

// Status must not touch the database: a health endpoint has to stay answerable
// precisely while the pool is exhausted, which is when a query would block.
func TestMonitor_StatusDoesNotTouchTheDatabase(t *testing.T) {
	db, done := exhaustedDB(t)
	m := New("test", db, slog.New(&capture{}))
	done() // close the DB out from under it
	got := make(chan Status, 1)
	go func() { got <- m.Status() }()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("Status blocked on a closed database; a health endpoint would hang exactly when it is needed")
	}
}
